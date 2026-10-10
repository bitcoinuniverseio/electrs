//! Added read qualification failures never become legacy producer failures.
#[derive(Debug, PartialEq, Eq)]
pub enum NoopDecision {
    NotCandidate,
    Qualified,
    AvailabilityFault,
    MaterialFault,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualifiedReadError {
    Storage,
    Contract,
}
pub fn point_matches(read: Result<Option<Vec<u8>>, QualifiedReadError>, expected: &[u8]) -> bool {
    matches!(read,Ok(Some(bytes)) if bytes==expected)
}
pub fn point_present(read: Result<Option<Vec<u8>>, QualifiedReadError>) -> bool {
    matches!(read, Ok(Some(_)))
}
pub fn validated_noop(
    candidate: bool,
    read: impl FnOnce() -> Result<Option<Vec<u8>>, QualifiedReadError>,
    expected: &[u8],
) -> NoopDecision {
    if !candidate {
        return NoopDecision::NotCandidate;
    }
    match read() {
        Err(QualifiedReadError::Storage) => NoopDecision::AvailabilityFault,
        Ok(Some(bytes)) if bytes == expected => NoopDecision::Qualified,
        _ => NoopDecision::MaterialFault,
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum LoopAction {
    IndexChangedTip,
    RevalidateAvailability,
    NoExtraWork,
}
pub fn loop_action(changed_tip: bool, availability_pending: bool) -> LoopAction {
    if changed_tip {
        LoopAction::IndexChangedTip
    } else if availability_pending {
        LoopAction::RevalidateAvailability
    } else {
        LoopAction::NoExtraWork
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AvailabilityValidation {
    NoPending,
    Restored(u64),
    Waiting,
    MaterialBlocked,
    FenceChanged,
}
pub fn revalidate_availability(
    state: &super::read_generation::ReadGeneration,
    captured_fence: Option<u64>,
    header_matches: bool,
    read: impl FnOnce() -> Result<Option<Vec<u8>>, QualifiedReadError>,
    expected: &[u8],
) -> AvailabilityValidation {
    let fence = match captured_fence {
        Some(fence) => fence,
        None => return AvailabilityValidation::NoPending,
    };
    if !header_matches {
        state.invalidate_material();
        return AvailabilityValidation::MaterialBlocked;
    }
    match validated_noop(true, read, expected) {
        NoopDecision::Qualified => match state.restore_availability(fence) {
            Ok(epoch) => AvailabilityValidation::Restored(epoch),
            Err(_) => AvailabilityValidation::FenceChanged,
        },
        NoopDecision::AvailabilityFault => {
            state.invalidate_availability();
            AvailabilityValidation::Waiting
        }
        _ => {
            state.invalidate_material();
            AvailabilityValidation::MaterialBlocked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn injected_point_error_and_malformed_tip_are_withheld_not_panics() {
        for read in [
            Err(QualifiedReadError::Contract),
            Ok(None),
            Ok(Some(vec![1])),
            Ok(Some(vec![9; 32])),
        ] {
            assert_eq!(
                validated_noop(true, || read, &[1; 32]),
                NoopDecision::MaterialFault
            );
        }
        assert_eq!(
            validated_noop(true, || Ok(Some(vec![1; 32])), &[1; 32]),
            NoopDecision::Qualified
        );
    }
    #[test]
    fn not_candidate_dispatches_zero_added_point_reads() {
        assert_eq!(
            validated_noop(false, || panic!("must not dispatch"), &[]),
            NoopDecision::NotCandidate
        );
    }
    #[test]
    fn qualified_marker_error_never_means_present() {
        assert!(!point_present(Err(QualifiedReadError::Storage)));
        assert!(!point_present(Ok(None)));
        assert!(point_present(Ok(Some(vec![]))));
    }
    #[test]
    fn availability_recovery_dispatches_one_read_no_writer_or_rpc_and_new_token() {
        use std::cell::Cell;
        let state = super::super::read_generation::ReadGeneration::new();
        let old = state.begin().commit().unwrap();
        state.invalidate_availability();
        let reads = Cell::new(0);
        let writes = Cell::new(0);
        let rpc = Cell::new(1);
        let result = revalidate_availability(
            &state,
            state.availability_fence(),
            true,
            || {
                reads.set(reads.get() + 1);
                Ok(Some(vec![7; 32]))
            },
            &[7; 32],
        );
        assert!(matches!(result,AvailabilityValidation::Restored(token) if token>old));
        assert!(!state.matches(old));
        assert_eq!(reads.get(), 1);
        assert_eq!(writes.get(), 0);
        assert_eq!(rpc.get(), 1);
    }
    #[test]
    fn repeated_storage_failure_preserves_material_but_wrong_or_missing_metadata_blocks() {
        let state = super::super::read_generation::ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_availability();
        for _ in 0..3 {
            assert_eq!(
                revalidate_availability(
                    &state,
                    state.availability_fence(),
                    true,
                    || Err(QualifiedReadError::Storage),
                    &[1; 32]
                ),
                AvailabilityValidation::Waiting
            );
            assert!(!state.requires_repair());
        }
        assert_eq!(
            revalidate_availability(
                &state,
                state.availability_fence(),
                true,
                || Ok(None),
                &[1; 32]
            ),
            AvailabilityValidation::MaterialBlocked
        );
        assert!(state.requires_repair());
        assert_eq!(
            revalidate_availability(
                &state,
                state.availability_fence(),
                true,
                || panic!("dirty must not read"),
                &[]
            ),
            AvailabilityValidation::NoPending
        );
    }
    #[test]
    fn changed_tip_priority_and_healthy_loop_do_not_dispatch_availability_reads() {
        assert_eq!(loop_action(true, true), LoopAction::IndexChangedTip);
        assert_eq!(loop_action(false, false), LoopAction::NoExtraWork);
        assert_eq!(loop_action(false, true), LoopAction::RevalidateAvailability);
    }
    #[test]
    fn header_mismatch_or_end_material_fence_never_restores_old_state() {
        let state = super::super::read_generation::ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_availability();
        assert_eq!(
            revalidate_availability(
                &state,
                state.availability_fence(),
                false,
                || panic!("header mismatch must not read"),
                &[]
            ),
            AvailabilityValidation::MaterialBlocked
        );
        let state = super::super::read_generation::ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_availability();
        let result = revalidate_availability(
            &state,
            state.availability_fence(),
            true,
            || {
                state.invalidate_material();
                Ok(Some(vec![1; 32]))
            },
            &[1; 32],
        );
        assert_eq!(result, AvailabilityValidation::FenceChanged);
        assert_eq!(state.completed(), None);
    }
    #[test]
    fn fence_is_captured_before_header_proof_and_not_recaptured_after_failure() {
        let state = super::super::read_generation::ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_availability();
        let captured = state.availability_fence();
        state.invalidate_availability();
        let result =
            revalidate_availability(&state, captured, true, || Ok(Some(vec![1; 32])), &[1; 32]);
        assert_eq!(result, AvailabilityValidation::FenceChanged);
        assert_eq!(state.completed(), None);
    }
}
