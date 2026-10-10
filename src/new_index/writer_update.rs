//! Retained phases for the existing sole writer. No database or RPC owner here.
//! A plan is removed only after every phase and the persisted-tip fence succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Rollback,
    Reorg,
    Add,
    Index,
    Flush,
    PersistTip,
    Verify,
    Complete,
}

pub struct UpdatePlan<H, T> {
    pub target: T,
    pub headers: Vec<H>,
    pub reorged: Vec<H>,
    pub rollback_tip: Option<T>,
    pub phase: Phase,
}

/// Only the actual phase driver constructs this proof. Starting a new mutation
/// lease or seeing equal header tips cannot construct it.
pub struct CompletedPlan {
    _private: (),
}

pub trait UpdateWriter<H, T> {
    type Error;
    fn rollback(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn reorg(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn add(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn index(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn flush(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn persist_tip(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn verify(&mut self, plan: &UpdatePlan<H, T>) -> Result<(), Self::Error>;
    fn read_qualified(&self) -> bool {
        true
    }
}

pub fn finish_plan<H, T, W: UpdateWriter<H, T>>(
    writer: &mut W,
    plan: &mut UpdatePlan<H, T>,
) -> Result<CompletedPlan, W::Error> {
    loop {
        plan.phase = match plan.phase {
            Phase::Rollback => {
                writer.rollback(plan)?;
                Phase::Reorg
            }
            Phase::Reorg => {
                writer.reorg(plan)?;
                Phase::Add
            }
            Phase::Add => {
                writer.add(plan)?;
                Phase::Index
            }
            Phase::Index => {
                writer.index(plan)?;
                Phase::Flush
            }
            Phase::Flush => {
                writer.flush(plan)?;
                Phase::PersistTip
            }
            Phase::PersistTip => {
                writer.persist_tip(plan)?;
                Phase::Verify
            }
            Phase::Verify => {
                writer.verify(plan)?;
                Phase::Complete
            }
            Phase::Complete => return Ok(CompletedPlan { _private: () }),
        };
    }
}

/// Qualification-only faults discard read proof; only legacy producer errors
/// propagate through the original main-loop exit policy.
pub fn finish_qualified_plan<H, T, W: UpdateWriter<H, T>>(
    writer: &mut W,
    plan: &mut UpdatePlan<H, T>,
) -> Result<Option<CompletedPlan>, W::Error> {
    let proof = finish_plan(writer, plan)?;
    Ok(if writer.read_qualified() {
        Some(proof)
    } else {
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    #[derive(Default)]
    struct Writer {
        fail: Option<Phase>,
        calls: Vec<Phase>,
        added: HashSet<u8>,
        indexed: HashSet<u8>,
        removed: HashSet<u8>,
        persisted: Option<u8>,
        headers_tip: u8,
        qualification_read_error: bool,
        read_withheld: bool,
    }
    impl Writer {
        fn after_write(&mut self, phase: Phase) -> Result<(), &'static str> {
            self.calls.push(phase);
            if self.fail == Some(phase) {
                self.fail = None;
                Err("injected after write")
            } else {
                Ok(())
            }
        }
    }
    impl UpdateWriter<u8, u8> for Writer {
        type Error = &'static str;
        fn rollback(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            if !p.reorged.is_empty() {
                self.persisted = p.rollback_tip;
            }
            self.after_write(Phase::Rollback)
        }
        fn reorg(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            for h in &p.reorged {
                self.added.remove(h);
                self.indexed.remove(h);
                self.removed.insert(*h);
            }
            self.after_write(Phase::Reorg)
        }
        fn add(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            self.added.extend(p.headers.iter().copied());
            self.after_write(Phase::Add)
        }
        fn index(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            assert!(p.headers.iter().all(|h| self.added.contains(h)));
            self.indexed.extend(p.headers.iter().copied());
            self.after_write(Phase::Index)
        }
        fn flush(&mut self, _: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            self.after_write(Phase::Flush)
        }
        fn persist_tip(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            self.persisted = Some(p.target);
            self.after_write(Phase::PersistTip)
        }
        fn verify(&mut self, p: &UpdatePlan<u8, u8>) -> Result<(), Self::Error> {
            if self.qualification_read_error
                && !super::super::qualification::point_present(Err(
                    super::super::qualification::QualifiedReadError::Storage,
                ))
            {
                self.read_withheld = true;
                return Ok(());
            }
            if self.persisted != Some(p.target)
                || self.headers_tip != p.target
                || !p
                    .headers
                    .iter()
                    .all(|h| self.added.contains(h) && self.indexed.contains(h))
                || !p.reorged.iter().all(|h| self.removed.contains(h))
            {
                return Err("incomplete phases");
            }
            self.after_write(Phase::Verify)
        }
        fn read_qualified(&self) -> bool {
            !self.read_withheld
        }
    }
    fn plan(target: u8) -> UpdatePlan<u8, u8> {
        UpdatePlan {
            target,
            headers: vec![target],
            reorged: vec![9],
            rollback_tip: Some(1),
            phase: Phase::Rollback,
        }
    }
    #[test]
    fn every_failed_phase_retains_exact_work_and_retries_before_completion() {
        for phase in [
            Phase::Rollback,
            Phase::Reorg,
            Phase::Add,
            Phase::Index,
            Phase::Flush,
            Phase::PersistTip,
            Phase::Verify,
        ] {
            let mut writer = Writer {
                fail: Some(phase),
                headers_tip: 2,
                ..Writer::default()
            };
            let mut pending = plan(2);
            assert!(finish_plan(&mut writer, &mut pending).is_err());
            assert_eq!(pending.phase, phase);
            assert_eq!(pending.headers, vec![2]);
            assert_eq!(pending.reorged, vec![9]);
            finish_plan(&mut writer, &mut pending).unwrap();
            assert_eq!(pending.phase, Phase::Complete);
            assert_eq!(writer.calls.iter().filter(|p| **p == phase).count(), 2);
            assert!(writer.added.contains(&2) && writer.indexed.contains(&2));
            assert_eq!(writer.persisted, Some(2));
        }
    }
    #[test]
    fn unchanged_header_tip_never_replaces_failed_pending_work() {
        let mut writer = Writer {
            fail: Some(Phase::Index),
            headers_tip: 2,
            ..Writer::default()
        };
        let mut pending = plan(2);
        assert!(finish_plan(&mut writer, &mut pending).is_err());
        writer.indexed.clear(); // same tip, partial required database rows
        finish_plan(&mut writer, &mut pending).unwrap();
        assert!(writer.indexed.contains(&2));
        assert!(writer.calls.contains(&Phase::Reorg));
    }
    #[test]
    fn missing_marker_or_changed_anchor_refuses_completion() {
        let mut writer = Writer {
            headers_tip: 3,
            ..Writer::default()
        };
        let mut pending = plan(2);
        assert!(finish_plan(&mut writer, &mut pending).is_err());
        assert_eq!(pending.phase, Phase::Verify);
        writer.headers_tip = 2;
        writer.indexed.clear();
        assert!(finish_plan(&mut writer, &mut pending).is_err());
    }
    #[test]
    fn failed_writer_phase_then_exact_repair_publishes_a_new_epoch() {
        for phase in [
            Phase::Rollback,
            Phase::Reorg,
            Phase::Add,
            Phase::Index,
            Phase::Flush,
            Phase::PersistTip,
            Phase::Verify,
        ] {
            let generation = super::super::read_generation::ReadGeneration::new();
            let before = generation.begin().commit().unwrap();
            let lease = generation.begin();
            let mut writer = Writer {
                fail: Some(phase),
                headers_tip: 2,
                ..Writer::default()
            };
            let mut pending = plan(2);
            assert!(finish_plan(&mut writer, &mut pending).is_err());
            drop(lease);
            assert!(generation.requires_repair());
            assert!(!generation.matches(before));
            let retry = generation.begin();
            assert_eq!(generation.completed(), None);
            let proof = finish_plan(&mut writer, &mut pending).unwrap();
            let after = retry.commit_repaired(proof).unwrap();
            assert!(after > before);
            assert!(generation.matches(after));
            assert!(!generation.matches(before));
        }
    }
    #[test]
    fn recovery_target_change_is_not_published_between_plans() {
        let generation = super::super::read_generation::ReadGeneration::new();
        let mut writer = Writer {
            headers_tip: 2,
            ..Writer::default()
        };
        let lease = generation.begin();
        let mut old = plan(2);
        finish_plan(&mut writer, &mut old).unwrap();
        assert_eq!(generation.completed(), None);
        writer.headers_tip = 3;
        let mut next = plan(3);
        let proof = finish_plan(&mut writer, &mut next).unwrap();
        assert_eq!(generation.completed(), None);
        assert!(generation.matches(lease.commit_repaired(proof).unwrap()));
        assert_eq!(writer.persisted, Some(3));
    }
    #[test]
    fn qualifying_storage_fault_is_nonfatal_and_discards_proof() {
        let generation = super::super::read_generation::ReadGeneration::new();
        let lease = generation.begin();
        let mut writer = Writer {
            headers_tip: 2,
            qualification_read_error: true,
            ..Writer::default()
        };
        let mut pending = plan(2);
        let result = finish_qualified_plan(&mut writer, &mut pending);
        assert!(matches!(result, Ok(None)));
        assert_eq!(writer.persisted, Some(2));
        drop(lease);
        assert_eq!(generation.completed(), None);
    }
    #[test]
    fn original_producer_error_still_propagates_without_qualification_swallow() {
        let mut writer = Writer {
            headers_tip: 2,
            fail: Some(Phase::Add),
            ..Writer::default()
        };
        let mut pending = plan(2);
        assert!(finish_qualified_plan(&mut writer, &mut pending).is_err());
        assert_eq!(pending.phase, Phase::Add);
    }
}
