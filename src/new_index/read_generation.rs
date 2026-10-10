//! Read publication never waits for database IO or holds writer metadata locks.
use std::sync::{Mutex, MutexGuard};

struct State {
    sequence: u64,
    dirty: bool,
    active: Option<u64>,
    material_completed: bool,
    availability_only: bool,
    exhausted: bool,
    startup_unqualified: bool,
}
pub struct ReadGeneration {
    state: Mutex<State>,
}
pub struct Mutation<'a> {
    owner: &'a ReadGeneration,
    odd: Option<u64>,
    committed: bool,
}
impl ReadGeneration {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                sequence: 1,
                dirty: false,
                active: None,
                material_completed: false,
                availability_only: false,
                exhausted: false,
                startup_unqualified: false,
            }),
        }
    }
    /// Existing data has no historical writer generation proof. An empty/new
    /// update plan is not startup reconciliation; no operator flag bypasses it.
    pub fn new_existing_unqualified() -> Self {
        let state = Self::new();
        {
            let mut inner = state.writer_state();
            inner.startup_unqualified = true;
            inner.dirty = true;
        }
        state
    }
    // Writer metadata guard is held only for scalar state updates, never IO.
    // Poison cannot introduce a new producer panic or a readable publication.
    fn writer_state(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                state.dirty = true;
                state.material_completed = false;
                state.availability_only = false;
                state
            }
        }
    }
    fn next_odd(state: &mut State) -> Option<u64> {
        match (state.sequence | 1)
            .checked_add(2)
            .filter(|v| v.checked_add(1).is_some())
        {
            Some(next) => {
                state.sequence = next;
                Some(next)
            }
            None => {
                state.exhausted = true;
                state.dirty = true;
                state.material_completed = false;
                state.availability_only = false;
                None
            }
        }
    }
    pub fn begin(&self) -> Mutation<'_> {
        let mut state = self.writer_state();
        let odd = Self::next_odd(&mut state);
        state.active = odd;
        state.material_completed = false;
        state.availability_only = false;
        Mutation {
            owner: self,
            odd,
            committed: false,
        }
    }
    pub fn completed(&self) -> Option<u64> {
        let state = self.state.try_lock().ok()?;
        if !state.startup_unqualified
            && !state.dirty
            && !state.exhausted
            && state.active.is_none()
            && state.material_completed
            && !state.availability_only
            && state.sequence & 1 == 0
        {
            Some(state.sequence)
        } else {
            None
        }
    }
    pub fn requires_repair(&self) -> bool {
        self.state
            .try_lock()
            .map(|s| s.dirty || s.exhausted)
            .unwrap_or(true)
    }
    pub fn matches(&self, value: u64) -> bool {
        self.completed() == Some(value)
    }
    pub fn invalidate_material(&self) {
        let mut state = self.writer_state();
        let _ = Self::next_odd(&mut state);
        state.dirty = true;
        state.material_completed = false;
        state.availability_only = false;
    }
    /// Only a failed pre-mutation storage read of an already closed state may
    /// use this path. Missing/mismatched/poisoned metadata is material failure.
    pub fn invalidate_availability(&self) {
        let mut state = self.writer_state();
        if state.dirty || state.exhausted || state.active.is_some() || !state.material_completed {
            return;
        }
        if Self::next_odd(&mut state).is_some() {
            state.availability_only = true;
        }
    }
    pub fn availability_fence(&self) -> Option<u64> {
        let state = self.state.try_lock().ok()?;
        if state.availability_only
            && state.material_completed
            && !state.dirty
            && !state.exhausted
            && state.active.is_none()
        {
            Some(state.sequence)
        } else {
            None
        }
    }
    /// Exact local unchanged-header/tip proof is checked by the sole Indexer.
    /// Scalar compare fence prevents availability ABA/material interleaving.
    pub fn restore_availability(&self, fence: u64) -> Result<u64, &'static str> {
        if self.state.is_poisoned() {
            return Err("poisoned publication");
        }
        let mut state = self.writer_state();
        if state.startup_unqualified
            || state.sequence != fence
            || !state.availability_only
            || !state.material_completed
            || state.dirty
            || state.exhausted
            || state.active.is_some()
        {
            return Err("availability fence changed");
        }
        let next = fence.checked_add(1).ok_or("read generation exhausted")?;
        state.sequence = next;
        state.availability_only = false;
        Ok(next)
    }
}
impl Mutation<'_> {
    pub fn commit(self) -> Result<u64, &'static str> {
        self.publish(false)
    }
    pub(crate) fn commit_repaired(
        self,
        _proof: super::writer_update::CompletedPlan,
    ) -> Result<u64, &'static str> {
        self.publish(true)
    }
    fn publish(mut self, repaired: bool) -> Result<u64, &'static str> {
        if self.owner.state.is_poisoned() {
            return Err("poisoned publication");
        }
        let mut state = self.owner.writer_state();
        let odd = self.odd.ok_or("read generation exhausted")?;
        if state.startup_unqualified {
            return Err("existing store requires proven baseline");
        }
        if state.active != Some(odd) || state.sequence != odd || state.exhausted {
            return Err("read generation superseded");
        }
        if state.dirty && !repaired {
            return Err("failed writer requires proven recovery");
        }
        state.sequence = odd.checked_add(1).ok_or("read generation exhausted")?;
        state.active = None;
        state.dirty = false;
        state.availability_only = false;
        state.material_completed = true;
        self.committed = true;
        Ok(state.sequence)
    }
}
impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let mut state = self.owner.writer_state();
            state.dirty = true;
            state.material_completed = false;
            state.availability_only = false;
            if state.active == self.odd {
                state.active = None;
            }
        }
    }
}
/// Material + availability token for the existing mempool writer. Successful
/// unchanged refresh keeps the token; every failure/material mutation advances.
#[derive(Default)]
pub struct MempoolPublication {
    token: u64,
    qualified: bool,
    chain: Option<u64>,
    exhausted: bool,
}
impl MempoolPublication {
    pub fn token(&self) -> u64 {
        self.token
    }
    pub fn invalidate(&mut self) {
        match self.token.checked_add(1) {
            Some(next) => self.token = next,
            None => self.exhausted = true,
        }
        self.qualified = false;
        self.chain = None;
    }
    pub fn epoch(&self, chain: Option<u64>) -> Option<(u64, u64)> {
        if self.qualified && !self.exhausted && chain == self.chain {
            self.chain.map(|c| (c, self.token))
        } else {
            None
        }
    }
    pub fn finish_refresh(
        &mut self,
        after_remove: u64,
        before_add: u64,
        chain_before: Option<u64>,
        chain_after: Option<u64>,
        complete: bool,
    ) {
        // Compare before OWN add mutation, which is expected to advance token.
        let qualified = !self.exhausted
            && after_remove == before_add
            && complete
            && chain_before.is_some()
            && chain_before == chain_after;
        if !qualified && self.qualified {
            self.invalidate();
        }
        self.qualified = qualified;
        self.chain = if qualified { chain_before } else { None };
    }
}

// No Drop completion: a failed/panicking writer remains unavailable until a
// explicit writer-phase recovery proof is available. A new lease alone is not repair.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_tip_partial_batch_is_not_completed() {
        let state = ReadGeneration::new();
        assert_eq!(state.completed(), None);
        let initial = state.begin().commit().unwrap();
        assert!(state.matches(initial));
        let update = state.begin();
        assert!(!state.matches(initial));
        // A persisted or header tip equality is deliberately irrelevant.
        drop(update);
        assert_eq!(state.completed(), None);
        assert!(state.begin().commit().is_err());
        assert_eq!(state.completed(), None);
        // A new publication alone is not data repair, even when tip stays equal.
    }
    #[test]
    fn superseded_writer_cannot_publish_ready() {
        let state = ReadGeneration::new();
        let old = state.begin();
        let new = state.begin();
        assert!(old.commit().is_err());
        assert_eq!(state.completed(), None);
        assert!(new.commit().is_err());
    }
    #[test]
    fn writer_start_after_snapshot_invalidates_captured_epoch() {
        let state = ReadGeneration::new();
        let captured = state.begin().commit().unwrap();
        let _writer = state.begin();
        assert!(!state.matches(captured));
    }
    #[test]
    fn mempool_error_then_equal_membership_is_not_an_aba_epoch() {
        let mut p = MempoolPublication::default();
        p.finish_refresh(0, 0, Some(2), Some(2), true);
        let old = p.epoch(Some(2)).unwrap();
        p.invalidate();
        assert_eq!(p.epoch(Some(2)), None);
        let token = p.token();
        p.finish_refresh(token, token, Some(2), Some(2), true);
        assert_ne!(p.epoch(Some(2)), Some(old));
    }
    #[test]
    fn mempool_broadcast_during_unlocked_fetch_cannot_publish() {
        let mut p = MempoolPublication::default();
        let after_remove = p.token();
        p.invalidate(); // broadcast, even if tx membership eventually matches
        p.finish_refresh(after_remove, p.token(), Some(2), Some(2), true);
        assert_eq!(p.epoch(Some(2)), None);
    }
    #[test]
    fn mempool_unchanged_success_keeps_cursor_but_missing_parent_does_not_qualify() {
        let mut p = MempoolPublication::default();
        p.finish_refresh(0, 0, Some(2), Some(2), true);
        let stable = p.epoch(Some(2));
        p.finish_refresh(0, 0, Some(2), Some(2), true);
        assert_eq!(p.epoch(Some(2)), stable);
        p.finish_refresh(0, 0, Some(2), Some(2), false);
        assert_eq!(p.epoch(Some(2)), None);
        assert!(p.token() > stable.unwrap().1);
    }
    #[test]
    fn mempool_changed_chain_rejects_captured_generation() {
        let mut p = MempoolPublication::default();
        p.finish_refresh(0, 0, Some(2), Some(4), true);
        assert_eq!(p.epoch(Some(4)), None);
    }
    #[test]
    fn availability_invalidation_restores_new_token_not_old_cursor() {
        let state = ReadGeneration::new();
        let old = state.begin().commit().unwrap();
        state.invalidate_availability();
        assert_eq!(state.completed(), None);
        assert!(!state.requires_repair());
        let fence = state.availability_fence().unwrap();
        let fresh = state.restore_availability(fence).unwrap();
        assert!(fresh > old);
        assert!(state.matches(fresh));
        assert!(!state.matches(old));
    }
    #[test]
    fn repeated_availability_failure_invalidates_intermediate_fence_aba() {
        let state = ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_availability();
        let first = state.availability_fence().unwrap();
        state.invalidate_availability();
        assert!(state.restore_availability(first).is_err());
        let latest = state.availability_fence().unwrap();
        assert!(latest > first);
        assert!(state.restore_availability(latest).is_ok());
    }
    #[test]
    fn failed_writer_or_material_mismatch_never_becomes_availability_recovery() {
        let state = ReadGeneration::new();
        state.begin().commit().unwrap();
        drop(state.begin());
        state.invalidate_availability();
        assert_eq!(state.availability_fence(), None);
        assert!(state.requires_repair());
        assert!(state.restore_availability(1).is_err());
        let state = ReadGeneration::new();
        state.begin().commit().unwrap();
        state.invalidate_material();
        state.invalidate_availability();
        assert_eq!(state.availability_fence(), None);
        assert!(state.requires_repair());
    }
    #[test]
    fn overflow_never_wraps_or_panics_a_legacy_writer() {
        let state = ReadGeneration::new();
        state.writer_state().sequence = u64::MAX - 3;
        let mutation = state.begin();
        assert!(mutation.commit().is_err());
        assert_eq!(state.completed(), None);
        assert!(state.requires_repair());
        let state = ReadGeneration::new();
        state.begin().commit().unwrap();
        state.writer_state().sequence = u64::MAX - 3;
        state.invalidate_availability();
        assert_eq!(state.availability_fence(), None);
        assert_eq!(state.completed(), None);
    }
    #[test]
    fn existing_store_cannot_be_qualified_by_new_lease_or_empty_noop() {
        let state = ReadGeneration::new_existing_unqualified();
        assert!(state.begin().commit().is_err());
        state.invalidate_availability();
        assert_eq!(state.availability_fence(), None);
        assert_eq!(state.completed(), None);
    }
    #[test]
    fn mempool_token_overflow_is_unavailable_not_a_new_producer_panic() {
        let mut publication = MempoolPublication::default();
        publication.token = u64::MAX;
        publication.invalidate();
        publication.finish_refresh(u64::MAX, u64::MAX, Some(2), Some(2), true);
        assert_eq!(publication.epoch(Some(2)), None);
        assert!(publication.exhausted);
    }
}
