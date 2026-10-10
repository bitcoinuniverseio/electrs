//! Supplemental block-qualified spending index used by the existing history
//! writer. Existing-store historical completeness is deliberately separate:
//! writing future edges never grants historical coverage or startup readiness.
use std::convert::TryInto;

pub const EDGE_KEY_BYTES: usize = 146;
pub const MAX_VISITS: usize = 500;
pub const MAX_TOTAL_VISITS: usize = 1_000_000;
pub const MAX_HISTORY_KEY: usize = 256;
const DOMAIN: [u8; 4] = [0xff, b'U', b'E', 1];

/// One logical request budget, shared by all nested point reads and output
/// workers. Reserving never resets on a nested call or after partial success.
pub struct ReadBudget(std::sync::atomic::AtomicUsize);
impl ReadBudget {
    pub fn new() -> Self {
        Self(std::sync::atomic::AtomicUsize::new(0))
    }
    pub fn reserve(&self, reads: usize) -> Result<(), EdgeError> {
        use std::sync::atomic::Ordering;
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(reads)
                    .filter(|next| *next <= MAX_TOTAL_VISITS)
            })
            .map(|_| ())
            .map_err(|_| EdgeError::Capacity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeKey {
    pub script_hash: [u8; 32],
    pub funding_txid: [u8; 32],
    pub funding_vout: u32,
    pub spending_height: u32,
    pub spending_block_hash: [u8; 32],
    pub spending_position: u16,
    pub spending_txid: [u8; 32],
    pub spending_vin: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeError {
    Encoding,
    Capacity,
    SourceChanged,
    MissingCoverage,
    Incomplete,
    Storage,
}

impl EdgeKey {
    /// Versioned supplemental namespace. Exact block hash prevents deleting
    /// an orphan occurrence from erasing an ancestor's identical legacy S key.
    pub fn encode(self) -> [u8; EDGE_KEY_BYTES] {
        let mut key = [0u8; EDGE_KEY_BYTES];
        key[0..4].copy_from_slice(&DOMAIN);
        key[4..36].copy_from_slice(&self.script_hash);
        key[36..68].copy_from_slice(&self.funding_txid);
        key[68..72].copy_from_slice(&self.funding_vout.to_be_bytes());
        key[72..76].copy_from_slice(&self.spending_height.to_be_bytes());
        key[76..108].copy_from_slice(&self.spending_block_hash);
        key[108..110].copy_from_slice(&self.spending_position.to_be_bytes());
        key[110..142].copy_from_slice(&self.spending_txid);
        key[142..146].copy_from_slice(&self.spending_vin.to_be_bytes());
        key
    }

    pub fn decode(raw: &[u8]) -> Result<Self, EdgeError> {
        if raw.len() != EDGE_KEY_BYTES || raw[0..4] != DOMAIN {
            return Err(EdgeError::Encoding);
        }
        Ok(Self {
            script_hash: raw[4..36].try_into().map_err(|_| EdgeError::Encoding)?,
            funding_txid: raw[36..68].try_into().map_err(|_| EdgeError::Encoding)?,
            funding_vout: u32::from_be_bytes(
                raw[68..72].try_into().map_err(|_| EdgeError::Encoding)?,
            ),
            spending_height: u32::from_be_bytes(
                raw[72..76].try_into().map_err(|_| EdgeError::Encoding)?,
            ),
            spending_block_hash: raw[76..108].try_into().map_err(|_| EdgeError::Encoding)?,
            spending_position: u16::from_be_bytes(
                raw[108..110].try_into().map_err(|_| EdgeError::Encoding)?,
            ),
            spending_txid: raw[110..142].try_into().map_err(|_| EdgeError::Encoding)?,
            spending_vin: u32::from_be_bytes(
                raw[142..146].try_into().map_err(|_| EdgeError::Encoding)?,
            ),
        })
    }

    pub fn prefix(script_hash: [u8; 32], funding_txid: [u8; 32], funding_vout: u32) -> [u8; 72] {
        let mut prefix = [0; 72];
        prefix[..4].copy_from_slice(&DOMAIN);
        prefix[4..36].copy_from_slice(&script_hash);
        prefix[36..68].copy_from_slice(&funding_txid);
        prefix[68..72].copy_from_slice(&funding_vout.to_be_bytes());
        prefix
    }
    pub fn outpoint_prefix(self) -> [u8; 72] {
        Self::prefix(self.script_hash, self.funding_txid, self.funding_vout)
    }

    /// Both caller-supplied funding and spending block membership still need
    /// actual completed-header proof; this does not derive that proof.
    pub fn follows_funding(self, funding_height: u32, funding_position: u16) -> bool {
        self.spending_height > funding_height
            || (self.spending_height == funding_height && self.spending_position > funding_position)
    }
}

/// Existing fixed-int little-endian X roster: u64 count then exact 32-byte
/// transaction hashes. Check length BEFORE deserializing/allocating a vector.
/// Missing, duplicate, oversized or truncated roster is unavailable, not a
/// fabricated transaction position. Full caller verifies the header Merkle root.
pub fn roster_position(raw: &[u8], txid: [u8; 32]) -> Result<u16, EdgeError> {
    if raw.len() < 8 || raw.len() > 4 * 1024 * 1024 {
        return Err(EdgeError::Capacity);
    }
    let count = u64::from_le_bytes(raw[..8].try_into().map_err(|_| EdgeError::Encoding)?);
    if count == 0 || count > u16::MAX as u64 || 8 + count * 32 != raw.len() as u64 {
        return Err(EdgeError::Encoding);
    }
    let mut found = None;
    for (position, hash) in raw[8..].chunks_exact(32).enumerate() {
        if hash == txid {
            if found.is_some() {
                return Err(EdgeError::Encoding);
            }
            found = Some(position as u16);
        }
    }
    found.ok_or(EdgeError::MissingCoverage)
}

/// Retain exactly the original bounded deletion keys. Never regenerate keys
/// after dependent txstore data was deleted. No legacy S/D/H key is accepted.
pub struct DeleteIntent {
    orphan_block: [u8; 32],
    keys: Vec<[u8; EDGE_KEY_BYTES]>,
    completed: bool,
}

impl DeleteIntent {
    pub fn new(orphan_block: [u8; 32], edges: &[EdgeKey]) -> Result<Self, EdgeError> {
        if edges.is_empty() || edges.len() > MAX_VISITS {
            return Err(EdgeError::Capacity);
        }
        if edges
            .iter()
            .any(|edge| edge.spending_block_hash != orphan_block)
        {
            return Err(EdgeError::SourceChanged);
        }
        Ok(Self {
            orphan_block,
            keys: edges.iter().map(|edge| edge.encode()).collect(),
            completed: false,
        })
    }

    /// Future backend must apply a single fallible atomic batch. An error may
    /// not advance progress or authorize readiness, even if an unsafe backend
    /// partially deleted rows. Retained exact keys allow a separately approved
    /// replay adapter; no producer retry is implemented by this helper.
    pub fn apply(
        &mut self,
        write: impl FnOnce(&[[u8; EDGE_KEY_BYTES]]) -> Result<(), EdgeError>,
    ) -> Result<(), EdgeError> {
        if self.completed {
            return Ok(());
        }
        if self.keys.iter().any(|key| {
            EdgeKey::decode(key)
                .map(|edge| edge.spending_block_hash != self.orphan_block)
                .unwrap_or(true)
        }) {
            return Err(EdgeError::Encoding);
        }
        write(&self.keys)?;
        self.completed = true;
        Ok(())
    }

    pub fn completed(&self) -> bool {
        self.completed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineProgress {
    scope: [u8; 32],
    fence: u64,
    last_full_history_key: Vec<u8>,
    visits: usize,
    total_visits: usize,
    nested_complete: bool,
    nested_after_key: Vec<u8>,
    eof: bool,
    future_writes_covered: bool,
}

impl BaselineProgress {
    pub fn new(scope: [u8; 32], fence: u64) -> Result<Self, EdgeError> {
        if fence == 0 {
            return Err(EdgeError::SourceChanged);
        }
        Ok(Self {
            scope,
            fence,
            last_full_history_key: vec![],
            visits: 0,
            total_visits: 0,
            nested_complete: true,
            nested_after_key: vec![],
            eof: false,
            future_writes_covered: false,
        })
    }

    pub fn charge(&mut self) -> Result<(), EdgeError> {
        if self.visits == MAX_VISITS || self.total_visits == MAX_TOTAL_VISITS {
            return Err(EdgeError::Capacity);
        }
        self.visits += 1;
        self.total_visits += 1;
        Ok(())
    }

    pub fn observe_history(&mut self, full_key: &[u8]) -> Result<(), EdgeError> {
        if !self.nested_complete
            || full_key.is_empty()
            || full_key.len() > MAX_HISTORY_KEY
            || (!self.last_full_history_key.is_empty()
                && full_key <= self.last_full_history_key.as_slice())
        {
            return Err(EdgeError::Encoding);
        }
        self.charge()?;
        self.last_full_history_key = full_key.to_vec();
        self.nested_complete = false;
        self.nested_after_key.clear();
        Ok(())
    }

    pub fn observe_nested(&mut self, full_key: &[u8]) -> Result<(), EdgeError> {
        if self.nested_complete
            || full_key.is_empty()
            || full_key.len() > MAX_HISTORY_KEY
            || (!self.nested_after_key.is_empty() && full_key <= self.nested_after_key.as_slice())
        {
            return Err(EdgeError::Encoding);
        }
        self.charge()?;
        self.nested_after_key = full_key.to_vec();
        Ok(())
    }

    pub fn next_operation(&mut self, scope: [u8; 32], fence: u64) -> Result<(), EdgeError> {
        if self.eof || scope != self.scope || fence != self.fence {
            return Err(EdgeError::SourceChanged);
        }
        self.visits = 0;
        Ok(())
    }

    pub fn complete_nested(&mut self, evidence_complete: bool) -> Result<(), EdgeError> {
        self.charge()?; // Every nested row and EOF must be charged by the adapter.
        if !evidence_complete {
            return Err(EdgeError::Incomplete);
        }
        self.nested_complete = true;
        Ok(())
    }

    pub fn complete_scan(
        &mut self,
        scope: [u8; 32],
        fence: u64,
        future_writes_covered: bool,
    ) -> Result<(), EdgeError> {
        self.charge()?;
        if scope != self.scope || fence != self.fence {
            return Err(EdgeError::SourceChanged);
        }
        if !self.nested_complete || !future_writes_covered {
            return Err(EdgeError::Incomplete);
        }
        self.eof = true;
        self.future_writes_covered = future_writes_covered;
        Ok(())
    }

    /// Counts, markers, source hash references and EOF are NOT a historical H
    /// completeness certificate. No actual certificate factory exists yet.
    pub fn ready_without_historical_coverage(&self) -> Result<(), EdgeError> {
        if !self.eof || !self.future_writes_covered {
            return Err(EdgeError::Incomplete);
        }
        Err(EdgeError::MissingCoverage)
    }

    pub fn exact_resume_key(&self) -> &[u8] {
        &self.last_full_history_key
    }

    pub fn exact_nested_resume_key(&self) -> &[u8] {
        &self.nested_after_key
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_and_parallel_readers_share_one_nonresetting_request_budget() {
        let budget = std::sync::Arc::new(super::ReadBudget::new());
        budget.reserve(super::MAX_TOTAL_VISITS - 2).unwrap();
        let a = budget.clone();
        let b = budget.clone();
        let first = std::thread::spawn(move || a.reserve(2));
        let second = std::thread::spawn(move || b.reserve(2));
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(budget.reserve(1), Err(super::EdgeError::Capacity));
        // A rejected reservation did not wrap the counter or reset admission.
        assert_eq!(budget.reserve(usize::MAX), Err(super::EdgeError::Capacity));
    }
    use super::*;
    use std::collections::BTreeMap;
    fn edge(height: u32, hash: u8) -> EdgeKey {
        EdgeKey {
            script_hash: [1; 32],
            funding_txid: [2; 32],
            funding_vout: 3,
            spending_height: height,
            spending_block_hash: [hash; 32],
            spending_position: 4,
            spending_txid: [5; 32],
            spending_vin: 6,
        }
    }

    #[test]
    fn block_qualified_orphan_delete_preserves_identical_ancestor_spender() {
        let ancestor = edge(100, 7);
        let orphan = edge(110, 8);
        assert_eq!(ancestor.outpoint_prefix(), orphan.outpoint_prefix());
        assert_ne!(ancestor.encode(), orphan.encode());
        let mut db = BTreeMap::from([(ancestor.encode(), ()), (orphan.encode(), ())]);
        let mut intent = DeleteIntent::new([8; 32], &[orphan]).unwrap();
        intent
            .apply(|keys| {
                for key in keys {
                    db.remove(key);
                }
                Ok(())
            })
            .unwrap();
        assert!(db.contains_key(&ancestor.encode()));
        assert!(!db.contains_key(&orphan.encode()));
    }

    #[test]
    fn exact_codec_rejects_legacy_unknown_version_trailing_or_short_keys() {
        let key = edge(u32::MAX, 9);
        assert_eq!(EdgeKey::decode(&key.encode()).unwrap(), key);
        let mut bad = key.encode();
        bad[3] = 2;
        assert_eq!(EdgeKey::decode(&bad), Err(EdgeError::Encoding));
        assert_eq!(EdgeKey::decode(&bad[..145]), Err(EdgeError::Encoding));
        let mut trailing = key.encode().to_vec();
        trailing.push(0);
        assert_eq!(EdgeKey::decode(&trailing), Err(EdgeError::Encoding));
    }

    #[test]
    fn fallible_delete_retains_exact_keys_and_never_marks_partial_success() {
        let first = edge(110, 8);
        let mut second = first;
        second.spending_vin = 9;
        let mut intent = DeleteIntent::new([8; 32], &[first, second]).unwrap();
        let mut calls = Vec::new();
        assert_eq!(
            intent.apply(|keys| {
                calls.push(keys.to_vec());
                Err(EdgeError::Storage)
            }),
            Err(EdgeError::Storage)
        );
        assert!(!intent.completed());
        intent
            .apply(|keys| {
                calls.push(keys.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(calls[0], calls[1]);
        assert!(intent.completed());
        intent
            .apply(|_| panic!("completed exact batch may not redispatch"))
            .unwrap();
    }

    #[test]
    fn foreign_block_or_unbounded_deletion_rejected_before_storage() {
        assert!(matches!(
            DeleteIntent::new([9; 32], &[edge(100, 8)]),
            Err(EdgeError::SourceChanged)
        ));
        assert!(matches!(
            DeleteIntent::new([8; 32], &vec![edge(100, 8); 501]),
            Err(EdgeError::Capacity)
        ));
    }

    #[test]
    fn local_roster_position_rejects_missing_duplicate_truncated_and_forged_length() {
        let roster = [&2u64.to_le_bytes()[..], &[1; 32][..], &[2; 32][..]].concat();
        assert_eq!(roster_position(&roster, [1; 32]), Ok(0));
        assert_eq!(roster_position(&roster, [2; 32]), Ok(1));
        assert_eq!(
            roster_position(&roster, [3; 32]),
            Err(EdgeError::MissingCoverage)
        );
        assert!(roster_position(&roster[..70], [1; 32]).is_err());
        assert!(roster_position(&u64::MAX.to_le_bytes(), [1; 32]).is_err());
        let duplicate = [&2u64.to_le_bytes()[..], &[1; 32][..], &[1; 32][..]].concat();
        assert!(roster_position(&duplicate, [1; 32]).is_err());
    }

    #[test]
    fn old_spend_does_not_spend_new_duplicate_funding_incarnation() {
        let old = edge(100, 7);
        assert!(!old.follows_funding(110, 0));
        assert!(!edge(110, 8).follows_funding(110, 4));
        assert!(edge(110, 8).follows_funding(110, 3));
    }

    #[test]
    fn rowcount_and_eof_never_create_missing_historical_coverage() {
        let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
        progress.observe_history(&[1]).unwrap();
        progress.complete_nested(true).unwrap();
        progress.complete_scan([1; 32], 2, true).unwrap();
        assert_eq!(
            progress.ready_without_historical_coverage(),
            Err(EdgeError::MissingCoverage)
        );
    }

    #[test]
    fn dense_and_nested_work_charges_all500_visits_and_retains_fullkey() {
        let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
        progress.observe_history(&[1, 2, 3, 4]).unwrap();
        for _ in 1..500 {
            progress.charge().unwrap();
        }
        assert_eq!(progress.complete_nested(true), Err(EdgeError::Capacity));
        assert_eq!(progress.exact_resume_key(), &[1, 2, 3, 4]);
        assert_eq!(progress.observe_history(&[2]), Err(EdgeError::Encoding));
    }

    #[test]
    fn changed_scope_reorg_fence_or_uncovered_below_cursor_insert_blocks() {
        for (scope, fence, covered) in [([2; 32], 2, true), ([1; 32], 4, true), ([1; 32], 2, false)]
        {
            let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
            assert!(progress.complete_scan(scope, fence, covered).is_err());
            assert!(progress.ready_without_historical_coverage().is_err());
        }
    }

    #[test]
    fn nested_scan_resumes_at_fullkey_with_no_skipped_dense_rows() {
        let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
        progress.observe_history(&[1, 2, 3]).unwrap();
        for index in 1u32..500 {
            progress.observe_nested(&index.to_be_bytes()).unwrap();
        }
        assert_eq!(progress.complete_nested(true), Err(EdgeError::Capacity));
        assert_eq!(progress.exact_nested_resume_key(), &499u32.to_be_bytes());
        progress.next_operation([1; 32], 2).unwrap();
        assert_eq!(
            progress.observe_nested(&499u32.to_be_bytes()),
            Err(EdgeError::Encoding)
        );
        progress.observe_nested(&500u32.to_be_bytes()).unwrap();
        progress.complete_nested(true).unwrap();
        progress.complete_scan([1; 32], 2, true).unwrap();
        assert_eq!(
            progress.ready_without_historical_coverage(),
            Err(EdgeError::MissingCoverage)
        );
    }

    #[test]
    fn operation_resumption_cannot_launder_scope_or_generation_drift() {
        let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
        progress.observe_history(&[1, 2, 3]).unwrap();
        assert_eq!(
            progress.next_operation([2; 32], 2),
            Err(EdgeError::SourceChanged)
        );
        assert_eq!(
            progress.next_operation([1; 32], 4),
            Err(EdgeError::SourceChanged)
        );
        assert_eq!(progress.exact_resume_key(), &[1, 2, 3]);
    }

    #[test]
    fn per_operation_reset_never_resets_total_work_budget() {
        let mut progress = BaselineProgress::new([1; 32], 2).unwrap();
        progress.total_visits = MAX_TOTAL_VISITS;
        progress.next_operation([1; 32], 2).unwrap();
        assert_eq!(progress.charge(), Err(EdgeError::Capacity));
    }
}
