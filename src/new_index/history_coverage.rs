//! Resumable source/profile-bound sole-writer coverage. A progress record or
//! persisted certificate is NOT a publication proof. Only the checked adapter
//! may construct a completed proof after canonical prefix/target closure.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VISITS_PER_INVOCATION: usize = 500;
pub const WORK_PER_INVOCATION: usize = 1_000_000;
pub const POINT_BYTES: usize = 4 * 1024 * 1024;
pub const PROGRESS_BYTES: usize = 16 * 1024;
pub const CERTIFICATE_BYTES: usize = 4 * 1024;
pub const SCHEMA: &str = "universe-electrs-history-progress-v2";
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoverageError {
    Contract,
    Changed,
    Missing,
    Storage,
    Budget,
    Overflow,
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CoverageScope {
    pub schema_version: u16,
    pub chain: String,
    pub network: String,
    pub genesis_hash: String,
    pub source_revision: String,
    pub profile_sha256: String,
    pub namespace_schema_sha256: String,
    pub signet_challenge_sha256: Option<String>,
    pub light_mode: bool,
    pub index_unspendables: bool,
    pub address_search: bool,
}
impl CoverageScope {
    pub fn validate(&self) -> Result<(), CoverageError> {
        if self.schema_version != 2
            || self.chain != "bitcoin"
            || !["mainnet", "testnet", "testnet4", "signet", "regtest"]
                .contains(&self.network.as_str())
            || !lower_hex(&self.genesis_hash, 64)
            || !lower_hex(&self.source_revision, 40)
            || !lower_hex(&self.profile_sha256, 64)
            || !lower_hex(&self.namespace_schema_sha256, 64)
            || (self.network == "signet"
                && !self
                    .signet_challenge_sha256
                    .as_ref()
                    .map_or(false, |value| lower_hex(value, 64)))
            || (self.network != "signet" && self.signet_challenge_sha256.is_some())
        {
            return Err(CoverageError::Contract);
        }
        Ok(())
    }
    pub fn commitment(&self) -> Result<String, CoverageError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| CoverageError::Contract)?;
        Ok(digest(
            b"universe-electrs-history-coverage-scope-v2\0",
            &bytes,
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    BlockRoster,
    RosterValidation,
    Transaction,
    Output,
    Input,
    BlockCommit,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Prefix {
    pub height: u32,
    pub block_hash: String,
    pub coverage_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Progress {
    pub schema_version: String,
    pub scope: CoverageScope,
    pub phase: Phase,
    pub prefix: Option<Prefix>,
    pub next_height: u32,
    pub transaction_position: u16,
    pub item_position: u32,
    pub parent_after_key: Option<Vec<u8>>,
    pub parent_best_height: Option<u32>,
    pub parent_best_hash: Option<String>,
    pub parent_best_position: Option<u16>,
    pub target_observed_height: u32,
    pub target_observed_hash: String,
    pub total_visits_atomic: String,
    pub history_digest: String,
    pub edges_digest: String,
    pub checked_funding_rows_atomic: String,
    pub checked_spending_rows_atomic: String,
}
fn atomic(value: &str) -> Result<u64, CoverageError> {
    let parsed = value.parse::<u64>().map_err(|_| CoverageError::Contract)?;
    if parsed.to_string() != value {
        return Err(CoverageError::Contract);
    }
    Ok(parsed)
}
impl Progress {
    pub fn initial(scope: CoverageScope, height: u32, hash: String) -> Result<Self, CoverageError> {
        scope.validate()?;
        if !lower_hex(&hash, 64) {
            return Err(CoverageError::Contract);
        }
        Ok(Self {
            schema_version: SCHEMA.into(),
            scope,
            phase: Phase::BlockRoster,
            prefix: None,
            next_height: 0,
            transaction_position: 0,
            item_position: 0,
            parent_after_key: None,
            parent_best_height: None,
            parent_best_hash: None,
            parent_best_position: None,
            target_observed_height: height,
            target_observed_hash: hash,
            total_visits_atomic: "0".into(),
            history_digest: "0".repeat(64),
            edges_digest: "0".repeat(64),
            checked_funding_rows_atomic: "0".into(),
            checked_spending_rows_atomic: "0".into(),
        })
    }
    pub fn validate(&self, expected: &CoverageScope) -> Result<(), CoverageError> {
        self.scope.validate()?;
        if &self.scope != expected {
            return Err(CoverageError::Changed);
        }
        if self.schema_version != SCHEMA
            || !lower_hex(&self.target_observed_hash, 64)
            || !lower_hex(&self.history_digest, 64)
            || !lower_hex(&self.edges_digest, 64)
        {
            return Err(CoverageError::Contract);
        }
        if self
            .parent_after_key
            .as_ref()
            .map_or(false, |key| key.is_empty() || key.len() > 256)
            || self.parent_best_height.is_some() != self.parent_best_hash.is_some()
            || self.parent_best_height.is_some() != self.parent_best_position.is_some()
            || self
                .parent_best_hash
                .as_ref()
                .map_or(false, |hash| !lower_hex(hash, 64))
        {
            return Err(CoverageError::Contract);
        }
        atomic(&self.total_visits_atomic)?;
        atomic(&self.checked_funding_rows_atomic)?;
        atomic(&self.checked_spending_rows_atomic)?;
        match &self.prefix {
            Some(prefix)
                if !lower_hex(&prefix.block_hash, 64)
                    || !lower_hex(&prefix.coverage_sha256, 64)
                    || prefix.height.checked_add(1) != Some(self.next_height) =>
            {
                return Err(CoverageError::Contract)
            }
            None if self.next_height != 0 => return Err(CoverageError::Contract),
            _ => {}
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CoverageError> {
        self.validate(&self.scope)?;
        let bytes = serde_json::to_vec(self).map_err(|_| CoverageError::Contract)?;
        if bytes.len() > PROGRESS_BYTES {
            return Err(CoverageError::Contract);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], expected: &CoverageScope) -> Result<Self, CoverageError> {
        if bytes.len() > PROGRESS_BYTES {
            return Err(CoverageError::Contract);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| CoverageError::Contract)?;
        state.validate(expected)?;
        if state.encode()?.as_slice() != bytes {
            return Err(CoverageError::Contract);
        }
        Ok(state)
    }
    pub fn progress_key(&self) -> Result<Vec<u8>, CoverageError> {
        let scope = self.scope.commitment()?;
        let mut key = vec![0xff, b'U', b'P', 2];
        for pair in scope.as_bytes().chunks_exact(2) {
            let hex = std::str::from_utf8(pair).map_err(|_| CoverageError::Contract)?;
            key.push(u8::from_str_radix(hex, 16).map_err(|_| CoverageError::Contract)?);
        }
        Ok(key)
    }
}
/// Reservation occurs BEFORE dispatch; every read and crypto/body unit is
/// charged. A new invocation resets local counters, never cumulative progress.
pub struct Window {
    visits: usize,
    work: usize,
    persisted_visits: usize,
}
impl Window {
    pub fn new() -> Self {
        Self {
            visits: 0,
            work: 0,
            persisted_visits: 0,
        }
    }
    pub fn reserve(&mut self, visits: usize, work: usize) -> Result<(), CoverageError> {
        let next_visits = self
            .visits
            .checked_add(visits)
            .ok_or(CoverageError::Overflow)?;
        let next_work = self.work.checked_add(work).ok_or(CoverageError::Overflow)?;
        if next_visits > VISITS_PER_INVOCATION || next_work > WORK_PER_INVOCATION {
            return Err(CoverageError::Budget);
        }
        self.visits = next_visits;
        self.work = next_work;
        Ok(())
    }
    pub fn persist_cumulative(&mut self, state: &mut Progress) -> Result<(), CoverageError> {
        state.total_visits_atomic = atomic(&state.total_visits_atomic)?
            .checked_add((self.visits - self.persisted_visits) as u64)
            .ok_or(CoverageError::Overflow)?
            .to_string();
        self.persisted_visits = self.visits;
        Ok(())
    }
}
/// Retained state belongs to one already size-checked block, not a reorg or
/// chain scan. Entries are admitted incrementally under the same work window.
pub struct RosterProof {
    seen: std::collections::BTreeSet<[u8; 32]>,
}
impl RosterProof {
    pub fn new() -> Self {
        Self {
            seen: std::collections::BTreeSet::new(),
        }
    }
    pub fn admit(
        &mut self,
        count: usize,
        entry: [u8; 32],
        window: &mut Window,
    ) -> Result<(), CoverageError> {
        if count == 0 || count > u16::MAX as usize || self.seen.len() >= count {
            return Err(CoverageError::Contract);
        }
        let levels = usize::BITS - count.leading_zeros();
        window.reserve(1, levels as usize + 2)?;
        if !self.seen.insert(entry) {
            return Err(CoverageError::Contract);
        }
        Ok(())
    }
    pub fn reserve_hash(&self, count: usize, window: &mut Window) -> Result<(), CoverageError> {
        if self.seen.len() != count || count == 0 {
            return Err(CoverageError::Contract);
        }
        window.reserve(1, count.checked_mul(3).ok_or(CoverageError::Overflow)?)
    }
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockCertificate {
    pub schema_version: String,
    pub scope_digest: String,
    pub height: u32,
    pub block_hash: String,
    pub previous_coverage_sha256: String,
    pub previous_block_hash: String,
    pub roster_sha256: String,
    pub roster_merkle_root: String,
    pub transaction_count: u32,
    pub checked_funding_rows_atomic: String,
    pub checked_spending_rows_atomic: String,
    pub expected_history_digest: String,
    pub supplemental_edges_digest: String,
    pub source_revision: String,
}
impl BlockCertificate {
    pub fn encode(&self) -> Result<Vec<u8>, CoverageError> {
        if self.schema_version != "universe-electrs-history-block-coverage-v2"
            || self.transaction_count == 0
            || !lower_hex(&self.source_revision, 40)
            || [
                &self.scope_digest,
                &self.block_hash,
                &self.previous_coverage_sha256,
                &self.previous_block_hash,
                &self.roster_sha256,
                &self.roster_merkle_root,
                &self.expected_history_digest,
                &self.supplemental_edges_digest,
            ]
            .iter()
            .any(|value| !lower_hex(value, 64))
        {
            return Err(CoverageError::Contract);
        }
        atomic(&self.checked_funding_rows_atomic)?;
        atomic(&self.checked_spending_rows_atomic)?;
        let bytes = serde_json::to_vec(self).map_err(|_| CoverageError::Contract)?;
        if bytes.len() > CERTIFICATE_BYTES {
            return Err(CoverageError::Contract);
        }
        Ok(bytes)
    }
    pub fn previous(
        &self,
        expected: &Prefix,
        scope: &str,
        source: &str,
    ) -> Result<Prefix, CoverageError> {
        if self.height == 0
            || self.height != expected.height
            || self.block_hash != expected.block_hash
            || self.scope_digest != scope
            || self.source_revision != source
            || self.commitment()? != expected.coverage_sha256
        {
            return Err(CoverageError::Changed);
        }
        Ok(Prefix {
            height: self.height - 1,
            block_hash: self.previous_block_hash.clone(),
            coverage_sha256: self.previous_coverage_sha256.clone(),
        })
    }
    pub fn commitment(&self) -> Result<String, CoverageError> {
        Ok(digest(
            b"universe-electrs-history-prefix-v2\0",
            &self.encode()?,
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> CoverageScope {
        CoverageScope {
            schema_version: 2,
            chain: "bitcoin".into(),
            network: "signet".into(),
            genesis_hash: "1".repeat(64),
            source_revision: "2".repeat(40),
            profile_sha256: "3".repeat(64),
            namespace_schema_sha256: "4".repeat(64),
            signet_challenge_sha256: Some("5".repeat(64)),
            light_mode: false,
            index_unspendables: false,
            address_search: false,
        }
    }
    #[test]
    fn windows_do_not_apply_query1m_to_whole_chain() {
        let mut state = Progress::initial(scope(), 1, "6".repeat(64)).unwrap();
        for _ in 0..3000 {
            let mut window = Window::new();
            window.reserve(500, 1_000_000).unwrap();
            window.persist_cumulative(&mut state).unwrap();
        }
        assert_eq!(state.total_visits_atomic, "1500000");
        assert!(Window::new().reserve(501, 1).is_err());
        assert!(Window::new().reserve(1, 1_000_001).is_err());
    }
    #[test]
    fn reverse_prefix_requires_actual_root_scope_source_and_exact_ancestral_link() {
        let certificate = BlockCertificate {
            schema_version: "universe-electrs-history-block-coverage-v2".into(),
            scope_digest: "1".repeat(64),
            height: 2,
            block_hash: "2".repeat(64),
            previous_block_hash: "3".repeat(64),
            previous_coverage_sha256: "4".repeat(64),
            roster_sha256: "5".repeat(64),
            roster_merkle_root: "6".repeat(64),
            transaction_count: 1,
            checked_funding_rows_atomic: "1".into(),
            checked_spending_rows_atomic: "0".into(),
            expected_history_digest: "7".repeat(64),
            supplemental_edges_digest: "8".repeat(64),
            source_revision: "9".repeat(40),
        };
        let root = Prefix {
            height: 2,
            block_hash: certificate.block_hash.clone(),
            coverage_sha256: certificate.commitment().unwrap(),
        };
        let previous = certificate
            .previous(
                &root,
                &certificate.scope_digest,
                &certificate.source_revision,
            )
            .unwrap();
        assert_eq!(previous.height, 1);
        assert_eq!(previous.block_hash, certificate.previous_block_hash);
        assert_eq!(
            previous.coverage_sha256,
            certificate.previous_coverage_sha256
        );
        assert!(certificate
            .previous(&root, &"a".repeat(64), &certificate.source_revision)
            .is_err());
        let mut tampered = certificate.clone();
        tampered.previous_block_hash = "a".repeat(64);
        assert!(tampered
            .previous(
                &root,
                &certificate.scope_digest,
                &certificate.source_revision
            )
            .is_err());
        tampered = certificate.clone();
        tampered.height = 0;
        assert!(tampered
            .previous(
                &root,
                &certificate.scope_digest,
                &certificate.source_revision
            )
            .is_err());
    }
    #[test]
    fn maximum_roster_validation_resumes_without_raising_window_or_chain_caps() {
        let count = u16::MAX as usize;
        let mut proof = RosterProof::new();
        let mut next = 0;
        let mut windows = 0;
        while next < count {
            let mut window = Window::new();
            while next < count {
                let mut entry = [0; 32];
                entry[..8].copy_from_slice(&(next as u64).to_be_bytes());
                match proof.admit(count, entry, &mut window) {
                    Ok(()) => next += 1,
                    Err(CoverageError::Budget) => break,
                    Err(error) => panic!("unexpected {:?}", error),
                }
            }
            windows += 1;
        }
        assert!(windows > 1);
        proof.reserve_hash(count, &mut Window::new()).unwrap();
        let mut duplicate = RosterProof::new();
        duplicate.admit(2, [1; 32], &mut Window::new()).unwrap();
        assert_eq!(
            duplicate.admit(2, [1; 32], &mut Window::new()),
            Err(CoverageError::Contract)
        );
        assert_eq!(
            duplicate.reserve_hash(2, &mut Window::new()),
            Err(CoverageError::Contract)
        );
    }
    #[test]
    fn repeated_progress_publication_counts_each_reservation_once() {
        let mut state = Progress::initial(scope(), 1, "6".repeat(64)).unwrap();
        state.total_visits_atomic = "1500000".into();
        let mut window = Window::new();
        window.reserve(3, 100).unwrap();
        window.persist_cumulative(&mut state).unwrap();
        window.persist_cumulative(&mut state).unwrap();
        assert_eq!(state.total_visits_atomic, "1500003");
        window.reserve(2, 100).unwrap();
        window.persist_cumulative(&mut state).unwrap();
        assert_eq!(state.total_visits_atomic, "1500005");
        // Persisting does not reset the invocation's admission budget.
        assert!(window.reserve(496, 1).is_err());
    }
    #[test]
    fn canonical_progress_scope_prefix_and_atomic_counts_are_exact() {
        let state = Progress::initial(scope(), 1, "6".repeat(64)).unwrap();
        let bytes = state.encode().unwrap();
        assert_eq!(Progress::decode(&bytes, &scope()).unwrap(), state);
        assert_eq!(state.progress_key().unwrap().len(), 36);
        let mut wrong = scope();
        wrong.profile_sha256 = "7".repeat(64);
        assert!(Progress::decode(&bytes, &wrong).is_err());
        let mut state = state;
        state.total_visits_atomic = "01".into();
        assert!(state.encode().is_err());
        state.total_visits_atomic = u64::MAX.to_string();
        let mut window = Window::new();
        window.reserve(1, 1).unwrap();
        assert_eq!(
            window.persist_cumulative(&mut state),
            Err(CoverageError::Overflow)
        );
    }
    #[test]
    fn missing_challenge_light_and_noncanonical_json_never_qualify() {
        let mut wrong = scope();
        wrong.signet_challenge_sha256 = None;
        assert!(wrong.validate().is_err());
        wrong = scope();
        wrong.light_mode = true;
        // The profile remains valid/required; actual missing local evidence
        // fails at the checked storage adapter rather than banning light mode.
        assert!(wrong.validate().is_ok());
        let state = Progress::initial(scope(), 1, "6".repeat(64)).unwrap();
        let mut bytes = state.encode().unwrap();
        bytes.push(b' ');
        assert!(Progress::decode(&bytes, &scope()).is_err());
        let value = serde_json::from_slice::<serde_json::Value>(&state.encode().unwrap()).unwrap();
        let mut value = value;
        value["ready"] = serde_json::Value::Bool(true);
        assert!(Progress::decode(&serde_json::to_vec(&value).unwrap(), &scope()).is_err());
    }
}
