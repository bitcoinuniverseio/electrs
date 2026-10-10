//! Work-budgeted script output read state; no whole-address UTXO vector/cache.
use crate::chain::{OutPoint, Txid};
use crate::util::BlockId;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const WORK_LIMIT: usize = 500;
pub const BODY_LIMIT: usize = 128 * 1024;
pub const TOTAL_OUTPUT_LIMIT: u64 = 100000;
pub const TOTAL_WORK_LIMIT: u64 = 1000000;
pub const KEY_LIMIT: usize = 256;
pub const CURSOR_LIMIT: usize = 8192;
pub const MAX_MONEY: u64 = 2100000000000000;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageError {
    Unavailable,
    Changed,
    Storage,
    Contract,
    Capacity,
    Deadline,
    Expired,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReadScope {
    pub source_authority: String,
    pub chain: String,
    pub network: String,
    pub bootstrap: super::read_context::BootstrapObservation,
    pub genesis_hash: String,
    pub artifact_revision: String,
    pub profile_sha256: String,
    pub script_hash: String,
    pub chain_generation: u64,
    pub mempool_generation: u64,
    pub height: u32,
    pub block_hash: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Funding {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub funding: Funding,
    pub funding_key: Vec<u8>,
    pub confirmation_key: Option<Vec<u8>>,
    pub confirmation_seen: bool,
    pub funding_confirmation_complete: bool,
    pub latest_incarnation: Option<BlockId>,
    pub block_hash: Option<String>,
    pub spend_key: Option<Vec<u8>>,
    pub spend_txid: Option<Txid>,
    pub spend_confirmation_key: Option<Vec<u8>>,
    pub spend_confirmation_seen: bool,
    pub emitted: bool,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PageCursor {
    pub created_unix_seconds: u64,
    pub expires_unix_seconds: u64,
    pub scope: ReadScope,
    pub last_history_key: Option<Vec<u8>>,
    pub pending: Option<Pending>,
    pub history_complete: bool,
    pub mempool_offset: usize,
    pub complete: bool,
    pub output_count: u64,
    pub balance_atomic: u64,
    pub scanned: u64,
}
#[derive(Clone, Serialize, Debug)]
pub struct Output {
    pub txid: Txid,
    pub vout: u32,
    pub value_atomic: String,
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<String>,
}
#[derive(Serialize)]
pub struct OutputPage {
    pub schema: &'static str,
    pub scope: ReadScope,
    pub items: Vec<Output>,
    pub complete: bool,
    pub work: usize,
    pub total_work: u64,
    pub output_count: u64,
    pub balance_atomic: String,
}
pub struct HistoryRecord {
    pub key: Vec<u8>,
    pub funding: Option<Funding>,
}
pub struct ConfirmationRecord {
    pub key: Vec<u8>,
    pub canonical: Option<BlockId>,
}
pub struct SpendRecord {
    pub key: Vec<u8>,
    pub txid: Txid,
}
pub struct MempoolRecord {
    pub funding: Option<Funding>,
    pub spent: bool,
}
/// All next-record methods perform one error-preserving exact-key seek/visit.
/// Snapshot implementations must not call legacy whole-vector/hidden-loop helpers.
pub trait PageSource {
    fn valid(&self, scope: &ReadScope) -> Result<(), PageError>;
    fn history(&self, after: Option<&[u8]>) -> Result<Option<HistoryRecord>, PageError>;
    fn confirmation(
        &self,
        txid: &Txid,
        after: Option<&[u8]>,
    ) -> Result<Option<ConfirmationRecord>, PageError>;
    fn spend(
        &self,
        point: &OutPoint,
        after: Option<&[u8]>,
    ) -> Result<Option<SpendRecord>, PageError>;
    fn mempool_spent(&self, point: &OutPoint) -> Result<bool, PageError>;
    fn mempool(&self, offset: usize) -> Result<Option<MempoolRecord>, PageError>;
}
struct Budget {
    used: usize,
    deadline: Instant,
}
impl Budget {
    fn charge(&mut self) -> Result<bool, PageError> {
        if Instant::now() >= self.deadline {
            return Err(PageError::Deadline);
        }
        if self.used == WORK_LIMIT {
            return Ok(false);
        }
        self.used += 1;
        Ok(true)
    }
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl ReadScope {
    pub fn validate(&self) -> Result<(), PageError> {
        if self.source_authority != "mempool-electrs"
            || self.chain != "bitcoin"
            || !["mainnet", "testnet", "testnet4", "signet", "regtest"]
                .contains(&self.network.as_str())
            || !self.bootstrap.validate(&self.network)
            || !lower_hex(&self.genesis_hash, 64)
            || !lower_hex(&self.block_hash, 64)
            || !lower_hex(&self.artifact_revision, 40)
            || !lower_hex(&self.profile_sha256, 64)
            || !lower_hex(&self.script_hash, 64)
            || self.chain_generation == 0
            || self.chain_generation & 1 != 0
        {
            return Err(PageError::Contract);
        }
        Ok(())
    }
}
impl PageCursor {
    pub fn initial(scope: ReadScope) -> Self {
        let created_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs())
            .unwrap_or(0);
        Self {
            created_unix_seconds,
            expires_unix_seconds: created_unix_seconds.saturating_add(3600),
            scope,
            last_history_key: None,
            pending: None,
            history_complete: false,
            mempool_offset: 0,
            complete: false,
            output_count: 0,
            balance_atomic: 0,
            scanned: 0,
        }
    }
    pub fn validate(&self) -> Result<(), PageError> {
        self.scope.validate()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PageError::Unavailable)?
            .as_secs();
        if self.created_unix_seconds == 0
            || self.created_unix_seconds > now
            || self.expires_unix_seconds
                != self
                    .created_unix_seconds
                    .checked_add(3600)
                    .ok_or(PageError::Contract)?
        {
            return Err(PageError::Contract);
        }
        if now >= self.expires_unix_seconds {
            return Err(PageError::Expired);
        }
        if self.output_count > TOTAL_OUTPUT_LIMIT
            || self.balance_atomic > MAX_MONEY
            || self.scanned > TOTAL_WORK_LIMIT
            || self.mempool_offset as u64 > self.scanned
            || self.output_count > self.scanned
        {
            return Err(PageError::Capacity);
        }
        if (!self.history_complete && self.mempool_offset != 0)
            || (self.complete && (!self.history_complete || self.pending.is_some()))
            || (self.history_complete && self.pending.is_some())
        {
            return Err(PageError::Contract);
        }
        let key_valid =
            |key: Option<&[u8]>| key.map_or(true, |k| !k.is_empty() && k.len() <= KEY_LIMIT);
        if !key_valid(self.last_history_key.as_deref()) {
            return Err(PageError::Contract);
        }
        if let Some(p) = &self.pending {
            if !key_valid(Some(&p.funding_key))
                || !key_valid(p.confirmation_key.as_deref())
                || !key_valid(p.spend_key.as_deref())
                || !key_valid(p.spend_confirmation_key.as_deref())
                || p.funding.value > MAX_MONEY
                || p.funding.height > self.scope.height
                || p.confirmation_seen != p.confirmation_key.is_some()
                || p.spend_confirmation_seen != p.spend_confirmation_key.is_some()
                || (p.spend_txid.is_none() && p.spend_confirmation_key.is_some())
                || (p.spend_txid.is_some() && p.spend_key.is_none())
                || p.block_hash
                    .as_ref()
                    .map_or(false, |hash| !lower_hex(hash, 64) || !p.confirmation_seen)
                || (p.funding_confirmation_complete && p.block_hash.is_none())
                || (!p.funding_confirmation_complete && p.block_hash.is_some())
                || p.latest_incarnation.as_ref().map_or(false, |block| {
                    block.height as u64 > self.scope.height as u64
                })
                || (p.emitted && (p.block_hash.is_none() || p.spend_txid.is_some()))
            {
                return Err(PageError::Contract);
            }
        }
        // Bound actual encoded cursor size before it can be copied or signed.
        let bytes = serde_json::to_vec(self).map_err(|_| PageError::Contract)?;
        let encoded = bytes.len() * 2 + 65; // hex payload + dot + SHA256 HMAC hex
        if encoded > CURSOR_LIMIT {
            return Err(PageError::Capacity);
        }
        Ok(())
    }
}
fn add_output(
    state: &mut PageCursor,
    output: Output,
    items: &mut Vec<Output>,
) -> Result<bool, PageError> {
    let value = output
        .value_atomic
        .parse::<u64>()
        .map_err(|_| PageError::Contract)?;
    let next_balance = state
        .balance_atomic
        .checked_add(value)
        .filter(|v| *v <= MAX_MONEY)
        .ok_or(PageError::Capacity)?;
    let mut preview = items.clone();
    preview.push(output.clone());
    // Reserve bounded scope/cursor metadata; no eligible row is skipped at byte limit.
    if serde_json::to_vec(&preview)
        .map_err(|_| PageError::Contract)?
        .len()
        > BODY_LIMIT - CURSOR_LIMIT - 2048
    {
        return Ok(false);
    }
    if state.output_count == TOTAL_OUTPUT_LIMIT {
        return Err(PageError::Capacity);
    }
    state.balance_atomic = next_balance;
    state.output_count += 1;
    items.push(output);
    Ok(true)
}
/// The caller commits cursor only after this whole page and end-generation fence succeed.
pub fn read_page(
    source: &impl PageSource,
    original: &PageCursor,
) -> Result<(OutputPage, PageCursor), PageError> {
    read_page_until(source, original, Instant::now() + Duration::from_secs(10))
}
/// Caller-owned deadline spans snapshot/codec/serialization too. No caller can
/// raise production duration; native query always creates its own10s deadline.
pub(crate) fn read_page_until(
    source: &impl PageSource,
    original: &PageCursor,
    deadline: Instant,
) -> Result<(OutputPage, PageCursor), PageError> {
    original.validate()?;
    source.valid(&original.scope)?;
    let mut state = original.clone();
    let mut budget = Budget { used: 0, deadline };
    let mut items = Vec::new();
    while !state.complete {
        source.valid(&state.scope)?;
        if let Some(mut p) = state.pending.take() {
            let point = OutPoint {
                txid: p.funding.txid,
                vout: p.funding.vout,
            };
            if !p.funding_confirmation_complete {
                if !budget.charge()? {
                    state.pending = Some(p);
                    break;
                }
                match source.confirmation(&p.funding.txid, p.confirmation_key.as_deref())? {
                    Some(row) => {
                        p.confirmation_seen = true;
                        p.confirmation_key = Some(row.key);
                        if let Some(block) = row.canonical {
                            if block.height as u64 > state.scope.height as u64 {
                                return Err(PageError::Contract);
                            }
                            match &p.latest_incarnation {
                                Some(old)
                                    if old.height == block.height && old.hash != block.hash =>
                                {
                                    return Err(PageError::Contract)
                                }
                                Some(old) if old.height >= block.height => {}
                                _ => p.latest_incarnation = Some(block),
                            }
                        }
                    }
                    None => {
                        if !p.confirmation_seen {
                            return Err(PageError::Unavailable);
                        }
                        match &p.latest_incarnation {
                            Some(block) if block.height as u32 == p.funding.height => {
                                p.block_hash = Some(block.hash.to_string());
                                p.funding_confirmation_complete = true;
                            }
                            // Explicit orphan, earlier incarnation or historic
                            // overwrite: this history row is not the current coin.
                            _ => {
                                state.last_history_key = Some(p.funding_key);
                                continue;
                            }
                        }
                    }
                }
                state.pending = Some(p);
                continue;
            }
            if let Some(txid) = p.spend_txid {
                if !budget.charge()? {
                    state.pending = Some(p);
                    break;
                }
                match source.confirmation(&txid, p.spend_confirmation_key.as_deref())? {
                    Some(row) => {
                        p.spend_confirmation_seen = true;
                        p.spend_confirmation_key = Some(row.key);
                        if let Some(block) = row.canonical {
                            if block.height as u64 > state.scope.height as u64 {
                                return Err(PageError::Contract);
                            }
                            // A spend of a previous identical-txid incarnation
                            // cannot consume a later funding incarnation.
                            if block.height as u32 >= p.funding.height {
                                state.last_history_key = Some(p.funding_key);
                                continue;
                            }
                        }
                    }
                    None => {
                        if !p.spend_confirmation_seen {
                            return Err(PageError::Unavailable);
                        }
                        p.spend_txid = None;
                        p.spend_confirmation_key = None;
                        p.spend_confirmation_seen = false;
                    }
                }
                state.pending = Some(p);
                continue;
            }
            if !p.emitted {
                if !budget.charge()? {
                    state.pending = Some(p);
                    break;
                }
                match source.spend(&point, p.spend_key.as_deref())? {
                    Some(row) => {
                        p.spend_key = Some(row.key);
                        p.spend_txid = Some(row.txid);
                        state.pending = Some(p);
                        continue;
                    }
                    None => {
                        if !budget.charge()? {
                            state.pending = Some(p);
                            break;
                        }
                        if source.mempool_spent(&point)? {
                            state.last_history_key = Some(p.funding_key);
                            continue;
                        }
                        p.emitted = true;
                    }
                }
            }
            let output = Output {
                txid: p.funding.txid,
                vout: p.funding.vout,
                value_atomic: p.funding.value.to_string(),
                confirmed: true,
                block_height: Some(p.funding.height),
                block_hash: p.block_hash.clone(),
            };
            if !add_output(&mut state, output, &mut items)? {
                state.pending = Some(p);
                break;
            }
            state.last_history_key = Some(p.funding_key);
        } else if !state.history_complete {
            if !budget.charge()? {
                break;
            }
            match source.history(state.last_history_key.as_deref())? {
                Some(row) => {
                    if let Some(funding) = row.funding {
                        state.pending = Some(Pending {
                            funding,
                            funding_key: row.key,
                            confirmation_key: None,
                            confirmation_seen: false,
                            funding_confirmation_complete: false,
                            latest_incarnation: None,
                            block_hash: None,
                            spend_key: None,
                            spend_txid: None,
                            spend_confirmation_key: None,
                            spend_confirmation_seen: false,
                            emitted: false,
                        });
                    } else {
                        state.last_history_key = Some(row.key);
                    }
                }
                None => state.history_complete = true,
            }
        } else {
            if !budget.charge()? {
                break;
            }
            match source.mempool(state.mempool_offset)? {
                Some(row) => {
                    if let Some(funding) = row.funding {
                        if !row.spent {
                            let output = Output {
                                txid: funding.txid,
                                vout: funding.vout,
                                value_atomic: funding.value.to_string(),
                                confirmed: false,
                                block_height: None,
                                block_hash: None,
                            };
                            if !add_output(&mut state, output, &mut items)? {
                                break;
                            }
                        }
                    }
                    state.mempool_offset = state
                        .mempool_offset
                        .checked_add(1)
                        .ok_or(PageError::Capacity)?;
                }
                None => state.complete = true,
            }
        }
    }
    state.scanned = state
        .scanned
        .checked_add(budget.used as u64)
        .filter(|v| *v <= TOTAL_WORK_LIMIT)
        .ok_or(PageError::Capacity)?;
    if Instant::now() >= deadline {
        return Err(PageError::Deadline);
    }
    source.valid(&state.scope)?;
    state.validate()?;
    let page = OutputPage {
        schema: "universe-electrs-script-output-page-v1",
        scope: state.scope.clone(),
        items,
        complete: state.complete,
        work: budget.used,
        total_work: state.scanned,
        output_count: state.output_count,
        balance_atomic: state.balance_atomic.to_string(),
    };
    // Wire envelope reserves exact hex cursor bytes and MAC delimiters, not
    // an assumed unbounded metadata allowance. Endpoint must serialize this
    // envelope and enforce the same limit before committing any cursor.
    let cursor_bytes = serde_json::to_vec(&state)
        .map_err(|_| PageError::Contract)?
        .len();
    let encoded_cursor = cursor_bytes * 2 + 65;
    let page_bytes = serde_json::to_vec(&page)
        .map_err(|_| PageError::Contract)?
        .len();
    if page_bytes
        .checked_add(encoded_cursor + 32)
        .filter(|v| *v <= BODY_LIMIT)
        .is_none()
    {
        return Err(PageError::Capacity);
    }
    if Instant::now() >= deadline {
        return Err(PageError::Deadline);
    }
    Ok((page, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::convert::TryInto;
    use std::str::FromStr;
    fn scope() -> ReadScope {
        ReadScope {
            source_authority:"mempool-electrs".into(),chain:"bitcoin".into(),
            network: "signet".into(),
            bootstrap:super::super::read_context::BootstrapObservation::from_ready_response("signet",
                &serde_json::json!({"chain":"signet","blocks":100,"headers":100,"bestblockhash":"5".repeat(64),"initialblockdownload":false,"signet_challenge":"51"}),1).unwrap(),
            genesis_hash: "1".repeat(64),
            artifact_revision: "2".repeat(40),
            profile_sha256: "3".repeat(64),
            script_hash: "4".repeat(64),
            chain_generation: 2,
            mempool_generation: 0,
            height: 100,
            block_hash: "5".repeat(64),
        }
    }
    fn funding(index: usize) -> Funding {
        Funding {
            txid: Txid::from_str(&format!("{:064x}", index + 1)).unwrap(),
            vout: 0,
            value: 100,
            height: 100,
        }
    }
    fn key(index: usize) -> Vec<u8> {
        (index as u64).to_be_bytes().to_vec()
    }
    fn after_index(after: Option<&[u8]>) -> usize {
        after.map_or(0, |bytes| {
            u64::from_be_bytes(bytes.try_into().unwrap()) as usize + 1
        })
    }
    struct Source {
        rows: usize,
        orphans: usize,
        spent: bool,
        storage_error: bool,
        changed_after: Option<usize>,
        visits: Cell<usize>,
    }
    impl Source {
        fn new(rows: usize) -> Self {
            Self {
                rows,
                orphans: 0,
                spent: false,
                storage_error: false,
                changed_after: None,
                visits: Cell::new(0),
            }
        }
        fn visit(&self) {
            self.visits.set(self.visits.get() + 1);
        }
    }
    impl PageSource for Source {
        fn valid(&self, scope: &ReadScope) -> Result<(), PageError> {
            if scope != &super::tests::scope() {
                return Err(PageError::Contract);
            }
            if self
                .changed_after
                .map_or(false, |limit| self.visits.get() >= limit)
            {
                return Err(PageError::Changed);
            }
            Ok(())
        }
        fn history(&self, after: Option<&[u8]>) -> Result<Option<HistoryRecord>, PageError> {
            self.visit();
            if self.storage_error {
                return Err(PageError::Storage);
            }
            let i = after_index(after);
            Ok(if i < self.rows {
                Some(HistoryRecord {
                    key: key(i),
                    funding: Some(funding(i)),
                })
            } else {
                None
            })
        }
        fn confirmation(
            &self,
            _: &Txid,
            after: Option<&[u8]>,
        ) -> Result<Option<ConfirmationRecord>, PageError> {
            self.visit();
            let i = after_index(after);
            Ok(if i <= self.orphans {
                Some(ConfirmationRecord {
                    key: key(i),
                    canonical: if i == self.orphans {
                        Some(BlockId {
                            height: 100,
                            hash: bitcoin::BlockHash::from_str(&"5".repeat(64)).unwrap(),
                            time: 1,
                        })
                    } else {
                        None
                    },
                })
            } else {
                None
            })
        }
        fn spend(&self, _: &OutPoint, _: Option<&[u8]>) -> Result<Option<SpendRecord>, PageError> {
            self.visit();
            Ok(None)
        }
        fn mempool_spent(&self, _: &OutPoint) -> Result<bool, PageError> {
            self.visit();
            Ok(self.spent)
        }
        fn mempool(&self, _: usize) -> Result<Option<MempoolRecord>, PageError> {
            self.visit();
            Ok(None)
        }
    }
    #[test]
    fn dense_same_height_history_resumes_exact_full_key_without_loss() {
        let source = Source::new(1200);
        let mut cursor = PageCursor::initial(scope());
        let mut ids = std::collections::HashSet::new();
        for _ in 0..20 {
            let (page, next) = read_page(&source, &cursor).unwrap();
            assert!(page.work <= 500);
            for item in page.items {
                assert!(ids.insert(item.txid));
            }
            cursor = next;
            if cursor.complete {
                break;
            }
        }
        assert!(cursor.complete);
        assert_eq!(ids.len(), 1200);
        assert_eq!(cursor.balance_atomic, 120000);
    }
    #[test]
    fn nested_orphan_work_can_cross_pages_and_each_row_counts() {
        let mut source = Source::new(1);
        source.orphans = 700;
        let (page, pending) = read_page(&source, &PageCursor::initial(scope())).unwrap();
        assert_eq!(page.work, 500);
        assert!(page.items.is_empty());
        assert!(!page.complete);
        assert!(pending.pending.is_some());
        let (page, done) = read_page(&source, &pending).unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(done.complete);
        assert!(page.work <= 500);
    }
    #[test]
    fn spent_empty_page_retains_a_nonterminal_cursor() {
        let mut source = Source::new(200);
        source.spent = true;
        let (page, cursor) = read_page(&source, &PageCursor::initial(scope())).unwrap();
        assert!(page.items.is_empty());
        assert!(!cursor.complete);
        assert!(cursor.last_history_key.is_some());
        assert_eq!(page.work, 500);
        let (_, cursor) = read_page(&source, &cursor).unwrap();
        let (_, cursor) = read_page(&source, &cursor).unwrap();
        assert!(cursor.complete);
        assert_eq!(cursor.balance_atomic, 0);
    }
    #[test]
    fn storage_error_never_turns_into_empty_complete_response() {
        let mut source = Source::new(0);
        source.storage_error = true;
        assert!(matches!(
            read_page(&source, &PageCursor::initial(scope())),
            Err(PageError::Storage)
        ));
    }
    #[test]
    fn end_generation_fence_rejects_material_change_without_advancing_original() {
        let mut source = Source::new(1);
        source.changed_after = Some(4);
        let original = PageCursor::initial(scope());
        assert!(matches!(
            read_page(&source, &original),
            Err(PageError::Changed)
        ));
        assert_eq!(original.scanned, 0);
        assert_eq!(original.output_count, 0);
    }
    #[test]
    fn cursor_scope_strings_unknown_fields_and_phase_invariants_are_bounded() {
        let mut cursor = PageCursor::initial(scope());
        cursor.scope.profile_sha256 = "a".repeat(100000);
        assert!(matches!(cursor.validate(), Err(PageError::Contract)));
        let mut cursor = PageCursor::initial(scope());
        cursor.complete = true;
        assert!(cursor.validate().is_err());
        let mut value = serde_json::to_value(PageCursor::initial(scope())).unwrap();
        value["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<PageCursor>(value).is_err());
    }
    #[test]
    fn encoded_page_and_cursor_remain_within_actual_wire_budget() {
        let source = Source::new(400);
        let (page, cursor) = read_page(&source, &PageCursor::initial(scope())).unwrap();
        let bytes = serde_json::to_vec(&cursor).unwrap();
        let cursor_size = bytes.len() * 2 + 65;
        assert!(cursor_size <= CURSOR_LIMIT);
        assert!(serde_json::to_vec(&page).unwrap().len() + cursor_size + 32 <= BODY_LIMIT);
    }
    struct Incarnations {
        confirmations: Vec<Option<BlockId>>,
        spending: Vec<Option<BlockId>>,
        visits: Cell<usize>,
        changed: Option<usize>,
    }
    fn block(height: usize, hash: u8) -> BlockId {
        BlockId {
            height,
            hash: bitcoin::BlockHash::from_str(&format!("{:064x}", hash)).unwrap(),
            time: 1,
        }
    }
    impl PageSource for Incarnations {
        fn valid(&self, scope: &ReadScope) -> Result<(), PageError> {
            if scope != &super::tests::scope() {
                return Err(PageError::Contract);
            }
            if self.changed.map_or(false, |n| self.visits.get() >= n) {
                return Err(PageError::Changed);
            }
            Ok(())
        }
        fn history(&self, after: Option<&[u8]>) -> Result<Option<HistoryRecord>, PageError> {
            self.visits.set(self.visits.get() + 1);
            let index = after_index(after);
            Ok(if index < 2 {
                let mut f = funding(0);
                f.height = if index == 0 { 40 } else { 90 };
                Some(HistoryRecord {
                    key: key(index),
                    funding: Some(f),
                })
            } else {
                None
            })
        }
        fn confirmation(
            &self,
            txid: &Txid,
            after: Option<&[u8]>,
        ) -> Result<Option<ConfirmationRecord>, PageError> {
            self.visits.set(self.visits.get() + 1);
            let rows = if txid == &funding(0).txid {
                &self.confirmations
            } else {
                &self.spending
            };
            let i = after_index(after);
            Ok(rows.get(i).map(|canonical| ConfirmationRecord {
                key: key(i),
                canonical: canonical.clone(),
            }))
        }
        fn spend(
            &self,
            _: &OutPoint,
            after: Option<&[u8]>,
        ) -> Result<Option<SpendRecord>, PageError> {
            self.visits.set(self.visits.get() + 1);
            Ok(if after.is_none() && !self.spending.is_empty() {
                Some(SpendRecord {
                    key: key(0),
                    txid: funding(999).txid,
                })
            } else {
                None
            })
        }
        fn mempool_spent(&self, _: &OutPoint) -> Result<bool, PageError> {
            self.visits.set(self.visits.get() + 1);
            Ok(false)
        }
        fn mempool(&self, _: usize) -> Result<Option<MempoolRecord>, PageError> {
            self.visits.set(self.visits.get() + 1);
            Ok(None)
        }
    }
    fn incarnations(
        confirmations: Vec<Option<BlockId>>,
        spending: Vec<Option<BlockId>>,
    ) -> Incarnations {
        Incarnations {
            confirmations,
            spending,
            visits: Cell::new(0),
            changed: None,
        }
    }
    #[test]
    fn duplicate_txid_uses_latest_current_incarnation_and_ignores_old_spend() {
        let source = incarnations(
            vec![Some(block(40, 1)), None, Some(block(90, 2))],
            vec![Some(block(60, 3))],
        );
        let (page, cursor) = read_page(&source, &PageCursor::initial(scope())).unwrap();
        assert!(cursor.complete);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].block_height, Some(90));
        assert_eq!(cursor.output_count, 1);
        assert_eq!(cursor.balance_atomic, 100);
    }
    #[test]
    fn spend_of_latest_incarnation_suppresses_output() {
        let source = incarnations(
            vec![Some(block(90, 2)), Some(block(40, 1))],
            vec![Some(block(60, 3)), None, Some(block(95, 4))],
        );
        let (page, cursor) = read_page(&source, &PageCursor::initial(scope())).unwrap();
        assert!(cursor.complete);
        assert!(page.items.is_empty());
    }
    #[test]
    fn same_height_conflicting_current_confirmation_is_contract_error() {
        let source = incarnations(vec![Some(block(90, 2)), Some(block(90, 3))], vec![]);
        assert!(matches!(
            read_page(&source, &PageCursor::initial(scope())),
            Err(PageError::Contract)
        ));
    }
    #[test]
    fn halfway_confirmation_scan_never_emits_previous_incarnation() {
        let mut confirmations = vec![Some(block(40, 1))];
        confirmations.extend((0..700).map(|_| None));
        confirmations.push(Some(block(90, 2)));
        let source = incarnations(confirmations, vec![]);
        let mut cursor = PageCursor::initial(scope());
        let mut heights = vec![];
        for index in 0..10 {
            let (page, next) = read_page(&source, &cursor).unwrap();
            assert!(page.work <= 500);
            if index == 0 {
                assert!(page.items.is_empty());
                assert!(!next.complete);
            }
            heights.extend(page.items.iter().map(|row| row.block_height));
            cursor = next;
            if cursor.complete {
                break;
            }
        }
        assert!(cursor.complete);
        assert_eq!(heights, vec![Some(90)]);
    }
    #[test]
    fn missing_confirmation_is_unknown_and_reorg_invalidates_incarnation_scan() {
        let source = incarnations(vec![], vec![]);
        assert!(matches!(
            read_page(&source, &PageCursor::initial(scope())),
            Err(PageError::Unavailable)
        ));
        let mut source = incarnations(vec![Some(block(40, 1)), Some(block(90, 2))], vec![]);
        source.changed = Some(3);
        assert!(matches!(
            read_page(&source, &PageCursor::initial(scope())),
            Err(PageError::Changed)
        ));
    }
    #[test]
    fn logical_deadline_exhaustion_does_not_charge_more_io_work() {
        let mut budget = Budget {
            used: 0,
            deadline: Instant::now(),
        };
        assert!(matches!(budget.charge(), Err(PageError::Deadline)));
        assert_eq!(budget.used, 0);
    }
    #[test]
    fn io_returning_terminal_after_deadline_never_publishes_complete_page() {
        struct DelayedTerminal(Source);
        impl PageSource for DelayedTerminal {
            fn valid(&self, s: &ReadScope) -> Result<(), PageError> {
                self.0.valid(s)
            }
            fn history(&self, a: Option<&[u8]>) -> Result<Option<HistoryRecord>, PageError> {
                self.0.history(a)
            }
            fn confirmation(
                &self,
                t: &Txid,
                a: Option<&[u8]>,
            ) -> Result<Option<ConfirmationRecord>, PageError> {
                self.0.confirmation(t, a)
            }
            fn spend(
                &self,
                p: &OutPoint,
                a: Option<&[u8]>,
            ) -> Result<Option<SpendRecord>, PageError> {
                self.0.spend(p, a)
            }
            fn mempool_spent(&self, p: &OutPoint) -> Result<bool, PageError> {
                self.0.mempool_spent(p)
            }
            fn mempool(&self, _: usize) -> Result<Option<MempoolRecord>, PageError> {
                std::thread::sleep(Duration::from_millis(30));
                Ok(None)
            }
        }
        let source = DelayedTerminal(Source::new(0));
        let mut original = PageCursor::initial(scope());
        original.history_complete = true;
        let result = read_page_until(
            &source,
            &original,
            Instant::now() + Duration::from_millis(20),
        );
        assert!(matches!(result, Err(PageError::Deadline)));
        assert!(!original.complete);
        assert_eq!(original.scanned, 0);
    }
}
