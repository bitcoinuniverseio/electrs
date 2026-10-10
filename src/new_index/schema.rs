use super::read_generation::ReadGeneration;
use super::writer_update::{finish_qualified_plan, Phase, UpdatePlan, UpdateWriter};
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
#[cfg(not(feature = "liquid"))]
use bitcoin::merkle_tree::MerkleBlock;
#[cfg(not(feature = "liquid"))]
use bitcoin::VarInt;
use itertools::Itertools;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, serialize};
#[cfg(feature = "liquid")]
use elements::{
    encode::{deserialize, serialize, VarInt},
    AssetId,
};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::chain::{
    BlockHash, BlockHeader, Network, OutPoint, Script, Transaction, TxOut, Txid, TxidCompat, Value,
};
use crate::config::Config;
use crate::daemon::Daemon;
use crate::errors::*;
use crate::metrics::{Gauge, HistogramOpts, HistogramTimer, HistogramVec, MetricOpts, Metrics};
use crate::util::{
    bincode_util, full_hash, has_prevout, is_spendable, BlockHeaderMeta, BlockId, BlockMeta,
    BlockStatus, Bytes, HeaderEntry, HeaderList, ScriptToAddr,
};

use crate::new_index::db::{DBFlush, DBRow, ReverseScanIterator, ScanIterator, DB};
use crate::new_index::fetch::{start_fetcher, BlockEntry, FetchFrom};

#[cfg(feature = "liquid")]
use crate::elements::{asset, peg};

use super::{db::ReverseScanGroupIterator, fetch::bitcoind_sequential_fetcher};

const MIN_HISTORY_ITEMS_TO_CACHE: usize = 100;

pub struct Store {
    read_generation: ReadGeneration,
    #[cfg(not(feature = "liquid"))]
    coverage_scope: RwLock<Option<String>>,
    #[cfg(not(feature = "liquid"))]
    proof_txstore: Option<DB>,
    // TODO: should be column families
    txstore_db: DB,
    history_db: DB,
    cache_db: DB,
    added_blockhashes: RwLock<HashSet<BlockHash>>,
    indexed_blockhashes: RwLock<HashSet<BlockHash>>,
    indexed_headers: RwLock<HeaderList>,
}

impl Store {
    pub fn open(path: &Path, config: &Config) -> Self {
        // Fresh absent stores can derive an initial complete write generation.
        // Preexisting stores require a separate proven baseline; current native
        // producer behavior remains intact while the new lane stays unavailable.
        let fresh_read_baseline = !["txstore", "history", "cache"]
            .iter()
            .any(|name| path.join(name).exists());
        let txstore_db = DB::open(&path.join("txstore"), config);
        let added_blockhashes = load_blockhashes(&txstore_db, &BlockRow::done_filter());
        debug!("{} blocks were added", added_blockhashes.len());

        let history_db = DB::open(&path.join("history"), config);
        let indexed_blockhashes = load_blockhashes(&history_db, &BlockRow::done_filter());
        debug!("{} blocks were indexed", indexed_blockhashes.len());

        let cache_db = DB::open(&path.join("cache"), config);

        let headers = if let Some(tip_hash) = txstore_db.get(b"t") {
            let tip_hash = deserialize(&tip_hash).expect("invalid chain tip in `t`");
            let headers_map = load_blockheaders(&txstore_db);
            debug!(
                "{} headers were loaded, tip at {:?}",
                headers_map.len(),
                tip_hash
            );
            HeaderList::new(headers_map, tip_hash)
        } else {
            HeaderList::empty()
        };

        Store {
            read_generation: if fresh_read_baseline {
                ReadGeneration::new()
            } else {
                ReadGeneration::new_existing_unqualified()
            },
            txstore_db,
            history_db,
            cache_db,
            #[cfg(not(feature = "liquid"))]
            coverage_scope: RwLock::new(None),
            #[cfg(not(feature = "liquid"))]
            proof_txstore: config.history_proof_dir.as_ref().map(|directory| {
                DB::open_proof_read_only(&directory.join("txstore"))
                    .expect("explicit local proof store unavailable")
            }),
            added_blockhashes: RwLock::new(added_blockhashes),
            indexed_blockhashes: RwLock::new(indexed_blockhashes),
            indexed_headers: RwLock::new(headers),
        }
    }

    #[cfg(not(feature = "liquid"))]
    fn proof_point(
        &self,
        key: &[u8],
        maximum: usize,
    ) -> std::result::Result<Option<Bytes>, super::qualification::QualifiedReadError> {
        match self.txstore_db.qualified_get(key, maximum)? {
            Some(value) => Ok(Some(value)),
            None => {
                if !matches!(key.first(), Some(b'T') | Some(b'X') | Some(b'M')) {
                    return Ok(None);
                }
                match &self.proof_txstore {
                    Some(store) => store.qualified_get(key, maximum),
                    None => Ok(None),
                }
            }
        }
    }
    pub fn txstore_db(&self) -> &DB {
        &self.txstore_db
    }

    pub fn history_db(&self) -> &DB {
        &self.history_db
    }

    pub fn cache_db(&self) -> &DB {
        &self.cache_db
    }

    pub fn done_initial_sync(&self) -> bool {
        self.txstore_db.get(b"t").is_some()
    }
}

type UtxoMap = HashMap<OutPoint, (BlockId, Value)>;

#[derive(Debug)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub confirmed: Option<BlockId>,
    pub value: Value,

    #[cfg(feature = "liquid")]
    pub asset: elements::confidential::Asset,
    #[cfg(feature = "liquid")]
    pub nonce: elements::confidential::Nonce,
    #[cfg(feature = "liquid")]
    pub witness: elements::TxOutWitness,
}

impl From<&Utxo> for OutPoint {
    fn from(utxo: &Utxo) -> Self {
        OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }
    }
}

#[derive(Debug)]
pub struct SpendingInput {
    pub txid: Txid,
    pub vin: u32,
    pub confirmed: Option<BlockId>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ScriptStats {
    pub tx_count: usize,
    pub funded_txo_count: usize,
    pub spent_txo_count: usize,
    #[cfg(not(feature = "liquid"))]
    pub funded_txo_sum: u64,
    #[cfg(not(feature = "liquid"))]
    pub spent_txo_sum: u64,
}

impl ScriptStats {
    #[cfg(feature = "liquid")]
    fn is_sane(&self) -> bool {
        // See below for comments.
        self.spent_txo_count <= self.funded_txo_count
            && self.tx_count <= self.spent_txo_count + self.funded_txo_count
    }
    #[cfg(not(feature = "liquid"))]
    fn is_sane(&self) -> bool {
        // There are less or equal spends to funds
        self.spent_txo_count <= self.funded_txo_count
        // There are less or equal transactions to total spent+funded txo counts
        // (Most spread out txo case = N funds in 1 tx each + M spends in 1 tx each = N + M txes)
        && self.tx_count <= self.spent_txo_count + self.funded_txo_count
        // There are less or equal spent coins to funded coins
        && self.spent_txo_sum <= self.funded_txo_sum
        // If funded and spent txos are equal (0 balance)
        // Then funded and spent coins must be equal (0 balance)
        && (self.funded_txo_count == self.spent_txo_count)
            == (self.funded_txo_sum == self.spent_txo_sum)
    }
}

pub struct Indexer {
    pending_read_update: Option<UpdatePlan<HeaderEntry, BlockHash>>,
    availability_validation_tip: Option<BlockHash>,
    store: Arc<Store>,
    flush: DBFlush,
    from: FetchFrom,
    iconfig: IndexerConfig,
    duration: HistogramVec,
    tip_metric: Gauge,
    #[cfg(not(feature = "liquid"))]
    baseline_profile: super::read_context::StaticReadProfile,
    #[cfg(not(feature = "liquid"))]
    baseline: Option<BaselineRuntime>,
    #[cfg(not(feature = "liquid"))]
    verified_prefix: Option<super::history_coverage::Prefix>,
    #[cfg(not(feature = "liquid"))]
    prefix_recovery: Option<PrefixRecovery>,
    #[cfg(not(feature = "liquid"))]
    baseline_total_visits: String,
}

#[cfg(not(feature = "liquid"))]
struct PrefixRecovery {
    cursor: super::history_coverage::Prefix,
    target_height: u32,
    target_hash: String,
}
#[cfg(not(feature = "liquid"))]
struct BaselineRuntime {
    progress: super::history_coverage::Progress,
    header: Option<HeaderEntry>,
    roster: Vec<Txid>,
    roster_seen: super::history_coverage::RosterProof,
    transaction: Option<Transaction>,
    edges: Vec<[u8; super::qualified_edges::EDGE_KEY_BYTES]>,
    certificates_verified: bool,
}
#[cfg(not(feature = "liquid"))]
pub(crate) struct CompletedBaseline {
    scope: String,
    height: u32,
    hash: BlockHash,
}
#[cfg(not(feature = "liquid"))]
impl CompletedBaseline {
    pub(crate) fn matches(&self, scope: &str, height: u32, hash: &BlockHash) -> bool {
        self.scope == scope && self.height == height && &self.hash == hash
    }
}

#[cfg(not(feature = "liquid"))]
fn baseline_point(
    store: &Store,
    key: &[u8],
    maximum: usize,
    window: &mut super::history_coverage::Window,
) -> std::result::Result<Vec<u8>, super::history_coverage::CoverageError> {
    use super::history_coverage::CoverageError;
    window.reserve(1, 1 + maximum / 32)?;
    // Reserve primary and explicit fallback before either dispatch.
    if store.proof_txstore.is_some() && matches!(key.first(), Some(b'T') | Some(b'X') | Some(b'M'))
    {
        window.reserve(1, 1 + maximum / 32)?;
    }
    store
        .proof_point(key, maximum)
        .map_err(|_| CoverageError::Storage)?
        .ok_or(CoverageError::Missing)
}
#[cfg(not(feature = "liquid"))]
fn baseline_history_point(
    db: &DB,
    key: &[u8],
    maximum: usize,
    window: &mut super::history_coverage::Window,
) -> std::result::Result<Vec<u8>, super::history_coverage::CoverageError> {
    window.reserve(1, 1 + maximum / 32)?;
    db.qualified_get(key, maximum)
        .map_err(|_| super::history_coverage::CoverageError::Storage)?
        .ok_or(super::history_coverage::CoverageError::Missing)
}

#[cfg(not(feature = "liquid"))]
fn increment_atomic(
    value: &str,
) -> std::result::Result<String, super::history_coverage::CoverageError> {
    let value = value
        .parse::<u64>()
        .map_err(|_| super::history_coverage::CoverageError::Contract)?;
    Ok(value
        .checked_add(1)
        .ok_or(super::history_coverage::CoverageError::Overflow)?
        .to_string())
}
#[cfg(not(feature = "liquid"))]
fn decode_digest(
    value: &str,
) -> std::result::Result<Vec<u8>, super::history_coverage::CoverageError> {
    if value.len() != 64 {
        return Err(super::history_coverage::CoverageError::Contract);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or(super::history_coverage::CoverageError::Contract)
        })
        .collect()
}

#[cfg(not(feature = "liquid"))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerCache<T> {
    schema_version: u16,
    scope_digest: String,
    computation_version: String,
    block_hash: BlockHash,
    payload: T,
}
#[cfg(not(feature = "liquid"))]
fn ledger_cache_key(kind: u8, script: &[u8]) -> Vec<u8> {
    let mut key = vec![0xff, b'U', kind, 2];
    key.extend_from_slice(script);
    key
}

struct IndexerConfig {
    light_mode: bool,
    address_search: bool,
    index_unspendables: bool,
    network: Network,
    #[cfg(feature = "liquid")]
    parent_network: crate::chain::BNetwork,
}

impl From<&Config> for IndexerConfig {
    fn from(config: &Config) -> Self {
        IndexerConfig {
            light_mode: config.light_mode,
            address_search: config.address_search,
            index_unspendables: config.index_unspendables,
            network: config.network_type,
            #[cfg(feature = "liquid")]
            parent_network: config.parent_network,
        }
    }
}

pub struct ChainQuery {
    store: Arc<Store>, // TODO: should be used as read-only
    daemon: Arc<Daemon>,
    light_mode: bool,
    duration: HistogramVec,
    network: Network,
}

#[derive(Debug, Clone)]
pub enum Operation {
    AddBlocks,
    DeleteBlocks,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Operation::AddBlocks => "Adding",
            Operation::DeleteBlocks => "Deleting",
        })
    }
}

// TODO: &[Block] should be an iterator / a queue.
impl Indexer {
    pub fn open(store: Arc<Store>, from: FetchFrom, config: &Config, metrics: &Metrics) -> Self {
        Indexer {
            pending_read_update: None,
            availability_validation_tip: None,
            #[cfg(not(feature = "liquid"))]
            baseline: None,
            #[cfg(not(feature = "liquid"))]
            verified_prefix: None,
            #[cfg(not(feature = "liquid"))]
            prefix_recovery: None,
            #[cfg(not(feature = "liquid"))]
            baseline_total_visits: "0".into(),
            #[cfg(not(feature = "liquid"))]
            baseline_profile: super::read_context::StaticReadProfile {
                network: match config.network_type {
                    Network::Bitcoin => "mainnet",
                    Network::Testnet => "testnet",
                    Network::Testnet4 => "testnet4",
                    Network::Signet => "signet",
                    Network::Regtest => "regtest",
                }
                .into(),
                magic: config.magic,
                db_path: config.db_path.to_string_lossy().into_owned(),
                rpc_address: config.daemon_rpc_addr.to_string(),
                light_mode: config.light_mode,
                index_unspendables: config.index_unspendables,
                db_version: super::db::DB_VERSION,
                electrs_version: crate::config::ELECTRS_VERSION.into(),
                electrum_discovery: cfg!(feature = "electrum-discovery"),
                work_limit: super::paged_outputs::WORK_LIMIT,
                body_limit: super::paged_outputs::BODY_LIMIT,
                history_proof_dir: config
                    .history_proof_dir
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
            },
            store,
            flush: DBFlush::Disable,
            from,
            iconfig: IndexerConfig::from(config),
            duration: metrics.histogram_vec(
                HistogramOpts::new("index_duration", "Index update duration (in seconds)"),
                &["step"],
            ),
            tip_metric: metrics.gauge(MetricOpts::new("tip_height", "Current chain tip height")),
        }
    }

    #[cfg(not(feature = "liquid"))]
    pub fn continue_local_baseline(&mut self, daemon: &Daemon, current_tip: &BlockHash) {
        if self.pending_read_update.is_some() {
            return;
        }
        if self.store.read_generation.completed().is_some()
            && self
                .store
                .coverage_scope
                .try_read()
                .map_or(false, |scope| scope.is_some())
            && self.baseline.is_none()
        {
            return;
        }
        if let Err(error) = self.baseline_invocation(daemon, current_tip) {
            // Supplemental proof failure never aborts valid canonical indexing.
            // No progress/certificate is treated as ready after a failed step.
            self.store.read_generation.invalidate_material();
            self.baseline = None;
            self.verified_prefix = None;
            self.prefix_recovery = None;
            if let Ok(mut scope) = self.store.coverage_scope.write() {
                *scope = None;
            }
            warn!("history coverage unavailable: {:?}", error);
        }
    }
    #[cfg(not(feature = "liquid"))]
    fn baseline_scope(
        &self,
        daemon: &Daemon,
    ) -> std::result::Result<
        super::history_coverage::CoverageScope,
        super::history_coverage::CoverageError,
    > {
        use super::history_coverage::{digest, CoverageError, CoverageScope};
        let revision = option_env!("ELECTRS_SOURCE_REVISION").ok_or(CoverageError::Missing)?;
        let bootstrap = daemon
            .paged_bootstrap_observation()
            .filter(|value| value.validate(&self.baseline_profile.network))
            .ok_or(CoverageError::Missing)?;
        if self.baseline_profile.network == "signet" && bootstrap.height == 0 {
            return Err(CoverageError::Missing);
        }
        let genesis = self
            .store
            .indexed_headers
            .try_read()
            .map_err(|_| CoverageError::Changed)?
            .header_by_height(0)
            .map(|header| *header.hash())
            .ok_or(CoverageError::Missing)?;
        if genesis != crate::chain::genesis_hash(self.iconfig.network) {
            return Err(CoverageError::Changed);
        }
        let profile = self
            .baseline_profile
            .bytes(bootstrap)
            .map_err(|_| CoverageError::Contract)?;
        let scope = CoverageScope {
            schema_version: 2,
            chain: "bitcoin".into(),
            network: self.baseline_profile.network.clone(),
            genesis_hash: genesis.to_string(),
            source_revision: revision.into(),
            profile_sha256: digest(b"", &profile),
            namespace_schema_sha256: digest(
                b"",
                b"UE1:146/UP2:36/UC2:72/UA2:36/UU2:36;canonical-json-v2;funding-height-position-v2",
            ),
            signet_challenge_sha256: bootstrap.signet_challenge_sha256.clone(),
            light_mode: self.iconfig.light_mode,
            index_unspendables: self.iconfig.index_unspendables,
            address_search: self.iconfig.address_search,
        };
        scope.validate()?;
        Ok(scope)
    }
    #[cfg(not(feature = "liquid"))]
    fn persist_recovery_window(
        &mut self,
        scope: &super::history_coverage::CoverageScope,
        height: u32,
        hash: &BlockHash,
        window: &mut super::history_coverage::Window,
    ) -> std::result::Result<(), super::history_coverage::CoverageError> {
        use super::history_coverage::{CoverageError, Progress};
        // Persist accounting, never an orphan prefix as a ready certificate.
        // Restart will revalidate from genesis and carry this cumulative count.
        let mut state = Progress::initial(scope.clone(), height, hash.to_string())?;
        state.total_visits_atomic = self.baseline_total_visits.clone();
        window.persist_cumulative(&mut state)?;
        self.store
            .history_db
            .write_coverage(vec![DBRow {
                key: state.progress_key()?,
                value: state.encode()?,
            }])
            .map_err(|_| CoverageError::Storage)?;
        self.baseline_total_visits = state.total_visits_atomic;
        Ok(())
    }
    #[cfg(not(feature = "liquid"))]
    fn baseline_invocation(
        &mut self,
        daemon: &Daemon,
        current_tip: &BlockHash,
    ) -> std::result::Result<(), super::history_coverage::CoverageError> {
        use super::history_coverage::{
            self as coverage, digest, BlockCertificate, CoverageError, Phase, Progress, Window,
        };
        use bitcoin::hashes::Hash;
        let mut window = Window::new();
        window.reserve(4, 1000)?;
        let scope = self.baseline_scope(daemon)?;
        // Reserve the terminal progress write before any owned work starts.
        window.reserve(1, 1 + coverage::PROGRESS_BYTES / 32)?;
        let target = {
            let headers = self
                .store
                .indexed_headers
                .try_read()
                .map_err(|_| CoverageError::Changed)?;
            if headers.tip() != current_tip {
                return Err(CoverageError::Changed);
            }
            headers
                .header_by_blockhash(current_tip)
                .cloned()
                .ok_or(CoverageError::Missing)?
        };
        if baseline_point(&self.store, b"t", 32, &mut window)? != serialize(current_tip) {
            return Err(CoverageError::Changed);
        }
        if let Some(mut recovery) = self.prefix_recovery.take() {
            let scope_digest = scope.commitment()?;
            while recovery.cursor.height > recovery.target_height {
                let mut key = vec![0xff, b'U', b'C', 2];
                key.extend(decode_digest(&scope_digest)?);
                key.extend(recovery.cursor.height.to_be_bytes());
                key.extend(decode_digest(&recovery.cursor.block_hash)?);
                let bytes = match baseline_history_point(
                    &self.store.history_db,
                    &key,
                    coverage::CERTIFICATE_BYTES,
                    &mut window,
                ) {
                    Ok(bytes) => bytes,
                    Err(CoverageError::Budget) => {
                        self.persist_recovery_window(
                            &scope,
                            target.height() as u32,
                            current_tip,
                            &mut window,
                        )?;
                        self.prefix_recovery = Some(recovery);
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let certificate: BlockCertificate =
                    serde_json::from_slice(&bytes).map_err(|_| CoverageError::Contract)?;
                if certificate.encode()?.as_slice() != bytes {
                    return Err(CoverageError::Contract);
                }
                // The starting root is an in-process actual closed proof,
                // never a deserialized marker presented as a certificate.
                let previous = certificate.previous(
                    &recovery.cursor,
                    &scope_digest,
                    &scope.source_revision,
                )?;
                if let Err(CoverageError::Budget) = window.reserve(1, 1) {
                    self.persist_recovery_window(
                        &scope,
                        target.height() as u32,
                        current_tip,
                        &mut window,
                    )?;
                    self.prefix_recovery = Some(recovery);
                    return Ok(());
                }
                self.store
                    .history_db
                    .delete(vec![key])
                    .map_err(|_| CoverageError::Storage)?;
                recovery.cursor = previous;
            }
            if recovery.cursor.height != recovery.target_height
                || recovery.cursor.block_hash != recovery.target_hash
                || self
                    .store
                    .indexed_headers
                    .try_read()
                    .map_err(|_| CoverageError::Changed)?
                    .header_by_height(recovery.target_height as usize)
                    .map(|header| header.hash().to_string())
                    .as_deref()
                    != Some(&recovery.target_hash)
            {
                return Err(CoverageError::Changed);
            }
            self.verified_prefix = Some(recovery.cursor.clone());
            let mut progress = Progress::initial(
                scope.clone(),
                target.height() as u32,
                current_tip.to_string(),
            )?;
            progress.total_visits_atomic = self.baseline_total_visits.clone();
            window.persist_cumulative(&mut progress)?;
            self.baseline_total_visits = progress.total_visits_atomic.clone();
            progress.prefix = Some(recovery.cursor);
            progress.next_height = recovery
                .target_height
                .checked_add(1)
                .ok_or(CoverageError::Overflow)?;
            self.baseline = Some(BaselineRuntime {
                progress,
                header: None,
                roster: vec![],
                roster_seen: super::history_coverage::RosterProof::new(),
                transaction: None,
                edges: vec![],
                certificates_verified: true,
            });
        }
        if self.baseline.is_none() {
            let mut state = Progress::initial(
                scope.clone(),
                target.height() as u32,
                current_tip.to_string(),
            )?;
            // Persisted markers/progress are NOT historical proof. After a
            // process restart revalidate from genesis; preserve cumulative
            // reservation accounting and the previous canonical record.
            let key = state.progress_key()?;
            window.reserve(1, 1 + coverage::PROGRESS_BYTES / 32)?;
            if let Some(bytes) = self
                .store
                .history_db
                .qualified_get(&key, coverage::PROGRESS_BYTES)
                .map_err(|_| CoverageError::Storage)?
            {
                let saved = Progress::decode(&bytes, &scope)?;
                state.total_visits_atomic = saved.total_visits_atomic;
                self.baseline_total_visits = state.total_visits_atomic.clone();
            }
            self.baseline = Some(BaselineRuntime {
                progress: state,
                header: None,
                roster: vec![],
                roster_seen: super::history_coverage::RosterProof::new(),
                transaction: None,
                edges: vec![],
                certificates_verified: true,
            });
        }
        let mut runtime = self.baseline.take().ok_or(CoverageError::Missing)?;
        runtime.progress.validate(&scope)?;
        runtime.progress.target_observed_height = target.height() as u32;
        runtime.progress.target_observed_hash = current_tip.to_string();
        if let Some(prefix) = &runtime.progress.prefix {
            let actual = self
                .store
                .indexed_headers
                .try_read()
                .map_err(|_| CoverageError::Changed)?
                .header_by_height(prefix.height as usize)
                .map(|entry| entry.hash().to_string());
            if actual.as_deref() != Some(&prefix.block_hash) {
                return Err(CoverageError::Changed);
            }
        }
        // Closure is assessed only after every actual block/transaction/row
        // check, under current canonical metadata and persisted tip fence.
        if runtime.progress.next_height > target.height() as u32 {
            let prefix = runtime
                .progress
                .prefix
                .as_ref()
                .ok_or(CoverageError::Missing)?;
            if !runtime.certificates_verified
                || prefix.height != target.height() as u32
                || prefix.block_hash != current_tip.to_string()
            {
                return Err(CoverageError::Changed);
            }
            let owner = Arc::clone(&self.store);
            let mutation = owner.read_generation.begin();
            if baseline_point(&self.store, b"t", 32, &mut window)? != serialize(current_tip)
                || self
                    .store
                    .indexed_headers
                    .try_read()
                    .map_err(|_| CoverageError::Changed)?
                    .tip()
                    != current_tip
            {
                return Err(CoverageError::Changed);
            }
            let commitment = scope.commitment()?;
            let proof = CompletedBaseline {
                scope: commitment.clone(),
                height: prefix.height,
                hash: *current_tip,
            };
            mutation
                .commit_baseline(proof, &commitment, prefix.height, current_tip)
                .map_err(|_| CoverageError::Changed)?;
            *self
                .store
                .coverage_scope
                .write()
                .map_err(|_| CoverageError::Changed)? = Some(commitment);
            self.verified_prefix = Some(prefix.clone());
            return Ok(());
        }
        loop {
            let mut block_completed = false;
            let result = (|| -> std::result::Result<(), CoverageError> {
                match runtime.progress.phase {
                    Phase::BlockRoster => {
                        window.reserve(1, 1)?;
                        let header = self
                            .store
                            .indexed_headers
                            .try_read()
                            .map_err(|_| CoverageError::Changed)?
                            .header_by_height(runtime.progress.next_height as usize)
                            .cloned()
                            .ok_or(CoverageError::Missing)?;
                        let raw = baseline_point(
                            &self.store,
                            &BlockRow::txids_key(full_hash(&header.hash()[..])),
                            coverage::POINT_BYTES,
                            &mut window,
                        )?;
                        // Validate all count/length bytes before Vec allocation.
                        if raw.len() < 8 {
                            return Err(CoverageError::Contract);
                        }
                        let count = u64::from_le_bytes(
                            raw[..8].try_into().map_err(|_| CoverageError::Contract)?,
                        );
                        if count == 0
                            || count > u16::MAX as u64
                            || 8 + count * 32 != raw.len() as u64
                        {
                            return Err(CoverageError::Contract);
                        }
                        let roster: Vec<Txid> = bincode_util::deserialize_little(&raw)
                            .map_err(|_| CoverageError::Contract)?;
                        let meta = baseline_point(
                            &self.store,
                            &BlockRow::meta_key(full_hash(&header.hash()[..])),
                            128,
                            &mut window,
                        )?;
                        let meta: BlockMeta = bincode_util::deserialize_little(&meta)
                            .map_err(|_| CoverageError::Contract)?;
                        if meta.tx_count as usize != roster.len() || meta.weight > 4_000_000 {
                            return Err(CoverageError::Contract);
                        }
                        runtime.header = Some(header);
                        runtime.roster = roster;
                        runtime.edges.clear();
                        runtime.progress.transaction_position = 0;
                        runtime.progress.item_position = 0;
                        runtime.progress.history_digest = "0".repeat(64);
                        runtime.progress.edges_digest = "0".repeat(64);
                        runtime.progress.checked_funding_rows_atomic = "0".into();
                        runtime.progress.checked_spending_rows_atomic = "0".into();
                        runtime.progress.item_position = 0;
                        runtime.roster_seen.clear();
                        runtime.progress.phase = Phase::RosterValidation;
                    }
                    Phase::RosterValidation => {
                        let index = runtime.progress.item_position as usize;
                        if index < runtime.roster.len() {
                            runtime.roster_seen.admit(
                                runtime.roster.len(),
                                full_hash(&runtime.roster[index][..]),
                                &mut window,
                            )?;
                            runtime.progress.item_position = runtime
                                .progress
                                .item_position
                                .checked_add(1)
                                .ok_or(CoverageError::Overflow)?;
                            return Ok(());
                        }
                        // Read reservation and duplicate validation were carried
                        // by earlier windows. Hashing is separately reserved
                        // BEFORE dispatch and fits the unchanged 1M work cap.
                        runtime
                            .roster_seen
                            .reserve_hash(runtime.roster.len(), &mut window)?;
                        let merkle = bitcoin::merkle_tree::calculate_root(
                            runtime.roster.iter().map(|txid| {
                                bitcoin::TxMerkleNode::from_slice(&txid[..]).expect("fixed32")
                            }),
                        )
                        .ok_or(CoverageError::Contract)?;
                        if merkle
                            != runtime
                                .header
                                .as_ref()
                                .ok_or(CoverageError::Missing)?
                                .header()
                                .merkle_root
                        {
                            return Err(CoverageError::Contract);
                        }
                        runtime.roster_seen.clear();
                        runtime.progress.item_position = 0;
                        runtime.progress.phase = Phase::Transaction;
                    }
                    Phase::Transaction => {
                        let position = runtime.progress.transaction_position as usize;
                        if position == runtime.roster.len() {
                            runtime.progress.phase = Phase::BlockCommit;
                            return Ok(());
                        }
                        let txid = runtime
                            .roster
                            .get(position)
                            .ok_or(CoverageError::Contract)?;
                        let raw = baseline_point(
                            &self.store,
                            &TxRow::key(&txid[..]),
                            coverage::POINT_BYTES,
                            &mut window,
                        )?;
                        let tx: Transaction =
                            deserialize(&raw).map_err(|_| CoverageError::Contract)?;
                        if tx.get_txid() != *txid || (position == 0) != tx.is_coinbase() {
                            return Err(CoverageError::Contract);
                        }
                        let header = runtime.header.as_ref().ok_or(CoverageError::Missing)?;
                        let confirmation = TxConfKey {
                            code: b'C',
                            txid: full_hash(&txid[..]),
                            blockhash: full_hash(&header.hash()[..]),
                        };
                        let key = bincode_util::serialize_little(&confirmation)
                            .map_err(|_| CoverageError::Contract)?;
                        if !baseline_point(&self.store, &key, 0, &mut window)?.is_empty() {
                            return Err(CoverageError::Contract);
                        }
                        runtime.transaction = Some(tx);
                        runtime.progress.item_position = 0;
                        runtime.progress.phase = Phase::Output;
                    }
                    Phase::Output => {
                        window.reserve(1, 1)?;
                        let tx = runtime.transaction.as_ref().ok_or(CoverageError::Missing)?;
                        let index = runtime.progress.item_position as usize;
                        if index == tx.output.len() {
                            runtime.progress.phase = Phase::Input;
                            runtime.progress.item_position = 0;
                            return Ok(());
                        }
                        let output = tx.output.get(index).ok_or(CoverageError::Contract)?;
                        if is_spendable(output) || self.iconfig.index_unspendables {
                            let row = TxHistoryRow::new(
                                &output.script_pubkey,
                                runtime.progress.next_height,
                                runtime.progress.transaction_position,
                                TxHistoryInfo::Funding(FundingInfo {
                                    txid: full_hash(&tx.get_txid()[..]),
                                    vout: index as u32,
                                    value: output.value.to_sat(),
                                }),
                            )
                            .into_row();
                            if !baseline_history_point(
                                &self.store.history_db,
                                &row.key,
                                0,
                                &mut window,
                            )?
                            .is_empty()
                            {
                                return Err(CoverageError::Contract);
                            }
                            runtime.progress.history_digest =
                                digest(runtime.progress.history_digest.as_bytes(), &row.key);
                            runtime.progress.checked_funding_rows_atomic =
                                increment_atomic(&runtime.progress.checked_funding_rows_atomic)?;
                        }
                        runtime.progress.item_position = runtime
                            .progress
                            .item_position
                            .checked_add(1)
                            .ok_or(CoverageError::Overflow)?;
                    }
                    Phase::Input => {
                        window.reserve(1, 1)?;
                        let tx = runtime.transaction.as_ref().ok_or(CoverageError::Missing)?;
                        let index = runtime.progress.item_position as usize;
                        if index == tx.input.len() {
                            runtime.progress.transaction_position = runtime
                                .progress
                                .transaction_position
                                .checked_add(1)
                                .ok_or(CoverageError::Overflow)?;
                            runtime.progress.item_position = 0;
                            runtime.progress.phase = Phase::Transaction;
                            runtime.transaction = None;
                            return Ok(());
                        }
                        let input = tx.input.get(index).ok_or(CoverageError::Contract)?;
                        if has_prevout(input) {
                            let raw = baseline_point(
                                &self.store,
                                &TxRow::key(&input.previous_output.txid[..]),
                                coverage::POINT_BYTES,
                                &mut window,
                            )?;
                            let parent: Transaction =
                                deserialize(&raw).map_err(|_| CoverageError::Contract)?;
                            if parent.get_txid() != input.previous_output.txid {
                                return Err(CoverageError::Contract);
                            }
                            let previous = parent
                                .output
                                .get(input.previous_output.vout as usize)
                                .ok_or(CoverageError::Contract)?;
                            let output = baseline_point(
                                &self.store,
                                &TxOutRow::key(&input.previous_output),
                                coverage::POINT_BYTES,
                                &mut window,
                            )?;
                            if output != serialize(previous) {
                                return Err(CoverageError::Contract);
                            }
                            // Resume the exact parent-confirmation scan across
                            // windows. Every C/X read is reserved before IO;
                            // no large nested vector or restart-at-zero loop.
                            let parent_prefix = TxConfRow::filter(&input.previous_output.txid[..]);
                            window.reserve(1, 1)?;
                            let snapshot = self.store.txstore_db.bounded_snapshot();
                            if let Some(record) = snapshot
                                .next_record(
                                    &parent_prefix,
                                    runtime.progress.parent_after_key.as_deref(),
                                )
                                .map_err(|_| CoverageError::Storage)?
                            {
                                let confirmation: TxConfKey =
                                    bincode_util::deserialize_little(&record.key)
                                        .map_err(|_| CoverageError::Contract)?;
                                if confirmation.code != b'C'
                                    || confirmation.txid
                                        != full_hash(&input.previous_output.txid[..])
                                    || bincode_util::serialize_little(&confirmation)
                                        .map_err(|_| CoverageError::Contract)?
                                        != record.key
                                {
                                    return Err(CoverageError::Contract);
                                }
                                let hash: BlockHash = deserialize(&confirmation.blockhash)
                                    .map_err(|_| CoverageError::Contract)?;
                                let header = self
                                    .store
                                    .indexed_headers
                                    .try_read()
                                    .map_err(|_| CoverageError::Changed)?
                                    .header_by_blockhash(&hash)
                                    .cloned();
                                if let Some(header) = header {
                                    let raw = baseline_point(
                                        &self.store,
                                        &BlockRow::txids_key(full_hash(&hash[..])),
                                        coverage::POINT_BYTES,
                                        &mut window,
                                    )?;
                                    window.reserve(1, 1 + raw.len() / 16)?;
                                    let position = super::qualified_edges::roster_position(
                                        &raw,
                                        full_hash(&parent.get_txid()[..]),
                                    )
                                    .map_err(|_| CoverageError::Contract)?;
                                    // Reserve roster scan and SHA tree work before either
                                    // operation; a point-read reservation alone is not
                                    // a reservation for hashing all parent transactions.
                                    let merkle = bitcoin::merkle_tree::calculate_root(
                                        raw[8..].chunks_exact(32).map(|bytes| {
                                            bitcoin::TxMerkleNode::from_slice(bytes)
                                                .expect("fixed32")
                                        }),
                                    )
                                    .ok_or(CoverageError::Contract)?;
                                    if merkle != header.header().merkle_root {
                                        return Err(CoverageError::Contract);
                                    }
                                    let before = header.height()
                                        < runtime.progress.next_height as usize
                                        || (header.height()
                                            == runtime.progress.next_height as usize
                                            && position < runtime.progress.transaction_position);
                                    if before
                                        && runtime
                                            .progress
                                            .parent_best_height
                                            .map_or(true, |height| {
                                                header.height() > height as usize
                                            })
                                    {
                                        runtime.progress.parent_best_height =
                                            Some(header.height() as u32);
                                        runtime.progress.parent_best_hash = Some(hash.to_string());
                                        runtime.progress.parent_best_position = Some(position);
                                    }
                                }
                                runtime.progress.parent_after_key = Some(record.key);
                                return Ok(());
                            }
                            let parent_height = runtime
                                .progress
                                .parent_best_height
                                .ok_or(CoverageError::Missing)?;
                            if parent_height == 0
                                || (parent.is_coinbase()
                                    && runtime.progress.next_height
                                        < parent_height.saturating_add(100))
                            {
                                return Err(CoverageError::Contract);
                            }
                            let row = TxHistoryRow::new(
                                &previous.script_pubkey,
                                runtime.progress.next_height,
                                runtime.progress.transaction_position,
                                TxHistoryInfo::Spending(SpendingInfo {
                                    txid: full_hash(&tx.get_txid()[..]),
                                    vin: index as u32,
                                    prev_txid: full_hash(&input.previous_output.txid[..]),
                                    prev_vout: input.previous_output.vout,
                                    value: previous.value.to_sat(),
                                }),
                            )
                            .into_row();
                            if !baseline_history_point(
                                &self.store.history_db,
                                &row.key,
                                0,
                                &mut window,
                            )?
                            .is_empty()
                            {
                                return Err(CoverageError::Contract);
                            }
                            let edge = super::qualified_edges::EdgeKey {
                                script_hash: compute_script_hash(&previous.script_pubkey),
                                funding_txid: full_hash(&input.previous_output.txid[..]),
                                funding_vout: input.previous_output.vout,
                                spending_height: runtime.progress.next_height,
                                spending_block_hash: full_hash(
                                    &runtime
                                        .header
                                        .as_ref()
                                        .ok_or(CoverageError::Missing)?
                                        .hash()[..],
                                ),
                                spending_position: runtime.progress.transaction_position,
                                spending_txid: full_hash(&tx.get_txid()[..]),
                                spending_vin: index as u32,
                            }
                            .encode();
                            if (runtime.edges.len() + 1) * super::qualified_edges::EDGE_KEY_BYTES
                                > coverage::POINT_BYTES
                            {
                                return Err(CoverageError::Contract);
                            }
                            runtime.edges.push(edge);
                            runtime.progress.edges_digest =
                                digest(runtime.progress.edges_digest.as_bytes(), &edge);
                            runtime.progress.history_digest =
                                digest(runtime.progress.history_digest.as_bytes(), &row.key);
                            runtime.progress.checked_spending_rows_atomic =
                                increment_atomic(&runtime.progress.checked_spending_rows_atomic)?;
                        } else if runtime.progress.transaction_position != 0 || tx.input.len() != 1
                        {
                            return Err(CoverageError::Contract);
                        }
                        runtime.progress.parent_after_key = None;
                        runtime.progress.parent_best_height = None;
                        runtime.progress.parent_best_hash = None;
                        runtime.progress.parent_best_position = None;
                        runtime.progress.item_position = runtime
                            .progress
                            .item_position
                            .checked_add(1)
                            .ok_or(CoverageError::Overflow)?;
                    }
                    Phase::BlockCommit => {
                        window.reserve(
                            1,
                            1 + runtime.edges.len() * super::qualified_edges::EDGE_KEY_BYTES / 32,
                        )?;
                        let header = runtime.header.as_ref().ok_or(CoverageError::Missing)?;
                        let hash = header.hash().to_string();
                        if self
                            .store
                            .indexed_headers
                            .try_read()
                            .map_err(|_| CoverageError::Changed)?
                            .header_by_height(runtime.progress.next_height as usize)
                            .map(|value| value.hash().to_string())
                            .as_deref()
                            != Some(&hash)
                        {
                            return Err(CoverageError::Changed);
                        }
                        let raw = bincode_util::serialize_little(&runtime.roster)
                            .map_err(|_| CoverageError::Contract)?;
                        let certificate = BlockCertificate {
                            schema_version: "universe-electrs-history-block-coverage-v2".into(),
                            scope_digest: scope.commitment()?,
                            height: runtime.progress.next_height,
                            block_hash: hash.clone(),
                            previous_block_hash: header.header().prev_blockhash.to_string(),
                            previous_coverage_sha256: runtime
                                .progress
                                .prefix
                                .as_ref()
                                .map(|value| value.coverage_sha256.clone())
                                .unwrap_or_else(|| "0".repeat(64)),
                            roster_sha256: digest(b"", &raw),
                            roster_merkle_root: header.header().merkle_root.to_string(),
                            transaction_count: runtime.roster.len() as u32,
                            checked_funding_rows_atomic: runtime
                                .progress
                                .checked_funding_rows_atomic
                                .clone(),
                            checked_spending_rows_atomic: runtime
                                .progress
                                .checked_spending_rows_atomic
                                .clone(),
                            expected_history_digest: runtime.progress.history_digest.clone(),
                            supplemental_edges_digest: runtime.progress.edges_digest.clone(),
                            source_revision: scope.source_revision.clone(),
                        };
                        let bytes = certificate.encode()?;
                        let commitment = certificate.commitment()?;
                        let mut key = vec![0xff, b'U', b'C', 2];
                        key.extend(decode_digest(&certificate.scope_digest)?);
                        key.extend(certificate.height.to_be_bytes());
                        key.extend(full_hash(&header.hash()[..]));
                        let mut next = runtime.progress.clone();
                        next.prefix = Some(coverage::Prefix {
                            height: certificate.height,
                            block_hash: hash,
                            coverage_sha256: commitment,
                        });
                        next.next_height = next
                            .next_height
                            .checked_add(1)
                            .ok_or(CoverageError::Overflow)?;
                        next.phase = Phase::BlockRoster;
                        window.persist_cumulative(&mut next)?;
                        let mut rows: Vec<DBRow> = runtime
                            .edges
                            .iter()
                            .map(|key| DBRow {
                                key: key.to_vec(),
                                value: vec![],
                            })
                            .collect();
                        rows.push(DBRow { key, value: bytes });
                        rows.push(DBRow {
                            key: next.progress_key()?,
                            value: next.encode()?,
                        });
                        self.store
                            .history_db
                            .write_coverage(rows)
                            .map_err(|_| CoverageError::Storage)?;
                        self.baseline_total_visits = next.total_visits_atomic.clone();
                        runtime.progress = next;
                        runtime.header = None;
                        runtime.roster.clear();
                        runtime.roster_seen.clear();
                        runtime.transaction = None;
                        runtime.edges.clear();
                        // One completed block per invocation; independent next
                        // window resets local caps, never the cumulative count.
                        block_completed = true;
                        return Ok(());
                    }
                }
                Ok(())
            })();
            if block_completed {
                self.baseline = Some(runtime);
                return Ok(());
            }
            match result {
                Ok(()) => {}
                Err(CoverageError::Budget) => break,
                Err(error) => return Err(error),
            }
        }
        window.persist_cumulative(&mut runtime.progress)?;
        self.baseline_total_visits = runtime.progress.total_visits_atomic.clone();
        self.store
            .history_db
            .write_coverage(vec![DBRow {
                key: runtime.progress.progress_key()?,
                value: runtime.progress.encode()?,
            }])
            .map_err(|_| CoverageError::Storage)?;
        self.baseline = Some(runtime);
        Ok(())
    }

    fn start_timer(&self, name: &str) -> HistogramTimer {
        self.duration.with_label_values(&[name]).start_timer()
    }

    fn headers_to_add(&self, new_headers: &[HeaderEntry]) -> Vec<HeaderEntry> {
        let added_blockhashes = self.store.added_blockhashes.read().unwrap();
        new_headers
            .iter()
            .filter(|e| !added_blockhashes.contains(e.hash()))
            .cloned()
            .collect()
    }

    fn headers_to_index(&self, new_headers: &[HeaderEntry]) -> Vec<HeaderEntry> {
        let indexed_blockhashes = self.store.indexed_blockhashes.read().unwrap();
        new_headers
            .iter()
            .filter(|e| !indexed_blockhashes.contains(e.hash()))
            .cloned()
            .collect()
    }

    fn start_auto_compactions(&self, db: &DB) {
        let key = b"F".to_vec();
        if db.get(&key).is_none() {
            db.full_compaction();
            db.put_sync(&key, b"");
            assert!(db.get(&key).is_some());
        }
        db.enable_auto_compaction();
    }

    fn get_new_headers(&self, daemon: &Daemon, tip: &BlockHash) -> Result<Vec<HeaderEntry>> {
        let headers = self.store.indexed_headers.read().unwrap();
        let new_headers = daemon.get_new_headers(&headers, tip)?;
        let result = headers.order(new_headers);

        if let Some(tip) = result.last() {
            info!("{:?} ({} left to index)", tip, result.len());
        };
        Ok(result)
    }

    fn reorg(&self, reorged: &[HeaderEntry], daemon: &Daemon) -> Result<()> {
        if reorged.len() > 10 {
            warn!(
                "reorg of over 10 blocks ({}) detected! Wonky stuff might happen!",
                reorged.len()
            );
        }
        // Each history batch invalidates its exact affected caches before
        // deleting dependent rows. No reorg-wide script queue/set is retained.
        bitcoind_sequential_fetcher(daemon, reorged.to_vec())?
            .map(|blocks| self.index(&blocks, Operation::DeleteBlocks))?;
        bitcoind_sequential_fetcher(daemon, reorged.to_vec())?
            .map(|blocks| self.add(&blocks, Operation::DeleteBlocks))?;
        Ok(())
    }

    pub fn update(&mut self, daemon: &Daemon) -> Result<BlockHash> {
        let daemon = daemon.reconnect()?;
        let tip = daemon.getbestblockhash()?;
        // A failed retained plan is repaired before deriving work from headers
        // that may already have advanced. Never substitute empty new_headers.
        let publication_store = Arc::clone(&self.store);
        let has_pending = self.pending_read_update.is_some();
        // A missing retained plan after panic is NOT recoverable by an empty or
        // newly derived plan. Verified startup reconciliation is still required.
        let can_repair = has_pending || !publication_store.read_generation.requires_repair();
        let new_headers = if has_pending {
            None
        } else {
            Some(self.get_new_headers(&daemon, &tip)?)
        };
        let noop_candidate = !has_pending
            && new_headers.as_ref().unwrap().is_empty()
            && self.store.read_generation.completed().is_some();
        match super::qualification::validated_noop(
            noop_candidate,
            || self.store.txstore_db.qualified_get(b"t", 32),
            &serialize(&tip),
        ) {
            super::qualification::NoopDecision::Qualified => return Ok(tip),
            super::qualification::NoopDecision::AvailabilityFault => {
                // Only this pre-mutation storage failure retains closed data.
                let header_matches = self
                    .store
                    .indexed_headers
                    .try_read()
                    .map(|h| *h.tip() == tip)
                    .unwrap_or(false);
                if header_matches {
                    publication_store.read_generation.invalidate_availability();
                    self.availability_validation_tip = Some(tip);
                } else {
                    publication_store.read_generation.invalidate_material();
                    self.availability_validation_tip = None;
                }
                warn!("paged noop storage availability withheld; legacy producer continues");
                return Ok(tip);
            }
            super::qualification::NoopDecision::MaterialFault => {
                // No extra producer work or data writes to bless a failed point
                // proof. Invalidate old readers and keep the new lane unavailable.
                publication_store.read_generation.invalidate_material();
                self.availability_validation_tip = None;
                warn!("paged noop point proof withheld; legacy producer continues");
                return Ok(tip);
            }
            super::qualification::NoopDecision::NotCandidate => {}
        }
        self.availability_validation_tip = None;
        let read_mutation = publication_store.read_generation.begin();
        let mut completion = None;
        if has_pending {
            completion = self.finish_pending_read_update(&daemon)?;
        }
        let new_headers = match new_headers {
            Some(headers) => headers,
            None => self.get_new_headers(&daemon, &tip)?,
        };
        let prior_plan_qualified = !has_pending || completion.is_some();
        // If the source advanced during recovery, finish the old plan then
        // reconcile this target under the SAME odd lease before publishing.
        if !has_pending || !new_headers.is_empty() {
            let (reorged, rollback_tip) = {
                let mut headers = self.store.indexed_headers.write().unwrap();
                let result = headers.apply(new_headers.clone());
                assert_eq!(tip, *headers.tip());
                result
            };
            self.pending_read_update = Some(UpdatePlan {
                target: tip,
                headers: new_headers,
                reorged,
                rollback_tip,
                phase: Phase::Rollback,
            });
            completion = self.finish_pending_read_update(&daemon)?;
        }
        // The proof comes only from completed rollback/reorg/add/index/flush/
        // persisted-tip verification. A fresh lease is never recovery evidence.
        if let Some(proof) = completion {
            let publication = if can_repair && prior_plan_qualified {
                read_mutation.commit_repaired(proof)
            } else {
                read_mutation.commit()
            };
            if publication.is_err() {
                warn!("paged read publication remains unavailable after writer update");
            }
        }
        if let FetchFrom::BlkFiles = self.from {
            self.from = FetchFrom::Bitcoind;
        }
        if let Ok(headers) = self.store.indexed_headers.try_read() {
            self.tip_metric.set(headers.len() as i64 - 1);
        }
        Ok(tip)
    }

    pub fn availability_validation_pending(&self) -> bool {
        self.availability_validation_tip.is_some()
            && self.pending_read_update.is_none()
            && self.store.read_generation.availability_fence().is_some()
    }
    /// Called only at the existing loop boundary, using its already observed
    /// unchanged Core tip. No RPC, header apply, marker/DB write or fresh time.
    pub fn revalidate_read_availability(&mut self, current_tip: &BlockHash) {
        let fence = match self.store.read_generation.availability_fence() {
            Some(f) => f,
            None => return,
        };
        let anchor = match self.availability_validation_tip {
            Some(tip) => tip,
            None => {
                self.store.read_generation.invalidate_material();
                return;
            }
        };
        let headers_match = self
            .store
            .indexed_headers
            .try_read()
            .map(|headers| *headers.tip() == anchor)
            .unwrap_or(false);
        if self.pending_read_update.is_some() || *current_tip != anchor || !headers_match {
            self.store.read_generation.invalidate_material();
            self.availability_validation_tip = None;
            return;
        }
        let result = super::qualification::revalidate_availability(
            &self.store.read_generation,
            Some(fence),
            true,
            || self.store.txstore_db.qualified_get(b"t", 32),
            &serialize(&anchor),
        );
        match result {
            super::qualification::AvailabilityValidation::Restored(_)
            | super::qualification::AvailabilityValidation::MaterialBlocked => {
                self.availability_validation_tip = None
            }
            _ => {}
        }
    }

    fn finish_pending_read_update(
        &mut self,
        daemon: &Daemon,
    ) -> Result<Option<super::writer_update::CompletedPlan>> {
        let mut plan = self
            .pending_read_update
            .take()
            .expect("retained update plan required");
        let mut writer = IndexerReadWriter {
            indexer: self,
            daemon,
            qualified: true,
        };
        let result = finish_qualified_plan(&mut writer, &mut plan);
        // Ordinary error retains exact work and phase. A panic drops the plan:
        // the generation latch then deliberately refuses future qualification.
        if result.is_err() {
            self.pending_read_update = Some(plan);
        }
        // Only legacy producer errors propagate to the existing fatal main
        // error policy. Qualification-only failures discard the read proof,
        // causing the lease to remain failed without killing valid indexing.
        result
    }

    fn add(&self, blocks: &[BlockEntry], op: Operation) -> Result<()> {
        debug!("{} {} blocks to Indexer", op, blocks.len());
        let write_label = match &op {
            Operation::AddBlocks => "add_write",
            _ => "delete_write",
        };

        // TODO: skip orphaned blocks?
        let rows = {
            let _timer = self.start_timer("add_process");
            add_blocks(blocks, &self.iconfig)
        };
        {
            let _timer = self.start_timer(write_label);
            if let Operation::AddBlocks = op {
                self.store.txstore_db.write(rows, self.flush);
            } else {
                self.store
                    .txstore_db
                    .delete(self.canonical_shared_delete_keys(rows)?)?;
            }
        }

        if let Operation::AddBlocks = op {
            self.store
                .added_blockhashes
                .write()
                .unwrap()
                .extend(blocks.iter().map(|b| {
                    if b.entry.height() % 10_000 == 0 {
                        info!("Tx indexing is up to height={}", b.entry.height());
                    }
                    b.entry.hash()
                }));
        } else {
            let mut added_blockhashes = self.store.added_blockhashes.write().unwrap();
            for b in blocks {
                added_blockhashes.remove(b.entry.hash());
            }
        }
        Ok(())
    }

    fn canonical_shared_delete_keys(&self, rows: Vec<DBRow>) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            if matches!(row.key.first(), Some(b'T') | Some(b'O')) {
                let txid: FullHash = row
                    .key
                    .get(1..33)
                    .ok_or("malformed shared transaction key")?
                    .try_into()
                    .map_err(|_| Error::from("malformed shared transaction key"))?;
                if self.has_canonical_confirmation(&txid)? {
                    continue;
                }
            }
            keys.push(row.key);
        }
        Ok(keys)
    }
    fn has_canonical_confirmation(&self, txid: &FullHash) -> Result<bool> {
        // Exact full-key continuation, bounded retained state. Each window
        // processes at most500 records; the same owned critical operation
        // resumes at its cursor rather than restarting or admitting a writer.
        let prefix = TxConfRow::filter(txid);
        let mut after = None;
        loop {
            for _ in 0..super::qualified_edges::MAX_VISITS {
                let record = self
                    .store
                    .txstore_db
                    .next_empty_record(&prefix, after.as_deref())?;
                let record = match record {
                    Some(record) => record,
                    None => return Ok(false),
                };
                let conf: TxConfKey = bincode_util::deserialize_little(&record.key)
                    .chain_err(|| "invalid confirmation key")?;
                if conf.code != b'C'
                    || &conf.txid != txid
                    || bincode_util::serialize_little(&conf)
                        .chain_err(|| "invalid confirmation key")?
                        != record.key
                {
                    bail!("invalid confirmation key");
                }
                after = Some(record.key);
                let hash: BlockHash =
                    deserialize(&conf.blockhash).chain_err(|| "invalid confirmation hash")?;
                if self
                    .store
                    .indexed_headers
                    .try_read()
                    .map_err(|_| Error::from("canonical headers busy"))?
                    .header_by_blockhash(&hash)
                    .is_some()
                {
                    return Ok(true);
                }
            }
            std::thread::yield_now();
        }
    }

    fn index(&self, blocks: &[BlockEntry], op: Operation) -> Result<()> {
        debug!("Indexing ({}) {} blocks with Indexer", op, blocks.len());
        let previous_txos_map = {
            let _timer = self.start_timer("index_lookup");
            if matches!(op, Operation::AddBlocks) {
                lookup_txos(&self.store.txstore_db, &get_previous_txos(blocks), false)
            } else {
                lookup_txos_sequential(&self.store.txstore_db, &get_previous_txos(blocks), false)
            }
        };
        let rows = {
            let _timer = self.start_timer("index_process");
            if let Operation::AddBlocks = op {
                let added_blockhashes = self.store.added_blockhashes.read().unwrap();
                for b in blocks {
                    if b.entry.height() % 10_000 == 0 {
                        info!("History indexing is up to height={}", b.entry.height());
                    }
                    let blockhash = b.entry.hash();
                    // TODO: replace by lookup into txstore_db?
                    if !added_blockhashes.contains(blockhash) {
                        panic!("cannot index block {} (missing from store)", blockhash);
                    }
                }
            }
            index_blocks(blocks, &previous_txos_map, &self.iconfig, &op)?
        };
        if let Operation::AddBlocks = op {
            self.store.history_db.write(rows, self.flush);
        } else {
            // Canonical H (script) and Liquid I (asset) row prefixes contain
            // exactly the hashes previously emitted by indexing callbacks.
            // Invalidate BEFORE history deletion so an error retains the data
            // needed to replay the same cache keys on the sole writer.
            let keys = rows.iter().flat_map(|row| {
                match super::db::history_cache_keys(&row.key, cfg!(feature = "liquid")) {
                    Ok(keys) => keys.into_iter().map(Ok).collect::<Vec<_>>(),
                    Err(error) => vec![Err(Error::from(error))],
                }
            });
            super::db::delete_cache_chunks(keys, |keys| self.store.cache_db.delete(keys))?;
            self.store
                .history_db
                // Legacy S candidates lack containing-block identity. An
                // orphan occurrence must not erase an identical ancestor key.
                // Canonical confirmation/order proof filters retained reads.
                .delete(
                    rows.into_iter()
                        .filter(|row| row.key.first() != Some(&b'S'))
                        .map(|r| r.key)
                        .collect(),
                )?;
        }
        // Keep the existing marker filter consistent with the completed DB
        // batch, including a removed fork that later becomes current again.
        let mut indexed = self.store.indexed_blockhashes.write().unwrap();
        if let Operation::AddBlocks = op {
            indexed.extend(blocks.iter().map(|b| *b.entry.hash()));
        } else {
            for block in blocks {
                indexed.remove(block.entry.hash());
            }
        }
        Ok(())
    }
}

// Adapter uses the existing writer, fetchers, markers and flush policy. There is
// no second DB writer, background task, new RPC pool or reader-induced lock.
struct IndexerReadWriter<'a> {
    indexer: &'a mut Indexer,
    daemon: &'a Daemon,
    qualified: bool,
}
impl UpdateWriter<HeaderEntry, BlockHash> for IndexerReadWriter<'_> {
    type Error = Error;
    fn rollback(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        if !plan.reorged.is_empty() {
            match plan.rollback_tip {
                Some(tip) => self
                    .indexer
                    .store
                    .txstore_db
                    .put_sync(b"t", &serialize(&tip)),
                None => self.indexer.store.txstore_db.delete(vec![b"t".into()])?,
            }
        }
        Ok(())
    }
    fn reorg(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        if !plan.reorged.is_empty() {
            self.indexer.reorg(&plan.reorged, self.daemon)?;
        }
        Ok(())
    }
    fn add(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        let headers = self.indexer.headers_to_add(&plan.headers);
        start_fetcher(self.indexer.from, self.daemon, headers)?
            .map(|blocks| self.indexer.add(&blocks, Operation::AddBlocks))?;
        self.indexer
            .start_auto_compactions(&self.indexer.store.txstore_db);
        Ok(())
    }
    fn index(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        let headers = self.indexer.headers_to_index(&plan.headers);
        start_fetcher(self.indexer.from, self.daemon, headers)?
            .map(|blocks| self.indexer.index(&blocks, Operation::AddBlocks))?;
        self.indexer
            .start_auto_compactions(&self.indexer.store.history_db);
        Ok(())
    }
    fn flush(&mut self, _: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        if let DBFlush::Disable = self.indexer.flush {
            self.indexer.store.txstore_db.flush();
            self.indexer.store.history_db.flush();
            self.indexer.flush = DBFlush::Enable;
        }
        Ok(())
    }
    fn persist_tip(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        self.indexer
            .store
            .txstore_db
            .put_sync(b"t", &serialize(&plan.target));
        Ok(())
    }
    fn read_qualified(&self) -> bool {
        self.qualified
    }

    fn verify(&mut self, plan: &UpdatePlan<HeaderEntry, BlockHash>) -> Result<()> {
        let store = &self.indexer.store;
        let header_matches = store
            .indexed_headers
            .try_read()
            .map(|headers| *headers.tip() == plan.target)
            .unwrap_or(false);
        if !header_matches
            || !super::qualification::point_matches(
                store.txstore_db.qualified_get(b"t", 32),
                &serialize(&plan.target),
            )
        {
            self.qualified = false;
            warn!("paged writer target fence failed; legacy producer continues");
            return Ok(());
        }
        // Point reads of only the retained work, not a global database scan.
        for header in &plan.headers {
            let key = BlockRow::new_done(full_hash(&header.hash()[..]))
                .into_row()
                .key;
            if !super::qualification::point_present(store.txstore_db.qualified_get(&key, 0))
                || !super::qualification::point_present(store.history_db.qualified_get(&key, 0))
            {
                self.qualified = false;
                warn!("paged writer required phase marker missing; legacy producer continues");
                return Ok(());
            }
        }
        #[cfg(not(feature = "liquid"))]
        if let Some(prefix) = self.indexer.verified_prefix.clone() {
            if !plan.reorged.is_empty() {
                let rollback = plan.rollback_tip.and_then(|hash| {
                    store
                        .indexed_headers
                        .try_read()
                        .ok()?
                        .header_by_blockhash(&hash)
                        .cloned()
                });
                if let Some(rollback) = rollback {
                    self.indexer.prefix_recovery = Some(PrefixRecovery {
                        cursor: prefix,
                        target_height: rollback.height() as u32,
                        target_hash: rollback.hash().to_string(),
                    });
                    self.indexer.baseline = None;
                } else {
                    self.indexer.verified_prefix = None;
                    self.indexer.baseline = None;
                }
                self.qualified = false;
            } else if !plan.headers.is_empty() {
                // Continue coverage only for the new canonical suffix; the
                // previously closed prefix was actually verified in-process.
                let scope = self.indexer.baseline_scope(self.daemon);
                if let Ok(scope) = scope {
                    let target_height = store.indexed_headers.try_read().ok().and_then(|headers| {
                        headers
                            .header_by_blockhash(&plan.target)
                            .map(|header| header.height() as u32)
                    });
                    if let Some(height) = target_height {
                        let mut progress = super::history_coverage::Progress::initial(
                            scope,
                            height,
                            plan.target.to_string(),
                        )
                        .map_err(|_| Error::from("coverage scope unavailable"))?;
                        progress.total_visits_atomic = self.indexer.baseline_total_visits.clone();
                        progress.next_height = prefix
                            .height
                            .checked_add(1)
                            .ok_or("coverage height overflow")?;
                        progress.prefix = Some(prefix);
                        self.indexer.baseline = Some(BaselineRuntime {
                            progress,
                            header: None,
                            roster: vec![],
                            roster_seen: super::history_coverage::RosterProof::new(),
                            transaction: None,
                            edges: vec![],
                            certificates_verified: true,
                        });
                        self.qualified = false;
                    }
                } else {
                    self.qualified = false;
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(feature = "liquid"))]
pub struct PagedChainSnapshot<'a> {
    chain: &'a ChainQuery,
    history: super::db::BoundedSnapshot<'a>,
    txstore: super::db::BoundedSnapshot<'a>,
    proof_txstore: Option<super::db::BoundedSnapshot<'a>>,
    epoch: u64,
    script_hash: FullHash,
}
#[cfg(not(feature = "liquid"))]
impl PagedChainSnapshot<'_> {
    fn point_value(
        &self,
        key: &[u8],
        maximum: usize,
    ) -> std::result::Result<Option<Bytes>, super::paged_outputs::PageError> {
        match self.txstore.point_value(key, maximum)? {
            Some(value) => Ok(Some(value)),
            None => {
                if matches!(key.first(), Some(b'T') | Some(b'X') | Some(b'M')) {
                    if let Some(proof) = &self.proof_txstore {
                        return proof.point_value(key, maximum);
                    }
                }
                Ok(None)
            }
        }
    }
    pub fn operation_work(&self, operation: super::paged_outputs::ReadOperation) -> usize {
        use super::paged_outputs::ReadOperation;
        let body = if self.proof_txstore.is_some() { 2 } else { 1 };
        match operation {
            ReadOperation::History | ReadOperation::Spend => 1 + 2 * body,
            _ => 1,
        }
    }
    pub fn valid(&self) -> std::result::Result<(), super::paged_outputs::PageError> {
        if self.chain.matches_read_generation(self.epoch) {
            Ok(())
        } else {
            Err(super::paged_outputs::PageError::Changed)
        }
    }
    pub fn history(
        &self,
        after: Option<&[u8]>,
    ) -> std::result::Result<
        Option<super::paged_outputs::HistoryRecord>,
        super::paged_outputs::PageError,
    > {
        use super::paged_outputs::{Funding, HistoryRecord, PageError};
        self.valid()?;
        let prefix = TxHistoryRow::filter(b'H', &self.script_hash);
        let row = match self.history.next_record(&prefix, after)? {
            Some(row) => row,
            None => return Ok(None),
        };
        let decoded: TxHistoryKey =
            bincode_util::deserialize_big(&row.key).map_err(|_| PageError::Contract)?;
        if decoded.code != b'H'
            || decoded.hash != self.script_hash
            || bincode_util::serialize_big(&decoded).map_err(|_| PageError::Contract)? != row.key
        {
            return Err(PageError::Contract);
        }
        let funding = match &decoded.txinfo {
            TxHistoryInfo::Funding(value) => {
                let raw = self
                    .point_value(&TxRow::key(&value.txid), 4 * 1024 * 1024)?
                    .ok_or(PageError::Unavailable)?;
                let tx: Transaction = deserialize(&raw).map_err(|_| PageError::Contract)?;
                if full_hash(&tx.get_txid()[..]) != value.txid {
                    return Err(PageError::Contract);
                }
                let output = tx
                    .output
                    .get(value.vout as usize)
                    .ok_or(PageError::Contract)?;
                if output.value.to_sat() != value.value
                    || compute_script_hash(&output.script_pubkey) != self.script_hash
                {
                    return Err(PageError::Contract);
                }
                let header = self
                    .chain
                    .store
                    .indexed_headers
                    .try_read()
                    .map_err(|_| PageError::Unavailable)?
                    .header_by_height(decoded.confirmed_height as usize)
                    .cloned();
                match header {
                    Some(header) => {
                        let roster = self
                            .point_value(
                                &BlockRow::txids_key(full_hash(&header.hash()[..])),
                                4 * 1024 * 1024,
                            )?
                            .ok_or(PageError::Unavailable)?;
                        let position = super::qualified_edges::roster_position(&roster, value.txid);
                        match position {
                            Ok(position)
                                if position == decoded.tx_position
                                    && decoded.confirmed_height != 0
                                    && is_spendable(output) =>
                            {
                                Some(Funding {
                                    txid: tx.get_txid(),
                                    vout: value.vout,
                                    value: value.value,
                                    height: decoded.confirmed_height,
                                })
                            }
                            Err(super::qualified_edges::EdgeError::MissingCoverage) | Ok(_) => None,
                            Err(_) => return Err(PageError::Contract),
                        }
                    }
                    None => None,
                }
            }
            TxHistoryInfo::Spending(_) => None,
        };
        Ok(Some(HistoryRecord {
            key: row.key,
            funding,
            position: decoded.tx_position,
        }))
    }
    pub fn confirmation(
        &self,
        txid: &Txid,
        after: Option<&[u8]>,
    ) -> std::result::Result<
        Option<super::paged_outputs::ConfirmationRecord>,
        super::paged_outputs::PageError,
    > {
        use super::paged_outputs::{ConfirmationRecord, PageError};
        self.valid()?;
        let row = match self
            .txstore
            .next_record(&TxConfRow::filter(&txid[..]), after)?
        {
            Some(row) => row,
            None => return Ok(None),
        };
        let decoded: TxConfKey =
            bincode_util::deserialize_little(&row.key).map_err(|_| PageError::Contract)?;
        if decoded.code != b'C'
            || decoded.txid != full_hash(&txid[..])
            || bincode_util::serialize_little(&decoded).map_err(|_| PageError::Contract)? != row.key
        {
            return Err(PageError::Contract);
        }
        let hash: BlockHash = deserialize(&decoded.blockhash).map_err(|_| PageError::Contract)?;
        // Short, nonblocking header lock for ONE confirmation row.
        let headers = self
            .chain
            .store
            .indexed_headers
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        let canonical = headers.header_by_blockhash(&hash).map(BlockId::from);
        Ok(Some(ConfirmationRecord {
            key: row.key,
            canonical,
        }))
    }
    pub fn spend(
        &self,
        point: &OutPoint,
        after: Option<&[u8]>,
    ) -> std::result::Result<
        Option<super::paged_outputs::SpendRecord>,
        super::paged_outputs::PageError,
    > {
        use super::paged_outputs::{PageError, SpendRecord};
        use super::qualified_edges::EdgeKey;
        self.valid()?;
        let prefix = EdgeKey::prefix(self.script_hash, full_hash(&point.txid[..]), point.vout);
        let row = match self.history.next_record(&prefix, after)? {
            Some(row) => row,
            None => return Ok(None),
        };
        let edge = EdgeKey::decode(&row.key).map_err(|_| PageError::Contract)?;
        if edge.encode().as_slice() != row.key.as_slice() || edge.outpoint_prefix() != prefix {
            return Err(PageError::Contract);
        }
        let hash: BlockHash =
            deserialize(&edge.spending_block_hash).map_err(|_| PageError::Contract)?;
        let canonical = {
            let headers = self
                .chain
                .store
                .indexed_headers
                .try_read()
                .map_err(|_| PageError::Unavailable)?;
            headers.header_by_blockhash(&hash).map(BlockId::from)
        };
        if canonical
            .as_ref()
            .map_or(false, |block| block.height != edge.spending_height as usize)
        {
            return Err(PageError::Contract);
        }
        let txid: Txid = deserialize(&edge.spending_txid).map_err(|_| PageError::Contract)?;
        if let Some(block) = &canonical {
            let raw = self
                .point_value(&TxRow::key(&edge.spending_txid), 4 * 1024 * 1024)?
                .ok_or(PageError::Unavailable)?;
            let tx: Transaction = deserialize(&raw).map_err(|_| PageError::Contract)?;
            if tx.get_txid() != txid
                || tx
                    .input
                    .get(edge.spending_vin as usize)
                    .map(|input| input.previous_output)
                    != Some(*point)
            {
                return Err(PageError::Contract);
            }
            let roster = self
                .point_value(
                    &BlockRow::txids_key(full_hash(&block.hash[..])),
                    4 * 1024 * 1024,
                )?
                .ok_or(PageError::Unavailable)?;
            if super::qualified_edges::roster_position(&roster, edge.spending_txid)
                .map_err(|_| PageError::Contract)?
                != edge.spending_position
            {
                return Err(PageError::Contract);
            }
        }
        Ok(Some(SpendRecord {
            key: row.key,
            txid,
            canonical,
            position: edge.spending_position,
        }))
    }
}

impl ChainQuery {
    pub fn new(store: Arc<Store>, daemon: Arc<Daemon>, config: &Config, metrics: &Metrics) -> Self {
        ChainQuery {
            store,
            daemon,
            light_mode: config.light_mode,
            network: config.network_type,
            duration: metrics.histogram_vec(
                HistogramOpts::new("query_duration", "Index query duration (in seconds)"),
                &["name"],
            ),
        }
    }

    #[cfg(not(feature = "liquid"))]
    pub fn paged_read_context(
        &self,
    ) -> std::result::Result<(u64, BlockId, BlockHash), super::paged_outputs::PageError> {
        use super::paged_outputs::PageError;
        let epoch = self
            .completed_read_generation()
            .ok_or(PageError::Unavailable)?;
        let headers = self
            .store
            .indexed_headers
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        let tip = headers
            .header_by_blockhash(headers.tip())
            .map(BlockId::from)
            .ok_or(PageError::Unavailable)?;
        let genesis = *headers
            .header_by_height(0)
            .ok_or(PageError::Unavailable)?
            .hash();
        if !self.matches_read_generation(epoch) {
            return Err(PageError::Changed);
        }
        Ok((epoch, tip, genesis))
    }

    #[cfg(not(feature = "liquid"))]
    pub fn paged_snapshot(
        &self,
        script_hash: FullHash,
        epoch: u64,
    ) -> std::result::Result<PagedChainSnapshot<'_>, super::paged_outputs::PageError> {
        if !self.matches_read_generation(epoch) {
            return Err(super::paged_outputs::PageError::Unavailable);
        }
        let snapshot = PagedChainSnapshot {
            chain: self,
            history: self.store.history_db.bounded_snapshot(),
            txstore: self.store.txstore_db.bounded_snapshot(),
            proof_txstore: self
                .store
                .proof_txstore
                .as_ref()
                .map(|store| store.bounded_snapshot()),
            epoch,
            script_hash,
        };
        snapshot.valid()?;
        Ok(snapshot)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    fn start_timer(&self, name: &str) -> HistogramTimer {
        self.duration.with_label_values(&[name]).start_timer()
    }

    pub fn get_block_txids(&self, hash: &BlockHash) -> Option<Vec<Txid>> {
        let _timer = self.start_timer("get_block_txids");

        if self.light_mode {
            // TODO fetch block as binary from REST API instead of as hex
            let mut blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo["tx"].take()).unwrap())
        } else {
            self.store
                .txstore_db
                .get(&BlockRow::txids_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse block txids")
                })
        }
    }

    pub fn get_block_txs(&self, hash: &BlockHash) -> Option<Vec<Transaction>> {
        let _timer = self.start_timer("get_block_txs");

        let txids: Option<Vec<Txid>> = if self.light_mode {
            // TODO fetch block as binary from REST API instead of as hex
            let mut blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo["tx"].take()).unwrap())
        } else {
            self.store
                .txstore_db
                .get(&BlockRow::txids_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse block txids")
                })
        };

        txids.and_then(|txid_vec| {
            let mut transactions = Vec::with_capacity(txid_vec.len());

            for txid in txid_vec {
                match self.lookup_txn(&txid, Some(hash)) {
                    Some(transaction) => transactions.push(transaction),
                    None => return None,
                }
            }

            Some(transactions)
        })
    }

    pub fn get_block_meta(&self, hash: &BlockHash) -> Option<BlockMeta> {
        let _timer = self.start_timer("get_block_meta");

        if self.light_mode {
            let blockinfo = self.daemon.getblock_raw(hash, 1).ok()?;
            Some(serde_json::from_value(blockinfo).unwrap())
        } else {
            self.store
                .txstore_db
                .get(&BlockRow::meta_key(full_hash(&hash[..])))
                .map(|val| {
                    bincode_util::deserialize_little(&val).expect("failed to parse BlockMeta")
                })
        }
    }

    pub fn get_block_raw(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let _timer = self.start_timer("get_block_raw");

        if self.light_mode {
            let blockhex = self.daemon.getblock_raw(hash, 0).ok()?;
            Some(hex::decode(blockhex.as_str().unwrap()).unwrap())
        } else {
            let entry = self.header_by_hash(hash)?;
            let meta = self.get_block_meta(hash)?;
            let txids = self.get_block_txids(hash)?;

            // Reconstruct the raw block using the header and txids,
            // as <raw header><tx count varint><raw txs>
            let mut raw = Vec::with_capacity(meta.size as usize);

            raw.append(&mut serialize(entry.header()));
            raw.append(&mut serialize(&VarInt(txids.len() as u64)));

            for txid in txids {
                // we don't need to provide the blockhash because we know we're not in light mode
                raw.append(&mut self.lookup_raw_txn(&txid, None)?);
            }

            Some(raw)
        }
    }

    pub fn get_block_header(&self, hash: &BlockHash) -> Option<BlockHeader> {
        let _timer = self.start_timer("get_block_header");
        #[allow(clippy::clone_on_copy)]
        Some(self.header_by_hash(hash)?.header().clone())
    }

    pub fn get_mtp(&self, height: usize) -> u32 {
        let _timer = self.start_timer("get_block_mtp");
        self.store.indexed_headers.read().unwrap().get_mtp(height)
    }

    pub fn get_block_with_meta(&self, hash: &BlockHash) -> Option<BlockHeaderMeta> {
        let _timer = self.start_timer("get_block_with_meta");
        let header_entry = self.header_by_hash(hash)?;
        Some(BlockHeaderMeta {
            meta: self.get_block_meta(hash)?,
            mtp: self.get_mtp(header_entry.height()),
            header_entry,
        })
    }

    pub fn completed_read_generation(&self) -> Option<u64> {
        #[cfg(not(feature = "liquid"))]
        if !self.store.coverage_scope.try_read().ok()?.is_some() {
            return None;
        }
        self.store.read_generation.completed()
    }
    pub fn matches_read_generation(&self, generation: u64) -> bool {
        self.completed_read_generation() == Some(generation)
    }

    pub fn history_iter_scan(
        &self,
        code: u8,
        hash: &[u8],
        start_height: usize,
    ) -> ScanIterator<'_> {
        self.store.history_db.iter_scan_from(
            &TxHistoryRow::filter(code, hash),
            &TxHistoryRow::prefix_height(code, hash, start_height as u32),
        )
    }
    #[cfg(not(feature = "liquid"))]
    fn checked_history_iter<'a>(
        &'a self,
        hash: &'a [u8],
        start_height: usize,
        budget: &'a super::qualified_edges::ReadBudget,
    ) -> impl Iterator<Item = Result<TxHistoryRow>> + 'a {
        let snapshot = self.store.history_db.bounded_snapshot();
        let prefix = TxHistoryRow::filter(b'H', hash);
        let mut after = u32::try_from(start_height)
            .ok()
            .map(|height| TxHistoryRow::prefix_height(b'H', hash, height));
        let mut terminal = false;
        std::iter::from_fn(move || {
            if terminal {
                return None;
            }
            let read = (|| -> Result<Option<TxHistoryRow>> {
                if after.is_none() {
                    bail!(ErrorKind::LegacyPositionUnavailable);
                }
                budget
                    .reserve(1)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                let row = match snapshot
                    .next_record(&prefix, after.as_deref())
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                {
                    Some(row) => row,
                    None => return Ok(None),
                };
                let key: TxHistoryKey = bincode_util::deserialize_big(&row.key)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                if key.code != b'H'
                    || key.hash.as_slice() != hash
                    || bincode_util::serialize_big(&key)
                        .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                        != row.key
                {
                    bail!(ErrorKind::LegacyPositionUnavailable);
                }
                after = Some(row.key);
                Ok(Some(TxHistoryRow { key }))
            })();
            match read {
                Ok(Some(row)) => Some(Ok(row)),
                Ok(None) => {
                    terminal = true;
                    None
                }
                Err(error) => {
                    terminal = true;
                    Some(Err(error))
                }
            }
        })
    }
    fn history_iter_scan_reverse(
        &self,
        code: u8,
        hash: &[u8],
        start_height: Option<u32>,
    ) -> ReverseScanIterator<'_> {
        self.store.history_db.iter_scan_reverse(
            &TxHistoryRow::filter(code, hash),
            &start_height.map_or(TxHistoryRow::prefix_end(code, hash), |start_height| {
                TxHistoryRow::prefix_height_end(code, hash, start_height)
            }),
        )
    }
    fn history_iter_scan_group_reverse(
        &self,
        code: u8,
        hashes: &[[u8; 32]],
        start_height: Option<u32>,
    ) -> ReverseScanGroupIterator<'_> {
        self.store.history_db.iter_scan_group_reverse(
            hashes.iter().map(|hash| {
                let prefix = TxHistoryRow::filter(code, &hash[..]);
                let prefix_max = start_height
                    .map_or(TxHistoryRow::prefix_end(code, &hash[..]), |start_height| {
                        TxHistoryRow::prefix_height_end(code, &hash[..], start_height)
                    });
                (prefix, prefix_max)
            }),
            33,
        )
    }

    fn collate_summaries(
        &self,
        iter: impl Iterator<Item = TxHistoryRow>,
        last_seen_txid: Option<&Txid>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // collate utxo funding/spending events by transaction

        let rows = iter
            .map(|row| (row.get_txid(), row.key.txinfo, row.key.tx_position))
            // We should make sure that each history entry should be unique
            // We check uniqueness against equality of these 3 things:
            // ("current txid", "the position in the inputs or outputs", "whether it's an input or output")
            .unique_by(|(txid, info, _)| (*txid, info.get_vin_or_vout(), info.has_vin()))
            .skip_while(|(txid, _, _)| {
                // skip until we reach the last_seen_txid
                last_seen_txid.is_some_and(|last_seen_txid| last_seen_txid != txid)
            })
            .skip_while(|(txid, _, _)| {
                // skip the last_seen_txid itself
                last_seen_txid == Some(txid)
            })
            .filter_map(|(txid, info, tx_position)| {
                self.tx_confirming_block(&txid)
                    .map(|b| (txid, info, b.height, b.time, tx_position))
            });
        let mut map: HashMap<Txid, TxHistorySummary> = HashMap::new();
        for (txid, info, height, time, tx_position) in rows {
            if !map.contains_key(&txid) && map.len() >= limit {
                break;
            }
            match info {
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Funding(info) => {
                    map.entry(txid)
                        .and_modify(|tx| {
                            tx.value = tx.value.saturating_add(info.value.try_into().unwrap_or(0))
                        })
                        .or_insert(TxHistorySummary {
                            txid,
                            value: info.value.try_into().unwrap_or(0),
                            height,
                            time,
                            tx_position,
                        });
                }
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Spending(info) => {
                    map.entry(txid)
                        .and_modify(|tx| {
                            tx.value = tx.value.saturating_sub(info.value.try_into().unwrap_or(0))
                        })
                        .or_insert(TxHistorySummary {
                            txid,
                            value: 0_i64.saturating_sub(info.value.try_into().unwrap_or(0)),
                            height,
                            time,
                            tx_position,
                        });
                }
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Funding(_info) => {
                    map.entry(txid).or_insert(TxHistorySummary {
                        txid,
                        value: 0,
                        height,
                        time,
                        tx_position,
                    });
                }
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Spending(_info) => {
                    map.entry(txid).or_insert(TxHistorySummary {
                        txid,
                        value: 0,
                        height,
                        time,
                        tx_position,
                    });
                }
                #[cfg(feature = "liquid")]
                _ => {}
            }
        }
        let mut tx_summaries = map.into_values().collect::<Vec<TxHistorySummary>>();
        tx_summaries.sort_by(|a, b| {
            if a.height == b.height {
                if a.tx_position == b.tx_position {
                    a.value.cmp(&b.value)
                } else {
                    b.tx_position.cmp(&a.tx_position)
                }
            } else {
                b.height.cmp(&a.height)
            }
        });
        tx_summaries
    }

    pub fn summary(
        &self,
        scripthash: &[u8],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // scripthash lookup
        self._summary(b'H', scripthash, last_seen_txid, start_height, limit)
    }

    fn _summary(
        &self,
        code: u8,
        hash: &[u8],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        let _timer_scan = self.start_timer("address_summary");
        let rows = self
            .history_iter_scan_reverse(code, hash, start_height)
            .map(TxHistoryRow::from_row);

        self.collate_summaries(rows, last_seen_txid, limit)
    }

    pub fn summary_group(
        &self,
        scripthashes: &[[u8; 32]],
        last_seen_txid: Option<&Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> Vec<TxHistorySummary> {
        // scripthash lookup
        let _timer_scan = self.start_timer("address_group_summary");
        let rows = self
            .history_iter_scan_group_reverse(b'H', scripthashes, start_height)
            .map(TxHistoryRow::from_row);

        self.collate_summaries(rows, last_seen_txid, limit)
    }

    pub fn history<'a>(
        &'a self,
        scripthash: &[u8],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a {
        // scripthash lookup
        self._history(b'H', scripthash, last_seen_txid, start_height, limit)
    }

    pub fn history_txids_iter<'a>(&'a self, scripthash: &[u8]) -> impl Iterator<Item = Txid> + 'a {
        self.history_iter_scan_reverse(b'H', scripthash, None)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
    }

    fn _history<'a>(
        &'a self,
        code: u8,
        hash: &[u8],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a {
        let _timer_scan = self.start_timer("history");

        self.lookup_txns(
            self.history_iter_scan_reverse(code, hash, start_height)
                .map(TxHistoryRow::from_row)
                // XXX: unique_by() requires keeping an in-memory list of all txids, can we avoid that?
                .unique_by(|row| row.get_txid())
                // TODO seek directly to last seen tx without reading earlier rows
                .skip_while(move |row| {
                    // skip until we reach the last_seen_txid
                    last_seen_txid.is_some_and(|last_seen_txid| last_seen_txid != &row.get_txid())
                })
                .skip(match last_seen_txid {
                    Some(_) => 1, // skip the last_seen_txid itself
                    None => 0,
                })
                .filter_map(move |row| {
                    self.tx_confirming_block(&row.get_txid())
                        .map(|b| (row.get_txid(), b, row.get_tx_position()))
                }),
            limit,
        )
    }

    pub fn history_txids(&self, scripthash: &[u8], limit: usize) -> Vec<(Txid, BlockId)> {
        // scripthash lookup
        self._history_txids(b'H', scripthash, limit)
    }

    fn _history_txids(&self, code: u8, hash: &[u8], limit: usize) -> Vec<(Txid, BlockId)> {
        let _timer = self.start_timer("history_txids");
        self.history_iter_scan(code, hash, 0)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
            .filter_map(|txid| self.tx_confirming_block(&txid).map(|b| (txid, b)))
            .take(limit)
            .collect()
    }

    pub fn history_group<'a>(
        &'a self,
        scripthashes: &[[u8; 32]],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a {
        // scripthash lookup
        self._history_group(b'H', scripthashes, last_seen_txid, start_height, limit)
    }

    pub fn history_txids_iter_group(
        &self,
        scripthashes: &[[u8; 32]],
        start_height: Option<u32>,
    ) -> impl Iterator<Item = Txid> + '_ {
        self.history_iter_scan_group_reverse(b'H', scripthashes, start_height)
            .map(|row| TxHistoryRow::from_row(row).get_txid())
            .unique()
    }

    fn _history_group<'a>(
        &'a self,
        code: u8,
        hashes: &[[u8; 32]],
        last_seen_txid: Option<&'a Txid>,
        start_height: Option<u32>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a {
        debug!("limit {} | last_seen {:?}", limit, last_seen_txid);
        let _timer_scan = self.start_timer("history_group");

        self.lookup_txns(
            self.history_iter_scan_group_reverse(code, hashes, start_height)
                .map(TxHistoryRow::from_row)
                // XXX: unique_by() requires keeping an in-memory list of all txids, can we avoid that?
                .unique_by(|row| row.get_txid())
                .skip_while(move |row| {
                    // we already seeked to the last txid at this height
                    // now skip just past the last_seen_txid itself
                    last_seen_txid.is_some_and(|last_seen_txid| last_seen_txid != &row.get_txid())
                })
                .skip(match last_seen_txid {
                    Some(_) => 1, // skip the last_seen_txid itself
                    None => 0,
                })
                .filter_map(move |row| {
                    self.tx_confirming_block(&row.get_txid())
                        .map(|b| (row.get_txid(), b, row.get_tx_position()))
                }),
            limit,
        )
    }

    // TODO: avoid duplication with stats/stats_delta?
    pub fn utxo(&self, scripthash: &[u8], limit: usize, flush: DBFlush) -> Result<Vec<Utxo>> {
        #[cfg(not(feature = "liquid"))]
        let epoch = self
            .completed_read_generation()
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        let _timer = self.start_timer("utxo");

        // get the last known utxo set and the blockhash it was updated for.
        // invalidates the cache if the block was orphaned.
        #[cfg(feature = "liquid")]
        let cache: Option<(UtxoMap, usize)> = self
            .store
            .cache_db
            .get(&UtxoCacheRow::key(scripthash))
            .map(|c| bincode_util::deserialize_little(&c).unwrap())
            .and_then(|(utxos_cache, blockhash)| {
                self.height_by_hash(&blockhash)
                    .map(|height| (utxos_cache, height))
            })
            .map(|(utxos_cache, height)| (from_utxo_cache(utxos_cache, self), height));
        #[cfg(not(feature = "liquid"))]
        let cache: Option<(UtxoMap, usize)> =
            match self.ledger_cache::<Vec<((Txid, u32), (u32, Value))>>(scripthash, b'U')? {
                Some((rows, hash)) => {
                    let mut value = CachedUtxoMap::new();
                    for (outpoint, output) in rows {
                        if value.insert(outpoint, output).is_some() {
                            bail!(ErrorKind::LegacyPositionUnavailable);
                        }
                    }
                    self.height_by_hash(&hash)
                        .map(|height| (from_utxo_cache(value, self), height))
                }
                None => None,
            };
        if cache
            .as_ref()
            .map_or(false, |(utxos, _)| utxos.len() > limit)
        {
            bail!(ErrorKind::TooManyUtxos(limit));
        }
        let had_cache = cache.is_some();

        // update utxo set with new transactions since
        let (newutxos, lastblock, processed_items) = cache.map_or_else(
            || self.utxo_delta(scripthash, HashMap::new(), 0, limit),
            |(oldutxos, blockheight)| self.utxo_delta(scripthash, oldutxos, blockheight + 1, limit),
        )?;

        #[cfg(not(feature = "liquid"))]
        if !self.matches_read_generation(epoch) {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        // save updated utxo set to cache
        if let Some(lastblock) = lastblock {
            if had_cache || processed_items > MIN_HISTORY_ITEMS_TO_CACHE {
                #[cfg(feature = "liquid")]
                self.store.cache_db.write(
                    vec![UtxoCacheRow::new(scripthash, &newutxos, &lastblock).into_row()],
                    flush,
                );
                #[cfg(not(feature = "liquid"))]
                self.store.cache_db.write(
                    vec![self.ledger_cache_row(
                        scripthash,
                        b'U',
                        make_utxo_cache(&newutxos).into_iter().collect::<Vec<_>>(),
                        lastblock,
                    )?],
                    flush,
                );
            }
        }

        #[cfg(not(feature = "liquid"))]
        if !self.matches_read_generation(epoch) {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        // format as Utxo objects
        Ok(newutxos
            .into_iter()
            .map(|(outpoint, (blockid, value))| {
                // in elements/liquid chains, we have to lookup the txo in order to get its
                // associated asset. the asset information could be kept in the db history rows
                // alongside the value to avoid this.
                #[cfg(feature = "liquid")]
                let txo = self.lookup_txo(&outpoint).expect("missing utxo");

                Utxo {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    value,
                    confirmed: Some(blockid),

                    #[cfg(feature = "liquid")]
                    asset: txo.asset,
                    #[cfg(feature = "liquid")]
                    nonce: txo.nonce,
                    #[cfg(feature = "liquid")]
                    witness: txo.witness,
                }
            })
            .collect())
    }

    fn utxo_delta(
        &self,
        scripthash: &[u8],
        init_utxos: UtxoMap,
        start_height: usize,
        limit: usize,
    ) -> Result<(UtxoMap, Option<BlockHash>, usize)> {
        let _timer = self.start_timer("utxo_delta");
        let budget = super::qualified_edges::ReadBudget::new();
        #[cfg(not(feature = "liquid"))]
        let history_iter = self.checked_history_iter(scripthash, start_height, &budget);
        #[cfg(feature = "liquid")]
        let history_iter = self
            .history_iter_scan(b'H', scripthash, start_height)
            .map(|row| Ok::<_, Error>(TxHistoryRow::from_row(row)));
        let mut utxos = init_utxos;
        let mut processed_items = 0;
        let mut lastblock = None;

        for history in history_iter {
            let history = history?;
            let blockid = match self.current_history_occurrence(&history, &budget)? {
                Some(block) => block,
                None => continue,
            };
            // The genesis coinbase is indexed history, never a spendable UTXO.
            #[cfg(not(feature = "liquid"))]
            if history.key.confirmed_height == 0 {
                continue;
            }

            processed_items += 1;
            lastblock = Some(blockid.hash);

            match history.key.txinfo {
                TxHistoryInfo::Funding(ref info) => {
                    utxos.insert(history.get_funded_outpoint(), (blockid, info.value))
                }
                TxHistoryInfo::Spending(_) => utxos.remove(&history.get_funded_outpoint()),
                #[cfg(feature = "liquid")]
                TxHistoryInfo::Issuing(_)
                | TxHistoryInfo::Burning(_)
                | TxHistoryInfo::Pegin(_)
                | TxHistoryInfo::Pegout(_) => unreachable!(),
            };

            // abort if the utxo set size excedees the limit at any point in time
            if utxos.len() > limit {
                bail!(ErrorKind::TooManyUtxos(limit))
            }
        }

        Ok((utxos, lastblock, processed_items))
    }

    pub fn stats(&self, scripthash: &[u8], flush: DBFlush) -> Result<ScriptStats> {
        #[cfg(not(feature = "liquid"))]
        let epoch = self
            .completed_read_generation()
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        let _timer = self.start_timer("stats");

        // get the last known stats and the blockhash they are updated for.
        // invalidates the cache if the block was orphaned or if values are out of sync.
        #[cfg(feature = "liquid")]
        let cache: Option<(ScriptStats, usize)> = self
            .store
            .cache_db
            .get(&StatsCacheRow::key(scripthash))
            .map(|c| bincode_util::deserialize_little::<(ScriptStats, BlockHash)>(&c).unwrap())
            // Check that the values are sane (No negative balances or balances with 0 utxos)
            .filter(|(stats, _)| stats.is_sane())
            .and_then(|(stats, blockhash)| {
                self.height_by_hash(&blockhash)
                    .map(|height| (stats, height))
            });

        #[cfg(not(feature = "liquid"))]
        let cache: Option<(ScriptStats, usize)> = self
            .ledger_cache::<ScriptStats>(scripthash, b'A')?
            .filter(|(value, _)| value.is_sane())
            .and_then(|(value, hash)| self.height_by_hash(&hash).map(|height| (value, height)));

        // update stats with new transactions since
        let (newstats, lastblock) = cache.map_or_else(
            || self.stats_delta(scripthash, ScriptStats::default(), 0),
            |(oldstats, blockheight)| self.stats_delta(scripthash, oldstats, blockheight + 1),
        )?;

        #[cfg(not(feature = "liquid"))]
        if !self.matches_read_generation(epoch) {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        // save updated stats to cache
        if let Some(lastblock) = lastblock {
            if newstats.funded_txo_count + newstats.spent_txo_count > MIN_HISTORY_ITEMS_TO_CACHE {
                #[cfg(feature = "liquid")]
                self.store.cache_db.write(
                    vec![StatsCacheRow::new(scripthash, &newstats, &lastblock).into_row()],
                    flush,
                );
                #[cfg(not(feature = "liquid"))]
                self.store.cache_db.write(
                    vec![self.ledger_cache_row(scripthash, b'A', &newstats, lastblock)?],
                    flush,
                );
            }
        }

        #[cfg(not(feature = "liquid"))]
        if !self.matches_read_generation(epoch) {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        Ok(newstats)
    }

    fn stats_delta(
        &self,
        scripthash: &[u8],
        init_stats: ScriptStats,
        start_height: usize,
    ) -> Result<(ScriptStats, Option<BlockHash>)> {
        let _timer = self.start_timer("stats_delta"); // TODO: measure also the number of txns processed.
        let budget = super::qualified_edges::ReadBudget::new();
        #[cfg(not(feature = "liquid"))]
        let history_iter = self.checked_history_iter(scripthash, start_height, &budget);
        #[cfg(feature = "liquid")]
        let history_iter = self
            .history_iter_scan(b'H', scripthash, start_height)
            .map(|row| Ok::<_, Error>(TxHistoryRow::from_row(row)));
        let mut stats = init_stats;
        let mut seen_txids = HashSet::new();
        let mut lastblock = None;

        for history in history_iter {
            let history = history?;
            let blockid = match self.current_history_occurrence(&history, &budget)? {
                Some(block) => block,
                None => continue,
            };
            #[cfg(not(feature = "liquid"))]
            if history.key.confirmed_height == 0 {
                continue;
            }

            if lastblock != Some(blockid.hash) {
                seen_txids.clear();
            }

            if seen_txids.insert(history.get_txid()) {
                stats.tx_count = stats
                    .tx_count
                    .checked_add(1)
                    .ok_or(ErrorKind::LegacyPositionUnavailable)?;
            }

            match history.key.txinfo {
                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Funding(ref info) => {
                    stats.funded_txo_count = stats
                        .funded_txo_count
                        .checked_add(1)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                    stats.funded_txo_sum = stats
                        .funded_txo_sum
                        .checked_add(info.value)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                }

                #[cfg(not(feature = "liquid"))]
                TxHistoryInfo::Spending(ref info) => {
                    stats.spent_txo_count = stats
                        .spent_txo_count
                        .checked_add(1)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                    stats.spent_txo_sum = stats
                        .spent_txo_sum
                        .checked_add(info.value)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Funding(_) => {
                    stats.funded_txo_count = stats
                        .funded_txo_count
                        .checked_add(1)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Spending(_) => {
                    stats.spent_txo_count = stats
                        .spent_txo_count
                        .checked_add(1)
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                }

                #[cfg(feature = "liquid")]
                TxHistoryInfo::Issuing(_)
                | TxHistoryInfo::Burning(_)
                | TxHistoryInfo::Pegin(_)
                | TxHistoryInfo::Pegout(_) => unreachable!(),
            }

            lastblock = Some(blockid.hash);
        }

        Ok((stats, lastblock))
    }

    fn current_history_occurrence(
        &self,
        history: &TxHistoryRow,
        budget: &super::qualified_edges::ReadBudget,
    ) -> Result<Option<BlockId>> {
        #[cfg(feature = "liquid")]
        {
            let _ = budget;
            return Ok(self
                .tx_confirming_block(&history.get_txid())
                .filter(|block| block.height == history.key.confirmed_height as usize));
        }
        #[cfg(not(feature = "liquid"))]
        {
            let block = match self.blockid_by_height(history.key.confirmed_height as usize) {
                Some(block) => block,
                None => return Ok(None),
            };
            let txid = history.get_txid();
            let raw = self
                .checked_proof_point(
                    budget,
                    &BlockRow::txids_key(full_hash(&block.hash[..])),
                    4 * 1024 * 1024,
                )
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                .ok_or(ErrorKind::LegacyPositionUnavailable)?;
            let position = match super::qualified_edges::roster_position(&raw, full_hash(&txid[..]))
            {
                Ok(position) => position,
                Err(super::qualified_edges::EdgeError::MissingCoverage) => return Ok(None),
                Err(_) => bail!(ErrorKind::LegacyPositionUnavailable),
            };
            if position != history.key.tx_position {
                return Ok(None);
            }
            self.tx_position_in_block(&txid, &block, budget)?;
            self.validate_history_body(history, budget)?;
            Ok(Some(block))
        }
    }
    #[cfg(not(feature = "liquid"))]
    fn validate_history_body(
        &self,
        history: &TxHistoryRow,
        budget: &super::qualified_edges::ReadBudget,
    ) -> Result<()> {
        let raw = self
            .checked_proof_point(
                budget,
                &TxRow::key(&history.get_txid()[..]),
                4 * 1024 * 1024,
            )
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        let tx: Transaction =
            deserialize(&raw).map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
        if tx.get_txid() != history.get_txid() {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        let (output, value) = match &history.key.txinfo {
            TxHistoryInfo::Funding(info) => (
                tx.output
                    .get(info.vout as usize)
                    .cloned()
                    .ok_or(ErrorKind::LegacyPositionUnavailable)?,
                info.value,
            ),
            TxHistoryInfo::Spending(info) => {
                let input = tx
                    .input
                    .get(info.vin as usize)
                    .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                if full_hash(&input.previous_output.txid[..]) != info.prev_txid
                    || input.previous_output.vout != info.prev_vout
                {
                    bail!(ErrorKind::LegacyPositionUnavailable);
                }
                let raw = self
                    .checked_proof_point(budget, &TxRow::key(&info.prev_txid), 4 * 1024 * 1024)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                    .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                let parent: Transaction = deserialize(&raw)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                if full_hash(&parent.get_txid()[..]) != info.prev_txid {
                    bail!(ErrorKind::LegacyPositionUnavailable);
                }
                (
                    parent
                        .output
                        .get(info.prev_vout as usize)
                        .cloned()
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?,
                    info.value,
                )
            }
        };
        if output.value.to_sat() != value
            || compute_script_hash(&output.script_pubkey) != history.key.hash
        {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        Ok(())
    }
    #[cfg(not(feature = "liquid"))]
    fn checked_proof_point(
        &self,
        budget: &super::qualified_edges::ReadBudget,
        key: &[u8],
        maximum: usize,
    ) -> std::result::Result<Option<Bytes>, super::qualification::QualifiedReadError> {
        let reads = if self.store.proof_txstore.is_some()
            && matches!(key.first(), Some(b'T') | Some(b'X') | Some(b'M'))
        {
            2
        } else {
            1
        };
        budget
            .reserve(reads)
            .map_err(|_| super::qualification::QualifiedReadError::Contract)?;
        self.store.proof_point(key, maximum)
    }
    #[cfg(not(feature = "liquid"))]
    fn ledger_scope(&self) -> Result<String> {
        self.completed_read_generation()
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        self.store
            .coverage_scope
            .try_read()
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
            .clone()
            .ok_or_else(|| ErrorKind::LegacyPositionUnavailable.into())
    }
    #[cfg(not(feature = "liquid"))]
    fn ledger_cache<T: serde::de::DeserializeOwned>(
        &self,
        script: &[u8],
        kind: u8,
    ) -> Result<Option<(T, BlockHash)>> {
        let scope = self.ledger_scope()?;
        let key = ledger_cache_key(kind, script);
        let bytes = match self
            .store
            .cache_db
            .qualified_get(&key, 4 * 1024 * 1024)
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let entry: LedgerCache<T> = serde_json::from_slice(&bytes)
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
        if entry.schema_version != 2
            || entry.scope_digest != scope
            || entry.computation_version != "funding-incarnation-position-v2"
        {
            return Ok(None);
        }
        if self.blockid_by_hash(&entry.block_hash).is_none() {
            return Ok(None);
        }
        Ok(Some((entry.payload, entry.block_hash)))
    }
    #[cfg(not(feature = "liquid"))]
    fn ledger_cache_row<T: serde::Serialize>(
        &self,
        script: &[u8],
        kind: u8,
        payload: T,
        block_hash: BlockHash,
    ) -> Result<DBRow> {
        let entry = LedgerCache {
            schema_version: 2,
            scope_digest: self.ledger_scope()?,
            computation_version: "funding-incarnation-position-v2".into(),
            block_hash,
            payload,
        };
        let value = serde_json::to_vec(&entry)
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
        if value.len() > 4 * 1024 * 1024 {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        Ok(DBRow {
            key: ledger_cache_key(kind, script),
            value,
        })
    }

    pub fn address_search(&self, prefix: &str, limit: usize) -> Vec<String> {
        let _timer_scan = self.start_timer("address_search");
        self.store
            .history_db
            .iter_scan(&addr_search_filter(prefix))
            .take(limit)
            .map(|row| std::str::from_utf8(&row.key[1..]).unwrap().to_string())
            .collect()
    }

    fn header_by_hash(&self, hash: &BlockHash) -> Option<HeaderEntry> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_blockhash(hash)
            .cloned()
    }

    // Get the height of a blockhash, only if its part of the best chain
    pub fn height_by_hash(&self, hash: &BlockHash) -> Option<usize> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_blockhash(hash)
            .map(|header| header.height())
    }

    pub fn header_by_height(&self, height: usize) -> Option<HeaderEntry> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_height(height)
            .cloned()
    }

    pub fn hash_by_height(&self, height: usize) -> Option<BlockHash> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_height(height)
            .map(|entry| *entry.hash())
    }

    pub fn blockid_by_height(&self, height: usize) -> Option<BlockId> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_height(height)
            .map(BlockId::from)
    }

    // returns None for orphaned blocks
    pub fn blockid_by_hash(&self, hash: &BlockHash) -> Option<BlockId> {
        self.store
            .indexed_headers
            .read()
            .unwrap()
            .header_by_blockhash(hash)
            .map(BlockId::from)
    }

    pub fn best_height(&self) -> usize {
        self.store.indexed_headers.read().unwrap().len() - 1
    }

    pub fn best_hash(&self) -> BlockHash {
        *self.store.indexed_headers.read().unwrap().tip()
    }

    pub fn best_header(&self) -> HeaderEntry {
        let headers = self.store.indexed_headers.read().unwrap();
        headers
            .header_by_blockhash(headers.tip())
            .expect("missing chain tip")
            .clone()
    }

    // TODO: can we pass txids as a "generic iterable"?
    // TODO: should also use a custom ThreadPoolBuilder?
    pub fn lookup_txns<'a, I>(
        &'a self,
        txids: I,
        take: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a
    where
        I: Iterator<Item = (Txid, BlockId, u16)> + Send + rayon::iter::ParallelBridge + 'a,
    {
        txids
            .take(take)
            .par_bridge()
            .map(move |(txid, blockid, tx_position)| -> Result<_> {
                Ok((
                    self.lookup_txn(&txid, Some(&blockid.hash))
                        .chain_err(|| "missing tx")?,
                    blockid,
                    tx_position,
                ))
            })
    }

    pub fn lookup_txn(&self, txid: &Txid, blockhash: Option<&BlockHash>) -> Option<Transaction> {
        let _timer = self.start_timer("lookup_txn");
        self.lookup_raw_txn(txid, blockhash).map(|rawtx| {
            let txn: Transaction = deserialize(&rawtx).expect("failed to parse Transaction");
            assert_eq!(*txid, txn.get_txid());
            txn
        })
    }

    pub fn lookup_raw_txn(&self, txid: &Txid, blockhash: Option<&BlockHash>) -> Option<Bytes> {
        let _timer = self.start_timer("lookup_raw_txn");

        if self.light_mode {
            let queried_blockhash =
                blockhash.map_or_else(|| self.tx_confirming_block(txid).map(|b| b.hash), |_| None);
            let blockhash = blockhash.or(queried_blockhash.as_ref())?;
            // TODO fetch transaction as binary from REST API instead of as hex
            let txhex = self
                .daemon
                .gettransaction_raw(txid, blockhash, false)
                .ok()?;
            Some(hex::decode(txhex.as_str().unwrap()).unwrap())
        } else {
            self.store.txstore_db.get(&TxRow::key(&txid[..]))
        }
    }

    pub fn lookup_txo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let _timer = self.start_timer("lookup_txo");
        lookup_txo(&self.store.txstore_db, outpoint)
    }

    pub fn lookup_txos(&self, outpoints: &BTreeSet<OutPoint>) -> HashMap<OutPoint, TxOut> {
        let _timer = self.start_timer("lookup_txos");
        lookup_txos(&self.store.txstore_db, outpoints, false)
    }

    pub fn lookup_avail_txos(&self, outpoints: &BTreeSet<OutPoint>) -> HashMap<OutPoint, TxOut> {
        let _timer = self.start_timer("lookup_available_txos");
        lookup_txos(&self.store.txstore_db, outpoints, true)
    }

    pub fn lookup_spend(&self, outpoint: &OutPoint) -> Result<Option<SpendingInput>> {
        self.lookup_spend_with_budget(outpoint, &super::qualified_edges::ReadBudget::new())
    }
    pub fn lookup_spend_with_budget(
        &self,
        outpoint: &OutPoint,
        budget: &super::qualified_edges::ReadBudget,
    ) -> Result<Option<SpendingInput>> {
        #[cfg(feature = "liquid")]
        {
            let _ = budget;
            return Ok(self
                .store
                .history_db
                .iter_scan(&TxEdgeRow::filter(outpoint))
                .map(TxEdgeRow::from_row)
                .find_map(|edge| {
                    let txid: Txid = deserialize(&edge.key.spending_txid).unwrap();
                    self.tx_confirming_block(&txid).map(|block| SpendingInput {
                        txid,
                        vin: edge.key.spending_vin,
                        confirmed: Some(block),
                    })
                }));
        }
        #[cfg(not(feature = "liquid"))]
        {
            // Absence is meaningful only after actual historical coverage. A
            // partial future edge index/old shared S key may not say unspent.
            let epoch = self
                .completed_read_generation()
                .ok_or(ErrorKind::LegacyPositionUnavailable)?;
            let (funding_block, funding_position) =
                match self.canonical_tx_position(&outpoint.txid, budget)? {
                    Some(value) => value,
                    None => return Ok(None),
                };
            let raw = self
                .checked_proof_point(budget, &TxRow::key(&outpoint.txid[..]), 4 * 1024 * 1024)
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                .ok_or(ErrorKind::LegacyPositionUnavailable)?;
            let transaction: Transaction =
                deserialize(&raw).map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
            if transaction.get_txid() != outpoint.txid {
                bail!(ErrorKind::LegacyPositionUnavailable);
            }
            let output = transaction
                .output
                .get(outpoint.vout as usize)
                .ok_or(ErrorKind::LegacyPositionUnavailable)?;
            let script_hash = compute_script_hash(&output.script_pubkey);
            let snapshot = self.store.history_db.bounded_snapshot();
            let prefix = super::qualified_edges::EdgeKey::prefix(
                script_hash,
                full_hash(&outpoint.txid[..]),
                outpoint.vout,
            );
            let mut after = None;
            for _ in 0..super::qualified_edges::MAX_VISITS {
                budget
                    .reserve(1)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                let row = snapshot
                    .next_record(&prefix, after.as_deref())
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                let row = match row {
                    Some(row) => row,
                    None => {
                        if !self.matches_read_generation(epoch) {
                            bail!(ErrorKind::LegacyPositionUnavailable);
                        }
                        return Ok(None);
                    }
                };
                let edge = super::qualified_edges::EdgeKey::decode(&row.key)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                after = Some(row.key);
                let hash: BlockHash = deserialize(&edge.spending_block_hash)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                let canonical = self.blockid_by_hash(&hash);
                if let Some(block) = canonical {
                    if block.height != edge.spending_height as usize {
                        bail!(ErrorKind::LegacyPositionUnavailable);
                    }
                    if !edge.follows_funding(funding_block.height as u32, funding_position) {
                        continue;
                    }
                    let txid: Txid = deserialize(&edge.spending_txid)
                        .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                    let actual = self.tx_position_in_block(&txid, &block, budget)?;
                    if actual != edge.spending_position {
                        bail!(ErrorKind::LegacyPositionUnavailable);
                    }
                    let raw = self
                        .checked_proof_point(budget, &TxRow::key(&txid[..]), 4 * 1024 * 1024)
                        .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                        .ok_or(ErrorKind::LegacyPositionUnavailable)?;
                    let spending: Transaction = deserialize(&raw)
                        .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
                    if spending.get_txid() != txid
                        || spending
                            .input
                            .get(edge.spending_vin as usize)
                            .map(|input| input.previous_output)
                            != Some(*outpoint)
                        || !self.matches_read_generation(epoch)
                    {
                        bail!(ErrorKind::LegacyPositionUnavailable);
                    }
                    return Ok(Some(SpendingInput {
                        txid,
                        vin: edge.spending_vin,
                        confirmed: Some(block),
                    }));
                }
            }
            bail!(ErrorKind::LegacyPositionUnavailable)
        }
    }

    #[cfg(not(feature = "liquid"))]
    fn canonical_tx_position(
        &self,
        txid: &Txid,
        budget: &super::qualified_edges::ReadBudget,
    ) -> Result<Option<(BlockId, u16)>> {
        let snapshot = self.store.txstore_db.bounded_snapshot();
        let prefix = TxConfRow::filter(&txid[..]);
        let mut after = None;
        let mut latest: Option<BlockId> = None;
        for _ in 0..super::qualified_edges::MAX_VISITS {
            budget
                .reserve(1)
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
            let row = snapshot
                .next_record(&prefix, after.as_deref())
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
            let row = match row {
                Some(row) => row,
                None => {
                    return match latest {
                        Some(block) => {
                            let position = self.tx_position_in_block(txid, &block, budget)?;
                            Ok(Some((block, position)))
                        }
                        None => Ok(None),
                    }
                }
            };
            let decoded: TxConfKey = bincode_util::deserialize_little(&row.key)
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
            if decoded.code != b'C'
                || decoded.txid != full_hash(&txid[..])
                || bincode_util::serialize_little(&decoded)
                    .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
                    != row.key
            {
                bail!(ErrorKind::LegacyPositionUnavailable);
            }
            after = Some(row.key);
            let hash: BlockHash = deserialize(&decoded.blockhash)
                .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
            if let Some(block) = self.blockid_by_hash(&hash) {
                if latest
                    .as_ref()
                    .map_or(true, |previous| block.height > previous.height)
                {
                    latest = Some(block);
                }
            }
        }
        bail!(ErrorKind::LegacyPositionUnavailable)
    }

    #[cfg(not(feature = "liquid"))]
    fn tx_position_in_block(
        &self,
        txid: &Txid,
        block: &BlockId,
        budget: &super::qualified_edges::ReadBudget,
    ) -> Result<u16> {
        use bitcoin::hashes::Hash;
        let raw = self
            .checked_proof_point(
                budget,
                &BlockRow::txids_key(full_hash(&block.hash[..])),
                4 * 1024 * 1024,
            )
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        let position = super::qualified_edges::roster_position(&raw, full_hash(&txid[..]))
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
        let header = self
            .header_by_hash(&block.hash)
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        let merkle =
            bitcoin::merkle_tree::calculate_root(raw[8..].chunks_exact(32).map(|hash| {
                bitcoin::TxMerkleNode::from_slice(hash).expect("checked fixed32 hash")
            }))
            .ok_or(ErrorKind::LegacyPositionUnavailable)?;
        if merkle != header.header().merkle_root {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        let confirmation = TxConfKey {
            code: b'C',
            txid: full_hash(&txid[..]),
            blockhash: full_hash(&block.hash[..]),
        };
        let key = bincode_util::serialize_little(&confirmation)
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?;
        if self
            .checked_proof_point(budget, &key, 0)
            .map_err(|_| Error::from(ErrorKind::LegacyPositionUnavailable))?
            != Some(vec![])
        {
            bail!(ErrorKind::LegacyPositionUnavailable);
        }
        Ok(position)
    }
    pub fn tx_confirming_block(&self, txid: &Txid) -> Option<BlockId> {
        let _timer = self.start_timer("tx_confirming_block");
        let headers = self.store.indexed_headers.read().unwrap();
        self.store
            .txstore_db
            .iter_scan(&TxConfRow::filter(&txid[..]))
            .map(TxConfRow::from_row)
            // header_by_blockhash only returns blocks that are part of the best chain,
            // or None for orphaned blocks.
            .filter_map(|conf| {
                headers.header_by_blockhash(&deserialize(&conf.key.blockhash).unwrap())
            })
            .max_by_key(|header| header.height())
            .map(BlockId::from)
    }

    pub fn get_block_status(&self, hash: &BlockHash) -> BlockStatus {
        // TODO differentiate orphaned and non-existing blocks? telling them apart requires
        // an additional db read.

        let headers = self.store.indexed_headers.read().unwrap();

        // header_by_blockhash only returns blocks that are part of the best chain,
        // or None for orphaned blocks.
        headers
            .header_by_blockhash(hash)
            .map_or_else(BlockStatus::orphaned, |header| {
                BlockStatus::confirmed(
                    header.height(),
                    headers
                        .header_by_height(header.height() + 1)
                        .map(|h| *h.hash()),
                )
            })
    }

    #[cfg(not(feature = "liquid"))]
    pub fn get_merkleblock_proof(&self, txid: &Txid) -> Option<MerkleBlock> {
        let _timer = self.start_timer("get_merkleblock_proof");
        let blockid = self.tx_confirming_block(txid)?;
        let headerentry = self.header_by_hash(&blockid.hash)?;
        let block_txids = self.get_block_txids(&blockid.hash)?;

        Some(MerkleBlock::from_header_txids_with_predicate(
            headerentry.header(),
            &block_txids,
            |t| t == txid,
        ))
    }

    #[cfg(feature = "liquid")]
    pub fn asset_history<'a>(
        &'a self,
        asset_id: &'a AssetId,
        last_seen_txid: Option<&'a Txid>,
        limit: usize,
    ) -> impl rayon::iter::ParallelIterator<Item = Result<(Transaction, BlockId, u16)>> + 'a {
        self._history(
            b'I',
            &asset_id.into_inner()[..],
            last_seen_txid,
            None,
            limit,
        )
    }

    #[cfg(feature = "liquid")]
    pub fn asset_history_txids(&self, asset_id: &AssetId, limit: usize) -> Vec<(Txid, BlockId)> {
        self._history_txids(b'I', &asset_id.into_inner()[..], limit)
    }
}

fn load_blockhashes(db: &DB, prefix: &[u8]) -> HashSet<BlockHash> {
    db.iter_scan(prefix)
        .map(BlockRow::from_row)
        .map(|r| deserialize(&r.key.hash).expect("failed to parse BlockHash"))
        .collect()
}

fn load_blockheaders(db: &DB) -> HashMap<BlockHash, BlockHeader> {
    db.iter_scan(&BlockRow::header_filter())
        .map(BlockRow::from_row)
        .map(|r| {
            let key: BlockHash = deserialize(&r.key.hash).expect("failed to parse BlockHash");
            let value: BlockHeader = deserialize(&r.value).expect("failed to parse BlockHeader");
            (key, value)
        })
        .collect()
}

fn add_blocks(block_entries: &[BlockEntry], iconfig: &IndexerConfig) -> Vec<DBRow> {
    // persist individual transactions:
    //      T{txid} → {rawtx}
    //      C{txid}{blockhash}{height} →
    //      O{txid}{index} → {txout}
    // persist block headers', block txids' and metadata rows:
    //      B{blockhash} → {header}
    //      X{blockhash} → {txid1}...{txidN}
    //      M{blockhash} → {tx_count}{size}{weight}
    block_entries
        .par_iter() // serialization is CPU-intensive
        .map(|b| {
            let mut rows = vec![];
            let blockhash = full_hash(&b.entry.hash()[..]);
            let txids: Vec<Txid> = b.block.txdata.iter().map(|tx| tx.get_txid()).collect();
            for tx in &b.block.txdata {
                add_transaction(tx, blockhash, &mut rows, iconfig);
            }

            if !iconfig.light_mode {
                rows.push(BlockRow::new_txids(blockhash, &txids).into_row());
                rows.push(BlockRow::new_meta(blockhash, &BlockMeta::from(b)).into_row());
            }

            rows.push(BlockRow::new_header(b).into_row());
            rows.push(BlockRow::new_done(blockhash).into_row()); // mark block as "added"
            rows
        })
        .flatten()
        .collect()
}

fn add_transaction(
    tx: &Transaction,
    blockhash: FullHash,
    rows: &mut Vec<DBRow>,
    iconfig: &IndexerConfig,
) {
    rows.push(TxConfRow::new(tx, blockhash).into_row());

    if !iconfig.light_mode {
        rows.push(TxRow::new(tx).into_row());
    }

    let txid = full_hash(&tx.get_txid()[..]);
    for (txo_index, txo) in tx.output.iter().enumerate() {
        if is_spendable(txo) {
            rows.push(TxOutRow::new(&txid, txo_index, txo).into_row());
        }
    }
}

fn get_previous_txos(block_entries: &[BlockEntry]) -> BTreeSet<OutPoint> {
    block_entries
        .iter()
        .flat_map(|b| b.block.txdata.iter())
        .flat_map(|tx| {
            tx.input
                .iter()
                .filter(|txin| has_prevout(txin))
                .map(|txin| txin.previous_output)
        })
        .collect()
}

fn lookup_txos(
    txstore_db: &DB,
    outpoints: &BTreeSet<OutPoint>,
    allow_missing: bool,
) -> HashMap<OutPoint, TxOut> {
    super::THREAD_POOL.install(|| {
        // Should match lookup_txos_sequential
        outpoints
            .par_iter()
            .filter_map(|outpoint| {
                lookup_txo(txstore_db, outpoint)
                    .or_else(|| {
                        if !allow_missing {
                            panic!("missing txo {} in {:?}", outpoint, txstore_db);
                        }
                        None
                    })
                    .map(|txo| (*outpoint, txo))
            })
            .collect()
    })
}

fn lookup_txos_sequential(
    txstore_db: &DB,
    outpoints: &BTreeSet<OutPoint>,
    allow_missing: bool,
) -> HashMap<OutPoint, TxOut> {
    // Should match lookup_txos
    outpoints
        .iter()
        .filter_map(|outpoint| {
            lookup_txo(txstore_db, outpoint)
                .or_else(|| {
                    if !allow_missing {
                        panic!("missing txo {} in {:?}", outpoint, txstore_db);
                    }
                    None
                })
                .map(|txo| (*outpoint, txo))
        })
        .collect()
}

fn lookup_txo(txstore_db: &DB, outpoint: &OutPoint) -> Option<TxOut> {
    txstore_db
        .get(&TxOutRow::key(outpoint))
        .map(|val| deserialize(&val).expect("failed to parse TxOut"))
}

fn index_blocks(
    block_entries: &[BlockEntry],
    previous_txos_map: &HashMap<OutPoint, TxOut>,
    iconfig: &IndexerConfig,
    op: &Operation,
) -> Result<Vec<DBRow>> {
    block_entries
        .par_iter() // serialization is CPU-intensive
        .map(|b| {
            if b.block.block_hash() != *b.entry.hash() {
                return Err("block/header identity mismatch".into());
            }
            #[cfg(not(feature = "liquid"))]
            if b.block.compute_merkle_root() != Some(b.block.header.merkle_root) {
                return Err("block transaction merkle mismatch".into());
            }
            let block_hash = full_hash(&b.entry.hash()[..]);
            let mut rows = vec![];
            for (idx, tx) in b.block.txdata.iter().enumerate() {
                let height = b.entry.height() as u32;
                index_transaction(
                    tx,
                    height,
                    u16::try_from(idx)
                        .map_err(|_| Error::from("block transaction position overflow"))?,
                    block_hash,
                    previous_txos_map,
                    &mut rows,
                    iconfig,
                    op,
                );
            }
            rows.push(BlockRow::new_done(full_hash(&b.entry.hash()[..])).into_row()); // mark block as "indexed"
            Ok(rows)
        })
        .collect::<Result<Vec<Vec<DBRow>>>>()
        .map(|batches| batches.into_iter().flatten().collect())
}

// TODO: return an iterator?
fn index_transaction(
    tx: &Transaction,
    confirmed_height: u32,
    tx_position: u16,
    _block_hash: FullHash,
    previous_txos_map: &HashMap<OutPoint, TxOut>,
    rows: &mut Vec<DBRow>,
    iconfig: &IndexerConfig,
    _op: &Operation,
) {
    // persist history index:
    //      H{funding-scripthash}{spending-height}{spending-block-pos}S{spending-txid:vin}{funding-txid:vout} → ""
    //      H{funding-scripthash}{funding-height}{funding-block-pos}F{funding-txid:vout} → ""
    // persist "edges" for fast is-this-TXO-spent check
    //      S{funding-txid:vout}{spending-txid:vin} → ""
    let txid = full_hash(&tx.get_txid()[..]);
    for (txo_index, txo) in tx.output.iter().enumerate() {
        if is_spendable(txo) || iconfig.index_unspendables {
            #[cfg(not(feature = "liquid"))]
            let value = txo.value.to_sat();
            #[cfg(feature = "liquid")]
            let value = txo.value;
            let history = TxHistoryRow::new(
                &txo.script_pubkey,
                confirmed_height,
                tx_position,
                TxHistoryInfo::Funding(FundingInfo {
                    txid,
                    vout: txo_index as u32,
                    value,
                }),
            );
            rows.push(history.into_row());

            if iconfig.address_search {
                if let Some(row) = addr_search_row(&txo.script_pubkey, iconfig.network) {
                    rows.push(row);
                }
            }
        }
    }
    for (txi_index, txi) in tx.input.iter().enumerate() {
        if !has_prevout(txi) {
            continue;
        }
        let prev_txo = previous_txos_map
            .get(&txi.previous_output)
            .unwrap_or_else(|| panic!("missing previous txo {}", txi.previous_output));

        #[cfg(not(feature = "liquid"))]
        let prev_value = prev_txo.value.to_sat();
        #[cfg(feature = "liquid")]
        let prev_value = prev_txo.value;

        let history = TxHistoryRow::new(
            &prev_txo.script_pubkey,
            confirmed_height,
            tx_position,
            TxHistoryInfo::Spending(SpendingInfo {
                txid,
                vin: txi_index as u32,
                prev_txid: full_hash(&txi.previous_output.txid[..]),
                prev_vout: txi.previous_output.vout,
                value: prev_value,
            }),
        );
        rows.push(history.into_row());

        let edge = TxEdgeRow::new(
            full_hash(&txi.previous_output.txid[..]),
            txi.previous_output.vout,
            txid,
            txi_index as u32,
        );
        rows.push(edge.into_row());
        #[cfg(not(feature = "liquid"))]
        rows.push(DBRow {
            key: super::qualified_edges::EdgeKey {
                script_hash: compute_script_hash(&prev_txo.script_pubkey),
                funding_txid: full_hash(&txi.previous_output.txid[..]),
                funding_vout: txi.previous_output.vout,
                spending_height: confirmed_height,
                spending_block_hash: _block_hash,
                spending_position: tx_position,
                spending_txid: txid,
                spending_vin: txi_index as u32,
            }
            .encode()
            .to_vec(),
            value: vec![],
        });
    }

    // Index issued assets & native asset pegins/pegouts/burns
    #[cfg(feature = "liquid")]
    asset::index_confirmed_tx_assets(
        tx,
        confirmed_height,
        tx_position,
        iconfig.network,
        iconfig.parent_network,
        rows,
        _op,
    );
}

fn addr_search_row(spk: &Script, network: Network) -> Option<DBRow> {
    spk.to_address_str(network).map(|address| DBRow {
        key: [b"a", address.as_bytes()].concat(),
        value: vec![],
    })
}

fn addr_search_filter(prefix: &str) -> Bytes {
    [b"a", prefix.as_bytes()].concat()
}

// TODO: replace by a separate opaque type (similar to Sha256dHash, but without the "double")
pub type FullHash = [u8; 32]; // serialized SHA256 result

pub fn compute_script_hash(script: &Script) -> FullHash {
    let mut hasher = Sha256::new();
    hasher.update(script.as_bytes());
    hasher.finalize()[..]
        .try_into()
        .expect("SHA256 size is 32 bytes")
}

pub fn parse_hash(hash: &FullHash) -> Sha256dHash {
    deserialize(hash).expect("failed to parse Sha256dHash")
}

#[derive(Serialize, Deserialize)]
struct TxRowKey {
    code: u8,
    txid: FullHash,
}

struct TxRow {
    key: TxRowKey,
    value: Bytes, // raw transaction
}

impl TxRow {
    fn new(txn: &Transaction) -> TxRow {
        let txid = full_hash(&txn.get_txid()[..]);
        TxRow {
            key: TxRowKey { code: b'T', txid },
            value: serialize(txn),
        }
    }

    fn key(prefix: &[u8]) -> Bytes {
        [b"T", prefix].concat()
    }

    fn into_row(self) -> DBRow {
        let TxRow { key, value } = self;
        DBRow {
            key: bincode_util::serialize_little(&key).unwrap(),
            value,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TxConfKey {
    code: u8,
    txid: FullHash,
    blockhash: FullHash,
}

struct TxConfRow {
    key: TxConfKey,
}

impl TxConfRow {
    fn new(txn: &Transaction, blockhash: FullHash) -> TxConfRow {
        let txid = full_hash(&txn.get_txid()[..]);
        TxConfRow {
            key: TxConfKey {
                code: b'C',
                txid,
                blockhash,
            },
        }
    }

    fn filter(prefix: &[u8]) -> Bytes {
        [b"C", prefix].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: vec![],
        }
    }

    fn from_row(row: DBRow) -> Self {
        TxConfRow {
            key: bincode_util::deserialize_little(&row.key).expect("failed to parse TxConfKey"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TxOutKey {
    code: u8,
    txid: FullHash,
    vout: u32,
}

struct TxOutRow {
    key: TxOutKey,
    value: Bytes, // serialized output
}

impl TxOutRow {
    fn new(txid: &FullHash, vout: usize, txout: &TxOut) -> TxOutRow {
        TxOutRow {
            key: TxOutKey {
                code: b'O',
                txid: *txid,
                vout: vout as u32,
            },
            value: serialize(txout),
        }
    }
    fn key(outpoint: &OutPoint) -> Bytes {
        bincode_util::serialize_little(&TxOutKey {
            code: b'O',
            txid: full_hash(&outpoint.txid[..]),
            vout: outpoint.vout,
        })
        .unwrap()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BlockKey {
    code: u8,
    hash: FullHash,
}

struct BlockRow {
    key: BlockKey,
    value: Bytes, // serialized output
}

impl BlockRow {
    fn new_header(block_entry: &BlockEntry) -> BlockRow {
        BlockRow {
            key: BlockKey {
                code: b'B',
                hash: full_hash(&block_entry.entry.hash()[..]),
            },
            value: serialize(&block_entry.block.header),
        }
    }

    fn new_txids(hash: FullHash, txids: &[Txid]) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'X', hash },
            value: bincode_util::serialize_little(txids).unwrap(),
        }
    }

    fn new_meta(hash: FullHash, meta: &BlockMeta) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'M', hash },
            value: bincode_util::serialize_little(meta).unwrap(),
        }
    }

    fn new_done(hash: FullHash) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'D', hash },
            value: vec![],
        }
    }

    fn header_filter() -> Bytes {
        b"B".to_vec()
    }

    fn txids_key(hash: FullHash) -> Bytes {
        [b"X", &hash[..]].concat()
    }

    fn meta_key(hash: FullHash) -> Bytes {
        [b"M", &hash[..]].concat()
    }

    fn done_filter() -> Bytes {
        b"D".to_vec()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }

    fn from_row(row: DBRow) -> Self {
        BlockRow {
            key: bincode_util::deserialize_little(&row.key).unwrap(),
            value: row.value,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct FundingInfo {
    pub txid: FullHash,
    pub vout: u32,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SpendingInfo {
    pub txid: FullHash, // spending transaction
    pub vin: u32,
    pub prev_txid: FullHash, // funding transaction
    pub prev_vout: u32,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum TxHistoryInfo {
    // If a spend and a fund for the same scripthash
    // occur in the same tx, spends should come first.
    // This ordering comes from the enum order.
    Spending(SpendingInfo),
    Funding(FundingInfo),

    #[cfg(feature = "liquid")]
    Issuing(asset::IssuingInfo),
    #[cfg(feature = "liquid")]
    Burning(asset::BurningInfo),
    #[cfg(feature = "liquid")]
    Pegin(peg::PeginInfo),
    #[cfg(feature = "liquid")]
    Pegout(peg::PegoutInfo),
}

impl TxHistoryInfo {
    pub fn get_txid(&self) -> Txid {
        match self {
            TxHistoryInfo::Funding(FundingInfo { txid, .. })
            | TxHistoryInfo::Spending(SpendingInfo { txid, .. }) => deserialize(txid),

            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(asset::IssuingInfo { txid, .. })
            | TxHistoryInfo::Burning(asset::BurningInfo { txid, .. })
            | TxHistoryInfo::Pegin(peg::PeginInfo { txid, .. })
            | TxHistoryInfo::Pegout(peg::PegoutInfo { txid, .. }) => deserialize(txid),
        }
        .expect("cannot parse Txid")
    }

    pub fn get_vin_or_vout(&self) -> u32 {
        match self {
            TxHistoryInfo::Funding(FundingInfo { vout: val, .. })
            | TxHistoryInfo::Spending(SpendingInfo { vin: val, .. }) => *val,

            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(asset::IssuingInfo { vin: val, .. })
            | TxHistoryInfo::Burning(asset::BurningInfo { vout: val, .. })
            | TxHistoryInfo::Pegin(peg::PeginInfo { vin: val, .. })
            | TxHistoryInfo::Pegout(peg::PegoutInfo { vout: val, .. }) => *val,
        }
    }

    pub fn has_vin(&self) -> bool {
        match self {
            TxHistoryInfo::Funding(_) => false,
            TxHistoryInfo::Spending(_) => true,

            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(_) | TxHistoryInfo::Pegin(_) => true,
            #[cfg(feature = "liquid")]
            TxHistoryInfo::Burning(_) | TxHistoryInfo::Pegout(_) => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct TxHistoryKey {
    pub code: u8,              // H for script history or I for asset history (elements only)
    pub hash: FullHash, // either a scripthash (always on bitcoin) or an asset id (elements only)
    pub confirmed_height: u32, // MUST be serialized as big-endian (for correct scans).
    pub tx_position: u16, // MUST be serialized as big-endian (for correct scans). Position in block.
    pub txinfo: TxHistoryInfo,
}

pub struct TxHistoryRow {
    pub key: TxHistoryKey,
}

impl TxHistoryRow {
    fn new(
        script: &Script,
        confirmed_height: u32,
        tx_position: u16,
        txinfo: TxHistoryInfo,
    ) -> Self {
        let key = TxHistoryKey {
            code: b'H',
            hash: compute_script_hash(script),
            confirmed_height,
            tx_position,
            txinfo,
        };
        TxHistoryRow { key }
    }

    fn filter(code: u8, hash_prefix: &[u8]) -> Bytes {
        [&[code], hash_prefix].concat()
    }

    fn prefix_end(code: u8, hash: &[u8]) -> Bytes {
        bincode_util::serialize_big(&(code, full_hash(hash), u32::MAX)).unwrap()
    }

    fn prefix_height(code: u8, hash: &[u8], height: u32) -> Bytes {
        bincode_util::serialize_big(&(code, full_hash(hash), height)).unwrap()
    }

    // prefix representing the end of a given block (used for reverse scans)
    fn prefix_height_end(code: u8, hash: &[u8], height: u32) -> Bytes {
        // u16::MAX for the tx_position ensures we get all transactions at this height
        bincode_util::serialize_big(&(code, full_hash(hash), height, u16::MAX)).unwrap()
    }

    pub fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_big(&self.key).unwrap(),
            value: vec![],
        }
    }

    pub fn from_row(row: DBRow) -> Self {
        let key =
            bincode_util::deserialize_big(&row.key).expect("failed to deserialize TxHistoryKey");
        TxHistoryRow { key }
    }

    pub fn get_txid(&self) -> Txid {
        self.key.txinfo.get_txid()
    }

    pub fn get_tx_position(&self) -> u16 {
        self.key.tx_position
    }

    fn get_funded_outpoint(&self) -> OutPoint {
        self.key.txinfo.get_funded_outpoint()
    }
}

impl TxHistoryInfo {
    // for funding rows, returns the funded output.
    // for spending rows, returns the spent previous output.
    pub fn get_funded_outpoint(&self) -> OutPoint {
        match self {
            TxHistoryInfo::Funding(ref info) => OutPoint {
                txid: deserialize(&info.txid).unwrap(),
                vout: info.vout,
            },
            TxHistoryInfo::Spending(ref info) => OutPoint {
                txid: deserialize(&info.prev_txid).unwrap(),
                vout: info.prev_vout,
            },
            #[cfg(feature = "liquid")]
            TxHistoryInfo::Issuing(_)
            | TxHistoryInfo::Burning(_)
            | TxHistoryInfo::Pegin(_)
            | TxHistoryInfo::Pegout(_) => unreachable!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxHistorySummary {
    txid: Txid,
    height: usize,
    value: i64,
    time: u32,
    tx_position: u16,
}

#[derive(Serialize, Deserialize)]
struct TxEdgeKey {
    code: u8,
    funding_txid: FullHash,
    funding_vout: u32,
    spending_txid: FullHash,
    spending_vin: u32,
}

struct TxEdgeRow {
    key: TxEdgeKey,
}

impl TxEdgeRow {
    fn new(
        funding_txid: FullHash,
        funding_vout: u32,
        spending_txid: FullHash,
        spending_vin: u32,
    ) -> Self {
        let key = TxEdgeKey {
            code: b'S',
            funding_txid,
            funding_vout,
            spending_txid,
            spending_vin,
        };
        TxEdgeRow { key }
    }

    fn filter(outpoint: &OutPoint) -> Bytes {
        // TODO build key without using bincode? [ b"S", &outpoint.txid[..], outpoint.vout?? ].concat()
        bincode_util::serialize_little(&(b'S', full_hash(&outpoint.txid[..]), outpoint.vout))
            .unwrap()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: vec![],
        }
    }

    fn from_row(row: DBRow) -> Self {
        TxEdgeRow {
            key: bincode_util::deserialize_little(&row.key)
                .expect("failed to deserialize TxEdgeKey"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ScriptCacheKey {
    code: u8,
    scripthash: FullHash,
}

struct StatsCacheRow {
    key: ScriptCacheKey,
    value: Bytes,
}

impl StatsCacheRow {
    fn new(scripthash: &[u8], stats: &ScriptStats, blockhash: &BlockHash) -> Self {
        StatsCacheRow {
            key: ScriptCacheKey {
                code: b'A',
                scripthash: full_hash(scripthash),
            },
            value: bincode_util::serialize_little(&(stats, blockhash)).unwrap(),
        }
    }

    pub fn key(scripthash: &[u8]) -> Bytes {
        [b"A", scripthash].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

type CachedUtxoMap = HashMap<(Txid, u32), (u32, Value)>; // (txid,vout) => (block_height,output_value)

struct UtxoCacheRow {
    key: ScriptCacheKey,
    value: Bytes,
}

impl UtxoCacheRow {
    fn new(scripthash: &[u8], utxos: &UtxoMap, blockhash: &BlockHash) -> Self {
        let utxos_cache = make_utxo_cache(utxos);

        UtxoCacheRow {
            key: ScriptCacheKey {
                code: b'U',
                scripthash: full_hash(scripthash),
            },
            value: bincode_util::serialize_little(&(utxos_cache, blockhash)).unwrap(),
        }
    }

    pub fn key(scripthash: &[u8]) -> Bytes {
        [b"U", scripthash].concat()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: bincode_util::serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }
}

// keep utxo cache with just the block height (the hash/timestamp are read later from the headers to reconstruct BlockId)
// and use a (txid,vout) tuple instead of OutPoints (they don't play nicely with bincode serialization)
fn make_utxo_cache(utxos: &UtxoMap) -> CachedUtxoMap {
    utxos
        .iter()
        .map(|(outpoint, (blockid, value))| {
            (
                (outpoint.txid, outpoint.vout),
                (blockid.height as u32, *value),
            )
        })
        .collect()
}

fn from_utxo_cache(utxos_cache: CachedUtxoMap, chain: &ChainQuery) -> UtxoMap {
    utxos_cache
        .into_iter()
        .map(|((txid, vout), (height, value))| {
            let outpoint = OutPoint { txid, vout };
            let blockid = chain
                .blockid_by_height(height as usize)
                .expect("missing blockheader for valid utxo cache entry");
            (outpoint, (blockid, value))
        })
        .collect()
}

#[cfg(all(test, feature = "liquid"))]
mod tests {
    use super::{DBRow, TxHistoryRow};
    use crate::chain::Value;
    use std::convert::{TryFrom, TryInto};

    #[test]
    fn tx_history_row_ser_deser_tests() {
        #[rustfmt::skip]
        let inputs = [
            vec![
                // code
                72,
                // hash
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                // confirmed_height
                0, 0, 0, 2,
                // tx_position
                0, 3,
                // TxHistoryInfo variant (Funding)
                0, 0, 0, 1,
                // FundingInfo
                // txid
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                // vout
                0, 0, 0, 3,
                // Value variant (Explicit)
                0, 0, 0, 0, 0, 0, 0, 2,
                // number of tuple elements
                1,
                // Inner value (u64)
                7, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 1,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                0, 0, 0, 3,
                // Value variant (Null)
                0, 0, 0, 0, 0, 0, 0, 1,
                // number of tuple elements
                0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 0,
                18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                0, 0, 0, 12,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                    98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                0, 0, 0, 9,
                0, 0, 0, 0, 0, 0, 0, 2,
                1,
                14, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                72,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                0, 0, 0, 2,
                0, 3,
                0, 0, 0, 0,
                18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
                0, 0, 0, 12,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                    98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                0, 0, 0, 9,
                0, 0, 0, 0, 0, 0, 0, 1,
                0,
            ],
        ];
        let expected = [
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Explicit(7),
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Funding(super::FundingInfo {
                        txid: [2; 32],
                        vout: 3,
                        value: Value::Null,
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Spending(super::SpendingInfo {
                        txid: [18; 32],
                        vin: 12,
                        prev_txid: "beef".repeat(8).as_bytes().try_into().unwrap(),
                        prev_vout: 9,
                        value: Value::Explicit(14),
                    }),
                },
            },
            super::TxHistoryRow {
                key: super::TxHistoryKey {
                    code: b'H',
                    hash: [1; 32],
                    confirmed_height: 2,
                    tx_position: 3,
                    txinfo: super::TxHistoryInfo::Spending(super::SpendingInfo {
                        txid: [18; 32],
                        vin: 12,
                        prev_txid: "beef".repeat(8).as_bytes().try_into().unwrap(),
                        prev_vout: 9,
                        value: Value::Null,
                    }),
                },
            },
        ];
        for (expected_row, input) in
            IntoIterator::into_iter(expected).zip(IntoIterator::into_iter(inputs))
        {
            let input_row = DBRow {
                key: input,
                value: vec![],
            };
            assert_eq!(TxHistoryRow::from_row(input_row).key, expected_row.key);
        }

        #[rustfmt::skip]
        assert_eq!(
            TxHistoryRow::prefix_height(b'H', "beef".repeat(8).as_bytes(), 1337),
            vec![
                // code
                72,
                // hash
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102, 98, 101, 101, 102,
                // height
                0, 0, 5, 57
            ]
        );
    }
}

#[cfg(test)]
mod cache_invalidation_layout_tests {
    use super::*;
    #[test]
    fn actual_history_serialization_matches_old_script_and_asset_callback_keys() {
        #[cfg(feature = "liquid")]
        let value = Value::Explicit(1);
        #[cfg(not(feature = "liquid"))]
        let value = 1;
        for code in [b'H', b'I'] {
            let row = TxHistoryRow {
                key: TxHistoryKey {
                    code,
                    hash: [7; 32],
                    confirmed_height: 42,
                    tx_position: 3,
                    txinfo: TxHistoryInfo::Funding(FundingInfo {
                        txid: [9; 32],
                        vout: 2,
                        value,
                    }),
                },
            }
            .into_row();
            assert_eq!(row.key[0], code);
            assert_eq!(&row.key[1..33], &[7; 32]);
            let keys =
                super::super::db::history_cache_keys(&row.key, cfg!(feature = "liquid")).unwrap();
            if code == b'I' && !cfg!(feature = "liquid") {
                assert!(keys.is_empty());
                continue;
            }
            assert_eq!(keys[0], StatsCacheRow::key(&[7; 32]));
            assert_eq!(keys[1], UtxoCacheRow::key(&[7; 32]));
            #[cfg(feature = "liquid")]
            assert_eq!(keys[2], [b"z", &[7; 32][..]].concat());
        }
    }
}

#[cfg(all(test, not(feature = "liquid")))]
mod supplemental_edge_writer_tests {
    use super::*;
    #[test]
    fn actual_history_batch_contains_block_qualified_edges_and_keeps_ancestor_key_on_orphan_delete()
    {
        let point = OutPoint {
            txid: deserialize(&[3u8; 32]).unwrap(),
            vout: 0,
        };
        let previous = TxOut {
            value: bitcoin::Amount::from_sat(5),
            script_pubkey: Script::new(),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: point,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(4),
                script_pubkey: Script::new(),
            }],
        };
        let config = IndexerConfig {
            light_mode: false,
            address_search: false,
            index_unspendables: false,
            network: Network::Regtest,
        };
        let prevouts = HashMap::from([(point, previous)]);
        let mut ancestor = vec![];
        let mut orphan = vec![];
        index_transaction(
            &tx,
            10,
            2,
            [7; 32],
            &prevouts,
            &mut ancestor,
            &config,
            &Operation::AddBlocks,
        );
        index_transaction(
            &tx,
            20,
            3,
            [8; 32],
            &prevouts,
            &mut orphan,
            &config,
            &Operation::DeleteBlocks,
        );
        let edge = |rows: &[DBRow]| {
            rows.iter()
                .find_map(|row| super::super::qualified_edges::EdgeKey::decode(&row.key).ok())
                .unwrap()
        };
        let ancestor_edge = edge(&ancestor);
        let orphan_edge = edge(&orphan);
        let amounts = ancestor
            .iter()
            .filter(|row| row.key.first() == Some(&b'H'))
            .map(|row| {
                let history: TxHistoryKey = bincode_util::deserialize_big(&row.key).unwrap();
                match history.txinfo {
                    TxHistoryInfo::Funding(info) => (false, info.value),
                    TxHistoryInfo::Spending(info) => (true, info.value),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(amounts, vec![(false, 4), (true, 5)]);
        assert_eq!(ancestor_edge.funding_txid, full_hash(&point.txid[..]));
        assert_eq!(ancestor_edge.spending_txid, full_hash(&tx.get_txid()[..]));
        assert_eq!(ancestor_edge.spending_block_hash, [7; 32]);
        assert_eq!(orphan_edge.spending_block_hash, [8; 32]);
        assert_eq!(ancestor_edge.spending_position, 2);
        assert_ne!(ancestor_edge.encode(), orphan_edge.encode());
        assert!(ancestor.iter().any(|row| row.key.first() == Some(&b'H')));
        assert_eq!(
            ancestor
                .iter()
                .find(|row| row.key.first() == Some(&b'S'))
                .unwrap()
                .key,
            orphan
                .iter()
                .find(|row| row.key.first() == Some(&b'S'))
                .unwrap()
                .key
        );
        let deleted: HashSet<_> = orphan
            .into_iter()
            .filter(|row| row.key.first() != Some(&b'S'))
            .map(|row| row.key)
            .collect();
        assert!(deleted.contains(&orphan_edge.encode().to_vec()));
        assert!(!deleted.contains(&ancestor_edge.encode().to_vec()));
        assert!(!deleted.iter().any(|key| key.first() == Some(&b'S')));
    }
}
