use rayon::prelude::*;

use std::collections::{BTreeSet, HashMap};
#[cfg(not(feature = "liquid"))]
use std::convert::TryFrom;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use crate::chain::{Network, OutPoint, Transaction, TxOut, Txid};
use crate::config::Config;
use crate::daemon::{Daemon, MempoolAcceptResult, SubmitPackageResult};
use crate::errors::*;
use crate::new_index::{ChainQuery, Mempool, ScriptStats, SpendingInput, Utxo};
use crate::util::{is_spendable, BlockId, Bytes, TransactionStatus};

#[cfg(feature = "liquid")]
use crate::{
    chain::{asset::AssetRegistryLock, AssetId},
    elements::{lookup_asset, AssetRegistry, AssetSorting, LiquidAsset},
};

const FEE_ESTIMATES_TTL: u64 = 60; // seconds

const CONF_TARGETS: [u16; 28] = [
    1u16, 2u16, 3u16, 4u16, 5u16, 6u16, 7u16, 8u16, 9u16, 10u16, 11u16, 12u16, 13u16, 14u16, 15u16,
    16u16, 17u16, 18u16, 19u16, 20u16, 21u16, 22u16, 23u16, 24u16, 25u16, 144u16, 504u16, 1008u16,
];

pub struct Query {
    chain: Arc<ChainQuery>, // TODO: should be used as read-only
    mempool: Arc<RwLock<Mempool>>,
    daemon: Arc<Daemon>,
    config: Arc<Config>,
    cached_estimates: RwLock<(HashMap<u16, f64>, Option<Instant>)>,
    cached_relayfee: RwLock<Option<f64>>,
    #[cfg(not(feature = "liquid"))]
    page_readers: super::page_http::ReaderBudget,
    #[cfg(not(feature = "liquid"))]
    page_codec: Option<super::page_http::CursorCodec>,
    #[cfg(feature = "liquid")]
    asset_db: Option<Arc<RwLock<AssetRegistry>>>,
}

#[cfg(not(feature = "liquid"))]
struct PagedQuerySnapshot<'a> {
    query: &'a Query,
    chain: super::schema::PagedChainSnapshot<'a>,
    scope: super::paged_outputs::ReadScope,
    script_hash: super::schema::FullHash,
}
#[cfg(not(feature = "liquid"))]
impl super::paged_outputs::PageSource for PagedQuerySnapshot<'_> {
    fn operation_work(&self, operation: super::paged_outputs::ReadOperation) -> usize {
        self.chain.operation_work(operation)
    }
    fn valid(
        &self,
        scope: &super::paged_outputs::ReadScope,
    ) -> Result<(), super::paged_outputs::PageError> {
        use super::paged_outputs::PageError;
        if scope != &self.scope {
            return Err(PageError::Contract);
        }
        self.chain.valid()?;
        let mempool = self
            .query
            .mempool
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        if mempool.paged_read_epoch() != Some((scope.chain_generation, scope.mempool_generation)) {
            return Err(PageError::Changed);
        }
        Ok(())
    }
    fn history(
        &self,
        after: Option<&[u8]>,
    ) -> Result<Option<super::paged_outputs::HistoryRecord>, super::paged_outputs::PageError> {
        self.chain.history(after)
    }
    fn confirmation(
        &self,
        txid: &Txid,
        after: Option<&[u8]>,
    ) -> Result<Option<super::paged_outputs::ConfirmationRecord>, super::paged_outputs::PageError>
    {
        self.chain.confirmation(txid, after)
    }
    fn spend(
        &self,
        point: &OutPoint,
        after: Option<&[u8]>,
    ) -> Result<Option<super::paged_outputs::SpendRecord>, super::paged_outputs::PageError> {
        self.chain.spend(point, after)
    }
    fn mempool_spent(&self, point: &OutPoint) -> Result<bool, super::paged_outputs::PageError> {
        use super::paged_outputs::PageError;
        let mempool = self
            .query
            .mempool
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        if mempool.paged_read_epoch()
            != Some((self.scope.chain_generation, self.scope.mempool_generation))
        {
            return Err(PageError::Changed);
        }
        Ok(mempool.paged_has_spend(point))
    }
    fn mempool(
        &self,
        offset: usize,
    ) -> Result<Option<super::paged_outputs::MempoolRecord>, super::paged_outputs::PageError> {
        use super::paged_outputs::PageError;
        let mempool = self
            .query
            .mempool
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        if mempool.paged_read_epoch()
            != Some((self.scope.chain_generation, self.scope.mempool_generation))
        {
            return Err(PageError::Changed);
        }
        mempool.paged_history_record(&self.script_hash, offset)
    }
}

impl Query {
    #[cfg(not(feature = "liquid"))]
    pub fn new(
        chain: Arc<ChainQuery>,
        mempool: Arc<RwLock<Mempool>>,
        daemon: Arc<Daemon>,
        config: Arc<Config>,
    ) -> Self {
        Query {
            chain,
            mempool,
            daemon,
            config,
            cached_estimates: RwLock::new((HashMap::new(), None)),
            cached_relayfee: RwLock::new(None),
            page_readers: super::page_http::ReaderBudget::new(),
            page_codec: option_env!("ELECTRS_SOURCE_REVISION")
                .and_then(|_| super::page_http::CursorCodec::new_os()),
        }
    }

    pub fn chain(&self) -> &ChainQuery {
        &self.chain
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn network(&self) -> Network {
        self.config.network_type
    }

    pub fn mempool(&self) -> RwLockReadGuard<'_, Mempool> {
        self.mempool.read().unwrap()
    }

    pub fn broadcast_raw(&self, txhex: &str) -> Result<Txid> {
        let txid = self.daemon.broadcast_raw(txhex)?;
        // The important part is whether we succeeded in broadcasting.
        // Ignore errors in adding to the cache and show an internal warning.
        if let Err(e) = self
            .mempool
            .write()
            .unwrap()
            .add_by_txid(&self.daemon, &txid)
        {
            warn!(
                "broadcast_raw of {txid} succeeded to broadcast \
                but failed to add to mempool-electrs Mempool cache: {e}"
            );
        }
        Ok(txid)
    }

    pub fn test_mempool_accept(
        &self,
        txhex: Vec<String>,
        maxfeerate: Option<f64>,
    ) -> Result<Vec<MempoolAcceptResult>> {
        self.daemon.test_mempool_accept(txhex, maxfeerate)
    }

    pub fn submit_package(
        &self,
        txhex: Vec<String>,
        maxfeerate: Option<f64>,
        maxburnamount: Option<f64>,
    ) -> Result<SubmitPackageResult> {
        self.daemon.submit_package(txhex, maxfeerate, maxburnamount)
    }

    /// New opt-in bounded lane; independent of legacy utxo/vector/cache calls.
    #[cfg(not(feature = "liquid"))]
    pub(crate) fn paged_outputs(
        &self,
        script_hash: super::schema::FullHash,
        cursor: Option<&super::paged_outputs::PageCursor>,
        expected: &super::page_http::ExpectedScope,
        deadline: Instant,
    ) -> Result<
        (
            super::paged_outputs::OutputPage,
            super::paged_outputs::PageCursor,
        ),
        super::paged_outputs::PageError,
    > {
        use super::paged_outputs::{PageCursor, PageError, PageSource, ReadScope};
        use sha2::{Digest, Sha256};
        // Full immutable build stamp is required only by this new lane.
        let revision = option_env!("ELECTRS_SOURCE_REVISION").ok_or(PageError::Unavailable)?;
        let (chain_generation, tip, genesis) = self.chain.paged_read_context()?;
        let mempool_generation = {
            let mempool = self
                .mempool
                .try_read()
                .map_err(|_| PageError::Unavailable)?;
            let (chain, mempool) = mempool.paged_read_epoch().ok_or(PageError::Unavailable)?;
            if chain != chain_generation {
                return Err(PageError::Changed);
            }
            mempool
        };
        let network = match self.network() {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        };
        let bootstrap = self
            .daemon
            .paged_bootstrap_observation()
            .filter(|value| value.validate(network))
            .ok_or(PageError::Unavailable)?
            .clone();
        // Binding hashes static read-affecting configuration, excluding cookie
        // and credentials. It is a profile binding, not a source observation.
        let profile = super::read_context::StaticReadProfile {
            network: network.into(),
            magic: self.config.magic,
            db_path: self.config.db_path.to_string_lossy().into_owned(),
            rpc_address: self.config.daemon_rpc_addr.to_string(),
            light_mode: self.config.light_mode,
            index_unspendables: self.config.index_unspendables,
            db_version: super::db::DB_VERSION,
            electrs_version: crate::config::ELECTRS_VERSION.into(),
            electrum_discovery: cfg!(feature = "electrum-discovery"),
            work_limit: super::paged_outputs::WORK_LIMIT,
            body_limit: super::paged_outputs::BODY_LIMIT,
            history_proof_dir: self
                .config
                .history_proof_dir
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        }
        .bytes(&bootstrap)
        .map_err(|_| PageError::Contract)?;
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };
        let scope = ReadScope {
            source_authority: "mempool-electrs".into(),
            chain: "bitcoin".into(),
            network: network.into(),
            bootstrap,
            genesis_hash: genesis.to_string(),
            artifact_revision: revision.into(),
            profile_sha256: hex(&Sha256::digest(&profile)),
            script_hash: hex(&script_hash),
            chain_generation,
            mempool_generation,
            height: u32::try_from(tip.height).map_err(|_| PageError::Contract)?,
            block_hash: tip.hash.to_string(),
        };
        scope.validate()?;
        if !expected.matches(&scope) {
            return Err(PageError::Changed);
        }
        let initial = PageCursor::initial(scope.clone());
        let state = cursor.unwrap_or(&initial);
        if state.scope != scope {
            return Err(PageError::Changed);
        }
        state.validate()?;
        let source = PagedQuerySnapshot {
            query: self,
            chain: self.chain.paged_snapshot(script_hash, chain_generation)?,
            scope,
            script_hash,
        };
        source.valid(&state.scope)?;
        super::paged_outputs::read_page_until(&source, state, deadline)
    }

    #[cfg(not(feature = "liquid"))]
    pub fn paged_wire_response(
        &self,
        script_hash: super::schema::FullHash,
        request: &super::page_http::PageRequest,
    ) -> Result<Vec<u8>, super::paged_outputs::PageError> {
        use super::paged_outputs::{PageError, BODY_LIMIT};
        // Synchronous owner keeps lease through all actual IO, serialization and
        // final fences. Client disconnect/deadline cannot release it early.
        let _lease = self.page_readers.acquire()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let codec = self.page_codec.as_ref().ok_or(PageError::Unavailable)?;
        let cursor = request
            .cursor
            .as_ref()
            .map(|value| codec.decode(value))
            .transpose()?;
        let (page, next) =
            self.paged_outputs(script_hash, cursor.as_ref(), &request.expected, deadline)?;
        let token = if next.complete {
            None
        } else {
            Some(codec.encode(&next)?)
        };
        let bytes=serde_json::to_vec(&serde_json::json!({"page":page,"cursor":token,
            "created_unix_seconds":next.created_unix_seconds,"expires_unix_seconds":next.expires_unix_seconds}))
            .map_err(|_|PageError::Contract)?;
        if bytes.len() > BODY_LIMIT {
            return Err(PageError::Capacity);
        }
        let (epoch, tip, genesis) = self.chain.paged_read_context()?;
        if epoch != next.scope.chain_generation
            || tip.height as u64 != next.scope.height as u64
            || tip.hash.to_string() != next.scope.block_hash
            || genesis.to_string() != next.scope.genesis_hash
        {
            return Err(PageError::Changed);
        }
        let mempool = self
            .mempool
            .try_read()
            .map_err(|_| PageError::Unavailable)?;
        if mempool.paged_read_epoch()
            != Some((next.scope.chain_generation, next.scope.mempool_generation))
        {
            return Err(PageError::Changed);
        }
        if Instant::now() >= deadline {
            return Err(PageError::Deadline);
        }
        Ok(bytes)
    }

    pub fn utxo(&self, scripthash: &[u8]) -> Result<Vec<Utxo>> {
        let mut utxos = self.chain.utxo(
            scripthash,
            self.config.utxos_limit,
            super::db::DBFlush::Enable,
        )?;
        let mempool = self.mempool();
        utxos.retain(|utxo| !mempool.has_spend(&OutPoint::from(utxo)));
        utxos.extend(mempool.utxo(scripthash));
        Ok(utxos)
    }

    pub fn history_txids(&self, scripthash: &[u8], limit: usize) -> Vec<(Txid, Option<BlockId>)> {
        let confirmed_txids = self.chain.history_txids(scripthash, limit);
        let confirmed_len = confirmed_txids.len();
        let confirmed_txids = confirmed_txids.into_iter().map(|(tx, b)| (tx, Some(b)));

        let mempool_txids = self
            .mempool()
            .history_txids(scripthash, limit - confirmed_len)
            .into_iter()
            .map(|tx| (tx, None));

        confirmed_txids.chain(mempool_txids).collect()
    }

    pub fn stats(&self, scripthash: &[u8]) -> Result<(ScriptStats, ScriptStats)> {
        Ok((
            self.chain.stats(scripthash, super::db::DBFlush::Enable)?,
            self.mempool().stats(scripthash),
        ))
    }

    pub fn lookup_txn(&self, txid: &Txid) -> Option<Transaction> {
        self.chain
            .lookup_txn(txid, None)
            .or_else(|| self.mempool().lookup_txn(txid))
    }
    pub fn lookup_raw_txn(&self, txid: &Txid) -> Option<Bytes> {
        self.chain
            .lookup_raw_txn(txid, None)
            .or_else(|| self.mempool().lookup_raw_txn(txid))
    }

    /// Not all OutPoints from mempool transactions are guaranteed to be included in the result
    pub fn lookup_txos(&self, outpoints: &BTreeSet<OutPoint>) -> HashMap<OutPoint, TxOut> {
        // the mempool lookup_txos() internally looks up confirmed txos as well
        self.mempool().lookup_txos(outpoints)
    }

    pub fn lookup_spend(&self, outpoint: &OutPoint) -> Result<Option<SpendingInput>> {
        Ok(self
            .chain
            .lookup_spend(outpoint)?
            .or_else(|| self.mempool().lookup_spend(outpoint)))
    }

    pub fn lookup_tx_spends(&self, tx: Transaction) -> Result<Vec<Option<SpendingInput>>> {
        let txid = tx.txid();
        #[cfg(not(feature = "liquid"))]
        let budget = super::qualified_edges::ReadBudget::new();

        tx.output
            .par_iter()
            .enumerate()
            .map(|(vout, txout)| {
                if is_spendable(txout) {
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    #[cfg(feature = "liquid")]
                    {
                        self.lookup_spend(&outpoint)
                    }
                    #[cfg(not(feature = "liquid"))]
                    {
                        Ok(self
                            .chain
                            .lookup_spend_with_budget(&outpoint, &budget)?
                            .or_else(|| self.mempool().lookup_spend(&outpoint)))
                    }
                } else {
                    Ok(None)
                }
            })
            .collect()
    }

    pub fn get_tx_status(&self, txid: &Txid) -> TransactionStatus {
        TransactionStatus::from(self.chain.tx_confirming_block(txid))
    }

    pub fn get_mempool_tx_fee(&self, txid: &Txid) -> Option<u64> {
        self.mempool().get_tx_fee(txid)
    }

    pub fn has_unconfirmed_parents(&self, txid: &Txid) -> bool {
        self.mempool().has_unconfirmed_parents(txid)
    }

    pub fn estimate_fee(&self, conf_target: u16) -> Option<f64> {
        if self.config.network_type.is_regtest() {
            return self.get_relayfee().ok();
        }
        if let (ref cache, Some(cache_time)) = *self.cached_estimates.read().unwrap() {
            if cache_time.elapsed() < Duration::from_secs(FEE_ESTIMATES_TTL) {
                return cache.get(&conf_target).copied();
            }
        }

        self.update_fee_estimates();
        self.cached_estimates
            .read()
            .unwrap()
            .0
            .get(&conf_target)
            .copied()
    }

    pub fn estimate_fee_map(&self) -> HashMap<u16, f64> {
        if let (ref cache, Some(cache_time)) = *self.cached_estimates.read().unwrap() {
            if cache_time.elapsed() < Duration::from_secs(FEE_ESTIMATES_TTL) {
                return cache.clone();
            }
        }

        self.update_fee_estimates();
        self.cached_estimates.read().unwrap().0.clone()
    }

    fn update_fee_estimates(&self) {
        match self.daemon.estimatesmartfee_batch(&CONF_TARGETS) {
            Ok(estimates) => {
                *self.cached_estimates.write().unwrap() = (estimates, Some(Instant::now()));
            }
            Err(err) => {
                warn!("failed estimating feerates: {:?}", err);
            }
        }
    }

    pub fn get_relayfee(&self) -> Result<f64> {
        if let Some(cached) = *self.cached_relayfee.read().unwrap() {
            return Ok(cached);
        }

        let relayfee = self.daemon.get_relayfee()?;
        self.cached_relayfee.write().unwrap().replace(relayfee);
        Ok(relayfee)
    }

    #[cfg(feature = "liquid")]
    pub fn new(
        chain: Arc<ChainQuery>,
        mempool: Arc<RwLock<Mempool>>,
        daemon: Arc<Daemon>,
        config: Arc<Config>,
        asset_db: Option<Arc<RwLock<AssetRegistry>>>,
    ) -> Self {
        Query {
            chain,
            mempool,
            daemon,
            config,
            asset_db,
            cached_estimates: RwLock::new((HashMap::new(), None)),
            cached_relayfee: RwLock::new(None),
        }
    }

    #[cfg(feature = "liquid")]
    pub fn lookup_asset(&self, asset_id: &AssetId) -> Result<Option<LiquidAsset>> {
        lookup_asset(
            self,
            self.asset_db.as_ref().map(AssetRegistryLock::RwLock),
            asset_id,
            None,
        )
    }

    #[cfg(feature = "liquid")]
    pub fn list_registry_assets(
        &self,
        start_index: usize,
        limit: usize,
        sorting: AssetSorting,
    ) -> Result<(usize, Vec<LiquidAsset>)> {
        let asset_db = match &self.asset_db {
            None => return Ok((0, vec![])),
            Some(db) => db.read().unwrap(),
        };
        let (total_num, results) = asset_db.list(start_index, limit, sorting);
        // Attach on-chain information alongside the registry metadata
        let results = results
            .into_iter()
            .map(|(asset_id, metadata)| {
                lookup_asset(
                    self,
                    Some(AssetRegistryLock::RwLockReadGuard(&asset_db)),
                    asset_id,
                    Some(metadata),
                )?
                .chain_err(|| "missing registered asset")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((total_num, results))
    }
}
