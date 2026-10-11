pub mod db;
mod fetch;
#[cfg(not(feature = "liquid"))]
pub mod history_coverage;
mod mempool;
#[cfg(not(feature = "liquid"))]
pub mod page_http;
#[cfg(not(feature = "liquid"))]
pub mod paged_outputs;
pub mod precache;
#[cfg(not(feature = "liquid"))]
pub mod proof_rows;
pub mod qualification;
pub mod qualified_edges;
mod query;
#[cfg(not(feature = "liquid"))]
pub mod read_context;
pub mod read_generation;
pub mod schema;
mod writer_update;

use std::sync::LazyLock;

pub(crate) static THREAD_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(0) // 0 = use number of logical CPUs
        .thread_name(|i| format!("electrs-worker-{}", i))
        .build()
        .expect("failed to create global rayon thread pool")
});

pub use self::db::{DBRow, DB};
pub use self::fetch::{BlockEntry, FetchFrom};
pub use self::mempool::Mempool;
pub use self::query::Query;
pub use self::schema::{
    compute_script_hash, parse_hash, ChainQuery, FundingInfo, Indexer, ScriptStats, SpendingInfo,
    SpendingInput, Store, TxHistoryInfo, TxHistoryKey, TxHistoryRow, Utxo,
};
