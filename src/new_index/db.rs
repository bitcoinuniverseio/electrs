use rocksdb;

use std::path::Path;

use crate::config::Config;
use crate::util::{bincode_util, Bytes};

/// Each version will break any running instance with a DB that has a differing version.
/// It will also break if light mode is enabled or disabled.
// 1 = Original DB (since fork from Blockstream)
// 2 = Add tx position to TxHistory rows and place Spending before Funding
pub(crate) const DB_VERSION: u32 = 2;

#[derive(Debug, Eq, PartialEq)]
pub struct DBRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct ScanIterator<'a> {
    prefix: Vec<u8>,
    iter: rocksdb::DBIterator<'a>,
    done: bool,
}

impl Iterator for ScanIterator<'_> {
    type Item = DBRow;

    fn next(&mut self) -> Option<DBRow> {
        if self.done {
            return None;
        }
        let (key, value) = self.iter.next().map(Result::ok)??;
        if !key.starts_with(&self.prefix) {
            self.done = true;
            return None;
        }
        Some(DBRow {
            key: key.to_vec(),
            value: value.to_vec(),
        })
    }
}

pub struct ReverseScanIterator<'a> {
    prefix: Vec<u8>,
    iter: rocksdb::DBRawIterator<'a>,
    done: bool,
}

impl Iterator for ReverseScanIterator<'_> {
    type Item = DBRow;

    fn next(&mut self) -> Option<DBRow> {
        if self.done || !self.iter.valid() {
            return None;
        }

        let key = self.iter.key().unwrap();
        if !key.starts_with(&self.prefix) {
            self.done = true;
            return None;
        }

        let row = DBRow {
            key: key.into(),
            value: self.iter.value().unwrap().into(),
        };

        self.iter.prev();

        Some(row)
    }
}

pub struct ReverseScanGroupIterator<'a> {
    iters: Vec<ReverseScanIterator<'a>>,
    next_rows: Vec<Option<DBRow>>,
    value_offset: usize,
    done: bool,
}

impl<'a> ReverseScanGroupIterator<'a> {
    pub fn new(
        mut iters: Vec<ReverseScanIterator<'a>>,
        value_offset: usize,
    ) -> ReverseScanGroupIterator<'a> {
        let mut next_rows: Vec<Option<DBRow>> = Vec::with_capacity(iters.len());
        for iter in &mut iters {
            let next = iter.next();
            next_rows.push(next);
        }
        let done = next_rows.iter().all(|row| row.is_none());
        ReverseScanGroupIterator {
            iters,
            next_rows,
            value_offset,
            done,
        }
    }
}

impl Iterator for ReverseScanGroupIterator<'_> {
    type Item = DBRow;

    fn next(&mut self) -> Option<DBRow> {
        if self.done {
            return None;
        }

        let best_index = self
            .next_rows
            .iter()
            .enumerate()
            .max_by(|(a_index, a_opt), (b_index, b_opt)| match (a_opt, b_opt) {
                (None, None) => a_index.cmp(b_index),

                (Some(_), None) => std::cmp::Ordering::Greater,

                (None, Some(_)) => std::cmp::Ordering::Less,

                (Some(a), Some(b)) => a.key[self.value_offset..].cmp(&(b.key[self.value_offset..])),
            })
            .map(|(index, _)| index)
            .unwrap_or(0);

        let best = self.next_rows[best_index].take();
        self.next_rows[best_index] = self.iters.get_mut(best_index)?.next();
        if self.next_rows.iter().all(|row| row.is_none()) {
            self.done = true;
        }

        best
    }
}

#[derive(Debug)]
pub struct DB {
    db: rocksdb::DB,
}

/// Error-preserving snapshots used only by the new bounded read lane.
#[cfg(not(feature = "liquid"))]
pub struct BoundedSnapshot<'a> {
    snapshot: rocksdb::Snapshot<'a>,
}
#[cfg(not(feature = "liquid"))]
impl BoundedSnapshot<'_> {
    pub fn point_value(
        &self,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<Bytes>, super::paged_outputs::PageError> {
        use super::paged_outputs::PageError;
        let value = self
            .snapshot
            .get_pinned(key)
            .map_err(|_| PageError::Storage)?;
        match value {
            Some(value) if value.len() <= maximum => Ok(Some(value.to_vec())),
            Some(_) => Err(PageError::Capacity),
            None => Ok(None),
        }
    }
    pub fn next_record(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<DBRow>, super::paged_outputs::PageError> {
        use super::paged_outputs::{PageError, KEY_LIMIT};
        if prefix.is_empty() || prefix.len() > KEY_LIMIT {
            return Err(PageError::Contract);
        }
        let start = match after {
            Some(key) => {
                if key.len() > KEY_LIMIT || !key.starts_with(prefix) {
                    return Err(PageError::Contract);
                }
                // Exact exclusive full-key seek. This also preserves descendants
                // of a shorter key; there is no height+skip scan.
                let mut next = key.to_vec();
                next.push(0);
                next
            }
            None => prefix.to_vec(),
        };
        // A fresh raw iterator performs ONLY this bounded exact seek. Using
        // DBIterator::next would advance after returning a row and could hide
        // an advancement error when the per-record iterator is then dropped.
        let mut iter = self.snapshot.raw_iterator();
        iter.seek(&start);
        iter.status().map_err(|_| PageError::Storage)?;
        if !iter.valid() {
            return Ok(None);
        }
        let key = iter.key().ok_or(PageError::Storage)?;
        let value = iter.value().ok_or(PageError::Storage)?;
        if !key.starts_with(prefix) {
            return Ok(None);
        }
        if key.len() > KEY_LIMIT || !value.is_empty() {
            return Err(PageError::Contract);
        }
        let row = DBRow {
            key: key.to_vec(),
            value: value.to_vec(),
        };
        iter.status().map_err(|_| PageError::Storage)?;
        Ok(Some(row))
    }
}

#[derive(Copy, Clone, Debug)]
pub enum DBFlush {
    Disable,
    Enable,
}

impl DB {
    pub(crate) fn open_proof_read_only(path: &Path) -> crate::errors::Result<Self> {
        use crate::errors::ResultExt;
        let options = rocksdb::Options::default();
        Ok(Self {
            db: rocksdb::DB::open_for_read_only(&options, path, false)
                .chain_err(|| "local proof store unavailable")?,
        })
    }
    pub fn open(path: &Path, config: &Config) -> DB {
        let db = DB {
            db: open_raw_db(path, OpenMode::ReadWrite),
        };
        db.verify_compatibility(config);
        db
    }

    #[cfg(not(feature = "liquid"))]
    pub fn bounded_snapshot(&self) -> BoundedSnapshot<'_> {
        BoundedSnapshot {
            snapshot: self.db.snapshot(),
        }
    }

    pub fn full_compaction(&self) {
        // TODO: make sure this doesn't fail silently
        debug!("starting full compaction on {:?}", self.db);
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        debug!("finished full compaction on {:?}", self.db);
    }

    pub fn enable_auto_compaction(&self) {
        let opts = [("disable_auto_compactions", "false")];
        self.db.set_options(&opts).unwrap();
    }

    pub fn raw_iterator(&self) -> rocksdb::DBRawIterator<'_> {
        self.db.raw_iterator()
    }

    pub fn iter_scan(&self, prefix: &[u8]) -> ScanIterator<'_> {
        ScanIterator {
            prefix: prefix.to_vec(),
            iter: self.db.prefix_iterator(prefix),
            done: false,
        }
    }

    pub fn iter_scan_from(&self, prefix: &[u8], start_at: &[u8]) -> ScanIterator<'_> {
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            start_at,
            rocksdb::Direction::Forward,
        ));
        ScanIterator {
            prefix: prefix.to_vec(),
            iter,
            done: false,
        }
    }

    pub fn iter_scan_reverse(&self, prefix: &[u8], prefix_max: &[u8]) -> ReverseScanIterator<'_> {
        let mut iter = self.db.raw_iterator();
        iter.seek_for_prev(prefix_max);

        ReverseScanIterator {
            prefix: prefix.to_vec(),
            iter,
            done: false,
        }
    }

    pub fn iter_scan_group_reverse(
        &self,
        prefixes: impl Iterator<Item = (Vec<u8>, Vec<u8>)>,
        value_offset: usize,
    ) -> ReverseScanGroupIterator<'_> {
        let iters = prefixes
            .map(|(prefix, prefix_max)| {
                let mut iter = self.db.raw_iterator();
                iter.seek_for_prev(prefix_max);
                ReverseScanIterator {
                    prefix: prefix.to_vec(),
                    iter,
                    done: false,
                }
            })
            .collect();
        ReverseScanGroupIterator::new(iters, value_offset)
    }

    pub fn write(&self, mut rows: Vec<DBRow>, flush: DBFlush) {
        debug!(
            "writing {} rows to {:?}, flush={:?}",
            rows.len(),
            self.db,
            flush
        );
        rows.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let mut batch = rocksdb::WriteBatch::default();
        for row in rows {
            batch.put(&row.key, &row.value);
        }
        let do_flush = match flush {
            DBFlush::Enable => true,
            DBFlush::Disable => false,
        };
        let mut opts = rocksdb::WriteOptions::new();
        opts.set_sync(do_flush);
        opts.disable_wal(!do_flush);
        self.db.write_opt(batch, &opts).unwrap();
    }

    // One atomic batch: a failed deletion must not leave a partially removed
    // block while callers advance their in-memory or persisted markers.
    pub fn delete(&self, keys: Vec<Vec<u8>>) -> crate::errors::Result<()> {
        use crate::errors::ResultExt;
        debug!("deleting {} DB rows", keys.len());
        let mut batch = rocksdb::WriteBatch::default();
        for key in keys {
            batch.delete(key);
        }
        self.db
            .write(batch)
            .chain_err(|| "failed to delete DB batch")
    }

    pub(crate) fn next_empty_record(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> crate::errors::Result<Option<DBRow>> {
        use crate::errors::ResultExt;
        if prefix.is_empty()
            || prefix.len() > 256
            || after.map_or(false, |key| key.len() > 256 || !key.starts_with(prefix))
        {
            return Err("invalid exact scan cursor".into());
        }
        let mut start = after.unwrap_or(prefix).to_vec();
        if after.is_some() {
            start.push(0);
        }
        let mut iterator = self.db.raw_iterator();
        iterator.seek(&start);
        iterator.status().chain_err(|| "confirmation scan failed")?;
        if !iterator.valid() {
            return Ok(None);
        }
        let key = iterator.key().ok_or("confirmation scan missing key")?;
        if !key.starts_with(prefix) {
            return Ok(None);
        }
        let value = iterator.value().ok_or("confirmation scan missing value")?;
        if key.len() > 256 || !value.is_empty() {
            return Err("malformed confirmation record".into());
        }
        let row = DBRow {
            key: key.to_vec(),
            value: vec![],
        };
        iterator.status().chain_err(|| "confirmation scan failed")?;
        Ok(Some(row))
    }
    /// Supplemental proof/progress writes use the existing DB owner, with a
    /// single sync/WAL-enabled atomic batch. Errors never advance progress.
    pub(crate) fn write_coverage(&self, rows: Vec<DBRow>) -> crate::errors::Result<()> {
        use crate::errors::ResultExt;
        let mut batch = rocksdb::WriteBatch::default();
        for row in rows {
            batch.put(row.key, row.value);
        }
        let mut options = rocksdb::WriteOptions::new();
        options.set_sync(true);
        self.db
            .write_opt(batch, &options)
            .chain_err(|| "coverage batch write failed")
    }
    pub fn flush(&self) {
        self.db.flush().unwrap();
    }

    pub fn put(&self, key: &[u8], value: &[u8]) {
        self.db.put(key, value).unwrap();
    }

    pub fn put_sync(&self, key: &[u8], value: &[u8]) {
        let mut opts = rocksdb::WriteOptions::new();
        opts.set_sync(true);
        self.db.put_opt(key, value, &opts).unwrap();
    }

    /// Added qualification-only point read: no unwrap/panic and no unbounded
    /// value copy. Preserve every original getter and its legacy error policy.
    pub fn qualified_get(
        &self,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<Bytes>, super::qualification::QualifiedReadError> {
        use super::qualification::QualifiedReadError;
        let value = self
            .db
            .get_pinned(key)
            .map_err(|_| QualifiedReadError::Storage)?;
        match value {
            Some(bytes) if bytes.len() <= maximum => Ok(Some(bytes.to_vec())),
            Some(_) => Err(QualifiedReadError::Contract),
            None => Ok(None),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.db.get(key).unwrap().map(|v| v.to_vec())
    }

    fn verify_compatibility(&self, config: &Config) {
        let mut compatibility_bytes = bincode_util::serialize_little(&DB_VERSION).unwrap();

        if config.light_mode {
            // append a byte to indicate light_mode is enabled.
            // we're not letting bincode serialize this so that the compatiblity bytes won't change
            // (and require a reindex) when light_mode is disabled. this should be chagned the next
            // time we bump DB_VERSION and require a re-index anyway.
            compatibility_bytes.push(1);
        }

        match self.get(b"V") {
            None => self.put(b"V", &compatibility_bytes),
            Some(ref x) if x != &compatibility_bytes => {
                panic!("Incompatible database found. Please reindex.")
            }
            Some(_) => (),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

pub fn open_raw_db<T: rocksdb::ThreadMode>(
    path: &Path,
    read_mode: OpenMode,
) -> rocksdb::DBWithThreadMode<T> {
    debug!("opening DB at {:?}", path);
    let mut db_opts = rocksdb::Options::default();
    db_opts.create_if_missing(true);
    db_opts.set_max_open_files(100_000); // TODO: make sure to `ulimit -n` this process correctly
    db_opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
    db_opts.set_compression_type(rocksdb::DBCompressionType::None);
    db_opts.set_target_file_size_base(1_073_741_824);
    db_opts.set_write_buffer_size(256 << 20);
    db_opts.set_disable_auto_compactions(true); // for initial bulk load

    // db_opts.set_advise_random_on_open(???);
    db_opts.set_compaction_readahead_size(1 << 20);
    db_opts.increase_parallelism(2);

    // let mut block_opts = rocksdb::BlockBasedOptions::default();
    // block_opts.set_block_size(???);

    match read_mode {
        OpenMode::ReadOnly => {
            rocksdb::DBWithThreadMode::<T>::open_for_read_only(&db_opts, path, false)
                .expect("failed to open RocksDB (READ ONLY)")
        }
        OpenMode::ReadWrite => {
            rocksdb::DBWithThreadMode::<T>::open(&db_opts, path).expect("failed to open RocksDB")
        }
    }
}

// Sole-writer cache invalidation, bounded independently of reorg length and
// duplicate script/asset occurrences. No channel, set, new DB owner or scan.
pub(crate) const CACHE_DELETE_KEYS: usize = 500;
pub(crate) fn delete_cache_chunks<K, E>(
    keys: impl IntoIterator<Item = Result<K, E>>,
    mut apply: impl FnMut(Vec<K>) -> Result<(), E>,
) -> Result<(), E> {
    let mut chunk = Vec::with_capacity(CACHE_DELETE_KEYS);
    for key in keys {
        chunk.push(key?);
        if chunk.len() == CACHE_DELETE_KEYS {
            apply(std::mem::replace(
                &mut chunk,
                Vec::with_capacity(CACHE_DELETE_KEYS),
            ))?;
        }
    }
    if !chunk.is_empty() {
        apply(chunk)?;
    }
    Ok(())
}

// TxHistoryKey's existing fixed-array big-endian serialization starts with
// code:u8, hash:[u8;32]. H script and Liquid I asset hashes shared the exact
// former callback. A/U/z key construction is unchanged, including duplicates.
pub(crate) fn history_cache_keys(key: &[u8], liquid: bool) -> Result<Vec<Vec<u8>>, &'static str> {
    if key.first() != Some(&b'H') && !(liquid && key.first() == Some(&b'I')) {
        return Ok(vec![]);
    }
    let hash = key.get(1..33).ok_or("malformed history cache hash")?;
    let mut keys = vec![[b"A", hash].concat(), [b"U", hash].concat()];
    if liquid {
        keys.push([b"z", hash].concat());
    } else {
        keys.push([&[0xff, b'U', b'A', 2][..], hash].concat());
        keys.push([&[0xff, b'U', b'U', 2][..], hash].concat());
    }
    Ok(keys)
}

#[cfg(test)]
mod bounded_cache_delete_tests {
    use super::{delete_cache_chunks, history_cache_keys, CACHE_DELETE_KEYS};
    #[test]
    fn exact_bitcoin_and_liquid_callback_hashes_preserved() {
        for code in [b'H', b'I'] {
            let history = [&[code][..], &[7; 32][..], &[9; 64][..]].concat();
            for liquid in [false, true] {
                let keys = history_cache_keys(&history, liquid).unwrap();
                if code == b'I' && !liquid {
                    assert!(keys.is_empty());
                    continue;
                }
                let prefixes = if liquid {
                    vec![b'A', b'U', b'z']
                } else {
                    vec![b'A', b'U']
                };
                let mut expected = prefixes
                    .into_iter()
                    .map(|prefix| [&[prefix][..], &[7; 32][..]].concat())
                    .collect::<Vec<_>>();
                if !liquid {
                    expected.push([&[0xff, b'U', b'A', 2][..], &[7; 32][..]].concat());
                    expected.push([&[0xff, b'U', b'U', 2][..], &[7; 32][..]].concat());
                }
                assert_eq!(keys, expected);
            }
        }
        for code in [b'D', b'S', b'a', b'i'] {
            assert!(history_cache_keys(&[code; 33], true).unwrap().is_empty());
        }
        assert!(history_cache_keys(b"H", false).is_err());
        assert!(history_cache_keys(b"I", true).is_err());
    }
    #[test]
    fn dense_duplicates_stream_exactly_without_reorg_wide_retention() {
        let mut visits = 0;
        let mut applied = vec![];
        let keys = (0..1501).map(|index| {
            visits += 1;
            Ok::<_, ()>(index % 7)
        });
        delete_cache_chunks(keys, |keys| {
            assert!(keys.len() <= CACHE_DELETE_KEYS);
            applied.extend(keys);
            Ok(())
        })
        .unwrap();
        assert_eq!(visits, 1501);
        assert_eq!(
            applied,
            (0..1501).map(|index| index % 7).collect::<Vec<_>>()
        );
    }
    #[test]
    fn failed_chunk_stops_iteration_and_exact_replay_can_finish() {
        use std::cell::Cell;
        let visits = Cell::new(0);
        let mut calls = vec![];
        let result = delete_cache_chunks(
            (0..1501).map(|index| {
                visits.set(visits.get() + 1);
                Ok(index)
            }),
            |keys| {
                calls.push(keys);
                if calls.len() == 2 {
                    Err("cache delete failed")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err("cache delete failed"));
        assert_eq!(visits.get(), 1000);
        assert_eq!(calls[0], (0..500).collect::<Vec<_>>());
        assert_eq!(calls[1], (500..1000).collect::<Vec<_>>());
        let mut replay = vec![];
        delete_cache_chunks((0..1501).map(Ok::<_, ()>), |keys| {
            replay.extend(keys);
            Ok(())
        })
        .unwrap();
        assert_eq!(replay, (0..1501).collect::<Vec<_>>());
    }
    #[test]
    fn malformed_key_or_empty_input_never_advances_later_work() {
        let mut calls = 0;
        assert!(delete_cache_chunks([Ok(1), Err("malformed"), Ok(2)], |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
        delete_cache_chunks(std::iter::empty::<Result<u8, ()>>(), |_| {
            panic!("empty cannot dispatch")
        })
        .unwrap();
    }
}

#[cfg(test)]
mod atomic_delete_tests {
    use super::*;

    #[test]
    fn deletion_batch_removes_all_requested_keys_and_preserves_others() {
        let directory = tempfile::tempdir().unwrap();
        let db = DB {
            db: rocksdb::DB::open_default(directory.path()).unwrap(),
        };
        for key in [b"a", b"b", b"t"] {
            db.db.put(key, b"value").unwrap();
        }
        db.delete(vec![b"a".to_vec(), b"b".to_vec()]).unwrap();
        assert!(db.db.get(b"a").unwrap().is_none());
        assert!(db.db.get(b"b").unwrap().is_none());
        assert_eq!(db.db.get(b"t").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn failed_readonly_batch_is_error_and_preserves_every_row_and_tip() {
        let directory = tempfile::tempdir().unwrap();
        {
            let db = rocksdb::DB::open_default(directory.path()).unwrap();
            for key in [b"a", b"b", b"t"] {
                db.put(key, b"value").unwrap();
            }
        }
        let db = DB {
            db: rocksdb::DB::open_for_read_only(
                &rocksdb::Options::default(),
                directory.path(),
                false,
            )
            .unwrap(),
        };
        assert!(db
            .delete(vec![b"a".to_vec(), b"b".to_vec(), b"t".to_vec()])
            .is_err());
        for key in [b"a", b"b", b"t"] {
            assert_eq!(db.db.get(key).unwrap(), Some(b"value".to_vec()));
        }
    }
}
