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
