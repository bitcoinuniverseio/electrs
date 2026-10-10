use rayon::prelude::*;

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, Decodable};
#[cfg(feature = "liquid")]
use elements::encode::{deserialize, Decodable};

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use crate::chain::{Block, BlockHash};
use crate::daemon::Daemon;
use crate::errors::*;
use crate::util::{spawn_thread, HeaderEntry, SyncChannel};

#[derive(Clone, Copy, Debug)]
pub enum FetchFrom {
    Bitcoind,
    BlkFiles,
}

pub fn start_fetcher(
    from: FetchFrom,
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    let fetcher = match from {
        FetchFrom::Bitcoind => bitcoind_fetcher,
        FetchFrom::BlkFiles => blkfiles_fetcher,
    };
    fetcher(daemon, new_headers)
}

pub struct BlockEntry {
    pub block: Block,
    pub entry: HeaderEntry,
    pub size: u32,
}

type SizedBlock = (Block, u32);

// Reorg fetching keeps only the current existing 100-header batch. Fetch and
// writer errors stop the next RPC; no thread or second producer is introduced.
pub struct SequentialFetcher<T> {
    fetcher: Box<dyn FnMut() -> Result<Option<Vec<T>>>>,
}

impl<T> SequentialFetcher<T> {
    fn from<F: FnMut() -> Result<Option<Vec<T>>> + 'static>(func: F) -> Self {
        Self {
            fetcher: Box::new(func),
        }
    }

    pub fn map<F>(mut self, mut func: F) -> Result<()>
    where
        F: FnMut(Vec<T>) -> Result<()>,
    {
        while let Some(batch) = (self.fetcher)()? {
            func(batch)?;
        }
        Ok(())
    }
}

pub fn bitcoind_sequential_fetcher(
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
) -> Result<SequentialFetcher<BlockEntry>> {
    let daemon = daemon.reconnect()?;
    let mut offset = 0;
    Ok(SequentialFetcher::from(move || {
        if offset == new_headers.len() {
            return Ok(None);
        }
        let end = (offset + 100).min(new_headers.len());
        let entries = &new_headers[offset..end];
        let hashes: Vec<BlockHash> = entries.iter().map(|e| *e.hash()).collect();
        let blocks = daemon.getblocks(&hashes)?;
        if blocks.len() != entries.len() {
            return Err("incomplete bitcoind block batch".into());
        }
        let batch = blocks
            .into_iter()
            .zip(entries)
            .map(|(block, entry)| BlockEntry {
                entry: entry.clone(),
                size: block.size() as u32,
                block,
            })
            .collect();
        offset = end;
        Ok(Some(batch))
    }))
}

pub struct Fetcher<T> {
    receiver: crossbeam_channel::Receiver<T>,
    thread: thread::JoinHandle<Result<()>>,
    cancelled: Arc<AtomicBool>,
}

impl<T> Fetcher<T> {
    fn from(
        receiver: crossbeam_channel::Receiver<T>,
        thread: thread::JoinHandle<Result<()>>,
    ) -> Self {
        Self::from_cancellable(receiver, thread, Arc::new(AtomicBool::new(false)))
    }

    fn from_cancellable(
        receiver: crossbeam_channel::Receiver<T>,
        thread: thread::JoinHandle<Result<()>>,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Fetcher {
            receiver,
            thread,
            cancelled,
        }
    }

    pub fn map<F>(self, mut func: F) -> Result<()>
    where
        F: FnMut(T) -> Result<()>,
    {
        let Self {
            receiver,
            thread,
            cancelled,
        } = self;
        // Drop the receiver even on callback panic, so a blocked owned producer
        // can finish. Join before returning or unwinding; never detach work.
        let consumed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for item in receiver.iter() {
                func(item)?;
            }
            Ok(())
        }));
        cancelled.store(true, Ordering::Release);
        drop(receiver);
        let produced = thread.join();
        match consumed {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(Err(err)) => Err(err),
            Ok(Ok(())) => match produced {
                Ok(result) => result,
                Err(_) => Err("fetcher thread panicked".into()),
            },
        }
    }
}

fn bitcoind_fetcher(
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    if let Some(tip) = new_headers.last() {
        debug!("{:?} ({} left to index)", tip, new_headers.len());
    };
    let daemon = daemon.reconnect()?;
    let chan = SyncChannel::new(1);
    let sender = chan.sender();
    let cancelled = Arc::new(AtomicBool::new(false));
    let producer_cancelled = Arc::clone(&cancelled);
    Ok(Fetcher::from_cancellable(
        chan.into_receiver(),
        spawn_thread("bitcoind_fetcher", move || {
            for entries in new_headers.chunks(100) {
                if producer_cancelled.load(Ordering::Acquire) {
                    return Err("block consumer stopped".into());
                }
                let blockhashes: Vec<BlockHash> = entries.iter().map(|e| *e.hash()).collect();
                let blocks = daemon.getblocks(&blockhashes)?;
                if blocks.len() != entries.len() {
                    return Err("incomplete bitcoind block batch".into());
                }
                let block_entries: Vec<BlockEntry> = blocks
                    .into_iter()
                    .zip(entries)
                    .map(|(block, entry)| BlockEntry {
                        entry: entry.clone(), // TODO: remove this clone()
                        size: block.size() as u32,
                        block,
                    })
                    .collect();
                assert_eq!(block_entries.len(), entries.len());
                sender
                    .send(block_entries)
                    .map_err(|_| Error::from("block consumer stopped"))?;
            }
            Ok(())
        }),
        cancelled,
    ))
}

fn blkfiles_fetcher(
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    let magic = daemon.magic();
    let blk_files = daemon.list_blk_files()?;

    let chan = SyncChannel::new(1);
    let sender = chan.sender();

    let mut entry_map: HashMap<BlockHash, HeaderEntry> =
        new_headers.into_iter().map(|h| (*h.hash(), h)).collect();

    let parser = blkfiles_parser(blkfiles_reader(blk_files), magic);
    Ok(Fetcher::from(
        chan.into_receiver(),
        spawn_thread("blkfiles_fetcher", move || {
            parser.map(|sizedblocks| {
                let block_entries: Vec<BlockEntry> = sizedblocks
                    .into_iter()
                    .filter_map(|(block, size)| {
                        let blockhash = block.block_hash();
                        entry_map
                            .remove(&blockhash)
                            .map(|entry| BlockEntry { block, entry, size })
                            .or_else(|| {
                                trace!("skipping block {}", blockhash);
                                None
                            })
                    })
                    .collect();
                trace!("fetched {} blocks", block_entries.len());
                sender
                    .send(block_entries)
                    .map_err(|_| Error::from("block consumer stopped"))
            })?;
            if !entry_map.is_empty() {
                return Err(format!(
                    "failed to index {} blocks from blk*.dat files",
                    entry_map.len()
                )
                .into());
            }
            Ok(())
        }),
    ))
}

fn blkfiles_reader(blk_files: Vec<PathBuf>) -> Fetcher<Vec<u8>> {
    let chan = SyncChannel::new(1);
    let sender = chan.sender();
    let xor_key = blk_files.first().and_then(|p| {
        let xor_file = p
            .parent()
            .expect("blk.dat files must exist in a directory")
            .join("xor.dat");
        if xor_file.exists() {
            Some(fs::read(xor_file).expect("xor.dat exists"))
        } else {
            None
        }
    });

    Fetcher::from(
        chan.into_receiver(),
        spawn_thread("blkfiles_reader", move || {
            for path in blk_files {
                trace!("reading {:?}", path);
                let mut blob = fs::read(&path).chain_err(|| "failed to read blk*.dat file")?;

                // If the xor.dat exists. Use it to decrypt the block files.
                if let Some(xor_key) = &xor_key {
                    for (&key, byte) in xor_key.iter().cycle().zip(blob.iter_mut()) {
                        *byte ^= key;
                    }
                }

                sender
                    .send(blob)
                    .map_err(|_| Error::from("block parser stopped"))?;
            }
            Ok(())
        }),
    )
}

fn blkfiles_parser(blobs: Fetcher<Vec<u8>>, magic: u32) -> Fetcher<Vec<SizedBlock>> {
    let chan = SyncChannel::new(1);
    let sender = chan.sender();

    Fetcher::from(
        chan.into_receiver(),
        spawn_thread("blkfiles_parser", move || {
            blobs.map(|blob| {
                trace!("parsing {} bytes", blob.len());
                let blocks = parse_blocks(blob, magic)?;
                sender
                    .send(blocks)
                    .map_err(|_| Error::from("block consumer stopped"))
            })
        }),
    )
}

fn parse_blocks(blob: Vec<u8>, magic: u32) -> Result<Vec<SizedBlock>> {
    let mut cursor = Cursor::new(&blob);
    let mut slices = vec![];
    let max_pos = blob.len() as u64;

    while cursor.position() < max_pos {
        let offset = cursor.position();
        match u32::consensus_decode(&mut cursor) {
            Ok(value) => {
                if magic != value {
                    cursor.set_position(offset + 1);
                    continue;
                }
            }
            Err(_) => break, // EOF
        };
        let block_size = u32::consensus_decode(&mut cursor).chain_err(|| "no block size")?;
        let start = cursor.position();
        let end = start + block_size as u64;

        // If Core's WriteBlockToDisk ftell fails, only the magic bytes and size will be written
        // and the block body won't be written to the blk*.dat file.
        // Since the first 4 bytes should contain the block's version, we can skip such blocks
        // by peeking the cursor (and skipping previous `magic` and `block_size`).
        match u32::consensus_decode(&mut cursor) {
            Ok(value) => {
                if magic == value {
                    cursor.set_position(start);
                    continue;
                }
            }
            Err(_) => break, // EOF
        }
        slices.push((&blob[start as usize..end as usize], block_size));
        cursor.set_position(end);
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(0) // CPU-bound
        .thread_name(|i| format!("parse-blocks-{}", i))
        .build()
        .unwrap();
    Ok(pool.install(|| {
        slices
            .into_par_iter()
            .map(|(slice, size)| (deserialize(slice).expect("failed to parse Block"), size))
            .collect()
    }))
}

#[cfg(test)]
mod owned_fetch_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn sequential_fetch_and_write_interleave_without_prefetching() {
        let progress = Arc::new(AtomicUsize::new(0));
        let fetched = Arc::clone(&progress);
        let mut next = 0;
        let fetcher = SequentialFetcher::from(move || {
            assert_eq!(fetched.load(Ordering::SeqCst), next);
            if next == 3 {
                return Ok(None);
            }
            next += 1;
            Ok(Some(vec![next; 100]))
        });
        fetcher
            .map(|batch| {
                assert_eq!(batch.len(), 100);
                progress.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert_eq!(progress.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn sequential_writer_failure_stops_next_fetch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let fetcher = SequentialFetcher::from(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(vec![1]))
        });
        assert!(fetcher.map(|_| Err("delete failed".into())).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sequential_rpc_failure_never_calls_writer() {
        let fetcher = SequentialFetcher::<u8>::from(|| Err("RPC failed".into()));
        assert!(fetcher.map(|_| panic!("writer must not run")).is_err());
    }

    #[test]
    fn consumer_failure_unblocks_and_joins_producer_preserving_original_error() {
        let (sender, receiver) = crossbeam_channel::bounded(0);
        let complete = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&complete);
        let cancelled = Arc::new(AtomicBool::new(false));
        let producer_cancelled = Arc::clone(&cancelled);
        let producer = thread::spawn(move || {
            sender.send(1).unwrap();
            assert!(sender.send(2).is_err());
            assert!(producer_cancelled.load(Ordering::Acquire));
            observed.store(1, Ordering::SeqCst);
            Err("producer observed cancellation".into())
        });
        let error = Fetcher::from_cancellable(receiver, producer, cancelled)
            .map(|_| Err("delete failed".into()))
            .unwrap_err();
        assert_eq!(error.to_string(), "delete failed");
        assert_eq!(complete.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn consumer_panic_still_joins_owned_work_before_unwind() {
        let (sender, receiver) = crossbeam_channel::bounded(0);
        let complete = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&complete);
        let producer = thread::spawn(move || {
            sender.send(1).unwrap();
            assert!(sender.send(2).is_err());
            observed.store(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Fetcher::from(receiver, producer).map(|_| panic!("consumer panic"))
        }))
        .is_err());
        assert_eq!(complete.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn producer_error_and_panic_are_not_successful_eof() {
        let (sender, receiver) = crossbeam_channel::bounded::<u8>(1);
        drop(sender);
        let producer = thread::spawn(|| Err("RPC failed".into()));
        assert_eq!(
            Fetcher::from(receiver, producer)
                .map(|_| Ok(()))
                .unwrap_err()
                .to_string(),
            "RPC failed"
        );
        let (sender, receiver) = crossbeam_channel::bounded::<u8>(1);
        drop(sender);
        let producer = thread::spawn(|| panic!("producer panic"));
        assert!(Fetcher::from(receiver, producer).map(|_| Ok(())).is_err());
    }

    #[test]
    fn nested_parser_failure_joins_upstream_reader() {
        let (raw_sender, raw_receiver) = crossbeam_channel::bounded(0);
        let done = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&done);
        let raw = thread::spawn(move || {
            raw_sender.send(1).unwrap();
            assert!(raw_sender.send(2).is_err());
            observed.store(1, Ordering::SeqCst);
            Ok(())
        });
        let (sender, receiver) = crossbeam_channel::bounded::<u8>(0);
        let parser = thread::spawn(move || {
            let result = Fetcher::from(raw_receiver, raw).map(|_| Err("parse failed".into()));
            drop(sender);
            result
        });
        assert!(Fetcher::from(receiver, parser).map(|_| Ok(())).is_err());
        assert_eq!(done.load(Ordering::SeqCst), 1);
    }
}
