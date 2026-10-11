#[cfg(feature = "liquid")]
fn main() {
    eprintln!("Local Bitcoin proof ingestion is unavailable in a Liquid build");
    std::process::exit(2);
}

#[cfg(not(feature = "liquid"))]
mod bitcoin_proof {
    use electrs::new_index::proof_rows::{decode_chunk, CHUNK_BYTES, HEADER_BYTES};
    use rocksdb::{Options, WriteBatch, WriteOptions, DB};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    const STATE: &[u8] = b"\xffPRF1";
    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    struct Progress {
        profile_sha256: String,
        next_chunk: u64,
        rows: u64,
        rolling_sha256: String,
        last_payload_sha256: String,
    }
    fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
        let metadata = fs::symlink_metadata(path).map_err(|_| "Proof input unavailable")?;
        if !metadata.is_file() || metadata.len() > maximum as u64 {
            return Err("Invalid proof input bounds".into());
        }
        let mut file = File::open(path).map_err(|_| "Proof input unavailable")?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "Proof input read failed")?;
        if bytes.len() != metadata.len() as usize {
            return Err("Proof input changed".into());
        }
        Ok(bytes)
    }
    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.len() != 3 {
            return Err(
                "Usage: history-proof-ingest PROOF_DIRECTORY PROFILE_SHA256 CHUNK_NUMBER".into(),
            );
        }
        let root = PathBuf::from(&args[0]);
        if !root.is_absolute()
            || fs::canonicalize(&root).map_err(|_| "Proof directory unavailable")? != root
        {
            return Err("Proof directory must be an explicit real absolute path".into());
        }
        let expected = hex::decode(&args[1]).map_err(|_| "Invalid proof profile hash")?;
        if expected.len() != 32 || args[1] != hex::encode(&expected) {
            return Err("Invalid proof profile hash".into());
        }
        let sealing = args[2] == "seal";
        let index: u64 = if sealing {
            0
        } else {
            args[2].parse().map_err(|_| "Invalid chunk number")?
        };
        if index > 99_999_999 {
            return Err("Chunk number exceeds fixed bound".into());
        }
        for name in ["chunks", "txstore"] {
            let path = root.join(name);
            if path.exists()
                && (!fs::symlink_metadata(&path)
                    .map_err(|_| "Proof path unavailable")?
                    .is_dir()
                    || fs::canonicalize(&path).map_err(|_| "Proof path unavailable")? != path)
            {
                return Err("Proof child directories must remain real owned paths".into());
            }
        }
        let manifest = bounded_file(&root.join("proof-job.json"), 65536)?;
        if Sha256::digest(&manifest).as_slice() != expected {
            return Err("Proof profile changed".into());
        }
        let profile: serde_json::Value =
            serde_json::from_slice(&manifest).map_err(|_| "Invalid proof profile")?;
        if profile["schemaVersion"] != "universe-local-history-proof-job-v1"
            || profile["network"] != "signet"
            || profile["genesis"]
                != "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
            || profile["rowSchema"] != "electrs-TXM-v2"
        {
            return Err("Proof profile identity is unavailable".into());
        }
        let challenge_text = profile["signetChallenge"]
            .as_str()
            .ok_or("Exact Signet challenge unavailable")?;
        let challenge = hex::decode(challenge_text).map_err(|_| "Invalid Signet challenge")?;
        if challenge.is_empty()
            || challenge.len() > 10000
            || hex::encode(&challenge) != challenge_text
            || hex::encode(Sha256::digest(&challenge))
                != profile["signetChallengeSha256"]
                    .as_str()
                    .ok_or("Signet challenge commitment unavailable")?
            || profile["pruned"] != false
            || profile["initialBlockDownload"] != false
            || profile["coreHeaders"].as_u64() != profile["targetHeight"].as_u64()
            || profile["targetHeight"].as_u64().is_none()
        {
            return Err("Complete independently captured source identity is unavailable".into());
        }
        if sealing {
            let ownership: serde_json::Value =
                serde_json::from_slice(&bounded_file(&root.join("proof-writer.json"), 4096)?)
                    .map_err(|_| "Invalid proof writer identity")?;
            if ownership["role"] != "auxiliary-TXM-only" || ownership["profileSha256"] != args[1] {
                return Err("Proof writer identity changed".into());
            }
            let generated: serde_json::Value = serde_json::from_slice(&bounded_file(
                &root.join("generation-complete.json"),
                16384,
            )?)
            .map_err(|_| "Invalid generation completion")?;
            if generated["profileSha256"] != args[1]
                || generated["phase"] != "rows-complete"
                || generated["bodyHeight"].as_u64()
                    != profile["targetHeight"]
                        .as_u64()
                        .and_then(|h| h.checked_add(1))
            {
                return Err("Incomplete auxiliary generation cannot be sealed".into());
            }
            let mut options = Options::default();
            options.set_max_open_files(64);
            options.set_max_background_jobs(2);
            let db = DB::open(&options, root.join("txstore"))
                .map_err(|_| "Auxiliary sealing owner unavailable")?;
            if db
                .get(b"V")
                .map_err(|_| "Proof storage read failed")?
                .is_some()
            {
                return Err("Refuse canonical index storage".into());
            }
            let bytes = db
                .get(STATE)
                .map_err(|_| "Proof storage read failed")?
                .ok_or("Missing auxiliary progress")?;
            let progress: Progress =
                serde_json::from_slice(&bytes).map_err(|_| "Invalid auxiliary progress")?;
            if progress.profile_sha256 != args[1]
                || Some(progress.next_chunk) != generated["chunks"].as_u64()
                || Some(progress.rows) != generated["rows"].as_u64()
                || Some(progress.rolling_sha256.as_str()) != generated["rolling"].as_str()
            {
                return Err("Auxiliary row ingestion is incomplete".into());
            }
            db.flush_wal(true)
                .map_err(|_| "Proof WAL persistence failed")?;
            db.flush().map_err(|_| "Proof table persistence failed")?;
            drop(db);
            let receipt = serde_json::json!({"schemaVersion":"universe-local-history-proof-sealed-v1","profileSha256":args[1],
                "targetHeight":profile["targetHeight"],"targetHash":profile["targetHash"],"chunks":progress.next_chunk,
                "rows":progress.rows,"rollingSha256":progress.rolling_sha256,"writerClosed":true,"readQualificationGranted":false});
            let path = root.join("proof-sealed.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| "Existing seal preserved")?;
            file.write_all(
                serde_json::to_vec(&receipt)
                    .map_err(|_| "Seal encoding failed")?
                    .as_slice(),
            )
            .map_err(|_| "Seal write failed")?;
            file.sync_all().map_err(|_| "Seal persistence failed")?;
            File::open(&root)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "Seal directory persistence failed")?;
            println!("{}", receipt);
            return Ok(());
        }
        if root.join("proof-sealed.json").exists() {
            return Err("Sealed auxiliary generation is immutable".into());
        }
        let path = root.join("chunks").join(format!("{:08}.row", index));
        let bytes = bounded_file(&path, HEADER_BYTES + CHUNK_BYTES)?;
        let chunk = decode_chunk(&bytes)?;
        if chunk.profile.as_slice() != expected || chunk.index != index {
            return Err("Chunk identity changed".into());
        }
        let ownership = root.join("proof-writer.json");
        if ownership.exists() {
            let value: serde_json::Value = serde_json::from_slice(&bounded_file(&ownership, 4096)?)
                .map_err(|_| "Invalid proof writer identity")?;
            if value["role"] != "auxiliary-TXM-only" || value["profileSha256"] != args[1] {
                return Err("Proof writer identity changed".into());
            }
        } else {
            let store = root.join("txstore");
            if store.exists()
                && fs::read_dir(&store)
                    .map_err(|_| "Proof directory unavailable")?
                    .next()
                    .is_some()
            {
                return Err("Refuse unowned existing storage before database open".into());
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&ownership)
                .map_err(|_| "Proof writer identity already claimed")?;
            file.write_all(
                serde_json::to_vec(
                    &serde_json::json!({"role":"auxiliary-TXM-only","profileSha256":args[1]}),
                )
                .map_err(|_| "Proof identity encoding failed")?
                .as_slice(),
            )
            .map_err(|_| "Proof identity write failed")?;
            file.sync_all()
                .map_err(|_| "Proof identity persistence failed")?;
            File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "Proof directory persistence failed")?;
        }
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_write_buffer_size(8 * 1024 * 1024);
        options.set_max_write_buffer_number(2);
        options.set_max_background_jobs(2);
        options.set_max_open_files(64);
        options.set_use_fsync(true);
        let db = DB::open(&options, root.join("txstore"))
            .map_err(|_| "Auxiliary proof writer is unavailable")?;
        if db
            .get(b"V")
            .map_err(|_| "Proof storage read failed")?
            .is_some()
        {
            return Err("Refuse canonical index storage".into());
        }
        let prior = db.get(STATE).map_err(|_| "Proof storage read failed")?;
        let mut progress: Progress = match prior {
            Some(value) => serde_json::from_slice(&value).map_err(|_| "Invalid proof progress")?,
            None => {
                if db.iterator(rocksdb::IteratorMode::Start).next().is_some() {
                    return Err("Unowned nonempty proof database".into());
                }
                Progress {
                    profile_sha256: args[1].clone(),
                    next_chunk: 0,
                    rows: 0,
                    rolling_sha256: "00".repeat(32),
                    last_payload_sha256: String::new(),
                }
            }
        };
        if progress.profile_sha256 != args[1] {
            return Err("Proof progress profile changed".into());
        }
        if index.checked_add(1) == Some(progress.next_chunk)
            && progress.last_payload_sha256 == hex::encode(chunk.digest)
        {
            println!(
                "{}",
                serde_json::json!({"status":"already-imported","nextChunk":progress.next_chunk,"ready":false})
            );
            return Ok(());
        }
        if index != progress.next_chunk {
            return Err("Proof chunks must be ingested sequentially".into());
        }
        let mut batch = WriteBatch::default();
        let mut pending: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for (key, value) in &chunk.rows {
            let existing = pending
                .get(key)
                .cloned()
                .or(db.get(key).map_err(|_| "Proof storage read failed")?);
            if let Some(old) = existing {
                if old != *value {
                    return Err("Conflicting proof occurrence; original evidence preserved".into());
                }
            }
            batch.put(key, value);
            pending.insert(key.clone(), value.clone());
        }
        let mut rolling =
            hex::decode(&progress.rolling_sha256).map_err(|_| "Invalid proof progress")?;
        if rolling.len() != 32 {
            return Err("Invalid proof progress".into());
        }
        rolling.extend(index.to_le_bytes());
        rolling.extend(chunk.digest);
        progress.rolling_sha256 = hex::encode(Sha256::digest(&rolling));
        progress.last_payload_sha256 = hex::encode(chunk.digest);
        progress.next_chunk = progress
            .next_chunk
            .checked_add(1)
            .ok_or("Proof progress overflow")?;
        progress.rows = progress
            .rows
            .checked_add(chunk.rows.len() as u64)
            .ok_or("Proof progress overflow")?;
        batch.put(
            STATE,
            serde_json::to_vec(&progress).map_err(|_| "Proof progress encoding failed")?,
        );
        let mut write = WriteOptions::default();
        write.set_sync(true);
        db.write_opt(batch, &write)
            .map_err(|_| "Proof chunk commit failed; resume requires exact progress readback")?;
        db.flush_wal(true)
            .map_err(|_| "Proof WAL persistence failed")?;
        drop(db);
        println!(
            "{}",
            serde_json::json!({"status":"imported","nextChunk":progress.next_chunk,
            "rows":progress.rows,"rollingSha256":progress.rolling_sha256,"ready":false})
        );
        Ok(())
    }
}

#[cfg(not(feature = "liquid"))]
fn main() {
    if let Err(error) = bitcoin_proof::run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
