//! Bounded auxiliary T/X/M row format. Never opens a canonical index database.
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub const CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const ROW_BYTES: usize = 4_000_000;
pub const ROWS: usize = 500;
pub const WORK: usize = 1_000_000;
pub const HEADER_BYTES: usize = 88;

pub struct ProofChunk {
    pub profile: [u8; 32],
    pub index: u64,
    pub digest: [u8; 32],
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

fn bad() -> String {
    "Invalid bounded history proof chunk".into()
}

pub fn decode_chunk(bytes: &[u8]) -> Result<ProofChunk, String> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > HEADER_BYTES + CHUNK_BYTES
        || &bytes[..8] != b"UPRFROW1"
    {
        return Err(bad());
    }
    let profile = bytes[8..40].try_into().map_err(|_| bad())?;
    let index = u64::from_le_bytes(bytes[40..48].try_into().map_err(|_| bad())?);
    let count = u32::from_le_bytes(bytes[48..52].try_into().map_err(|_| bad())?) as usize;
    let length = u32::from_le_bytes(bytes[52..56].try_into().map_err(|_| bad())?) as usize;
    let digest: [u8; 32] = bytes[56..88].try_into().map_err(|_| bad())?;
    if count == 0
        || count > ROWS
        || length != bytes.len() - HEADER_BYTES
        || Sha256::digest(&bytes[HEADER_BYTES..]).as_slice() != digest
    {
        return Err(bad());
    }
    let mut rows = Vec::with_capacity(count);
    let mut offset = HEADER_BYTES;
    let mut work = 0usize;
    for _ in 0..count {
        let end = offset.checked_add(37).ok_or_else(bad)?;
        if end > bytes.len() {
            return Err(bad());
        }
        let key = bytes[offset..offset + 33].to_vec();
        let size =
            u32::from_le_bytes(bytes[offset + 33..end].try_into().map_err(|_| bad())?) as usize;
        offset = end;
        let end = offset.checked_add(size).ok_or_else(bad)?;
        if size == 0 || size > ROW_BYTES || end > bytes.len() {
            return Err(bad());
        }
        let value = &bytes[offset..end];
        match key[0] {
            b'T' => {
                let tx: Transaction = deserialize(value).map_err(|_| bad())?;
                if serialize(&tx) != value || tx.compute_txid().to_byte_array() != key[1..] {
                    return Err(bad());
                }
                work = work
                    .checked_add(
                        1 + tx.input.len()
                            + tx.output.len()
                            + tx.input
                                .iter()
                                .map(|input| input.witness.len())
                                .sum::<usize>(),
                    )
                    .ok_or_else(bad)?;
            }
            b'X' => {
                if size < 8 {
                    return Err(bad());
                }
                let transactions = u64::from_le_bytes(value[..8].try_into().map_err(|_| bad())?);
                if transactions == 0
                    || transactions > (ROW_BYTES / 40) as u64
                    || 8 + transactions as usize * 40 != size
                {
                    return Err(bad());
                }
                for encoded in value[8..].chunks_exact(40) {
                    if encoded[..8] != 32u64.to_le_bytes() {
                        return Err(bad());
                    }
                }
                work = work
                    .checked_add(1 + transactions as usize)
                    .ok_or_else(bad)?;
            }
            b'M' => {
                if size != 12 {
                    return Err(bad());
                }
                let count = u32::from_le_bytes(value[..4].try_into().map_err(|_| bad())?);
                let size = u32::from_le_bytes(value[4..8].try_into().map_err(|_| bad())?);
                let weight = u32::from_le_bytes(value[8..].try_into().map_err(|_| bad())?);
                if count == 0
                    || size == 0
                    || size > ROW_BYTES as u32
                    || weight < size
                    || weight > 4_000_000
                {
                    return Err(bad());
                }
                work = work.checked_add(1).ok_or_else(bad)?;
            }
            _ => return Err(bad()),
        }
        if work > WORK {
            return Err("History proof operation budget exceeded".into());
        }
        rows.push((key, value.to_vec()));
        offset = end;
    }
    if offset != bytes.len() {
        return Err(bad());
    }
    Ok(ProofChunk {
        profile,
        index,
        digest,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chunk(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, value) in rows {
            body.extend(key);
            body.extend((value.len() as u32).to_le_bytes());
            body.extend(value);
        }
        let mut result = b"UPRFROW1".to_vec();
        result.extend([7u8; 32]);
        result.extend(0u64.to_le_bytes());
        result.extend((rows.len() as u32).to_le_bytes());
        result.extend((body.len() as u32).to_le_bytes());
        result.extend(Sha256::digest(&body));
        result.extend(body);
        result
    }
    #[test]
    fn exact_genesis_transaction_round_trips_and_no_canonical_keys_are_accepted() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet);
        let tx = &block.txdata[0];
        let mut key = vec![b'T'];
        key.extend(tx.compute_txid().to_byte_array());
        let encoded = chunk(&[(key.clone(), serialize(tx))]);
        assert_eq!(
            decode_chunk(&encoded).unwrap().rows,
            vec![(key.clone(), serialize(tx))]
        );
        for kind in [b'V', b'C', b'H', b'O', b'B', b'D'] {
            key[0] = kind;
            assert!(decode_chunk(&chunk(&[(key.clone(), serialize(tx))])).is_err());
        }
    }
    #[test]
    fn roster_requires_each_bincode_hash_length() {
        let mut key = vec![b'X'];
        key.extend([9u8; 32]);
        let mut value = 1u64.to_le_bytes().to_vec();
        value.extend(32u64.to_le_bytes());
        value.extend([3u8; 32]);
        assert!(decode_chunk(&chunk(&[(key.clone(), value.clone())])).is_ok());
        value[8] = 31;
        assert!(decode_chunk(&chunk(&[(key.clone(), value)])).is_err());
        let mut old_encoding = 1u64.to_le_bytes().to_vec();
        old_encoding.extend([3u8; 32]);
        assert!(decode_chunk(&chunk(&[(key, old_encoding)])).is_err());
    }
    #[test]
    fn digest_identity_lengths_eof_and_consensus_corruption_fail_closed() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet);
        let tx = &block.txdata[0];
        let mut key = vec![b'T'];
        key.extend(tx.compute_txid().to_byte_array());
        let valid = chunk(&[(key.clone(), serialize(tx))]);
        for index in [0usize, 8, 48, 52, 56, valid.len() - 1] {
            let mut altered = valid.clone();
            altered[index] ^= 1;
            // A changed profile is caught by the job owner, not by the row decoder.
            if index == 8 {
                assert_ne!(decode_chunk(&altered).unwrap().profile, [7; 32]);
            } else {
                assert!(decode_chunk(&altered).is_err());
            }
        }
        key[1] ^= 1;
        assert!(decode_chunk(&chunk(&[(key, serialize(tx))])).is_err());
        assert!(decode_chunk(&valid[..valid.len() - 1]).is_err());
        let mut extra = valid;
        extra.push(0);
        assert!(decode_chunk(&extra).is_err());
    }
}
