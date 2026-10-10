//! Strict bounded contract helpers for the separately versioned opt-in lane.
//! Admission stays held until synchronous IO actually exits, even if client left.
use super::paged_outputs::{PageCursor, PageError, CURSOR_LIMIT};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const READERS_LIMIT: usize = 8;
pub const ADDRESS_LIMIT: usize = 90;
pub const PATH_LIMIT: usize = 128;
pub const URI_LIMIT: usize = CURSOR_LIMIT + 512;
pub struct ReaderBudget {
    active: AtomicUsize,
}
pub struct ReaderLease<'a> {
    owner: &'a ReaderBudget,
}
impl ReaderBudget {
    pub fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
        }
    }
    pub fn acquire(&self) -> Result<ReaderLease<'_>, PageError> {
        self.active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n < READERS_LIMIT {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .map_err(|_| PageError::Capacity)?;
        Ok(ReaderLease { owner: self })
    }
}
impl Drop for ReaderLease<'_> {
    fn drop(&mut self) {
        self.owner.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub struct ExpectedScope {
    pub network: String,
    pub profile_sha256: String,
    pub artifact_revision: String,
}
impl ExpectedScope {
    pub fn matches(&self, scope: &super::paged_outputs::ReadScope) -> bool {
        self.network == scope.network
            && self.profile_sha256 == scope.profile_sha256
            && self.artifact_revision == scope.artifact_revision
    }
}
pub struct PageRequest {
    pub expected: ExpectedScope,
    pub cursor: Option<String>,
}
fn hex_valid(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn page_address(path: &str, total_uri_bytes: usize) -> Result<&str, PageError> {
    // Check borrowed lengths before any path vector, address decoding or copies.
    if total_uri_bytes > URI_LIMIT || path.len() > PATH_LIMIT {
        return Err(PageError::Capacity);
    }
    let address = path
        .strip_prefix("/v1/address/")
        .and_then(|p| p.strip_suffix("/utxo-pages"))
        .ok_or(PageError::Contract)?;
    if address.is_empty()
        || address.len() > ADDRESS_LIMIT
        || !address.bytes().all(|v| v.is_ascii_alphanumeric())
    {
        return Err(PageError::Contract);
    }
    Ok(address)
}
pub fn parse_request(raw: Option<&str>, body_length: usize) -> Result<PageRequest, PageError> {
    if body_length != 0 {
        return Err(PageError::Contract);
    }
    let raw = raw.ok_or(PageError::Contract)?;
    if raw.len() > CURSOR_LIMIT + 256 {
        return Err(PageError::Capacity);
    }
    let mut fields = std::collections::HashMap::new();
    for part in raw.split('&') {
        let (key, value) = part.split_once('=').ok_or(PageError::Contract)?;
        if !["network", "profile_sha256", "artifact_revision", "cursor"].contains(&key)
            || value.is_empty()
            || fields.insert(key, value).is_some()
        {
            return Err(PageError::Contract);
        }
    }
    let network = *fields.get("network").ok_or(PageError::Contract)?;
    if !["mainnet", "testnet", "testnet4", "signet", "regtest"].contains(&network) {
        return Err(PageError::Contract);
    }
    let profile = *fields.get("profile_sha256").ok_or(PageError::Contract)?;
    let artifact = *fields.get("artifact_revision").ok_or(PageError::Contract)?;
    if !hex_valid(profile, 64) || !hex_valid(artifact, 40) {
        return Err(PageError::Contract);
    }
    let cursor = fields.get("cursor").map(|s| (*s).to_owned());
    if cursor.as_ref().map_or(false, |s| s.len() > CURSOR_LIMIT) {
        return Err(PageError::Capacity);
    }
    Ok(PageRequest {
        expected: ExpectedScope {
            network: network.into(),
            profile_sha256: profile.into(),
            artifact_revision: artifact.into(),
        },
        cursor,
    })
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
fn hex_decode(value: &str) -> Result<Vec<u8>, PageError> {
    if value.len() % 2 != 0 || !hex_valid(value, value.len()) {
        return Err(PageError::Contract);
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let n = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
            n(pair[0]) * 16 + n(pair[1])
        })
        .collect())
}
fn hmac(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut normalized = [0u8; 64];
    if key.len() > 64 {
        normalized[..32].copy_from_slice(&sha256::Hash::hash(key)[..]);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = sha256::Hash::engine();
    inner.input(&normalized.map(|v| v ^ 0x36));
    inner.input(payload);
    let digest = sha256::Hash::from_engine(inner);
    let mut outer = sha256::Hash::engine();
    outer.input(&normalized.map(|v| v ^ 0x5c));
    outer.input(&digest[..]);
    sha256::Hash::from_engine(outer).to_byte_array()
}
pub struct CursorCodec {
    key: [u8; 32],
}
impl CursorCodec {
    pub fn new_os() -> Option<Self> {
        #[cfg(unix)]
        {
            use std::io::Read;
            let mut key = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .ok()?
                .read_exact(&mut key)
                .ok()?;
            Some(Self { key })
        }
        #[cfg(not(unix))]
        {
            None
        } // no insecure fallback, legacy API unaffected
    }
    pub fn encode(&self, cursor: &PageCursor) -> Result<String, PageError> {
        cursor.validate()?;
        let payload = serde_json::to_vec(cursor).map_err(|_| PageError::Contract)?;
        if payload.len() * 2 + 65 > CURSOR_LIMIT {
            return Err(PageError::Capacity);
        }
        Ok(format!(
            "{}.{}",
            hex_encode(&payload),
            hex_encode(&hmac(&self.key, &payload))
        ))
    }
    pub fn decode(&self, value: &str) -> Result<PageCursor, PageError> {
        if value.len() > CURSOR_LIMIT {
            return Err(PageError::Capacity);
        }
        let (payload, mac) = value.split_once('.').ok_or(PageError::Contract)?;
        if !hex_valid(mac, 64) {
            return Err(PageError::Contract);
        }
        let payload = hex_decode(payload)?;
        let signature = hex_decode(mac)?;
        let expected = hmac(&self.key, &payload);
        // Verify before parsing attacker-supplied bounded cursor JSON.
        let mismatch = expected
            .iter()
            .zip(&signature)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if mismatch != 0 {
            return Err(PageError::Contract);
        }
        let cursor: PageCursor =
            serde_json::from_slice(&payload).map_err(|_| PageError::Contract)?;
        cursor.validate()?;
        Ok(cursor)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hmac_rfc4231_vector() {
        assert_eq!(
            hex_encode(&hmac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
    #[test]
    fn duplicate_unknown_body_encoded_and_missing_scope_are_rejected() {
        let valid = format!(
            "network=signet&profile_sha256={}&artifact_revision={}",
            "a".repeat(64),
            "b".repeat(40)
        );
        assert!(parse_request(Some(&valid), 0).is_ok());
        for bad in [
            format!("{}&network=signet", valid),
            format!("{}&unknown=x", valid),
            valid.replace("signet", "%73ignet"),
            "network=signet".into(),
        ] {
            assert!(parse_request(Some(&bad), 0).is_err());
        }
        assert!(parse_request(Some(&valid), 1).is_err());
    }
    #[test]
    fn capacity_lease_remains_owned_until_actual_handler_exit() {
        let budget = ReaderBudget::new();
        let mut leases = Vec::new();
        for _ in 0..8 {
            leases.push(budget.acquire().unwrap());
        }
        assert!(matches!(budget.acquire(), Err(PageError::Capacity)));
        // Caller timeout/disconnect has no reference to release this owned lease.
        assert!(matches!(budget.acquire(), Err(PageError::Capacity)));
        drop(leases.pop());
        assert!(budget.acquire().is_ok());
        drop(leases);
        assert_eq!(budget.active.load(Ordering::SeqCst), 0);
    }
    fn cursor() -> PageCursor {
        let bootstrap=super::super::read_context::BootstrapObservation::from_ready_response("signet",
            &serde_json::json!({"chain":"signet","blocks":100,"headers":100,"bestblockhash":"5".repeat(64),"initialblockdownload":false,"signet_challenge":"51"}),1).unwrap();
        PageCursor::initial(super::super::paged_outputs::ReadScope {
            source_authority: "mempool-electrs".into(),
            chain: "bitcoin".into(),
            network: "signet".into(),
            bootstrap,
            genesis_hash: "1".repeat(64),
            artifact_revision: "2".repeat(40),
            profile_sha256: "3".repeat(64),
            script_hash: "4".repeat(64),
            chain_generation: 2,
            mempool_generation: 0,
            height: 100,
            block_hash: "5".repeat(64),
        })
    }
    #[test]
    fn authenticated_cursor_retains_original_scope_clock_and_expiry() {
        let codec = CursorCodec { key: [7; 32] };
        let original = cursor();
        let encoded = codec.encode(&original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.scope, original.scope);
        assert_eq!(decoded.created_unix_seconds, original.created_unix_seconds);
        assert_eq!(decoded.expires_unix_seconds, original.expires_unix_seconds);
        assert_eq!(codec.encode(&decoded).unwrap(), encoded);
        assert!(encoded.len() <= CURSOR_LIMIT);
    }
    #[test]
    fn tamper_wrong_process_key_unknown_fields_and_expired_cursor_reject() {
        let codec = CursorCodec { key: [7; 32] };
        let original = cursor();
        let encoded = codec.encode(&original).unwrap();
        let mut tampered = encoded.clone().into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        assert!(codec
            .decode(std::str::from_utf8(&tampered).unwrap())
            .is_err());
        assert!(CursorCodec { key: [8; 32] }.decode(&encoded).is_err());
        let mut value = serde_json::to_value(&original).unwrap();
        value["unrecognized"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        let signed = format!(
            "{}.{}",
            hex_encode(&bytes),
            hex_encode(&hmac(&codec.key, &bytes))
        );
        assert!(codec.decode(&signed).is_err());
        let mut expired = original.clone();
        expired.created_unix_seconds -= 3601;
        expired.expires_unix_seconds = expired.created_unix_seconds + 3600;
        let bytes = serde_json::to_vec(&expired).unwrap();
        let signed = format!(
            "{}.{}",
            hex_encode(&bytes),
            hex_encode(&hmac(&codec.key, &bytes))
        );
        assert!(matches!(codec.decode(&signed), Err(PageError::Expired)));
    }
    #[test]
    fn expected_profile_revision_network_and_challenge_are_distinct() {
        let original = cursor();
        let mut expected = ExpectedScope {
            network: original.scope.network.clone(),
            profile_sha256: original.scope.profile_sha256.clone(),
            artifact_revision: original.scope.artifact_revision.clone(),
        };
        assert!(expected.matches(&original.scope));
        expected.network = "mainnet".into();
        assert!(!expected.matches(&original.scope));
        expected.network = "signet".into();
        expected.profile_sha256 = "a".repeat(64);
        assert!(!expected.matches(&original.scope));
        expected.profile_sha256 = original.scope.profile_sha256.clone();
        expected.artifact_revision = "b".repeat(40);
        assert!(!expected.matches(&original.scope));
        let mut other = original.scope.clone();
        other.bootstrap.signet_challenge_sha256 = Some("c".repeat(64));
        assert_ne!(other, original.scope);
    }
    #[test]
    fn client_timeout_does_not_release_a_synchronous_owner_lease() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;
        let budget = Arc::new(ReaderBudget::new());
        let mut others = Vec::new();
        for _ in 0..7 {
            others.push(budget.acquire().unwrap());
        }
        let shared = Arc::clone(&budget);
        let (started_tx, started_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            let _lease = shared.acquire().unwrap();
            started_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // Model caller observation timeout; the synchronous worker has not exited.
        assert!(matches!(budget.acquire(), Err(PageError::Capacity)));
        finish_tx.send(()).unwrap();
        owner.join().unwrap();
        assert!(budget.acquire().is_ok());
        drop(others);
    }
    #[test]
    fn total_uri_path_and_address_are_bounded_before_decode() {
        let valid = "/v1/address/tb1qexample/utxo-pages";
        assert_eq!(page_address(valid, valid.len()).unwrap(), "tb1qexample");
        assert!(matches!(
            page_address(valid, URI_LIMIT + 1),
            Err(PageError::Capacity)
        ));
        assert!(page_address(&format!("/v1/address/{}/utxo-pages", "a".repeat(91)), 200).is_err());
        assert!(page_address("/v1/address/tb1q/extra/utxo-pages", 80).is_err());
        assert!(page_address("/v1/address/%74b1q/utxo-pages", 80).is_err());
        assert!(matches!(
            page_address(&"a".repeat(PATH_LIMIT + 1), PATH_LIMIT + 1),
            Err(PageError::Capacity)
        ));
    }
}
