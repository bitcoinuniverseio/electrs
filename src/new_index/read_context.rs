//! Existing final-ready Core bootstrap observation. Never per-page freshness.
use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

pub const SCRIPT_BYTES_LIMIT: usize = 10000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapObservation {
    pub provenance: String,
    pub core_chain: String,
    pub height: u32,
    pub block_hash: String,
    pub observed_unix_seconds: u64,
    pub signet_challenge_sha256: Option<String>,
    pub signet_challenge_commitment_encoding: Option<String>,
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn chain_matches(network: &str, chain: &str) -> bool {
    matches!(
        (network, chain),
        ("mainnet", "main")
            | ("testnet", "test")
            | ("testnet4", "testnet4")
            | ("signet", "signet")
            | ("regtest", "regtest")
    )
}
impl BootstrapObservation {
    pub fn from_ready_response(
        network: &str,
        response: &Value,
        observed_unix_seconds: u64,
    ) -> Option<Self> {
        let chain = response.get("chain")?.as_str()?;
        if !chain_matches(network, chain)
            || response.get("initialblockdownload")?.as_bool()?
            || observed_unix_seconds == 0
        {
            return None;
        }
        let blocks = u32::try_from(response.get("blocks")?.as_u64()?).ok()?;
        if response.get("headers")?.as_u64()? != u64::from(blocks) {
            return None;
        }
        let hash = response.get("bestblockhash")?.as_str()?;
        if hash.len() != 64 || !lower_hex(hash) {
            return None;
        }
        let challenge = response.get("signet_challenge").filter(|v| !v.is_null());
        let commitment = if network == "signet" {
            let hex = challenge?.as_str()?;
            if hex.is_empty()
                || hex.len() > SCRIPT_BYTES_LIMIT * 2
                || hex.len() % 2 != 0
                || !lower_hex(hex)
            {
                return None;
            }
            // Explicitly match qualified receipt convention: SHA256 of the
            // lowercase script-hex UTF8, not SHA256 of decoded script bytes and
            // not Signet network magic/signature validation.
            Some(sha256::Hash::hash(hex.as_bytes()).to_string())
        } else {
            if challenge.is_some() {
                return None;
            }
            None
        };
        Some(Self {
            provenance: "immutable-final-ready-bootstrap-not-current-core-proof".into(),
            core_chain: chain.into(),
            height: blocks,
            block_hash: hash.into(),
            observed_unix_seconds,
            signet_challenge_sha256: commitment,
            signet_challenge_commitment_encoding: if network == "signet" {
                Some("lowercase-script-hex-utf8".into())
            } else {
                None
            },
        })
    }
    pub fn validate(&self, network: &str) -> bool {
        self.provenance == "immutable-final-ready-bootstrap-not-current-core-proof"
            && chain_matches(network, &self.core_chain)
            && self.observed_unix_seconds > 0
            && self.block_hash.len() == 64
            && lower_hex(&self.block_hash)
            && if network == "signet" {
                self.signet_challenge_commitment_encoding.as_deref()
                    == Some("lowercase-script-hex-utf8")
                    && self
                        .signet_challenge_sha256
                        .as_ref()
                        .map_or(false, |h| h.len() == 64 && lower_hex(h))
            } else {
                self.signet_challenge_sha256.is_none()
                    && self.signet_challenge_commitment_encoding.is_none()
            }
    }
}

/// Shared unchanged static profile preimage used by query and sole writer.
/// Credentials/cookie are deliberately absent; callers publish only its hash.
#[derive(Clone)]
pub struct StaticReadProfile {
    pub network: String,
    pub magic: u32,
    pub db_path: String,
    pub rpc_address: String,
    pub light_mode: bool,
    pub retain_history_bodies: bool,
    pub index_unspendables: bool,
    pub db_version: u32,
    pub electrs_version: String,
    pub electrum_discovery: bool,
    pub work_limit: usize,
    pub body_limit: usize,
    pub history_proof_dir: Option<String>,
}
impl StaticReadProfile {
    pub fn bytes(&self, bootstrap: &BootstrapObservation) -> Result<Vec<u8>, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            &self.network,
            self.magic,
            &self.db_path,
            &self.rpc_address,
            self.light_mode,
            self.index_unspendables,
            self.db_version,
            &self.electrs_version,
            self.electrum_discovery,
            bootstrap.signet_challenge_sha256.as_ref(),
            self.work_limit,
            self.body_limit,
        ))?;
        if self.history_proof_dir.is_some() || self.retain_history_bodies {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            if let Some(fields) = value.as_array_mut() {
                if let Some(directory) = &self.history_proof_dir {
                    fields.push(serde_json::json!({"historyProofDirectory":directory}));
                }
                if self.retain_history_bodies {
                    fields.push(serde_json::json!({"retainHistoryBodies":true}));
                }
            }
            serde_json::to_vec(&value)
        } else {
            Ok(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> Value {
        serde_json::json!({"chain":"signet","blocks":100,"headers":100,"bestblockhash":"1".repeat(64),"initialblockdownload":false,"signet_challenge":"51"})
    }
    #[test]
    fn default_profile_preserves_old_tuple_and_explicit_local_evidence_binds_it() {
        let bootstrap=BootstrapObservation::from_ready_response("signet",&serde_json::json!({"chain":"signet","blocks":10,"headers":10,"bestblockhash":"1".repeat(64),"initialblockdownload":false,"signet_challenge":"51"}),1).unwrap();
        let mut profile = StaticReadProfile {
            network: "signet".into(),
            magic: 42,
            db_path: "owned-db".into(),
            rpc_address: "127.0.0.1:1".into(),
            light_mode: false,
            retain_history_bodies: false,
            index_unspendables: false,
            db_version: 2,
            electrs_version: "test".into(),
            electrum_discovery: false,
            work_limit: 500,
            body_limit: 131072,
            history_proof_dir: None,
        };
        let old = serde_json::to_vec(&(
            "signet",
            42,
            "owned-db",
            "127.0.0.1:1",
            false,
            false,
            2,
            "test",
            false,
            bootstrap.signet_challenge_sha256.as_ref(),
            500,
            131072,
        ))
        .unwrap();
        assert_eq!(profile.bytes(&bootstrap).unwrap(), old);
        profile.retain_history_bodies = true;
        assert_ne!(profile.bytes(&bootstrap).unwrap(), old);
        profile.retain_history_bodies = false;
        profile.history_proof_dir = Some("explicit-local-proof".into());
        assert_ne!(profile.bytes(&bootstrap).unwrap(), old);
    }
    #[test]
    fn missing_invalid_and_oversized_challenge_never_qualify() {
        for value in [
            Value::Null,
            serde_json::json!(3),
            serde_json::json!(""),
            serde_json::json!("GG"),
            serde_json::json!("0"),
            serde_json::json!("51".repeat(10001)),
        ] {
            let mut info = ready();
            info["signet_challenge"] = value;
            assert!(BootstrapObservation::from_ready_response("signet", &info, 1).is_none());
        }
    }
    #[test]
    fn custom_challenges_same_genesis_are_distinct_bootstrap_commitments() {
        let first = BootstrapObservation::from_ready_response("signet", &ready(), 1).unwrap();
        let mut info = ready();
        info["signet_challenge"] = serde_json::json!("52");
        let second = BootstrapObservation::from_ready_response("signet", &info, 1).unwrap();
        assert_eq!(first.block_hash, second.block_hash);
        assert_ne!(
            first.signet_challenge_sha256,
            second.signet_challenge_sha256
        );
        assert!(first.validate("signet"));
        assert!(!first.validate("mainnet"));
    }
    #[test]
    fn wrong_chain_ibd_incomplete_and_missing_clock_are_unqualified() {
        for (field, value) in [
            ("chain", serde_json::json!("main")),
            ("initialblockdownload", serde_json::json!(true)),
            ("headers", serde_json::json!(101)),
        ] {
            let mut info = ready();
            info[field] = value;
            assert!(BootstrapObservation::from_ready_response("signet", &info, 1).is_none());
        }
        assert!(BootstrapObservation::from_ready_response("signet", &ready(), 0).is_none());
    }
    #[test]
    fn non_signet_requires_absent_challenge_and_exact_alias() {
        let mut info = ready();
        info["chain"] = serde_json::json!("main");
        assert!(BootstrapObservation::from_ready_response("mainnet", &info, 1).is_none());
        info.as_object_mut().unwrap().remove("signet_challenge");
        let record = BootstrapObservation::from_ready_response("mainnet", &info, 1).unwrap();
        assert!(record.validate("mainnet"));
        assert!(record.signet_challenge_sha256.is_none());
    }
    #[test]
    fn default_signet_challenge_matches_pinned_native_fixture_commitment() {
        let mut info = ready();
        info["signet_challenge"]=serde_json::json!("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
        let observed = BootstrapObservation::from_ready_response("signet", &info, 1).unwrap();
        assert_eq!(
            observed.signet_challenge_sha256.as_deref(),
            Some("22c3ce9264fbe1b11bad8b82e277fc0d255561d20f56ed276bc43eb885ef9d9f")
        );
    }
}
