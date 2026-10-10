use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use std::{cmp, fs, path, thread};

use serde_json::Value as JsonValue;

use elements::AssetId;

use crate::errors::*;

// length of asset id prefix to use for sub-directory partitioning
// (in number of hex characters, not bytes)

const DIR_PARTITION_LEN: usize = 2;
const SEARCH_SORT_CANDIDATE_LIMIT: usize = 2000;

pub struct AssetRegistry {
    directory: path::PathBuf,
    assets_cache: HashMap<AssetId, (SystemTime, AssetMeta)>,
}

pub type AssetEntry<'a> = (&'a AssetId, &'a AssetMeta);

impl AssetRegistry {
    pub fn new(directory: path::PathBuf) -> Self {
        Self {
            directory,
            assets_cache: Default::default(),
        }
    }

    pub fn get(&self, asset_id: &AssetId) -> Option<&AssetMeta> {
        self.assets_cache
            .get(asset_id)
            .map(|(_, metadata)| metadata)
    }

    pub fn list(
        &self,
        start_index: usize,
        limit: usize,
        sorting: AssetSorting,
    ) -> (usize, Vec<AssetEntry<'_>>) {
        let mut assets: Vec<AssetEntry> = self
            .assets_cache
            .iter()
            .map(|(asset_id, (_, metadata))| (asset_id, metadata))
            .collect();
        assets.sort_by(sorting.as_comparator());
        (
            assets.len(),
            assets.into_iter().skip(start_index).take(limit).collect(),
        )
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<AssetEntry<'_>> {
        let query = query.trim();
        if query.is_empty() || limit == 0 {
            return vec![];
        }

        let (mut results, candidates) = search_by(
            self.assets_cache
                .iter()
                .map(|(asset_id, (_, metadata))| (asset_id, metadata)),
            query,
            limit,
            |metadata| metadata.ticker.as_deref(),
        );

        if results.len() < limit {
            let (name_matches, candidates) =
                search_by(candidates, query, limit - results.len(), |metadata| {
                    Some(&metadata.name)
                });
            results.extend(name_matches);

            if results.len() < limit {
                let (domain_matches, _) =
                    search_by(candidates, query, limit - results.len(), AssetMeta::domain);
                results.extend(domain_matches);
            }
        }

        results.truncate(limit);
        results
    }

    pub fn fs_sync(&mut self) -> Result<()> {
        for entry in fs::read_dir(&self.directory).chain_err(|| "failed reading asset dir")? {
            let entry = entry.chain_err(|| "invalid fh")?;
            let filetype = entry.file_type().chain_err(|| "failed getting file type")?;
            if !filetype.is_dir() || entry.file_name().len() != DIR_PARTITION_LEN {
                continue;
            }

            for file_entry in
                fs::read_dir(entry.path()).chain_err(|| "failed reading asset subdir")?
            {
                let file_entry = file_entry.chain_err(|| "invalid fh")?;
                let path = file_entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }

                let asset_id = AssetId::from_str(
                    path.file_stem()
                        .unwrap() // cannot fail if extension() succeeded
                        .to_str()
                        .chain_err(|| "invalid filename")?,
                )
                .chain_err(|| "invalid filename")?;

                let modified = file_entry
                    .metadata()
                    .chain_err(|| "failed reading metadata")?
                    .modified()
                    .chain_err(|| "metadata modified failed")?;

                if let Some((last_update, _)) = self.assets_cache.get(&asset_id) {
                    if *last_update == modified {
                        continue;
                    }
                }

                let metadata: AssetMeta = serde_json::from_str(
                    &fs::read_to_string(path).chain_err(|| "failed reading file")?,
                )
                .chain_err(|| "failed parsing file")?;

                self.assets_cache.insert(asset_id, (modified, metadata));
            }
        }
        Ok(())
    }

    pub fn spawn_sync(asset_db: Arc<RwLock<AssetRegistry>>) -> thread::JoinHandle<()> {
        crate::util::spawn_thread("asset-registry", move || loop {
            if let Err(e) = asset_db.write().unwrap().fs_sync() {
                error!("registry fs_sync failed: {:?}", e);
            }

            thread::sleep(Duration::from_secs(15));
            // TODO handle shutdowm
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssetMeta {
    #[serde(skip_serializing_if = "JsonValue::is_null")]
    pub contract: JsonValue,
    #[serde(skip_serializing_if = "JsonValue::is_null")]
    pub entity: JsonValue,
    pub precision: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,
}

impl AssetMeta {
    pub(crate) fn domain(&self) -> Option<&str> {
        self.entity["domain"].as_str()
    }
}

pub struct AssetSorting(AssetSortField, AssetSortDir);

pub enum AssetSortField {
    Name,
    Domain,
    Ticker,
}
pub enum AssetSortDir {
    Descending,
    Ascending,
}

type Comparator = Box<dyn Fn(&AssetEntry, &AssetEntry) -> cmp::Ordering>;

impl AssetSorting {
    #[allow(clippy::wrong_self_convention)]
    fn as_comparator(self) -> Comparator {
        let sort_fn: Comparator = match self.0 {
            AssetSortField::Name => {
                // Order by name first, use asset id as a tie breaker. the other sorting fields
                // don't require this because they're guaranteed to be unique.
                Box::new(|a, b| lc_cmp(&a.1.name, &b.1.name).then_with(|| a.0.cmp(b.0)))
            }
            AssetSortField::Domain => Box::new(|a, b| a.1.domain().cmp(&b.1.domain())),
            AssetSortField::Ticker => Box::new(|a, b| lc_cmp_opt(&a.1.ticker, &b.1.ticker)),
        };

        match self.1 {
            AssetSortDir::Ascending => sort_fn,
            AssetSortDir::Descending => Box::new(move |a, b| sort_fn(a, b).reverse()),
        }
    }

    pub fn from_query_params(query: &HashMap<String, String>) -> Result<Self> {
        let field = match query.get("sort_field").map(String::as_str) {
            None => AssetSortField::Ticker,
            Some("name") => AssetSortField::Name,
            Some("domain") => AssetSortField::Domain,
            Some("ticker") => AssetSortField::Ticker,
            _ => bail!("invalid sort field"),
        };

        let dir = match query.get("sort_dir").map(String::as_str) {
            None => AssetSortDir::Ascending,
            Some("asc") => AssetSortDir::Ascending,
            Some("desc") => AssetSortDir::Descending,
            _ => bail!("invalid sort direction"),
        };

        Ok(Self(field, dir))
    }
}

fn lc_cmp(a: &str, b: &str) -> cmp::Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}
fn lc_cmp_opt(a: &Option<String>, b: &Option<String>) -> cmp::Ordering {
    a.as_ref()
        .map(|a| a.to_lowercase())
        .cmp(&b.as_ref().map(|b| b.to_lowercase()))
}

fn search_by<'a, I, F>(
    candidates: I,
    query: &str,
    limit: usize,
    field: F,
) -> (Vec<AssetEntry<'a>>, Vec<AssetEntry<'a>>)
where
    I: IntoIterator<Item = AssetEntry<'a>>,
    F: Fn(&AssetMeta) -> Option<&str>,
{
    let mut matches = vec![];
    let mut remaining = vec![];

    for (asset_id, metadata) in candidates {
        let position = field(metadata).and_then(|field| {
            // registry fields are ascii, so we don't need full unicode case-folding
            ascii_ci_find(field, query).map(|position| (position, field))
        });

        if let Some((position, field)) = position {
            if matches.len() >= SEARCH_SORT_CANDIDATE_LIMIT {
                continue;
            }
            matches.push((position, field, asset_id, metadata));
        } else {
            remaining.push((asset_id, metadata));
        }
    }

    matches.sort_unstable_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| ascii_ci_cmp(a.1, b.1))
            .then_with(|| a.2.cmp(b.2))
    });

    (
        matches
            .into_iter()
            .take(limit)
            .map(|(_, _, asset_id, metadata)| (asset_id, metadata))
            .collect(),
        remaining,
    )
}

// zero-allocation case-insensitive ASCII substring search
// returns the byte offset of the first match
fn ascii_ci_find(haystack: &str, needle: &str) -> Option<usize> {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

// zero-allocation case-insensitive ASCII string comparison
fn ascii_ci_cmp(a: &str, b: &str) -> cmp::Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    for i in 0..a.len().min(b.len()) {
        match a[i].to_ascii_lowercase().cmp(&b[i].to_ascii_lowercase()) {
            cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    a.len().cmp(&b.len())
}
