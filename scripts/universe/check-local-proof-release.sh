#!/bin/bash
set -euo pipefail
cd "$1"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=2
INCLUDE_TESTS=1 bash scripts/checks.sh --release
# Liquid's all-feature selection excludes the Bitcoin proof modules.
cargo test --release --lib --offline --frozen --jobs 2
cargo build --release --bin electrs --bin history-proof-ingest --offline --frozen --jobs 2
