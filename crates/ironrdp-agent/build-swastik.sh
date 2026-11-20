#!/usr/bin/env bash
set -euo pipefail
cargo build -p ironrdp-agent --bin swastik-rdp --profile production --locked "$@"
