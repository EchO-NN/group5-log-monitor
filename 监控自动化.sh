#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if (( $# == 0 )); then set -- status; fi
exec python3 "$project_dir/scripts/monitor-control.py" "$@"
