#!/usr/bin/env bash
set -euo pipefail
version=4.14.9
build_root=${1:-/tmp/group5-wazuh-source}
mkdir -p "$build_root"
curl --fail --location "https://github.com/wazuh/wazuh/archive/refs/tags/v${version}.tar.gz" --output "$build_root/wazuh.tar.gz"
sha256sum "$build_root/wazuh.tar.gz"
tar -xzf "$build_root/wazuh.tar.gz" -C "$build_root"
make -C "$build_root/wazuh-$version/src" TARGET=agent deps
make -C "$build_root/wazuh-$version/src" TARGET=agent -j2
