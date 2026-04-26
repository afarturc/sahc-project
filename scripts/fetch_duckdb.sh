#!/usr/bin/env bash
# Fetch the precompiled DuckDB shared library + headers from the
# upstream release. Idempotent — skips the download if the .so is
# already in place. Pinned to v1.1.3 for reproducibility; bump
# DUCKDB_VERSION when the API surface we use needs a newer release.
set -euo pipefail

DUCKDB_VERSION="${DUCKDB_VERSION:-v1.1.3}"
DEST="$(cd "$(dirname "$0")/.." && pwd)/Common/third_party/duckdb"
SO="$DEST/libduckdb.so"

if [ -f "$SO" ]; then
    echo "fetch_duckdb: $SO already present — skipping"
    exit 0
fi

mkdir -p "$DEST"
URL="https://github.com/duckdb/duckdb/releases/download/${DUCKDB_VERSION}/libduckdb-linux-amd64.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetch_duckdb: downloading $URL"
curl -fsSL -o "$TMP/libduckdb.zip" "$URL"
unzip -o "$TMP/libduckdb.zip" -d "$TMP" >/dev/null

# Headers we vendor from the bundle; keep them next to the .so.
cp "$TMP/libduckdb.so" "$DEST/"
cp "$TMP/duckdb.h"     "$DEST/"
cp "$TMP/duckdb.hpp"   "$DEST/"

# Static lib is shipped too; we don't need it.
rm -f "$DEST/libduckdb_static.a"

echo "fetch_duckdb: installed $DUCKDB_VERSION into $DEST"
