#!/usr/bin/env bash
# Fetch Microsoft's Sentinel KQL analyzer package and table schemas from Azure/Azure-Sentinel.
# Only the KQL-validation test folder is downloaded (sparse checkout, ~12 MB).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$ROOT/.schemas/azure-sentinel"

if [ ! -d "$DEST/.git" ]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git "$DEST"
  git -C "$DEST" sparse-checkout set .script/tests/KqlvalidationsTests
else
  git -C "$DEST" pull --depth 1 --quiet
fi

mkdir -p "$ROOT/tools/kql-validator/.packages"
cp "$DEST"/.script/tests/KqlvalidationsTests/microsoft.azure.sentinel.kustoservices.*.nupkg "$ROOT/tools/kql-validator/.packages/"
echo "Schemas: $DEST/.script/tests/KqlvalidationsTests"
