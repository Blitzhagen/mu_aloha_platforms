#!/bin/sh
# Apply local gts7xllite WoA bring-up patches to submodules.
# Run from repo root AFTER `git submodule update --init --recursive`.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

apply() {
  sub="$1"; dir="$2"
  echo "== $sub <="
  # --ignore-whitespace: Upstream enthaelt CRLF-Dateien (z.B. DebugLib.c),
  # die Patches wurden auf einem LF-normalisierten Tree erzeugt - ohne das
  # Flag schlaegt das Kontext-Matching zeilenweise fehl.
  git -C "$ROOT/$sub" am --3way --whitespace=nowarn --ignore-whitespace "$ROOT/Patches/$dir"/*.patch
}

apply MU_BASECORE      MU_BASECORE
apply Common/MU        Common-MU
apply Common/MU_TIANO  Common-MU_TIANO

echo "All local patches applied. Build with: python3 build_uefi.py -d samsung-gts7xllite -t DEBUG"
