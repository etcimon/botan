#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# full_openssl: algorithms the OpenSSL engine actually implements.
set -euo pipefail
ARCH="${ARCH:-x86_64}"
DC="${DC:-ldc2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

dub build -c full_openssl --compiler="$DC" --arch="$ARCH" --combined

# Hash (SHA-1/2, MD4/5, RIPEMD), Block (DES/3DES/Blowfish/CAST/Camellia/RC2/SEED),
# RSA (modexp / RSA ops). One family per process.
families=(
  "Test_Hash"
  "Test_Block"
  "Test_RSA"
)

for fam in "${families[@]}"; do
  echo "==> full_openssl FocusTests $fam"
  dub test -c full_openssl --compiler="$DC" --arch="$ARCH" --combined \
    --d-version=FocusTests --d-version="$fam"
done
