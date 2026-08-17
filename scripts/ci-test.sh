#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# CI test runner: one combined compile per family so LDC does not AV
# when every unittest runs in a single process.
set -euo pipefail
ARCH="${ARCH:-x86_64}"
DC="${DC:-ldc2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

dub build --compiler="$DC" --arch="$ARCH" --combined

# Each invocation is a separate process. Families that historically AV when
# combined (x509+rsa+tls in one LDC process) stay split.
families=(
  "Test_TLS"
  "Test_X509"
  "Test_RSA"
  "Test_ECDSA"
  "Test_Hash"
  "Test_AEAD"
  "Test_MAC"
  "Test_ASN1"
)

for fam in "${families[@]}"; do
  echo "==> FocusTests $fam"
  dub test --compiler="$DC" --arch="$ARCH" --combined \
    --d-version=FocusTests --d-version="$fam"
done
