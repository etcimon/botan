# SPDX-License-Identifier: BSD-2-Clause
# Appveyor / Windows CI: one combined compile per family.
param(
    [string]$Arch = $env:Darch,
    [string]$Compiler = $env:DC
)
if (-not $Arch) { $Arch = "x86_64" }
if (-not $Compiler) { $Compiler = "ldc2" }
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

& dub build --compiler=$Compiler --arch=$Arch --combined
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$families = @(
    "Test_TLS",
    "Test_X509",
    "Test_RSA",
    "Test_ECDSA",
    "Test_Hash",
    "Test_AEAD",
    "Test_MAC",
    "Test_ASN1"
)
foreach ($fam in $families) {
    Write-Host "==> FocusTests $fam"
    & dub test --compiler=$Compiler --arch=$Arch --combined `
        --d-version=FocusTests --d-version=$fam
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
