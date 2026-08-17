# SPDX-License-Identifier: BSD-2-Clause
# Incremental LDC build: one .o per module, compilation cache, parallel.
# Usage (from botan root, after riscv-dev setenv.ps1):
#   .\scripts\inc-build.ps1
#   .\scripts\inc-build.ps1 test
#   .\scripts\inc-build.ps1 test rsa,rng
param(
    [ValidateSet("build", "test")]
    [string]$Command = "build",
    [string]$Focus = "",
    [string]$Config = "full",
    [string]$Compiler = "ldc2"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Combined compile: this tree has circular RefCounted/X509 types that
# --build-mode=singleFile cannot see. LDC --cache/--oq (dub.json dflags-ldc)
# still emit/reuse one object per module inside that one invocation.
$mode = @("--compiler=$Compiler", "--combined", "--parallel", "-c", $Config)

if ($Command -eq "build") {
    & dub build @mode
    exit $LASTEXITCODE
}

# test
$vers = @()
if ($Focus) {
    $vers += "--d-version=FocusTests"
    $map = @{
        transform = "Test_Transform"; x509 = "Test_X509"; block = "Test_Block"
        cvc = "Test_CVC"; cryptobox = "Test_CryptoBox"; rfc3394 = "Test_RFC3394"
        tss = "Test_TSS"; hash = "Test_Hash"; xof = "Test_XOF"; kdf = "Test_KDF"
        compression = "Test_Compression"; mac = "Test_MAC"; bigint = "Test_BigInt"
        ec = "Test_EC_GFP"; ec_gfp = "Test_EC_GFP"; aead = "Test_AEAD"; ocb = "Test_OCB"
        mode = "Test_CipherMode"; ciphermode = "Test_CipherMode"
        bcrypt = "Test_Bcrypt"; passhash9 = "Test_PassHash9"; pbkdf = "Test_PBKDF"
        argon2fmt = "Test_Argon2Fmt"; argon2_fmt = "Test_Argon2Fmt"; argon2pass = "Test_Argon2Fmt"
        hkdf = "Test_HKDF"; curve25519 = "Test_Curve25519"; x25519 = "Test_Curve25519"
        ed25519 = "Test_Ed25519"; eddsa = "Test_Ed25519"
        ed448 = "Test_Ed448"; x448 = "Test_X448"; sm2 = "Test_SM2"
        ml_kem = "Test_ML_KEM"; mlkem = "Test_ML_KEM"; kyber = "Test_ML_KEM"
        ml_dsa = "Test_ML_DSA"; mldsa = "Test_ML_DSA"; dilithium = "Test_ML_DSA"
        slh_dsa = "Test_SLH_DSA"; slhdsa = "Test_SLH_DSA"; sphincs = "Test_SLH_DSA"
        frodo = "Test_FRODOKEM"; frodokem = "Test_FRODOKEM"; frodo_kem = "Test_FRODOKEM"
        xmss = "Test_XMSS"
        hss = "Test_HSS_LMS"; hss_lms = "Test_HSS_LMS"; lms = "Test_HSS_LMS"
        hybrid = "Test_HYBRID_KEM"; hybrid_kem = "Test_HYBRID_KEM"
        cmce = "Test_CMCE"; classic_mceliece = "Test_CMCE"; mceliece = "Test_CMCE"
        ecgdsa = "Test_ECGDSA"; eckcdsa = "Test_ECKCDSA"; ecies = "Test_ECIES"
        dh = "Test_DH"; dlies = "Test_DLIES"; dsa = "Test_DSA"; ecdh = "Test_ECDH"
        ecdsa = "Test_ECDSA"; elgamal = "Test_ElGamal"; gost = "Test_GOST"
        nr = "Test_NR"; rfc6979 = "Test_RFC6979"; rsa = "Test_RSA"; rw = "Test_RW"
        x509_key = "Test_X509_Key"; rng = "Test_RNG"; system_rng = "Test_System_RNG"
        processor_rng = "Test_Processor_RNG"; procrng = "Test_Processor_RNG"; rdrand = "Test_Processor_RNG"
        rdseed = "Test_Entropy_Rdseed"; entropy_rdseed = "Test_Entropy_Rdseed"
        getentropy = "Test_Entropy_Getentropy"; entropy_getentropy = "Test_Entropy_Getentropy"
        sysrng = "Test_System_RNG"; stream = "Test_Stream"
        hotp = "Test_HOTP"; totp = "Test_HOTP"; otp = "Test_HOTP"
        base32 = "Test_Base32"; base58 = "Test_Base58"; base64 = "Test_Base64"
        codec = "Test_Base32"
        fpe = "Test_FPE"; fpe_fe1 = "Test_FPE"
        nist_keywrap = "Test_NIST_Keywrap"; keywrap = "Test_NIST_Keywrap"
        eme_raw = "Test_EME_RAW"; emeraw = "Test_EME_RAW"
        chacha_rng = "Test_ChaCha_RNG"; chacharng = "Test_ChaCha_RNG"
        spake2p = "Test_SPAKE2P"; spake2plus = "Test_SPAKE2P"
        srp6 = "Test_SRP6"; srp6a = "Test_SRP6"; srp = "Test_SRP6"
        iso9796 = "Test_ISO9796"; iso_9796 = "Test_ISO9796"
        tls = "Test_TLS"; tls_null = "Test_TLS"; tlsnull = "Test_TLS"
        zfec = "Test_ZFEC"; fec = "Test_ZFEC"
        pkcs12 = "Test_PKCS12"; p12 = "Test_PKCS12"; pfx = "Test_PKCS12"
        asn1 = "Test_ASN1"; oid = "Test_ASN1"
        workfactor = "Test_Workfactor"; wf = "Test_Workfactor"
        charset = "Test_Charset"
        parsing = "Test_Parsing"; read_kv = "Test_Parsing"; readkv = "Test_Parsing"
        calendar = "Test_Calendar"; dates = "Test_Calendar"
        roughtime = "Test_Roughtime"; rough_time = "Test_Roughtime"
        http = "Test_X509"; ocsp = "Test_X509"
    }
    foreach ($raw in $Focus.Split(",")) {
        $k = $raw.Trim().ToLowerInvariant()
        if (-not $k) { continue }
        if ($k -eq "codec") { $vers += "--d-version=Test_Base32"; $vers += "--d-version=Test_Base58"; $vers += "--d-version=Test_Base64"; $vers += "--d-version=Test_Charset"; $vers += "--d-version=Test_Parsing" }
        elseif ($k -eq "pbkdf") { $vers += "--d-version=Test_PBKDF"; $vers += "--d-version=Test_Argon2Fmt" }
        elseif ($map.ContainsKey($k)) { $vers += "--d-version=$($map[$k])" }
        elseif ($k.StartsWith("test_")) { $vers += "--d-version=$($raw.Trim())" }
        else { Write-Error "Unknown focus '$raw'. See architecture/incremental-build.md" }
    }
}

& dub test @mode @vers
exit $LASTEXITCODE
