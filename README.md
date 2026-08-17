[![Build Status](https://ci.appveyor.com/api/projects/status/github/etcimon/botan?branch=master&svg=true)](https://ci.appveyor.com/project/etcimon/botan)
[![CI](https://github.com/etcimon/botan/actions/workflows/ci.yml/badge.svg)](https://github.com/etcimon/botan/actions/workflows/ci.yml)

Botan Crypto Library
====================

Botan is a crypto and TLS library for D (package **3.13.0**).

It is a translation of the C++ library [Botan](https://botan.randombit.net/)
(synced toward the 3.13 line) and uses
[memutils](https://github.com/etcimon/memutils) instead of the C++ STL.

The D API keeps the 1.12-era callback/delegate TLS surface (no C++ 3
`Callbacks` type). A TLS client/server with ALPN, SNI, HTTP/2, TLS 1.2 and
opt-in TLS 1.3 lives in the [vibe.0](https://github.com/etcimon/vibe.0) port.

Getting Started
---------------

Tested on Windows, macOS and Linux with DMD v2.099.1+ and LDC v1.31.0+
(LDC 1.42+ for current CI).

```
dub test --compiler=ldc2 --combined --d-version=FocusTests --d-version=Test_TLS
```

Full `dub test` compiles every algorithm unittest in one process and can
exhaust LDC on large suites. CI and local incremental work run **one family
per process** (`scripts/ci-test.sh`, `scripts/inc-build.ps1 test tls`).

```
# Windows (after ldc2 is on PATH)
.\scripts\inc-build.ps1 test tls
.\scripts\inc-build.ps1 test x509
```

`full` is the default dub configuration (include-all). `standard` is the
popular subset (TLS 1.2, X.509, AES/GCM, RSA/ECDSA/Ed25519, …) without
TLS 1.3 or post-quantum suites.

Learning
--------

Start with the [GitHub Wiki](https://github.com/etcimon/botan/wiki) and the
API docs on [GitHub Pages](http://etcimon.github.io/botan). In-tree notes
for this port are under `architecture/`.

Supported Algorithms
--------------------

### TLS / Public Key Infrastructure

  * TLS 1.0–1.2 (default offer is **1.2**; `latestTlsVersion()` stays 1.2)
  * TLS 1.3 (`version(TLS_13)`): RFC 8446 record protection, hello
    extensions, in-process handshake, RFC 8448 vectors. Offer 1.3
    explicitly (`TLS_V13` / vibe `TLSVersion.tls1_3`); default policy
    still rejects 1.3
  * TLS 1.3 PQC hybrids (`version(TLS_13_PQC)`): X25519MLKEM768 and
    optional ML-KEM / eFrodo groups
  * DTLS 1.0 / 1.2
  * ALPN, SNI, session tickets, OCSP status_request (staple when compiled)
  * X.509 certificates, CRLs, path validation, name constraints
  * System and PEM-bundle certificate stores
  * OCSP (HTTP via an app-supplied `setHttpExchangeHandler`; vibe.0 wires
    `requestHTTP` with `maxRedirects = 0`)
  * PKCS #10 requests, PKCS #12, RFC 3779 AS/IP address blocks

### Public Key Cryptography

  * RSA (OAEP, PKCS #1 v1.5, PSS), DSA, ECDSA, ECDH, Ed25519, Ed448, X25519, X448
  * ElGamal, DLIES, ECIES (including ISO 18033-2), ECGDSA, ECKCDSA, SM2, GOST 34.10
  * FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA / SPHINCS+
  * FrodoKEM, Classic McEliece, XMSS, HSS/LMS, Hybrid KEM
  * Hash-to-curve / hash-to-scalar (RFC 9380)

### Block ciphers and modes

  * AEAD: GCM, GCM-SIV, EAX, OCB, SIV, CCM, ChaCha20-Poly1305, Ascon-AEAD128
  * Modes: CTR, CBC, XTS, CFB, OFB, ECB
  * AES (SSSE3 / AES-NI), ARIA, Camellia, Serpent, Twofish, SM4, SHACAL-2, Kuznyechik
  * DES/3DES, SEED, Blowfish, CAST-128, IDEA, Threefish-512, and the rest of the 1.12 set

### Stream ciphers, hashes, MACs, KDFs

  * ChaCha20, Salsa20, RC4, SHAKE as a stream cipher
  * SHA-1/2/3, SHAKE, BLAKE2b/s, SM3, Streebog, Ascon-Hash256, truncated hashes
  * HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash, BLAKE2b-MAC
  * HKDF, HKDF-Expand-Label, SP 800-108/56A/56C, PBKDF2, Argon2, scrypt, bcrypt, PGP S2K

### Other

  * HMAC_DRBG, ChaCha RNG, system/processor RNGs
  * HOTP/TOTP, SPAKE2+, SRP-6a, Roughtime, ZFEC, NIST key wrap, CryptoBox

### Recommended Algorithms

If your data is in motion, use TLS 1.2 or (when both peers support it)
TLS 1.3. For something custom:

* Message encryption: AES-256/GCM or ChaCha20-Poly1305
* Hash / MAC: SHA-256 or SHA-512, HMAC-SHA-256
* Signatures: ECDSA P-256, Ed25519, or RSA-2048+ with PSS
* Key agreement: X25519 or ECDH P-256; ML-KEM-768 when post-quantum is required

Issues
------

File D-port issues on this tracker. Algorithm defects that also exist in
C++ Botan should be reported upstream at
[randombit/botan](https://github.com/randombit/botan/issues).

License
-------

Botan is released under the Simplified BSD License (see LICENSE.md).
