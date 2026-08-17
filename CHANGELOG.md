
Change Log
==========

All Botan C++ algorithm changes are mirrored in this library.

The C++ change log is at https://botan.randombit.net/news.html

v3.13.0
-------------------

 - D package version jumps to the v3 range to match the C++ 3.13-line sync.
   `BOTAN_VERSION_*` is **3.13.0** (datestamp 20260817).
   `latestTlsVersion()` remains TLS 1.2; TLS 1.3 is opt-in (`version(TLS_13)`,
   offer `TLS_V13`).
 - TLS 1.3 record/handshake, RFC 8448 vectors, OCSP HTTP handler, system
   and PEM-bundle cert stores, RFC 3779 AS/IP blocks.
 - ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, Classic McEliece, XMSS, HSS/LMS,
   Ed25519/Ed448/X448, SM2, ECIES, Roughtime, Ascon, GCM-SIV, Argon2, scrypt.
 - SCAN/factory inheritance, Unique-wrapped allocations, `constants.d` versioning.
 - CI runs combined builds and one FocusTests family per process (LDC).
 - SIMD/AES-NI versions are LDC-only (`versions-x86_64-ldc`). DMD compiled
   those kernels into `AES_SSSE3` module constructors and exited
   `0xC000001D` / SIGILL before any unittest ran.
 - Win32 DMD TLS: Unique alias-this + template `start()` called GCM with a
   null `this`. Encrypt/decrypt now take the AEAD class ref first.
 - Win32: DER INTEGER/SEQUENCE length checks use `remaining - hdr` so a
   wrapped 32-bit `hdr + n` cannot reach `BigInt.binaryDecode`.
 - `full_openssl` DUB range is `>=3.3.4`. Engine/curve BN traffic uses
   `BN_bin2bn` / `BN_bn2bin` (OpenSSL 3 opaque `BIGNUM`). Config sets
   `DeimosOpenSSL_3_0`. CI runs Hash/Block/RSA under `full_openssl`
   on Ubuntu LDC (`scripts/ci-test-openssl.sh`). OpenSSL Blowfish is
   not registered (EVP max key 56 vs Botan 1..72); CAST uses `CAST-128`.

v1.11.10
-------------------

 - Initial release
