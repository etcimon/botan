
Change Log
==========

All Botan C++ algorithm changes are mirrored in this library.

The C++ change log is at https://botan.randombit.net/news.html

v3.13.0
-------------------

 - D package version jumps to the v3 range to match the C++ 3.13-line sync.
   `latestTlsVersion()` remains TLS 1.2; TLS 1.3 is opt-in (`version(TLS_13)`,
   offer `TLS_V13`).
 - TLS 1.3 record/handshake, RFC 8448 vectors, OCSP HTTP handler, system
   and PEM-bundle cert stores, RFC 3779 AS/IP blocks.
 - ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, Classic McEliece, XMSS, HSS/LMS,
   Ed25519/Ed448/X448, SM2, ECIES, Roughtime, Ascon, GCM-SIV, Argon2, scrypt.
 - SCAN/factory inheritance, Unique-wrapped allocations, `constants.d` versioning.
 - CI runs combined builds and one FocusTests family per process (LDC).

v1.11.10
-------------------

 - Initial release
