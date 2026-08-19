
Change Log
==========

All Botan C++ algorithm changes are mirrored in this library.

The C++ change log is at https://botan.randombit.net/news.html

v3.13.2
-------------------

 - `full` x86_64/LDC now registers `Engine_AES_ISA` (was only on `standard`).
   AES-128/GCM TLS records were bitsliced software AES (~35% Ir on `/64k`).
 - LDC CPUID always ORs `core.cpuid` AES-NI/CLMUL/SSSE3 bits (probe used to
   miss them; `hasAesNi` stayed false).
 - LDC AES-NI uses `ldc.gccbuiltins_x86` (`-mattr=+aes,+pclmul,+ssse3`) instead
   of per-round `movdqu` Intel asm. GHASH CLMUL on LDC uses the same single
   `asm` block as DMD (`USE_ASM`). TLS 1.3 record encrypt copies with
   `copyMem` and a reused inner buffer.
 - TLS 1.3 `prepareRecords` encrypts in place in a reused output buffer.
 - `xorBuf` for `ubyte*` uses unaligned `ulong` loads (CTR + GHASH).
 - GHASH CLMUL 64- then 128-byte aggregated stripes (`H…H^8`) on LDC.
 - LDC GHASH keeps pre-byteswapped `H^i` and Karatsuba (3×PCLMUL) accumulates;
   TLS 1.3 GCM encrypt stripes CTR+GHASH per 128 bytes.
 - LDC AES-NI load/xor/store stay in XMM (`long2` / `a^b`) instead of the
   spilled emmintrin Intel-asm helpers (~10% exclusive Ir on `/64k`).
 - CTR-BE `pad_blocks` (default 256); GCM uses 32 and adds N to each
   counter (skip-LSB was 256-only). GHASH byte shifts use `pslldq`/`psrldq`.
 - LDC x86_64 CPUID uses the `cpuid` instruction (`ldc.llvmasm`); GHASH
   CLMUL requires CLMUL+SSSE3+SSE2 (`hasGcmClmul`) so a CLMUL-only CPU
   cannot pshufb-SIGILL. AES-NI find also requires SSE2. LDC `psrldq`/
   `pslldq` live in `emmintrin` (LLVM asm opcode; no gccbuiltin). SHA-NI
   wrappers pin SHA256RNDS2's implicit XMM0 (`ldc.llvmasm`); `load_be` uses
   SSSE3 `pshufb` (C++ SIMD_4x32). SIMDEngine SHA-NI find is on when
   `hasIntelSha()` (`curl` TLS 1.3 `/hello` 200). `-mattr=+sha`.
 - LDC GHASH byte shifts (`gcmSlliBytes` / `gcmSrliBytes` / emmintrin
   `_mm_slli_si128`) use a long2 move for 8 bytes and SSSE3 `pshufb` for
   4/12: `ldc.llvmasm` `psrldq` did not inline (`_mm_srli_si128!(8)` was
   ~15% exclusive Ir on keep-alive `/64k`). CTR-BE `cipher` / increment
   use the pad/counter raw pointer (no `Vector.opIndex`). `xorBuf` is a
   32-byte `ulong` unroll without `arrayOp`. TLS 1.3 skip-copy of the
   inner plaintext is not used: a split GHASH of `pt` then the type byte
   is not the same as one GHASH of `pt||type` when `pt_len % 16 != 0`.
 - Public C++-ported types (TLS endpoints, PK keys, AEAD/KDF/PBKDF/MAC
   bases, TLS 1.3 record/cipher, ML-KEM, Ed25519, Argon2 PHC) carry the
   1.12/1.13 DDoc form (`Params:` / `Returns:`) so code-d can hover them.
   Also ML-DSA, SLH-DSA, Ed448, X448, XMSS, HSS/LMS, SM2, ECIES, FrodoKEM,
   Classic McEliece, ElGamal, ECGDSA, EC-KCDSA, Argon2/Scrypt ctors,
   NR, RW, GOST-34.10, Hybrid KEM, SHAKE, ChaCha, OCSP request, BER/DER,
   X.509 CRL isRevoked, HOTP/TOTP, SipHash, AutoSeededRNG, AlgorithmIdentifier,
   XOF, RFC 6979, GMAC/KMAC, DLIES, BigInt toString, SPAKE2+, ModularReducer,
   HKDF Extract/Expand, remaining hashes/modes (SHA-1, MD5, SM3, Streebog,
   BLAKE2s, SHA-3, CFB, ECB, CBC, XTS, GCM-SIV, ChaCha20-Poly1305), NIST
   keywrap, ZFEC, PKCS#12, Roughtime, KDFs, ChaCha_RNG. Signatures are unchanged.

v3.13.1
-------------------

 - `BOTAN_VERSION_*` / DUB package **3.13.1**.
 - `full_openssl` works against OpenSSL 3.4+ (opaque `BIGNUM`, `EVP_*_get_*`,
   `DeimosOpenSSL_3_0`, `openssl >=3.3.4`).
 - Ubuntu LDC CI job runs FocusTests Hash/Block/RSA under `full_openssl`.
 - OpenSSL Blowfish is not registered (EVP max key 56 vs Botan 1..72);
   CAST is advertised as `CAST-128`.

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
