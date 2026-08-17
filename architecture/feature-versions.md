# Feature versions — cherry-pick surface

This note is the catalog of D `version` identifiers the dub package actually exposes, how they become
`BOTAN_HAS_*`, and how a caller selects a subset. The upgrade rule is in `upgrade-randombit.md`:
**every new algorithm is a new identifier**, never a silent addition to every configuration.

## How a flag reaches code

`dub.json` configurations list identifier strings. The compiler sets `version(Identifier)`.
`source/botan/constants.d` maps each one to `enum BOTAN_HAS_* = true/false`. Implementation
modules wrap their body in `static if (BOTAN_HAS_*)`. Files still sit on `sourcePaths`; a disabled
feature is an empty husk.

Always-on (not cherry-picks): `Have_botan`, `Botan` (top-level `dub.json` `versions`).
Test gates: `CanTest` → `BOTAN_HAS_TESTS`; `unittest` → `BOTAN_TEST`. Both are required for KATs
(`hash/hash.d:108`).

Security vs speed: **`No_CT` is the default** (`BOTAN_HAS_CT = false`) — same shape as
algorithm identifiers (off unless listed). Enable constant-time paths with `--d-version=CT`
or `"versions": ["CT"]`. `version(No_CT)` is explicit and is the default; it conflicts with
`CT`. Implementation files use `static if (BOTAN_HAS_CT)` / `static if (BOTAN_HAS_*)`, never
raw `version(CT)` / `version(AES)` / `version(X509)`. `secureScrubMemory` stays on either
way. Do not put `CT` on `full` / `standard` unless a consumer wants the slower secure paths
as a compile default.

## Configurations the package already ships

| Configuration | Role | Who uses it |
|---|---|---|
| `full` (default) | Long portable list + x86/x86_64 extras (SIMD, AES-NI, RDRAND, ZLib) | `dub build`, `dub test`, vibe.0 unless it subconfigures |
| `standard` | Popular TLS + PKI + modern primitives (H2). Not first. | new apps; vibe.0 may subconfigure later |
| `full_openssl` | Same idea + `Engine_OPENSSL`; **only** `versions-x86_64` — other archs get almost nothing | optional OpenSSL engine |
| `lite` | hashes + HMAC + PBKDF + KDFs/PRFs + RNG/entropy. No TLS, no X.509, no PUBKEY, no block suite | small digest/KDF consumers |
| `pubkey` | PK + X.509 + a few hashes/HMAC/CBC/EME + entropy. No TLS | `examples/pubkey` |
| `hash` | SHA-1/2, MD4/5, CRC24, HMAC, Win32+RDRAND | `examples/hash` (adds extra `Skein_512`) |

Callers cherry-pick by:

1. `"subConfigurations": { "botan": "hash" }` (examples), and/or
2. extra `"versions": ["Ed25519", "Argon2"]` on their own `dub.json` (once those identifiers exist).

There is no runtime enable. `haveAlgorithm("Ed25519")` is false if the version was off at compile.

## Hard-true constants that should become versions (hygiene increment A1)

**Done.** Those four are `version` → `BOTAN_HAS_*` in `constants.d`. Modules that implement
them are now `static if (BOTAN_HAS_*)` husks when the identifier is off:

| `version` | Module gate |
|---|---|
| `Cipher_Mode_Padding` | `modes/mode_pad.d` (CBC/ECB `static assert` they need it) |
| `Auto_Seeding_RNG` | `rng/auto_rng.d` |
| `Codec_Filters` | `filters/{hex,b64}_filt.d`, `codec/pem.d`, `codec/openpgp.d` |
| `HKDF` | `prf/hkdf.d` (already) |

`pubkey` lists `Codec_Filters` because PEM/PKCS#8 use `Base64Encoder`. Hex/base64
*functions* (`codec/hex.d`, `codec/base64.d`) stay ungated — tests and SCAN helpers
need them as infrastructure.

`Locking_Allocator` is listed on `lite` / `pubkey` / `hash` and now maps to
`BOTAN_HAS_LOCKING_ALLOCATOR`. No in-tree consumer yet.

## Existing identifiers (do not rename)

Symmetric / hash / MAC / stream: `AES`, `ARIA`, `Blowfish`, `Camellia`, `CAST`, `Cascade`, `DES`,
`GOST_28147`, `IDEA`, `KASUMI`, `Kuznyechik`, `LION`, `MARS`, `MISTY1`, `NOEKEON`, `RC2`, `RC5`,
`RC6`, `SAFER`, `SEED`, `Serpent`, `SHACAL2`, `SM4`, `TEA`, `Twofish`, `Threefish`, `XTEA`,
`Adler32`, `CRC24`, `CRC32`, `BLAKE2B`, `BLAKE2S`, `SM3`, `Streebog`, `Ascon_Hash256`,
`Truncated_Hash`, `GOST_3411`, `HAS_160`, `Keccak`, `MD2`, `MD4`, `MD5`, `RIPEMD_128`,
`RIPEMD_160`, `SHA1`, `SHA2_32`, `SHA2_64`, `SHA3`, `Shake`, `SHAKE_XOF`, `CSHAKE_XOF`,
`Ascon_XOF`, `Skein_512`, `Tiger`, `Whirlpool`, `ParallelHash`, `Comb4P`, `HMAC`, `POLY1305`,
`CBC_MAC`, `CMAC`, `SSL3_MAC`, `ANSI_X919_MAC`, `SipHash`, `GMAC`, `KMAC`, `BLAKE2BMAC`, `RC4`,
`ChaCha`, `Salsa20`, `SHAKE_Cipher`.

Modes / AEAD: `ECB`, `CBC`, `XTS`, `OFB`, `CFB`, `CTR_BE`, `AEAD_FILTER`, `AEAD_CCM`, `AEAD_EAX`,
`AEAD_OCB`, `AEAD_GCM`, `AEAD_SIV`, `AEAD_GCM_SIV`, `AEAD_ASCON128`, `AEAD_CHACHA20_POLY1305`.

PK / pad: `PUBKEY`, `RSA`, `RW`, `DLIES`, `DSA`, `ECDSA`, `ElGamal`, `GOST_3410`, `Curve25519`,
`X25519` (alias of `Curve25519`), `Ed25519`, `Ed448`, `X448`, `SM2`, `ML_KEM`, `ML_DSA`, `SLH_DSA`, `Classic_McEliece`, `FrodoKEM`, `XMSS`, `HSS_LMS`, `Hybrid_KEM`, `ECGDSA`, `ECKCDSA`,
`ECIES`, `Nyberg_Rueppel`, `Diffie_Hellman`, `ECDH`, `RFC6979`, `EMSA1`, `EMSA1_BSI`,
`EMSA_X931`, `EMSA_PKCS1`, `EMSA_PSSR`, `EMSA_RAW`, `ISO9796`, `EME_OAEP`, `EME_PKCS1v15`,
`EME_RAW`, `PBE_PKCSv20`.

KDF / password / constructs: `PBKDF1`, `PBKDF2`, `Argon2`, `Scrypt`, `PBKDF_BCrypt`, `PGP_S2K`,
`PKCS12_KDF`, `Argon2_Fmt`, `KDF1`, `KDF2`, `KDF1_18033`, `XMD`, `SP800_108`, `SP800_56A`, `SP800_56C`, `HKDF`,
`SSL_V3_PRF`, `TLS_V10_PRF`, `TLS_V12_PRF`, `X942_PRF`, `PassHash9`, `BCrypt`, `SRP6`, `TSS`,
`CryptoBox`, `CryptoBox_PSK`, `FPE_FE1`, `RFC3394`, `NIST_Keywrap`, `HOTP`, `TOTP` (alias of
`HOTP`), `SPAKE2P`, `AONT`, `Base32`, `Base58`.

TLS / X.509: `TLS`, `TLS_13`, `TLS_NULL`, `X509`, `CVC`, `SQLite`, `CertStore_Flatfile`, `CertStore_System`.
Misc / XOF extras: `ZFEC`, `AES_CTR_XOF` (`full` only; AES-CTR XOF asserts `AES`+`CTR_BE`).

RNG / entropy / engines: `X931_RNG`, `HMAC_DRBG`, `Stateful_RNG`, `ChaCha_RNG`, `System_RNG`, `Processor_RNG`,
`Auto_Seeding_RNG`, `Entropy_*`, `Engine_ASM`, `Engine_AES_ISA`, `Engine_SIMD`, `Engine_GNU_MP`,
`Engine_OPENSSL`.

SIMD / ISA extras (usually `versions-x86_64` only): `AES_NI`, `AES_SSSE3`, `SIMD_SSE2`,
`Serpent_SIMD`, `Noekeon_SIMD`, `XTEA_SIMD`, `IDEA_SSE2`, `SHA1_SSE2`, `SHA1_x86_64`, `SHA1_x86_32`,
`MD4_x86_32`, `MD5_x86_32`, `GCM_CLMUL`, `ZLib`.

Security / timing: `CT` (opt-in `BOTAN_HAS_CT`); `No_CT` is the default and is valid as an
explicit identifier. Compiler OS versions (`Posix`, `Windows`) stay as `version(Posix)` in
entropy modules — they are not Botan algorithm flags.

Do not recycle these names for a different algorithm. Do not “clean up” `SSL_V3_PRF` / `RC4` /
`MD5` by deleting them — cherry-pick is the point; default **policy** (TLS) already avoids them.

## Ported C++ features → `constants.d` (every landed increment)

Each C++-side add is a **positive** `version` in `constants.d` → `BOTAN_HAS_*` →
`static if` on the module (and on the factory arm). Compile aliases use `else version`.
Do not invent a flag for a helper that only exists to serve a parent algo (POLYVAL,
Ascon-p, Ed25519 field, ESP padding).

| Increment | `version` | `BOTAN_HAS_*` | Module / factory |
|---|---|---|---|
| H1 | `HKDF`, `Auto_Seeding_RNG`, `Codec_Filters`, `Cipher_Mode_Padding` | matching | `prf/hkdf.d`, `rng/auto_rng.d`, hex/b64 filters + PEM, `mode_pad.d` |
| S7 | `RSA_Insecure` | `BOTAN_HAS_RSA_INSECURE` | RSA keygen floor |
| K1–K2 | `Argon2`, `Argon2_Fmt`, `Scrypt` | matching | `pbkdf/{argon2,scrypt}.d` + `passhash/argon2fmt.d` + `getPbkdf` |
| K3 | `SP800_108`, `SP800_56A`, `SP800_56C` | matching | `kdf/sp800_*.d` + `getKdf` |
| K4 | `KDF1_18033`, `XMD` | matching | `kdf/{kdf1_iso18033,xmd}.d` |
| K5 | `PBKDF_BCrypt`, `PGP_S2K`, `PKCS12_KDF` | matching | `pbkdf/{bcrypt_pbkdf,pgp_s2k,pkcs12_kdf}.d` |
| P1–P6 | `Ed25519`, `Ed448`, `X448`, `SM2`, `ECGDSA`, `ECKCDSA`, `ECIES` | matching | `pubkey/algo/*` + `pk_algs`; Ed25519ph/Ed448ph via `PKSigner` params |
| P2 | `X25519` **or** `Curve25519` | `BOTAN_HAS_CURVE25519` (`BOTAN_HAS_X25519` alias) | same `curve25519.d` / SCAN `"X25519"` |
| R1–R3 | `System_RNG`, `Stateful_RNG`, `ChaCha_RNG`, `Processor_RNG` | matching | `rng/{system,stateful,chacha,processor}_rng.d`; ChaCha_RNG asserts Stateful + ChaCha |
| B1–B4 | `ARIA`, `SHACAL2`, `SM4`, `Kuznyechik` | matching | `block/*` + `CoreEngine` |
| Hsh1–6 | `BLAKE2S`, `SM3`, `Streebog`, `Ascon_Hash256`, `Truncated_Hash`, `SHAKE_XOF`, `CSHAKE_XOF`, `Ascon_XOF` | matching (`Ascon_XOF` → `BOTAN_HAS_ASCON_XOF128`) | `hash/*`, `xof/*`; `ascon_p.d` is OR of Ascon flags |
| T5 | `SHA2_32_SSE2` | `BOTAN_HAS_SHA2_32_SSE2` (asserts `SHA2_32`+`SIMD`) | `hash/sha2_32_sse2.d`; SIMDEngine; `versions-x86_64` only |
| T5 | `SHA2_32_X86` | `BOTAN_HAS_SHA2_32_X86` (asserts `SHA2_32`+`SIMD`) | `hash/sha2_32_x86.d` SHA-NI; SIMDEngine prefers `hasIntelSha()`; `versions-x86_64` only |
| T5 | `ChaCha_SIMD` | `BOTAN_HAS_CHACHA_SIMD` (asserts `ChaCha`+`SIMD`) | `stream/chacha_sse2.d` x4; `versions-x86_64` only |
| T5 | `ChaCha_AVX2` | `BOTAN_HAS_CHACHA_AVX2` (asserts `ChaCha`) | `stream/chacha_avx2.d` x8 (LDC); `versions-x86_64` only |
| T5 | `SM4_HWAES` | `BOTAN_HAS_SM4_HWAES` (asserts `SM4`+`AES_NI`) | `block/sm4_hwaes.d` AES-NI S-box + 4-way; `versions-x86_64` only |
| T5 | `ARIA_HWAES` | `BOTAN_HAS_ARIA_HWAES` (asserts `ARIA`+`AES_NI`) | `block/aria_hwaes.d` AES-NI S1/X1 + affine S2/X2 + FO/FE 4-way; `versions-x86_64` only |
| T5 | `Camellia_HWAES` | `BOTAN_HAS_CAMELLIA_HWAES` (asserts `Camellia`+`AES_NI`) | `block/camellia_hwaes.d` AES-NI S1–S4 + 2-way; `versions-x86_64` only |
| M1 | `GMAC`, `KMAC`, `BLAKE2BMAC`, `SipHash` | matching | `mac/*`; GMAC also needs `AEAD_GCM`; KMAC needs `SHA3`; BLAKE2BMAC needs `BLAKE2B` |
| A1–A2 | `AEAD_GCM_SIV`, `AEAD_ASCON128` | matching | `gcm_siv.d` / `polyval.d`; `ascon_aead128.d`; `getAead` |
| Str1 | `SHAKE_Cipher` | matching | `stream/shake_cipher.d` (asserts `SHAKE_XOF`) |
| C2–C7 | `SPAKE2P`, `HOTP`/`TOTP`, `Base32`, `Base58`, `NIST_Keywrap`, `EME_RAW`, `ISO9796` | matching (`TOTP` → `BOTAN_HAS_HOTP`) | constructs / pk_pad; SPAKE2P asserts PUBKEY+HKDF+HMAC; HOTP asserts HMAC |
| CS1–2 | `CertStore_Flatfile`, `CertStore_System` | matching | `certstor_*.d` |
| T13a–d | `TLS_13` | `BOTAN_HAS_TLS_13` (asserts `TLS`) | `tls/tls13/*` + 1.3 hello/EE/Cert/CV/Finished |
| T13p | `TLS_13_PQC` | `BOTAN_HAS_TLS_13_PQC` (asserts `TLS_13`+`ML_KEM`+`Curve25519`) | X25519MLKEM768 + secp256/384 hybrids + pure ML-KEM + eFrodo OQS (needs `FrodoKEM`); concat SS; `full` only |
| T13e | `OCSP_Staple` | `BOTAN_HAS_OCSP_STAPLE` (asserts `TLS`+`X509`) | `status_request` on CH + 1.3 CertificateEntry |
| T12n | `TLS_NULL` | `BOTAN_HAS_TLS_NULL` (asserts `TLS`) | `tls/tls_null.d` NULL+HMAC AEAD; `full` only |
| C8 | `ZFEC` | `BOTAN_HAS_ZFEC` | `constructs/zfec.d`; `full` only |
| C1 | `PKCS12` | `BOTAN_HAS_PKCS12` (asserts X509+PUBKEY+PKCS12_KDF) | `constructs/pkcs12.d` + `pkcs12_pbe.d` parse+export; `full` only |
| P7 / P14 | `ML_KEM` | `BOTAN_HAS_ML_KEM` (asserts PUBKEY+SHA3+SHAKE_XOF) | `pubkey/algo/ml_kem.d` FIPS 203 + Kyber R3 + 90s; `full` only |
| P8 / P14 | `ML_DSA` | `BOTAN_HAS_ML_DSA` (asserts PUBKEY+SHAKE_XOF) | `pubkey/algo/ml_dsa.d` FIPS 204 + Dilithium R3 modern; `full` only |
| P9 / P14 | `SLH_DSA` | `BOTAN_HAS_SLH_DSA` (asserts PUBKEY+SHAKE_XOF+SHA2_32+SHA2_64+HMAC) | `pubkey/algo/slh_dsa.d` SHAKE+SHA2 128/192/256 s/f + HashSLH-DSA + SPHINCS+ r3.1; `full` only |
| P11 | `FrodoKEM` | `BOTAN_HAS_FRODOKEM` (asserts PUBKEY+SHAKE_XOF) | `pubkey/algo/frodo_kem.d` SHAKE+AES-A 640/976/1344 + eFrodo; `full` only |
| P12 | `XMSS` | `BOTAN_HAS_XMSS` (asserts PUBKEY+SHA2_32+SHA2_64+Truncated_Hash+Shake) | `pubkey/algo/xmss.d` RFC 8391 / SP 800-208 verify+keygen+sign (no BDS); `full` only |
| P12 | `HSS_LMS` | `BOTAN_HAS_HSS_LMS` (asserts PUBKEY+SHA2_32+Truncated_Hash+Shake) | `pubkey/algo/hss_lms.d` RFC 8554 verify+keygen+sign (no BDS); `full` only |
| P13 | `Hybrid_KEM` | `BOTAN_HAS_HYBRID_KEM` (asserts PUBKEY+ML_KEM+Curve25519+SHA3) | `pubkey/algo/hybrid_kem.d` Hybrid-ML-KEM-768-X25519; `full` only |
| P10 | `Classic_McEliece` | `BOTAN_HAS_CLASSIC_MCELIECE` (asserts PUBKEY+SHAKE_XOF) | `pubkey/algo/classic_mceliece.d` NIST+ISO 16 names; `full` only |
| XofA | `AES_CTR_XOF` | `BOTAN_HAS_AES_CTR_XOF` (asserts `AES`+`CTR_BE`) | `xof/aes_ctr_xof.d`; `full` only |
| CT | `CT` (opt-in); `No_CT` default | `BOTAN_HAS_CT` | `utils/ct.d` + unpad / codec / HMAC |

Shared permutation / field files stay behind an **OR** of their parents (`ascon_p.d`,
`curve448_gf.d`). ESP padding lives under `Cipher_Mode_Padding`, not its own identifier.

## Proposed identifiers (not in the tree until their pass)

Each row is off everywhere until its increment in `upgrade-randombit.md` lands with tests.
`full` membership is “add after green” unless the rank table says extra-`versions` only.
Do not delete D-only identifiers in the existing list (RC4, MD2, MARS, …).

| `version` | Increment | Add to `full` when green? |
|---|---|---|
| `SLH_DSA_SHA2` | P9 leftover | optional (SHAKE landed as `SLH_DSA`) |
| `Classic_McEliece` larger KATs | P10 leftover | already in `full` |
| `Processor_RNG` POWER DARN | R3 | x86 RDRAND + PPC DARN landed (DARN probe Linux HWCAP2) |
| `Entropy_Getentropy`, `Entropy_Rdseed` | R4 | landed |

| Frodo/OQS TLS hybrid groups | T13p leftover | no |

`TLS_13` is intentionally **not** implied by `TLS`. A consumer that wants 1.3 must say so. Default
`latestTlsVersion()` remains 1.2 even when `TLS_13` is compiled (`upgrade-randombit.md` API freeze).

## `standard` vs `full` (do not retire)

See `dub-configs.md`. **`full` is include-all** and stays the implicit default
until a documented move. **`standard` (H2)** is the useful/popular list (TLS +
X.509 + cert stores + AES/ChaCha/SHA-2/3 + RSA/ECDSA/X25519 + …). Historic
identifiers (MARS, RC4, MD2, …) remain in `constants.d` and on `full` only.

New increment: add the `version` to `full` always; also to `standard` only if
`dub-configs.md` lists it as popular. Extra `"versions": ["MD5"]` still works
on top of `standard`.

H2 has landed: `standard` is in `dub.json` (not first). Cherry-pick extras still work on top of `standard`.

## How to add one identifier (checklist)

1. Pick a name that does not collide with the existing list.
2. `constants.d`: `version` → `BOTAN_HAS_*`, plus `SKIP_*_TEST = false`.
3. New module `static if (BOTAN_HAS_*)` (never `version(Identifier):` in the module).
   Infrastructure (`algo_base`, `math`, `hex`/`base64` functions, `rng.d`) stays ungated.
4. Purpose arm under the same `static if`: `CoreEngine.find*` / `getCipher` mode
   token / `getPbkdf` / `getKdf` / `getEmsa` / `pk_algs`+`OIDS` — SCAN string
   equals C++ `name()` (`scan-asn1.md`). No extra registry.
5. `dub.json`: always add the **portable** identifier to `full` (and
   `standard` if popular). ISA/ASM flavours go only on `versions-x86_64` /
   `versions-x86` (or a later arch key), never the portable list
   (`asm-accel.md`). Never delete an identifier.
6. Vectors under the existing `test_data/<family>/` (or a new dir + `SKIP_*` in
   `constants.d`) and a unittest of the `hash.d` format, run only via
   `dub test` (`dub-test.md`).
7. This table: move the row from “proposed” to “existing”.
8. Copyright header on every new or rewritten file (`upgrade-randombit.md`).

## Loci

| Piece | Where |
|---|---|
| Identifier map | `source/botan/constants.d:53–448` |
| Configuration lists | `dub.json:55–97` |
| Lookup (runtime names) | `source/botan/libstate/lookup.d` |
| Consumer extra versions | `examples/hash/dub.json` (`Skein_512`) |

## Invariants

- An identifier in `dub.json` that has no `constants.d` arm does nothing.
- An identifier in `constants.d` that no configuration lists is only usable if a dependent
  package adds it — that is supported and is the cherry-pick path.
- Renaming an existing identifier is an API break (vibe.0 and examples compile against them
  indirectly via `full`).

## Open questions

- Whether to emit `BOTAN_D_PACKAGE_VERSION` from `dub.json`’s `"version"` (1.13.9) so code can
  `static if` on the D package rather than the C++ lineage triple.
- Whether `full_openssl` should gain a portable `versions` key (today x86_64-only).
