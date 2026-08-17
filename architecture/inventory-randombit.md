# Complete inventory vs randombit/botan

Pins (after `git fetch` 2026-08-15; both at origin/master, no commits behind):

| Tree | Branch (this work) | Tip | Meaning |
|---|---|---|---|
| this checkout | `feature/randombit-sync` (from `master` `460336f` / v1.13.9) | will merge to **etcimon/botan** `master` | D port |
| `../randombit-botan` | `master` | `6931ef6fd` / 3.13.0-24 | C++ reference |
| `../vibe.0` | `feature/botan-delegate-sync` (from `master` `7b77638`) | will merge to **etcimon/vibe.0** `master` | load-bearing TLS consumer |

366 C++ `info.txt` modules were enumerated under `../randombit-botan/src/lib`. This note is the **complete** algorithm/module difference list. Hardware-only submodules (AES-NI, ARMv8, AVX-512, …) are listed as *accel*, not as new algorithms. C++ product surfaces we will not import as D API (`ffi`, `compat/sodium`, `tls/asio`, `cli`, TPM/PKCS#11 providers) are listed as *out of D API*.

How a **missing** row is turned on: C++ `name()` as a SCAN string (or `OIDS` name for keys), wired into the existing purpose entry — not a new selector. See `scan-asn1.md`.

Status key: **same** (D has it), **D-only** (C++ 3.13 removed or never had; keep version-gated), **missing** (C++ has it, D does not), **accel** (ISA extra), **api-skip** (do not port as public D API).

## Block ciphers

| Algo | C++ define | D `version` / file | Status |
|---|---|---|---|
| AES | `AES` | `AES` / `aes.d` | same |
| AES-NI / vperm / VAES / ARMv8 / POWER8 | several | `AES_NI`, `AES_SSSE3` | accel (D has NI + SSSE3 only) |
| ARIA | `ARIA` | `ARIA` (B1) | **done** portable 128/192/256; **ARIA_HWAES** AES-NI S-boxes + FO/FE |
| Blowfish | `BLOWFISH` | `Blowfish` | same |
| Camellia | `CAMELLIA` | `Camellia` | same; **Camellia_HWAES** AES-NI S-boxes + 2-way |
| Cascade | `CASCADE` | `Cascade` | same |
| CAST-128 | `CAST_128` | `CAST` / `cast128.d` | same |
| CAST-256 | — (removed) | `CAST` / `cast256.d` | **D-only** keep |
| DES / 3DES | `DES` | `DES` | same |
| DESX | — | `desx.d` | **D-only** keep |
| GOST 28147 | `GOST_28147_89` | `GOST_28147` | same (C++ deprecated) |
| IDEA | `IDEA` | `IDEA` | same |
| KASUMI | — | `KASUMI` | **D-only** keep |
| Kuznyechik | `KUZNYECHIK` | `Kuznyechik` | **done** `block/kuznyechik.d` |
| Lion | `LION` | `LION` | same (C++ deprecated) |
| MARS | — | `MARS` | **D-only** keep |
| MISTY1 | — | `MISTY1` | **D-only** keep |
| Noekeon | `NOEKEON` | `NOEKEON` | same (C++ deprecated) |
| RC2 / RC5 / RC6 | — | `RC2`, `RC5`, `RC6` | **D-only** keep |
| SAFER-SK | — | `SAFER` | **D-only** keep |
| SEED | `SEED` | `SEED` | same |
| Serpent | `SERPENT` | `Serpent` | same |
| SHACAL-2 | `SHACAL2` | `SHACAL2` | **done** `block/shacal2.d` |
| SM4 | `SM4` | `SM4` | **done** `block/sm4.d` CT key schedule |
| TEA / XTEA | — | `TEA`, `XTEA` | **D-only** keep |
| Threefish-512 | `THREEFISH_512` | `Threefish` | same |
| Twofish | `TWOFISH` | `Twofish` | same |

## Hashes / checksums / XOFs

| Algo | C++ | D | Status |
|---|---|---|---|
| SHA-1 / SHA-2-32 / SHA-2-64 | `SHA1`, `SHA2_32`, `SHA2_64` (incl. SHA-512/256) | `SHA1`, `SHA2_32`, `SHA2_64` | same; **SHA-512/256** SCAN alias → `SHA-512-256` |
| SHA-3 | `SHA3` | `SHA3` | same |
| SHAKE (hash) | `SHAKE` | `Shake` | same |
| SHAKE XOF / cSHAKE / Ascon-XOF128 | `SHAKE_XOF`, `CSHAKE_XOF`, `ASCON_XOF128` | `SHAKE_XOF`, `CSHAKE_XOF`, `Ascon_XOF` | **done** `xof/*` + `getXof`; hash SHAKE-128(n) unchanged |
| Ascon-Hash256 | `ASCON_HASH256` | `Ascon_Hash256` | **done** `hash/ascon_hash256.d` |
| BLAKE2b | `BLAKE2B` | `BLAKE2B` | same |
| BLAKE2s | `BLAKE2S` | `BLAKE2S` (Hsh1) | **done** |
| Keccak (competition hash) | `KECCAK` | `Keccak` | same (C++ deprecated) |
| Skein-512 | `SKEIN_512` | `Skein_512` | same |
| SM3 | `SM3` | `SM3` | **done** `hash/sm3.d` |
| Streebog | `STREEBOG` | `Streebog` | **done** `hash/streebog.d` 256/512 |
| Truncated-hash wrapper | `TRUNCATED_HASH` | `Truncated_Hash` | **done** `hash/trunc_hash.d` |
| Whirlpool | `WHIRLPOOL` | `Whirlpool` | same |
| GOST 34.11 | `GOST_34_11` | `GOST_3411` | same (C++ deprecated) |
| Comb4P / Parallel | `COMB4P`, `PARALLEL_HASH` | `Comb4P`, `ParallelHash` | same |
| MD4 / MD5 | `MD4`, `MD5` | `MD4`, `MD5` | same (C++ deprecated) |
| MD2 | — | `MD2` | **D-only** keep |
| RIPEMD-160 | `RIPEMD_160` | `RIPEMD_160` | same |
| RIPEMD-128 | — | `RIPEMD_128` | **D-only** keep |
| HAS-160 | — | `HAS_160` | **D-only** keep |
| Tiger | — | `Tiger` | **D-only** keep |
| Adler32 / CRC24 / CRC32 | `ADLER32`, `CRC24`, `CRC32` | same names | same (Adler/CRC32 deprecated in C++) |

## MACs / stream / modes

| Algo | C++ | D | Status |
|---|---|---|---|
| HMAC / CMAC / Poly1305 / X9.19 | yes | yes | same |
| GMAC / KMAC / BLAKE2MAC / SipHash | `GMAC`, `KMAC`, `BLAKE2BMAC`, `SIPHASH` | `SipHash`, `GMAC`, `KMAC`, `BLAKE2BMAC` | **done** |
| CBC-MAC / SSL3-MAC | — | `CBC_MAC`, `SSL3_MAC` | **D-only** keep |
| ChaCha / Salsa20 / RC4 / CTR / OFB | yes | yes | same |
| SHAKE as stream cipher | `SHAKE_CIPHER` | `SHAKE_Cipher` | **done** `stream/shake_cipher.d` (C++ deprecated; `full` only) |
| CBC / CFB / XTS / mode padding | yes | yes | same |
| ECB | — (gone as a module) | `ECB` | **D-only** keep |
| GCM / CCM / EAX / OCB / SIV / ChaCha20-Poly1305 | yes | yes | same |
| GCM-SIV | `AEAD_GCM_SIV` | `AEAD_GCM_SIV` | **done** `modes/aead/gcm_siv.d` + POLYVAL |
| Ascon-AEAD128 | `ASCON_AEAD128` | `AEAD_ASCON128` | **done** `modes/aead/ascon_aead128.d` |

## KDF / PBKDF / passhash / PAKE

| Algo | C++ | D | Status |
|---|---|---|---|
| HKDF | `HKDF` | `HKDF` + `prf/hkdf.d` | **done** `HKDF`/`HKDF_Extract`/`HKDF_Expand` inherit `KDF`; `getKdf("HKDF(SHA-256)")` |
| KDF1 / KDF2 / X9.42 PRF | yes | yes | same |
| TLS 1.2 PRF | `TLS_V12_PRF` | `TLS_V12_PRF` | same |
| TLS 1.0 PRF / SSL3 PRF | — | `TLS_V10_PRF`, `SSL_V3_PRF` | **D-only** keep (needed for TLS 1.0/1.1 in this tree) |
| KDF1 ISO 18033 | `KDF1_18033` | `KDF1_18033` | **done** `kdf/kdf1_iso18033.d` `getKdf("KDF1-18033(…)")` |
| SP 800-108 / 56A / 56C | `SP800_*` | `SP800_108`, `SP800_56A`, `SP800_56C` | **done** `kdf/sp800_*.d` + `getKdf` |
| XMD (hash-to-curve expand) | `XMD` | `XMD` | **done** `kdf/xmd.d` `expandMessageXmd` (not SCAN) |
| PBKDF2 | `PBKDF2` | `PBKDF2` | same |
| PBKDF1 | — | `PBKDF1` | **D-only** keep |
| Argon2 / Argon2fmt | `ARGON2`, `ARGON2_FMT` | `Argon2`, `Argon2_Fmt` | **done** `pbkdf/argon2.d` + `passhash/argon2fmt.d` |
| scrypt | `SCRYPT` | — | **missing** |
| bcrypt PBKDF / PGP S2K / PKCS#12 KDF | `PBKDF_BCRYPT`, `PGP_S2K`, `PKCS12_KDF` | `PBKDF_BCrypt`, `PGP_S2K`, `PKCS12_KDF` | **done** `pbkdf/{bcrypt_pbkdf,pgp_s2k,pkcs12_kdf}.d` |
| bcrypt / PassHash9 | yes | yes | same |
| SPAKE2+ | `PAKE_SPAKE2PLUS` | `SPAKE2P` | **done** `constructs/spake2p.d` RFC 9383 HMAC suites (from_prehashed); password/Argon2id later |
| SRP6 | `SRP6` | `SRP6` | same |

## Public key / padding / constructs

| Algo | C++ | D | Status |
|---|---|---|---|
| RSA / DSA / ECDSA / ECDH / DH / ElGamal / DLIES / GOST 34.10 | yes | yes | same |
| Curve25519 / X25519 | `X25519`/`CURVE_25519` | `Curve25519` | same impl; **P2** OID/name alias `X25519` → Curve25519 |
| Ed25519 / Ed448 / X448 | `ED25519`, `ED448`, `X448` | `Ed25519` (P1), `Ed448`/`X448` (P3) | **Ed25519 + Ed448 Pure + ph + X448 done** |
| ECGDSA / ECKCDSA / ECIES / SM2 | yes | `SM2` (P4), `ECGDSA`/`ECKCDSA` (P5), `ECIES` (P6) | **SM2 + ECGDSA + ECKCDSA + ECIES done** |
| ML-KEM / Kyber R3 / Kyber-90s | `ML_KEM`, `KYBER`, `KYBER_90S` | `ML_KEM` (P7/P14) | **ML-KEM + Kyber R3 + 90s done** `pubkey/algo/ml_kem.d` |
| ML-DSA / Dilithium R3 / Dilithium-AES | `ML_DSA`, `DILITHIUM`, `DILITHIUM_AES` | `ML_DSA` (P8/P14) | **ML-DSA + Dilithium R3 + AES done** `pubkey/algo/ml_dsa.d` |
| SLH-DSA / SPHINCS+ | `SLH_DSA_*`, `SPHINCS_PLUS_*` | `SLH_DSA` (P9/P14) | **SLH-DSA SHAKE+SHA2 + HashSLH-DSA + SPHINCS+ r3.1 done** `pubkey/algo/slh_dsa.d` |
| Classic McEliece / old McEliece / FrodoKEM | yes | `FrodoKEM` (P11), `Classic_McEliece` (P10) | **FrodoKEM SHAKE+AES-A + CTR_DRBG KATs done** `pubkey/algo/frodo_kem.d`; **Classic McEliece done** `pubkey/algo/classic_mceliece.d` |
| XMSS / HSS-LMS | yes | `XMSS`, `HSS_LMS` (P12) | **XMSS verify+keygen+sign** `pubkey/algo/xmss.d` (no BDS); **HSS-LMS verify+keygen+sign** `pubkey/algo/hss_lms.d` (no BDS) |
| Hybrid KEM / KEX→KEM adapter | yes | `Hybrid_KEM` (P13) | **Hybrid-ML-KEM-768-X25519 done** `pubkey/algo/hybrid_kem.d` |
| Rabin-Williams / Nyberg-Rueppel | — | `RW`, `Nyberg_Rueppel` | **D-only** keep |
| RFC 6979 | yes | `RFC6979` | same |
| EMSA PKCS1/PSS/RAW/X9.31 / EMSA1 / EMSA1_BSI | yes (EMSA1 is EC/DSA path) | yes | same |
| ISO 9796 | `ISO_9796` | `ISO9796` | **done** `pk_pad/iso9796.d` DS2/DS3 via `getEmsa`; `full` only |
| EME OAEP / PKCS1 | yes | yes | same |
| EME RAW | `EME_RAW` | `EME_RAW` | **done** `pk_pad/eme_raw.d` `getEme("Raw")` |
| PKCS#12 | `PKCS12` | `PKCS12` | **done** parse + export (`constructs/pkcs12.d`); `PKCS12ExportOptions` modern/legacyCompat |
| CryptoBox / FPE-FE1 / RFC3394 / TSS / AONT / PBES2 | mostly yes | yes | same; AONT D-only extra |
| HOTP/TOTP | `HOTP` | `HOTP` | **done** `constructs/hotp.d` RFC 4226/6238 |
| ZFEC / Roughtime | yes | `ZFEC` / `Roughtime` | **done** `constructs/zfec.d`; **done** `constructs/roughtime.d` (`full` only; no online UDP) |
| NIST keywrap (beyond RFC3394) | `NIST_KEYWRAP` | `NIST_Keywrap` | **done** `constructs/nist_keywrap.d` KW+KWP |

## RNG / entropy

| Item | C++ | D | Status |
|---|---|---|---|
| AutoSeeded RNG | `AUTO_SEEDING_RNG` | hardcoded true + `auto_rng.d` | same; flag hygiene |
| HMAC_DRBG | `HMAC_DRBG` | `HMAC_DRBG` | same |
| HMAC_RNG (Botan 1.x) | — | `hmac_rng.d` (default process RNG) | **D-only** keep + harden (S5) |
| X9.31 RNG | — | `X931_RNG` | **D-only** keep |
| ChaCha_RNG / System_RNG / Processor_RNG / Jitter / ESDM | yes | `System_RNG` (R1), `ChaCha_RNG` (R2), `Processor_RNG` (R3) | **System_RNG + ChaCha_RNG + Processor_RNG (RDRAND) done**; Jitter/ESDM missing |
| /dev/urandom, Win32, RDRAND, RDSEED, getentropy, proc walk | different names | `Entropy_*` | **RDRAND + RDSEED + getentropy done** |
| getentropy / rdseed | C++ | — | **missing** accel/OS |
| EGD / BeOS / CAPI | — | `Entropy_EGD`, `Entropy_BEOS`, `Entropy_CAPI` | **D-only** keep |

## TLS / X.509 / codec / filters / compression

| Item | C++ | D | Status |
|---|---|---|---|
| TLS 1.2 common + CBC | `TLS`, `TLS_12`, `TLS_CBC` | `TLS` (monolithic 1.2) | same role; **architecture stay** (delegates, not `Callbacks`) |
| TLS 1.3 | `TLS_13` | `TLS_13` | **T13a+b+c** version + record + hello parse; latest still 1.2; in-process handshake T13d |
| TLS 1.3 PQC groups | `TLS_13_PQC` | `TLS_13_PQC` | **T13p** X25519MLKEM768 + secp256/384 hybrids + pure ML-KEM + libOQS eFrodo `0xFE00`–`0xFE0F` |
| TLS-NULL / ASIO stream | C++ | — | api-skip |
| Session SQL/SQLite | C++ | `SQLite` session manager unread | partial |
| X.509 / OCSP | `X509`, `OCSP` | `X509`; OCSP unread | same gate; staple **missing** |
| System / flatfile / SQL cert stores | C++ | — | **missing** |
| Base64 / hex / PEM | yes | yes | same |
| Base32 / Base58 | C++ | `Base32`, `Base58` | **done** `codec/{base32,base58}.d` RFC 4648 + Base58Check |
| Filters / pipe | yes | yes | same (wiki contract) |
| zlib / bzip2 / lzma | yes | version-gated | same |
| FFI / sodium compat | C++ | — | **api-skip** |
| Engines (OpenSSL, SIMD, ASM, GMP) | **removed in C++ 2.0** | `Engine_*` | **D-only spine — keep** |
| Heartbeats / ChannelID | gone / gone | `heartbeats.d`, ChannelID in credentials | **D-only** keep; do not advertise |

## Counts (algorithm-level, not accel)

- **same:** the 1.12 suite vibe.0 and the wiki already name (AES, SHA-2, HMAC, GCM, RSA, ECDSA, ECDH, X25519, TLS 1.2, X.509, …).
- **D-only (keep, never delete):** CAST-256, MARS, RC2/5/6, TEA/XTEA, SAFER, KASUMI, MISTY1, DESX, MD2, RIPEMD-128, HAS-160, Tiger, CBC-MAC, SSL3 MAC/PRF, TLS 1.0 PRF, PBKDF1, X9.31 RNG, HMAC_RNG, RW, NR, engines, ECB, heartbeats.
- **missing (must appear in the plan):** see `upgrade-randombit.md` full rank table — every **missing** row above has an increment id.

## How this inventory is refreshed

```
git -C ../randombit-botan fetch --tags --prune
git -C ../randombit-botan rev-parse --short origin/master
```

Re-run the `info.txt` walk; add new **missing** rows; do not drop D-only rows.
