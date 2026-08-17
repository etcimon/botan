# Incremental upgrade from randombit/botan (re-plan)

Working branch: **`feature/randombit-sync`** (from etcimon/botan `master` `460336f` / v1.13.9).
This branch is what merges to **etcimon/botan `master`**. Do not commit upgrade code on
`master` directly.

Compare tree: `../randombit-botan` @ `6931ef6fd` (fetched; even with origin/master).
Consumer branch: `../vibe.0` **`feature/botan-delegate-sync`** (from `7b77638`), merges to
etcimon/vibe.0 `master`.

Complete module list: [`inventory-randombit.md`](inventory-randombit.md).
Delegate freeze: [`vibe-delegates.md`](vibe-delegates.md).
Identifiers: [`feature-versions.md`](feature-versions.md).
Copyright: [`copyright.md`](copyright.md).
Pass rules: `../AGENTS-upgrade.md`.

## Architecture decision (why the C++ 3.x shape is not the D shape)

C++ Botan 2.0 deleted engines and replaced TLS function pointers with
`shared_ptr<TLS::Callbacks>`. This D tree’s spine is still 1.12:

- `LibraryState` (thread-local) → `AlgorithmFactory` → **engines** → SCAN prototypes.
- TLS is four delegates + three subclassable managers (`vibe-delegates.md`).
- Features are D `version` identifiers in `dub.json` → `BOTAN_HAS_*` → `static if`.

vibe.0 attaches **exactly** those delegates (`DataReader`/`DataWriter`/`OnAlert`/
`OnHandshakeComplete`/`NextProtocolHandler`/`SNIHandler`) and subclasses `TLSPolicy` /
`TLSCredentialsManager`. `createTLSContext` uses Botan for every version except
`TLSVersion.tls1_3` (OpenSSL), because 1.3 does not exist here.

Therefore:

1. **Do not** rebase onto Botan 3 headers or `Callbacks`.
2. **Do** port algorithms, KATs, and security behaviour from 3.13 into this spine.
3. **Do** allow an internal `tls/tls13/` package (C++ split) **behind** `TLSChannel`,
   selected by `offer_version`. vibe.0 keeps `BotanTLSStream` + `TLSBlockingChannel`.
4. **Do** keep every D-only algorithm (`inventory-randombit.md`) as a versioned husk.
   Removal is not an upgrade.
5. New public types are new modules. Existing ctor signatures and virtuals stay.
6. **Do** keep **ASN.1 and algorithm selection as implemented**: `SCANToken` +
   `retrieve*` / `getCipher` / `getPbkdf` / `getKdf` / `getEmsa` / `getEme` +
   `CoreEngine` name switches + `OIDS` / `pk_algs` / `ber_dec`. Missing algorithms
   are selected by **purpose-assembled SCAN strings** (and OID names for PK), not
   a second factory. See [`scan-asn1.md`](scan-asn1.md).
7. **Do not retire algorithms.** Historic identifiers stay on configuration
   `full` (include-all). Popular/useful ones also go on `standard`
   (`dub-configs.md`). Policy, not `dub.json`, stops offering RC4.
8. **Certificate chain sources** stay `CertificateStore` +
   `TLSCredentialsManager` virtuals, shared by TLS 1.2 and 1.3
   (`cert-stores.md`). Add PEM-bundle and optional system stores; map 1.3
   schemes to existing `algoName`s so vibe.0 `certChain` keeps working.
9. **ASM/SIMD** for a missing or existing algorithm is a **separate
   `version`** (`AES_NI`, `SHA2_32_x86`, …) on `versions-<arch>` only,
   inspired by current D `utils/simd` + engines and the C++ reference,
   written for LDC / GDC / `D_InlineAsm_*` — not C `asm`. Same SCAN name
   and same `dub test` KATs (`asm-accel.md`). Portable `CoreEngine` stays.

## Git sync (do this at the start of every increment)

```
git -C . fetch origin --tags --prune
git -C . status -sb                    # must be on feature/randombit-sync
git -C ../randombit-botan fetch origin --tags --prune
git -C ../randombit-botan merge --ff-only origin/master
git -C ../vibe.0 fetch origin --tags --prune
# vibe.0 stays on feature/botan-delegate-sync unless that increment is vibe-side
```

Update the pin lines in this file and in `inventory-randombit.md` if
`../randombit-botan` `HEAD` moved. Re-walk `src/lib/**/info.txt` only when
`news.rst` / a new tag appears.

This botan branch merges to **its** `master` (etcimon/botan). The LibreCore
`E:\cva6` `master` only hosts the nested clone; it is not the botan remote.

## API freeze (wiki + GitHub Pages + vibe.0)

Unchanged from the previous plan, now with loci:

- Lookup: `retrieve*`, `getCipher`, `getPbkdf`, `haveAlgorithm` (Pages).
- TLS: `TLSClient`/`TLSServer`/`TLSBlockingChannel` ctors; seven aliases;
  `TLSPolicy` virtuals `CustomTLSPolicy` overrides; `latestTlsVersion() == TLS_V12`.
- PK: construct `RSAPrivateKey` / `ECDSAPrivateKey` / … + `PKSigner` + EMSA names.
- memutils types in signatures.
- `all.d` stays a tiny umbrella.

`version(TLS)` does not imply `TLS_13`. Offering 1.3 is `offer_version` plus a
compiled `TLS_13` flag.

## Copyright

Touched files: copy the newer C++ author/year list, add `(C) 2014-2026 Etienne Cimon`.
See `copyright.md`.

## String assembly (how a missing algo is selected)

Do not add a parallel “algorithm registry”. Each increment’s public handle is
the C++ `name()` / `algo_name()` string, consumed by the **existing** purpose
entry (`scan-asn1.md`):

| Increment family | Selection string (examples) | Existing function |
|---|---|---|
| B* blocks | `"ARIA-128"`, `"SM4"`, `"SHACAL2"`, `"Kuznyechik"` | `retrieveBlockCipher` → `getCipher("ARIA-128/GCM")` |
| Hsh* hashes | `"BLAKE2s(256)"`, `"SM3"`, `"Streebog-256"`, `"Ascon-Hash256"` | `retrieveHash`; nested `"HMAC(SM3)"`, `"EMSA4(SM3)"` |
| Hsh6 XOF | `"SHAKE-128"` / `"SHAKE-256"` (no args), `"Ascon-XOF128"`; cSHAKE via name bytes | `getXof`; hash `"SHAKE-128(n)"` stays `retrieveHash` |
| M* MACs | `"GMAC(AES-128)"`, `"KMAC-256"`, `"SipHash"` | `retrieveMac` |
| A* AEAD | `"AES-256/GCM-SIV"`, `"Ascon-AEAD128"` | `getCipher` |
| K* password/KDF | `"Argon2id"`, `"Scrypt"`, `"HKDF(SHA-256)"`, `"SP800-108-Counter(HMAC(SHA-256))"` | `getPbkdf` / `getKdf` |
| P* keys | `algoName` `"Ed25519"`, `"ML-KEM-768"` + `OIDS` / `pk_algs` | construct key; `PKSigner(key, "Raw")` etc. |
| T13* TLS 1.3 | suite `cipher`/`mac`/`prf` remain SCAN (`"AES-128/GCM"`, `"ChaCha20Poly1305"`) | existing record `getAead` / `getKdf` |

A new hash automatically composes: no separate HMAC/PBKDF/EMSA port.

ASN.1 stays `ber_dec` / `der_enc` / `OIDS.setDefaults`. S2/S3 patch that
codec. Do not take 3.13 `DNSName` as a prerequisite for new OIDs.

## Test contract (every increment)

Bound to the **existing** suite (`dub-test.md`). Not C++ `botan-test`, not a
new runner.

1. Vectors from `../randombit-botan/src/tests/data/…` are copied into this
   tree’s `test_data/` in `runTestsBb` form (`Key = Value`, `[section]`). SCAN
   names in those keys are the factory strings (`Hash = SM3`,
   `Cipher = ARIA-128/GCM`). Prefer an **existing family directory** so
   `hash/hash.d` / `block/block_cipher.d` / … pick them up.
2. If a new family is required: `enum SKIP_FOO_TEST = false` in `constants.d`
   and a unittest of the **same format**:
   `static if (BOTAN_HAS_TESTS && !SKIP_FOO_TEST) unittest { globalState();
   runTestsBb / runTestsInDir; testReport; }`.
3. Negative tests (security) use the same `BOTAN_HAS_TESTS && !SKIP_*` gate
   and `CHECK` / `CHECK_MESSAGE` from `botan.test`.
4. Green command is **`dub test --compiler=ldc2`** (default `full` →
   `CanTest` + `unittest`). `dub build` does not compile KAT bodies.
5. Feature-off: identifier absent → empty husk; `haveAlgorithm` / lookup
   throws `AlgorithmNotFound`.
6. TLS: extend `tls/test.d` under `BOTAN_TEST && BOTAN_HAS_TLS`; 1.3 cases
   also `static if (BOTAN_HAS_TLS_13)`. Default offer stays 1.2.
7. `SKIP_*_TEST = true` is not a landing. No skip-to-ship.

T0 is recording that `dub test --compiler=ldc2` on this pin.

## Full increment table

IDs are stable. **S** = security on existing code. **H** = hygiene (flags/docs).
**B** = block, **Hsh** = hash/XOF, **M** = MAC, **A** = AEAD/mode, **K** = KDF/PBKDF,
**P** = pubkey, **R** = RNG, **T** = TLS/X.509, **C** = codec/constructs.
Do them in the **Seq** order, one green pass each (split a row if it is too large).

### 0. Gate

| Seq | ID | What | Tests | API |
|---|---|---|---|---|
| 0 | T0 | Record `dub test --compiler=ldc2` on this pin | the command itself | none |

### 1. Security backports (no new types)

| Seq | ID | What | C++ cue | D locus | Tests |
|---|---|---|---|---|---|
| 1 | S1 | Reject RSA cipher/sig not exactly `\|n\|` | news 3.13 | `pubkey/algo/rsa.d`, `pk_pad`, TLS `messages.d` | n±1 blobs fail; `rsa_*.vec` pass |
| 2 | S5 | RNG `clear` + empty `randomize` must not mark seeded | GH #5839 | `rng/auto_rng.d`, `hmac_rng.d` | sequence unittest |
| 3 | S6 | Default `TLSPolicy`: no FFDH, no RC4/3DES/static-RSA/MD5; prefer ECDSA | news 3.13 | `tls/policy.d` | policy unit on `ciphersuiteList`; DH version still compiles |
| 4 | S7 | RSA keygen floor 2048 unless `version(RSA_Insecure)` | modern floors | `rsa.d` | keygen 1024 throws; **ctor signature unchanged** |
| 5 | S8 | Bitslice AES word size / existing CT notes | news 3.14 | `block/aes.d` | **done** portable bitslice (2/4 blocks); T-tables gone; ISA engines unchanged |
| 6 | S2 | BER indefinite-length DoS bound | CVE-2026-44378 class | `asn1/ber_dec.d` | **done** max 16 nested indefinite; 17-deep throws |
| 7 | S3 | DN nameConstraint structure | CVE-2026-48057 class | `x509_ext.d` | **done** `NameConstraints` decode: empty lists / empty ext / min≠0 / max present rejected |
| 8 | S4 | OCSP fetch: no redirect SSRF | 3.13 advisory | `cert/x509/ocsp.d` + `http_util` | **done** `ocspHttpPost` / `setHttpExchangeHandler`; 0 redirects; no handler → skip |

### 2. Flag hygiene (proves cherry-pick)

| Seq | ID | What | Tests |
|---|---|---|---|
| 9 | H1 | `HKDF`, `AUTO_SEEDING_RNG`, `CODEC_FILTERS`, `CIPHER_MODE_PADDING` become real `version`s | existing hkdf/codec tests; feature-off `hash` still builds |

### 3. Missing algorithms (complete)

Each row is one identifier family. C++ path is under `../randombit-botan/src/lib/`.

#### Password / KDF (highest non-TLS value)

| Seq | ID | `version` | C++ | D dest | Tests |
|---|---|---|---|---|---|
| 10 | K1 | `Argon2`, `Argon2_Fmt` | `pbkdf/argon2`, `passhash/argon2fmt` | **done** portable `pbkdf/argon2.d` + `getPbkdf("Argon2id")`; PHC `$argon2{d,i,id}$` via `generateArgon2Pwhash` / `checkArgon2Pwhash` | official + golang KATs; `passhash/argon2.vec` 3+3 |
| 11 | K2 | `Scrypt` | `pbkdf/scrypt` | **done** `pbkdf/scrypt.d` + `getPbkdf("Scrypt")` | RFC 7914 + OpenSSL KATs; N/r/p/overflow negatives; 1 GiB cases omitted |
| 12 | K3 | `SP800_108`, `SP800_56A`, `SP800_56C` | **done** `kdf/sp800_{108,56a,56c}.d` + `getKdf` | `test_data/kdf/sp800_*.vec` 299×3 + 521 + 40 |
| 13 | K4 | `KDF1_18033`, `XMD` | **done** `kdf/kdf1_iso18033.d` + `kdf/xmd.d` (`expandMessageXmd`, not a SCAN KDF) | `kdf/kdf1_iso18033.vec` 4; `xmd/xmd.vec` 20 |
| 14 | K5 | `PBKDF_BCrypt`, `PGP_S2K`, `PKCS12_KDF` | **done** `pbkdf/{bcrypt_pbkdf,pgp_s2k,pkcs12_kdf}.d` + `getPbkdf` | `pbkdf/{bcrypt_pbkdf,pgp_s2k,pkcs12_kdf}.vec` 36+13+14 |

#### Signatures / KA that TLS and X.509 can use later

| Seq | ID | `version` | C++ | D dest | Tests |
|---|---|---|---|---|---|
| 15 | P1 | `Ed25519` | `pubkey/ed25519` | **done** `pubkey/algo/ed25519*.d` + `pk_algs` + OID `1.3.101.112`; Pure + Ed25519ph (SHA-512 + RFC 8032 dom2) + hashed SHA-256 | `ed25519.vec` 709 Pure + Ed25519ph 1 + SHA-256 1; `ed25519_verify.vec` 62; `ed25519_key_valid.vec` 10 |
| 16 | P2 | (alias) `X25519` SCAN | `pubkey/x25519` | **done** OID `1.3.101.110` + `pk_algs` name alias; `algoName` stays `Curve25519` | `c25519_scalar.vec` 18 + `x25519.vec` 90 Wycheproof |
| 17 | P3 | `Ed448`, `X448` | `pubkey/curve448` | **done** `pubkey/algo/{curve448_gf,curve448_scalar,ed448,x448}.d` + OIDs `1.3.101.113` / `1.3.101.111`; Pure + Ed448ph / SHAKE-256(512) (empty ctx) | `ed448.vec` 87 Pure + Ed448ph 1 + SHAKE-256(512) 1; `x448.vec` 498 |
| 18 | P4 | `SM2` | `pubkey/sm2` | **done** `pubkey/algo/sm2.d` + `pk_algs` + OIDs `1.2.156.10197.1.301.1` / `sm2p256v1`; sign + encrypt; `full` only | `sm2_sig.vec` 7; `sm2_enc.vec` 5; `sm2_invalid.vec` 20 |
| 19 | P5 | `ECGDSA`, `ECKCDSA` | matching | **done** `pubkey/algo/{ecgdsa,eckcdsa}.d` + inverse public \(Y=x^{-1}G\); `full` only; curve `frp256v1` added | `ecgdsa.vec` 12; `eckcdsa.vec` 11 |
| 20 | P6 | `ECIES` | `pubkey/ecies` | **done** `pubkey/algo/ecies.d` (ISO 18033-2 KEM+DEM+MAC; not `pk_algs`); `full` only; secp112r2 cofactor 4 | `ecies.vec` 12; `ecies-18033.vec` 2 |

#### Symmetric / hash fill (independent, any order after H1)

| Seq | ID | `version` | C++ | Tests |
|---|---|---|---|---|
| 21 | B1 | `ARIA` | `block/aria` | **done** `block/aria.d` 128/192/256 | `block/aria.vec` 9 |
| 22 | B2 | `SHACAL2` | `block/shacal2` | **done** `block/shacal2.d` | `block/shacal2.vec` 1021 |
| 23 | B3 | `SM4` | `block/sm4` | **done** `block/sm4.d` CT `SM4_Tp` | `block/sm4.vec` 22 |
| 24 | B4 | `Kuznyechik` | `block/kuznyechik` | **done** `block/kuznyechik.d` | `block/kuznyechik.vec` 65 |
| 25 | Hsh1 | `BLAKE2S` | `hash/blake2s` | **done** `hash/blake2s.d` | `hash/blake2s.vec` 257 |
| 26 | Hsh2 | `SM3` | `hash/sm3` | **done** `hash/sm3.d` | `hash/sm3.vec` 139 |
| 27 | Hsh3 | `Streebog` | `hash/streebog` | **done** `hash/streebog.d` 256/512 | `hash/streebog.vec` 265 |
| 28 | Hsh4 | `Ascon_Hash256` | `hash/ascon_hash256` | **done** `hash/ascon_hash256.d` + `ascon_p.d` | `hash/ascon_hash256.vec` 106 |
| 29 | Hsh5 | `Truncated_Hash` | `hash/trunc_hash` | **done** `hash/trunc_hash.d` | `hash/truncated.vec` 7 |
| 30 | Hsh6 | `SHAKE_XOF`, `CSHAKE_XOF`, `Ascon_XOF` | **done** `xof/{xof,shake_xof,cshake_xof,ascon_xof128}.d` + `getXof` | `test_data/xof/{shake,cshake,ascon_xof128}.vec` 177+8+106 |
| 31 | M1 | `GMAC`, `KMAC`, `BLAKE2BMac`, `SipHash` | `mac/*` | **done** | `mac/{siphash,gmac,kmac,blake2bmac}.vec` 59+143+14+273 |
| 32 | A1 | `AEAD_GCM_SIV` | `modes/aead` gcm_siv | **done** `gcm_siv.d` + `polyval.d`; `aead/gcm_siv.vec` 82 |
| 33 | A2 | `AEAD_ASCON128` | `modes/aead/ascon_aead128` | **done** `ascon_aead128.d` | `aead/ascon_aead128.vec` 121 |
| 34 | Str1 | `SHAKE_Cipher` | `stream/shake_cipher` | **done** `stream/shake_cipher.d` on SHAKE XOF; `full` only; SCAN `SHAKE-128`/`SHAKE-256` (no args) + `-XOF` aliases | `stream/shake.vec` 1145+1145 |

#### Post-quantum (keys first; no TLS)

| Seq | ID | `version` | C++ prefer | Tests |
|---|---|---|---|---|
| 35 | P7 | `ML_KEM` | `pubkey/kyber/ml_kem` (not 90s) | **done** `pubkey/algo/ml_kem.d` FIPS 203 (not Kyber-90s/R3); G(d‖k) / G(m‖H(ek)) / J(z‖c); OIDs `2.16.840.1.101.3.4.4.{1,2,3}`; seed PKCS#8 (64 B). `full` only | ACVP keygen 75 + encap 75 + pairwise 3 |
| 36 | P8 | `ML_DSA` | `pubkey/dilithium/ml_dsa` | **done** `pubkey/algo/ml_dsa.d` FIPS 204 + Dilithium R3 modern; G(ξ‖k‖l) / R3 G(ξ); ctx empty / R3 no prefix; seed PKCS#8 (32 B) / R3 expanded. `full` only | verify 221 + pairwise 3 + R3 hashed KAT |
| 37 | P9 | `SLH_DSA` | `sphincsplus/slh_dsa_*` | **done** `pubkey/algo/slh_dsa.d` FIPS 205 SHAKE+SHA2 128/192/256 s/f + HashSLH-DSA pre-hash + SPHINCS+ r3.1 (empty prefix, FORS LSB-first). `full` only | generic SHAKE-128s 2 + HashSigDet SHAKE/SHA2-128f + pairwise both 128f + HashSLH SHA-256/SHAKE-256 + SPHINCS+ HashSigRand shake/sha2-128f |
| 38 | P10 | `Classic_McEliece` | `pubkey/classic_mceliece` | **done** `pubkey/algo/classic_mceliece.d` NIST+ISO 16 names; Goppa/Benes/GE; implicit reject. `full` only | hashed KAT all 16 (one CTR_DRBG generate per encaps attempt) |
| 39 | P11 | `FrodoKEM` | `pubkey/frodokem` | **done** `pubkey/algo/frodo_kem.d` SHAKE+AES-A 640/976/1344 + eFrodo; ISO/NIST R3. `full` only | pairwise 12 + implicit reject + factory/OID + `frodokem_kat.vec` CTR_DRBG (25/instance) |
| 40 | P12 | `XMSS`, `HSS_LMS` | matching | **XMSS** verify+keygen+sign (no BDS); **HSS-LMS** verify+keygen+sign (SECRET_METHOD 2; no BDS) `pubkey/algo/hss_lms.d`. `full` only | XMSS verify 63 + invalid 336 + sign SHA2_10_256 + keygen SHA2_10_256; HSS verify 5 + invalid 4 + sign 2 |
| 41 | P13 | `Hybrid_KEM` | `pubkey/hybrid_kem` | **done** `pubkey/algo/hybrid_kem.d` Hybrid-ML-KEM-768-X25519, SHA-3-256 combiner | pairwise + mutate reject + factory/OID |
| 42 | P14 | `Kyber_R3` / `Dilithium_R3` / `SPHINCS_PLUS` | deprecated C++ | **SPHINCS+ r3.1**; **Kyber R3 + 90s**; **Dilithium R3 + AES** under `ML_DSA` | Dilithium hashed KAT R3+AES; Kyber 25/instance |

#### RNG / OS

| Seq | ID | `version` | C++ | Tests |
|---|---|---|---|---|
| 43 | R1 | `System_RNG` | `rng/system_rng` | **done** `rng/system_rng.d`; Windows `RtlGenRandom`, Posix `/dev/urandom`; not the AutoSeeded default | interface + two-buffer smoke |
| 44 | R2 | `ChaCha_RNG` | `rng/chacha_rng` | **done** `rng/{stateful_rng,chacha_rng}.d`; HMAC-SHA-256 + ChaCha20; `full`+`standard` | `rng/chacha_rng.vec` 21 |
| 45 | R3 | `Processor_RNG` | `rng/processor_rng` | **done** `rng/processor_rng.d`; x86 RDRAND + POWER DARN (XOR two conditioned 64-bit draws; Linux HWCAP2 probe). 10 retries; not AutoSeeded default. `full`+`standard` | available + name + 0–127-byte randomize |
| 46 | R4 | `Entropy_Getentropy` / `Entropy_Rdseed` | `entropy/*` | **done** `entropy/{rdseed,getentropy}.d`; RDSEED mixed not trusted; getentropy 256 B on POSIX. `full` + x86_64 Rdseed | name + poll |

#### X.509 / PKCS / constructs / codec / cert stores

| Seq | ID | `version` | C++ | Tests |
|---|---|---|---|---|
| 47 | C1 | `PKCS12` | `pkcs12/` | **done** parse + export (`constructs/pkcs12.d` + `pkcs12_pbe.d`); RFC 7292 + OpenSSL empty-pwd; `PKCS12ExportOptions` modern/legacyCompat | C++ `pkcs12/*.p12` fixtures + export roundtrip |
| 48 | C2 | `SPAKE2P` | `pake/spake2p` | **done** `constructs/spake2p.d`; RFC 9383 HMAC suites from_prehashed; `full`+`standard` | `pake/spake2p.vec` 5 |
| 49 | C3 | `HOTP` | `misc/hotp` | **done** `constructs/hotp.d` HOTP+TOTP; HMAC(SHA-1/256/512); `full`+`standard` | `otp/hotp.vec` 32; `otp/totp.vec` 3 |
| 50 | C4 | `NIST_Keywrap` | `misc/nist_keywrap` | **done** `constructs/nist_keywrap.d` KW (RFC 3394 + 8-byte ECB) + KWP (RFC 5649); `full`+`standard` | `keywrap/nist_key_wrap.vec` 7+129; invalid 7+3 |
| 51 | C5 | `Base32`, `Base58` | `codec/base32`, `base58` | **done** `codec/{base32,base58}.d`; RFC 4648 + Bitcoin Base58Check; `full`+`standard` | `codec/base32.vec` 33; `base58.vec` 50; `base58c.vec` 9 |
| 52 | C6 | `EME_RAW` | `pk_pad/…/eme_raw` | **done** `pk_pad/eme_raw.d` + `getEme("Raw")`; unpad strips leading zeros; `full`+`standard` | pad/unpad + RSAES 123 still green |
| 53 | C7 | `ISO9796` | `pk_pad/…/iso9796` | **done** `pk_pad/iso9796.d` DS2/DS3 inherit `EMSA`; `getEmsa("ISO_9796_DS2(SHA-256)")`; `full` only | `pubkey/iso9796.vec` 6 |
| 54 | C8 | `ZFEC` | `misc/zfec` | **done** `constructs/zfec.d` portable Vandermonde; `full` only | `zfec.vec` encode + decode-all + last-K |
| 55 | CS1 | `CertStore_Flatfile` + `CertificateStoreInMemory.addFromFile` | `x509/certstor_flatfile` | **done** PEM bundle + `SKIP_X509_TEST` |
| 55b | CS2 | `CertStore_System` | `x509/certstor_system*` | **done** Windows live store + POSIX bundle paths |
| 55c | CS3 | 1.3 scheme → `algoName` map for `certChain` | policy helper | **done** same credentials object answers `"RSA"` / `"ECDSA"` / `"Ed25519"` |
| 55d | H2 | add dub configuration `standard` (popular); `full` stays include-all | `dub-configs.md` | **done** `dub test` still `full`; `dub build -c standard` PASS |

### 4. TLS 1.3 (same delegates)

| Seq | ID | What | Tests | vibe.0 |
|---|---|---|---|---|
| 56 | T12 | Split nothing yet; document `TLS_12` as implicit in `TLS` | existing tls/test.d | none |
| 57 | T13a | `version(TLS_13)` + `TLS_V13` enum; **`latestTlsVersion()` stays 1.2** | **done** `TLS_V13=0x0304`; known iff `TLS_13`; default policy rejects 1.3; 1.2 handshakes still run | none |
| 58 | T13b | Record layer 1.3 behind `TLSChannel` (`tls/tls13/`) | **done** `tls/tls13/{record_layer,cipher_state}.d`; unprotected + AEAD wrap via `getAead`; suites 0x1301/02/03; not wired into `TLSChannel` until T13d | RFC 8448 ClientHello record + CCS + GCM roundtrip | none |
| 59 | T13c | Handshake 1.3 parse, `supported_versions`, key_share; still `receivedData`/`isActive` | **done** `tls/tls13/{hello_ext,hello}.d`; CH identified as legacy 0x0303 + `supported_versions` contains 0x0304; SH version from extension; HRR magic random; parse-only (no 1.3 emit from 1.2 ctor, not wired into `TLSChannel`) | RFC 8448 + 1.2 hello KATs (`test_data/tls_13/`) | none |
| 60 | T13d | In-process client↔server at 1.3 when both offer 1.3 | **done** in-process `isActive` + `TLS13RecordLayer` handshake/app keys; default policy still rejects 1.3; latest stays 1.2 | none |
| 61 | T13e | OCSP staple `OCSP_Staple` (needs S4) | **done** `status_request` in CH; 1.3 CertificateEntry CertificateStatus; `ocspStaple` on creds (default empty); S4 HTTP is the fetch seam | none |
| 61b | Vec | C++ KATs for already-ported D APIs | **done** drop-in + decode/decrypt: TLS 1.2 messages (incl. `CertificateStatus`), RFC3394, Base64, POLYVAL, RFC6979, FPE-FE1, CryptoBox raw, SPAKE2+ custom, HKDF-label, pad, bcrypt/passhash9, ECDH, ECDSA/DSA verify (FIPS leftmost-n-bits via `EMSA_RAW`), RSA-PSS, RSA OAEP decrypt (`OAEP(Hash,MGF1(Hash2)[,label])`), RSA invalid PKCS1v15, ElGamal enc/dec, DH invalid (subgroup), ECC var-point mul / mul2, GOST explicit verify, TLS CBC+HMAC AEAD (`tls_cbc.d` MAC-then-encrypt / EtM; Unique.opAssign must not null names before copy; `tls_cbc_kat.vec` + `tls_cbc.vec` ZeroMac/noop Valid), ASN.1 OID/time/string, PKCS1 EME unpad, X.509 DN compare, ECC invalid SPKI (order/cofactor), ECDSA Wycheproof DER (strict X.690), explicit-curve PKCS8, RFC 3766 `ifWorkFactor` + NIST `dlExponentSize`, `PSS_Raw` + `rsa_pss_raw`, SIV multi-AD (`setAssociatedDataN` on `AEADMode` + `siv_ad.vec`), charset UCS-2/UCS-4/UTF-8 (`charset.vec`), `poly_dbl` 8/16/24/32/64/128, salted Blowfish EKS, C++ `bn/*.vec` (add/sub/mul/sqr/div/mod/shift/powmod/gcd/jacobi/isprime/invmod/cmp/perfect_square/from_radix; large `ressol` leftover), TSS recovery, `readKv` + `read_kv.vec`, OCB RFC 7253 long from `ocb_long.vec`, IPv4/IPv6 + CIDR + non-canonical IPv6 + name-constraint IP masks, DNS name + RFC 6125 wildcard; `gcd(0,n)=|n|`; `isPrime` table omits sentinel; NIST hash Monte Carlo + 1 MiB long-rep (`hash_mc.vec` / `hash_rep.vec`, skip 1 GiB), `CalendarPoint` + `dates.vec`, SHA-512-256 (NIST IVs, not truncated SHA-512), `tryParseX509Dn` RFC 4514 (`x509_dn_valid`/`invalid`/`ordering`), C++ 3 `randomInteger` + `bn/random.vec`, TSS generation (`Hash=None`/`SHA-1`/`SHA-256`, C++ share-length header), RFC 4514 `X509_DN.toString`, BER/DER Limits (boolean/INTEGER, long-form tag, EOC, indefinite length, 128 MiB object cap, OID consume, BIT STRING padding) + `asn1_decoding.vec` walker, OCB wide-block (`ocb_wide.vec` / `ocb_wide_long.vec` Toy128/192/256/512 + SHACAL2; draft-krovetz-ocb-wide MASKLEN/stretch), `ASN1PrettyPrinter` (`asn1_print` 8 DER/txt; indefinite BER strips trailing EOC from `value`), Argon2 PHC (`passhash/argon2fmt.d` + `passhash/argon2.vec`), TLS extension parse (`tls/extensions/parsing`: ALPN, supported_groups, signature_algorithms_cert, supported_versions, cookie, key_share CH/SH/HRR), ECDSA key recovery (`ECDSAPublicKey` from `(msg,r,s,v)` + `recoveryParam`; `ecdsa_key_recovery.vec`), PKCS8 unencrypted BER PrivateKeyInfo (short secp521r1 `key_encoding.vec`) | none |
| 61c | T12n | Lucky13 extra HMAC compressions + `TLS_NULL` | **done** `tls_cbc.d` MtE failure path `performAdditionalCompressions` (SHA-1/256 block 64 / SHA-384 128); `checkTlsCbcPadding` via `CTMask`; `version(TLS_NULL)` `tls/tls_null.d` RFC 5246 GenericStreamCipher + `tls_null.vec`; `full` only (not `standard`) | `tls_cbc` + `tls_null` KATs | none |
| 61d | T13f | Dummy CCS + KeyUpdate | **done** `KEY_UPDATE=24`; `TLS13KeyUpdate`; `TLS13CipherState.update{Write,Read}Keys` (`traffic upd`); dummy CCS before first protected 1.3 record (RFC 8446 D.4) | KeyUpdate parse + traffic-upd roundtrip + CCS emit | none |
| 61e | XofA | AES-256/CTR XOF | **done** `xof/aes_ctr_xof.d` `AES_256_CTR_XOF`; `version(AES_CTR_XOF)`; `full` only | `xof/aes256_ctr.vec` | none |
| 62 | T13p | `TLS_13_PQC` (needs T13d + P7) | **done** X25519MLKEM768 `0x11EC` + SecP256r1MLKEM768 `0x11EB` + SecP384r1MLKEM1024 `0x11ED` + pure ML-KEM `0x0200`/`01`/`02` + libOQS eFrodo `0xFE00`–`0xFE0F` (classical-first); `tls13PqcKeyShareGroups()`; `full` only | hybrid + pure ML-KEM + eFrodo pairwise SS + memutils repeat | none |
| 63 | V1 | **vibe.0** `feature/botan-delegate-sync`: **done** `createTLSContext(tls1_3)` builds `BotanTLSContext` + `defaultProtocolOffer = TLS_V13`. Stream remains `BotanTLSStream` + same four delegates. After CS1: `useTrustedCertificateFile` loads a PEM **bundle**. | vibe HTTPS/h2 example | **that** repo |

T13* must not change `TLSBlockingChannel` ctors. Internal impl class is allowed.

### 5. Deliberately never as D public API

`ffi`, `compat/sodium`, `tls/asio`, TPM/PKCS#11 providers, Roughtime online UDP,
C++ `PasswordHash` class rename (D keeps `getPbkdf` / SCAN names).

#### ISA / ASM (never in portable `versions`)

Each C++ `*_aes_ni` / `*_avx2` / `*_sha` / `*_armv8` row in the inventory is
its own increment when ported: new `version`, `versions-x86_64` (or later
arch), engine arm, **same** family `.vec`. Do not batch “all AVX-512” in one
pass. First useful ones (AES-NI already exists): **SHA-2 SIMD done** (`SHA2_32_SSE2`),
**ChaCha SIMD/AVX2 done**, **SM4/ARIA/Camellia HWAES done**, **SHA-NI done** (`SHA2_32_X86`). Further ISA flavours leftover (AVX-512).

## Suggested batching for humans

A single contributor should not open P7 and T13a in one pass. Natural merge trains
on `feature/randombit-sync`:

1. T0 → S1,S5,S6,S7 → H1  (safe, vibe.0-invisible)
2. CS1 then CS3            (bundle store + 1.2/1.3 certChain map) before T13
3. H2 (`standard` config); `full` remains include-all, nothing retired
4. K1,K2 then P1–P3        (**done** passwords + Ed25519/Ed448 Pure + X25519/X448)
5. R1 then independent B/Hsh/M/A rows as needed  (**R1 done**)
6. T13a–T13d               (still no vibe.0 merge)
7. V1 on vibe.0 branch     (delegates + bundle file helper)
8. P7–P13 then T13p
7. Remaining inventory rows opportunistically

D-only algorithms are **not** a train. Leave them.

## Loci every increment still touches

`constants.d`, `dub.json`, `CoreEngine` or `pk_algs`/`oids`, `test_data/`, this table
(move row to done), copyright on touched files.

## Invariants

- Wiki / Pages / vibe.0 delegate ctors and `TLSPolicy` virtuals do not move.
- Algorithms are not retired; `full` lists all, `standard` lists popular (`dub-configs.md`).
- ASM/SIMD is a separate ISA `version` + `dub test` on the same SCAN KATs (`asm-accel.md`).
- Cert chains stay `CertificateStore` + `TLSCredentialsManager` for 1.2 and 1.3 (`cert-stores.md`).
- `../randombit-botan` is never a dub dependency.
- `BOTAN_VERSION_*` stays the 1.12.3 lineage claim; D package version stays
  `dub.json` `"version"` (1.13.9 until a release pass).
- Feature without the test contract is not implemented.
- Work stays on `feature/randombit-sync` until asked to merge to botan `master`.

## Open

- T0 unverified.
- OCSP HTTP or not (S4).
- BER/DN unread (S2/S3).
- SHA-512/256 SCAN: **done** alias `SHA-512/256` → `SHA-512-256`; `retrieveHash` both names.
- vibe.0 `peerCertificate` assert — vibe-side, not botan.
