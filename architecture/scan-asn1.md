# SCAN assembly + ASN.1 — keep as implemented

This is a **design goal**, not a new subsystem. Missing algorithms from
`inventory-randombit.md` are wired into the machinery that already exists.
They are not selected by new D types, a C++ 3.x provider registry, or a
second OID/ASN.1 stack.

## What stays

### String selection (SCAN + factory + engines)

Callers already assemble algorithms as strings. `SCANToken`
(`algo_base/scan_token.d`) parses JCE/SCAN form: `Name`, `Name(arg[,arg…])`,
`Name/mode`, `Name/mode/padding`. `LibraryState.initialize` installs
`SCANToken.setDefaultAliases()` (`scan_token.d:257–288`) so wiki names
(`"EMSA4(SHA-512)"`, `"EME-PKCS1-v1_5"`, `"SHA-1"`) deref to the canonical
token the engines switch on.

Resolution is **purpose-specific**, not one mega-map:

| Purpose | Entry | How the string is assembled | Where the arm lives |
|---|---|---|---|
| Block / stream / hash / MAC prototype | `retrieve*` / `AlgorithmFactory.prototype*` | bare SCAN name (`"AES-256"`, `"SHA-256"`, `"HMAC(SHA-256)"`) | `CoreEngine.findBlockCipher` / `findHash` / `findMac` / `findStreamCipher` (`request.algoName` + `request.arg`) |
| Composed cipher for `Pipe` | `getCipher` | `"CIPHER/MODE[/PADDING]"` (`"AES-256/GCM"`, `"AES-256/CBC/PKCS7"`) | `CoreEngine.getCipher` splits on `/` (`core_engine.d:131–186`), looks up the block/stream by the first part, builds the mode from the rest |
| PBKDF | `getPbkdf` | `"PBKDF2(SHA-256)"`, `"Scrypt"` | `findPbkdf` |
| KDF / TLS PRF | `getKdf` | `"KDF2(SHA-256)"`, `"HKDF(SHA-256)"` / `"HKDF(HMAC(SHA-256))"`, `"HKDF-Extract(…)"`, `"HKDF-Expand(…)"`, `"TLS-12-PRF(SHA-256)"` | `kdf/kdf.d` `SCANToken` + `macOrHmac` / `af.makeHashFunction(arg)`; returned object **is** a `KDF` (`cast(HKDF)` / `HKDF_Extract` / `HKDF_Expand`) |
| Signature encoding | `getEmsa` | `"EMSA1(SHA-256)"`, `"PSSR(SHA-512)"`, `"EMSA3(SHA-256)"`, `"ISO_9796_DS2(SHA-256)"`, `"ISO_9796_DS3(SHA-1,imp)"` | `pk_pad/factory.d`; returned object **is** an `EMSA` (`cast(ISO9796_DS2)` / `ISO9796_DS3`) |
| Encryption encoding | `getEme` | `"OAEP(SHA-256)"`, `"PKCS1v15"` | same factory |
| Public-key **algorithm** | construct the key type; `algoName` is a string | `"RSA"`, `"ECDSA"`, `"Ed25519"` | `CoreEngine.get*Op` switches on `key.algoName`; **not** `retrieve*` |
| Public-key **on the wire** | `AlgorithmIdentifier.oid` | OID → name via `OIDS.lookup` | `pk_algs.makePublicKey` / `makePrivateKey` (`pk_algs.d:32–80`) |
| TLS suite | IANA id in `ciphersuite.d` | suite fields are SCAN names (`cipher`, `mac`, `prf`) already | record layer calls `getAead` / `retrieveMac` / `getKdf`; TLS 1.3 record AEAD is `getAead("AES-128/GCM")` (`cast(AEADMode)`) |

`haveAlgorithm(name)` is the existence probe. A disabled `version` means the
`static if` arm is absent: the same string throws `AlgorithmNotFound`. That
**is** cherry-pick.

Do not replace this with C++ 3.x `BlockCipher::create`, a global
`std::unique_ptr` factory, or vibe.0 constructing concrete `ARIA128` types.
vibe.0 never names block ciphers; it names `TLSPolicy` / suites. New AEAD
that TLS might one day offer still enter as SCAN strings on the suite row.

### ASN.1 (BER/DER + OID table)

The D ASN.1 stack stays:

- `asn1/ber_dec.d`, `der_enc.d`, `asn1_oid.d`, `asn1_obj.d`, `alg_id.d`
- `asn1/oids.d` — `OIDS.setDefaults()` / `addOid` / `lookup(oid)` / `lookup(name)`
- `AlgorithmIdentifier` on keys and X.509
- `pk_algs.d` — `OIDS.lookup(alg_id.oid)` then `if (alg_name == "RSA") …`

C++ 3.13 added `DNSName` / `EmailAddress` / `URI` value types and a different
OID table shape. Those are **not** a replacement for `ber_dec` / `OIDS`. A
later increment may add helper types **beside** the existing decoder; it must
not reroute `makePublicKey`, PKCS#8, or `X509Certificate` through a new ASN.1
library.

Security backports S2/S3 (BER DoS, DN nameConstraint) edit **this** decoder
and `x509_dn.d`. They do not introduce the 3.13 name types as a prerequisite.

## How a missing algorithm is integrated

One pattern, every increment (`upgrade-randombit.md`):

1. **Canonical SCAN / `algoName` string** — copy C++ `name()` / `algo_name()`
   (e.g. `"ARIA-128"`, `"Argon2id"`, `"Ed25519"`, `"ML-KEM-768"`). Add
   `SCANToken.addAlias` only when the wiki or C++ already documents an alias.
2. **`version` + `BOTAN_HAS_*` + `static if`** — `feature-versions.md`.
3. **Purpose arm** — exactly one of the rows in the table above. A new hash
   is a `findHash` arm; it automatically becomes usable inside
   `"HMAC(NEW-HASH)"`, `"PBKDF2(NEW-HASH)"`, `"EMSA4(NEW-HASH)"` because those
   factories already call `af.makeHashFunction(request.arg(0))`.
4. **OID row** (PK / X.509 / PKCS#8 only) — `OIDS.addOid` in `setDefaults`
   plus a `pk_algs` `if (alg_name == "…")` arm. Do not invent a second OID
   map.
5. **TLS** (only if a suite exists) — new `ciphersuite.d` `byId` row whose
   `cipher` / `mac` / `prf` fields are SCAN strings that already resolve.
6. **Tests** — same strings in `test_data/` `.vec` files, run by **`dub test`**
   through the existing `BOTAN_HAS_TESTS && !SKIP_*` unittests (`dub-test.md`).
   `haveAlgorithm` true when on; `AlgorithmNotFound` when off.

Composed names are **assembled from purpose**, not hard-coded as new APIs:

| New primitive | Callers assemble |
|---|---|
| `ARIA-128` (block) | **done** `retrieveBlockCipher("ARIA-128")`; `getCipher("ARIA-128/GCM")`; `getCipher("ARIA-128/CBC/PKCS7")` |
| `SM4` | **done** `retrieveBlockCipher("SM4")`; `"SM4/CBC"`, `"SM4/CTR"` |
| `SHACAL2` | **done** `retrieveBlockCipher("SHACAL2")`; CMAC via `"CMAC(SHACAL2)"` |
| `Kuznyechik` | **done** `retrieveBlockCipher("Kuznyechik")`; `"Kuznyechik/CTR"` |
| `BLAKE2s(256)` | **done** `retrieveHash("BLAKE2s(256)")`; `"HMAC(BLAKE2s(256))"` |
| `SM3` / `Streebog-256` / `Ascon-Hash256` | **done** `retrieveHash("SM3")` / `"Streebog-256"` / `"Ascon-Hash256"` |
| `SHAKE-128` / `SHAKE-256` as XOF | **done** `getXof("SHAKE-128")` (no args); hash form stays `retrieveHash("SHAKE-128(256)")` |
| `SHAKE-128` / `SHAKE-256` as stream | **done** `retrieveStreamCipher("SHAKE-128")` (no args); aliases `SHAKE-128-XOF` / `SHAKE-256-XOF`; needs `SHAKE_XOF` |
| `Ascon-XOF128` | **done** `getXof("Ascon-XOF128")` |
| `cSHAKE-128` / `cSHAKE-256` | **done** `getXof("cSHAKE-128", name)` — not a public SCAN alias (C++ keeps it internal) |
| `GMAC(AES-128)` | **done** `retrieveMac("GMAC(AES-128)")` — `findMac` sees `algoName=="GMAC"`, arg `"AES-128"`; `MacStart` nonce |
| `KMAC-256` / `SipHash` / `BLAKE2b` MAC | **done** `retrieveMac("SipHash")` / `"KMAC-128"` / `"KMAC-256"` / `"BLAKE2b"` / `"BLAKE2b(256)"` |
| `AES-256/GCM-SIV` | **done** `getAead`/`getCipher("AES-256/GCM-SIV")` — mode token `GCM-SIV` (not RFC 5297 `SIV`) |
| `Ascon-AEAD128` | **done** `getAead("Ascon-AEAD128")` |
| `Argon2id` / `Argon2i` / `Argon2d` / `Scrypt` | `getPbkdf("Argon2id")` |
| `Bcrypt-PBKDF` | **done** `getPbkdf("Bcrypt-PBKDF")` (iterations = rounds) |
| `OpenPGP-S2K(SHA-1)` | **done** `getPbkdf` — iterations are bytes hashed |
| `PKCS12-KDF(SHA-256,1)` | **done** `getPbkdf` — id 1=key, 2=IV, 3=MAC |
| `HKDF(SHA-256)` | **done** `getKdf("HKDF(SHA-256)")` / `"HKDF(HMAC(SHA-256))"` returns `HKDF : KDF`; also `HKDF-Extract` / `HKDF-Expand` |
| `SP800-108-Counter(HMAC(SHA-256))` | **done** `getKdf("SP800-108-Counter(HMAC(SHA-256))")` (+ Feedback/Pipeline; optional `,r,L`) |
| `SP800-56A(SHA-256)` / `SP800-56A(HMAC(SHA-256))` / `SP800-56A(KMAC-128)` | **done** `getKdf` one-step |
| `SP800-56C(HMAC(SHA-256))` | **done** `getKdf` extract + SP800-108-Feedback expand |
| `KDF1-18033(SHA-256)` | **done** `getKdf("KDF1-18033(SHA-256)")` — not IEEE `KDF1` |
| `expandMessageXmd` | **done** RFC 9380 helper in `kdf/xmd.d`; not a `getKdf` name |
| `Ed25519` | **done** `Ed25519PrivateKey` + `PKSigner(key, "Raw")` / `"Ed25519ph"` / `"SHA-256"`; OID `1.3.101.112` |
| `X25519` | **done** OID `1.3.101.110` + `pk_algs` name alias; `algoName` stays `"Curve25519"` |
| `Ed448` | **done** `Ed448PrivateKey` + `PKSigner(key, "Raw")` / `"Ed448ph"` / `"SHAKE-256(512)"`; OID `1.3.101.113` (needs `SHAKE_XOF`) |
| `X448` | **done** `X448PrivateKey` + `PKKeyAgreement`; OID `1.3.101.111` |
| `SM2` | **done** `SM2PrivateKey` + `PKSigner(key, "Raw")` (ZA+SM3 inside the op); encrypt via primitive/`getEncryptionOp`; OID `1.2.156.10197.1.301.1`; curve `sm2p256v1` |
| `ECGDSA` | **done** `ECGDSAPrivateKey` + `PKSigner(key, "EMSA1(SHA-256)")`; OID `1.3.36.3.3.2.5.2.1`; \(Y=x^{-1}G\) |
| `ECKCDSA` | **done** `ECKCDSAPrivateKey` + `PKSigner(key, "Raw")` (prefix+hash inside); OID `1.0.14888.3.0.5`; \(Y=x^{-1}G\) |
| `ECIES` | **done** construct (`ECIESEncryptor`/`ECIESDecryptor`), not `pk_algs`; SCAN lives on KDF/DEM/MAC (`KDF1-18033(SHA-1)`, `AES-256/CBC`, `HMAC(SHA-1)`) |
| `HOTP` / `TOTP` | **done** construct (`constructs/hotp.d`), not factory; HMAC SCAN `HMAC(SHA-1)` / `HMAC(SHA-256)` / `HMAC(SHA-512)` |
| `SPAKE2P` | **done** construct (`constructs/spake2p.d`), not factory; key schedule uses `getKdf("HKDF(SHA-256)")` (castable `KDF`) + `retrieveMac("HMAC(…)")` |
| `base32Encode` / `base58Encode` | **done** free functions in `codec/{base32,base58}.d` (not SCAN); Base58Check uses `retrieveHash("SHA-256")` |
| `nistKeyWrap` / `nistKeyWrapPadded` | **done** construct (`constructs/nist_keywrap.d`); takes a keyed 128-bit `BlockCipher` (AES-128/192/256) |
| `Raw` (EME) | **done** `getEme("Raw")` → `EMERaw`; off → legacy null (no EME object) |
| `ISO_9796_DS2` / `ISO_9796_DS3` | **done** `getEmsa("ISO_9796_DS2(SHA-256)")` / `"ISO_9796_DS3(SHA-1,imp)"` → `ISO9796_DS2` / `ISO9796_DS3` : `EMSA` |
| `ML-KEM-512` / `ML-KEM-768` / `ML-KEM-1024` | **done** `MLKEMPublicKey` / `MLKEMPrivateKey`; `algoName` is the mode string; OIDs `2.16.840.1.101.3.4.4.{1,2,3}`; encaps/decaps are methods on the key (`mlkemEncaps` / `mlkemDecaps`). Do not add `retrieveKem`. |
| `Kyber-512-r3` / `768-r3` / `1024-r3` | **done** same `MLKEM*` types with `kyber_r3`; OIDs `1.3.6.1.4.1.25258.1.7.{1,2,3}`. |
| `Kyber-512-90s-r3` / `768-90s-r3` / `1024-90s-r3` | **done** same `MLKEM*` types with `kyber_90s`; OIDs `1.3.6.1.4.1.25258.1.11.{1,2,3}`. |
| `ML-DSA-4x4` / `ML-DSA-6x5` / `ML-DSA-8x7` | **done** `MLDSAPublicKey` / `MLDSAPrivateKey`; `algoName` is the mode string; OIDs `2.16.840.1.101.3.4.3.{17,18,19}`; `PKSigner(key, "Raw")` / `PKVerifier`; empty ctx. |
| `Dilithium-4x4-r3` / `6x5-r3` / `8x7-r3` | **done** same `MLDSA*` types with `dilithium_r3`; OIDs `1.3.6.1.4.1.25258.1.9.{1,2,3}`. |
| `Dilithium-4x4-AES-r3` / `6x5-AES-r3` / `8x7-AES-r3` | **done** same `MLDSA*` types with `dilithium_aes`; OIDs `1.3.6.1.4.1.25258.1.10.{1,2,3}`. |
| `SLH-DSA-SHAKE-128s` / `128f` / `192s` / `192f` / `256s` / `256f` | **done** `SLHDSAPublicKey` / `SLHDSAPrivateKey`; `algoName` is the mode string; OIDs `2.16.840.1.101.3.4.3.{20–31}`; `PKSigner(key, "Raw")`; empty ctx. HashSLH-DSA via `slhdsaHashSign` / `slhdsaHashVerify`. |
| `SphincsPlus-{shake,sha2}-{128,192,256}{s,f}-r3.1` | **done** same `SLHDSA*` types; empty prefix; FORS LSB-first; OIDs `1.3.6.1.4.1.25258.1.12.{1,2}.{1–6}`. |
| `XMSS` | **done** `XMSSPublicKey` / `XMSSPrivateKey`; `algoName` is `"XMSS"`; OID `0.4.0.127.0.15.1.1.13.0`; raw key is 4-byte param OID + n root + n seed; `PKSigner`/`PKVerifier` `"Raw"`. |
| `HSS-LMS` | **done** `HSSLMSPublicKey` / `HSSLMSPrivateKey`; OID `1.2.840.113549.1.9.16.3.17`; `PKSigner`/`PKVerifier` `"Raw"`. |
| `Hybrid-ML-KEM-768-X25519` | **done** `HybridPublicKey` / `HybridPrivateKey`; OID `1.3.6.1.4.1.25258.1.21`; encaps/decaps on the key. |
| `ClassicMcEliece_348864` / `348864f` / … / `8192128pcf` | **done** `ClassicMcEliecePublicKey` / `ClassicMcEliecePrivateKey`; `algoName` is the mode string; NIST OIDs `1.3.6.1.4.1.22554.5.1.{1–10}`; ISO pc `1.3.6.1.4.1.25258.1.18.{1–6}`; encaps/decaps on the key. |
| TLS 1.3 cipher | suite row: cipher `"AES-128/GCM"` / `"ChaCha20Poly1305"` (already valid SCAN) |

Nested SCAN is the composition rule: `HMAC(SHA-256)`, `PBKDF2(SHA-256)`,
`PSSR(SHA-512)`, `GMAC(AES-128)`, `SP800-108-Counter(HMAC(SHA-256))`. A new
hash or block does **not** need a parallel HMAC/PBKDF/EMSA implementation.

## What an increment must not do

- New public `createARIA()` / `new MLKEM()` factory beside `lookup.d`.
- Replace `OIDS` / `AlgorithmIdentifier` / `pk_algs` with C++ 3.13 OID
  codegen or `DNSName` as the X.509 subject type.
- Change `SCANToken` grammar to match a newer C++ parser unless a KAT
  cannot be expressed (record that as an open question first).
- Teach `retrieveBlockCipher("AES-256/GCM")` to return a mode (factory
  already returns null when `cipherMode() != ""`).
- Put TLS 1.3 record crypto behind a different name scheme than SCAN.

## Loci (do not fork)

| Concern | File |
|---|---|
| SCAN parse + aliases | `source/botan/algo_base/scan_token.d` |
| Lookup façade | `source/botan/libstate/lookup.d` |
| XOF façade | `source/botan/xof/xof.d` (`getXof`) |
| Engine switch | `source/botan/engine/core_engine.d` |
| EMSA/EME | `source/botan/pk_pad/factory.d` |
| KDF | `source/botan/kdf/kdf.d:139` |
| OID table | `source/botan/asn1/oids.d` |
| OID → key | `source/botan/pubkey/pk_algs.d` |
| BER/DER | `source/botan/asn1/ber_dec.d`, `der_enc.d` |
| TLS suite → SCAN | `source/botan/tls/ciphersuite.d` |
| Alias install | `source/botan/libstate/libstate.d` (`setDefaultAliases`, `OIDS.setDefaults`) |

## Invariants

- One string language (SCAN + aliases). One OID table (`OIDS`). One ASN.1
  codec (`ber_dec` / `der_enc`).
- Purpose decides **which function** consumes the string, not a new
  dispatcher type.
- A `version` that is off makes the string fail at lookup, not at a second
  registry.
- Wiki / Pages / vibe.0 keep calling `retrieve*` / `getCipher` / `getEmsa` /
  `OIDS` / `pkcs8.loadKey` as they do now.

## Open

- Exact C++ SCAN for GCM-SIV (`AES-256/GCM-SIV` vs `AES-256/SIV`) — copy
  `name()` from the 3.13 mode object in that increment.
- KEM: no `retrieve*` until a caller exists; `algoName` + OID are enough
  for keys.
