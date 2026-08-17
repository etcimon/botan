# Public key, padding, math, ASN.1, X.509

## How it works

Public-key support is gated on `version(PUBKEY)` → `BOTAN_HAS_PUBLIC_KEY_CRYPTO`. Individual algorithms have their own versions (`RSA`, `ECDSA`, `ECDH`, `Diffie_Hellman`, `Curve25519`, …). TLS and X.509 both require this gate plus their own (`TLS`, `X509`).

Unlike symmetric crypto, you do **not** ask the factory for `"RSA"`. You construct a key object, then ask an engine for an **operation**.

### Key types

`PublicKey` / `PrivateKey` (`pk_keys.d:25–150`) are interfaces: `algoName`, `estimatedStrength`, `checkKey`, `algorithmIdentifier`, `x509SubjectPublicKey`, PKCS#8 encoding, `loadCheck` / `genCheck`.

Concrete algorithms are D **structs** that `mixin Embed!(inner, owned)` to impersonate those interfaces (`rsa.d:55–86, 90–159`). The inner object is typically a shared scheme class:

- RSA / RW / (IF family) → `IFSchemePublicKey` / `IFSchemePrivateKey` (`algo/if_algo.d`, unread beyond RSA’s use).
- DSA / DH / NR / ElGamal → `dl_algo.d` + `dl_group.d`.
- ECDSA / ECDH / GOST 34.10 → `ecc_key.d` + `ec_group.d`.
- Curve25519 → `curve25519.d` (+ `curve25519_donna.d`). OID `X25519` (`1.3.101.110`) is a `pk_algs` alias; `algoName` stays `"Curve25519"`.
- Ed25519 → `ed25519.d` (+ `ed25519_fe.d` / `_sc.d` / `_ge.d`). Sign with `PKSigner(key, "Raw")` (Pure) or `"Ed25519ph"` (SHA-512 + RFC 8032 dom2) or `"SHA-256"` (hashed, no domain). OID `1.3.101.112`. KATs: `ed25519.vec` Pure+ph+SHA-256, `ed25519_verify.vec`, `ed25519_key_valid.vec`.
- Ed448 → `ed448.d` (+ `curve448_gf.d` / `curve448_scalar.d`). Sign with `PKSigner(key, "Raw")` (Pure) or `"Ed448ph"` / `"SHAKE-256(512)"` (empty ctx). OID `1.3.101.113`. SHAKE-256 via `getXof`. KATs: `ed448.vec` Pure+ph.
- X448 → `x448.d` (+ `curve448_gf.d`). RFC 7748 ladder + RFC 8410 raw/OCTET STRING keys. OID `1.3.101.111`. KATs: `x448.vec`.
- SM2 → `sm2.d` (on `ecc_key` / `ECGroup`). GB/T 32918 signatures (ZA = H(ENTLA‖IDA‖a‖b‖xG‖yG‖xA‖yA)) and encryption (KDF2 + DER C1/C3/C2). OID `1.2.156.10197.1.301.1`; named curve `sm2p256v1`. `full` only. KATs: `sm2_sig.vec`, `sm2_enc.vec`, `sm2_invalid.vec`.
- ECGDSA → `ecgdsa.d`. BSI TR-03111; public point is \(x^{-1}G\). Sign with `PKSigner(key, "EMSA1(SHA-256)")`. OID `1.3.36.3.3.2.5.2.1`. `full` only. KATs: `ecgdsa.vec`.
- ECKCDSA → `eckcdsa.d`. ISO 14888-3 / TTAK.KO-12.0015; same inverse public; prefix is \(x_A\|y_A\) padded to the hash block. `PKSigner(key, "Raw")`. OID `1.0.14888.3.0.5`. `full` only. KATs: `eckcdsa.vec`. Named curve `frp256v1` added for one KAT.
- ECIES → `ecies.d`. ISO 18033-2: ECDH x-coordinate + KDF (C0‖peh unless SingleHash) + DEM (`getCipher`) + MAC. Not in `pk_algs`. Encrypt never applies cofactor; decrypt CofactorMode is BSI ECKAEG \((hQ)(xh^{-1})\). `full` only. KATs: `ecies.vec` 12, `ecies-18033.vec` 2 (128-byte KEM). Named `secp112r2` PEM cofactor is 4.
- SPAKE2+ → `constructs/spake2p.d`. RFC 9383 HMAC suites (P256/P384/P521 × SHA-256/512). `fromPrehashed` + protocol; M/N from §4. Not in `pk_algs`. Password/Argon2id and hash2curve custom params later. `full` + `standard`. KATs: `pake/spake2p.vec` 5.
- ISO-9796-2 → `pk_pad/iso9796.d`. DS2 (salted) / DS3 (deterministic) inherit `EMSA`. SCAN `ISO_9796_DS2(hash[,imp|exp[,salt]])` / `ISO_9796_DS3(hash[,imp|exp])` via `getEmsa`; `cast(ISO9796_DS2)`. `full` only. KATs: `pubkey/iso9796.vec` 6.
- ML-KEM / Kyber R3 / Kyber-90s → `ml_kem.d`. FIPS 203 ML-KEM-512/768/1024 plus Kyber Round 3 modern (`Kyber-{512,768,1024}-r3`) and 90s (`Kyber-{512,768,1024}-90s-r3`). ML-KEM OIDs `2.16.840.1.101.3.4.4.{1,2,3}`; R3 `1.3.6.1.4.1.25258.1.7.{1,2,3}`; 90s `1.3.6.1.4.1.25258.1.11.{1,2,3}`. R3: G(d) without k; encaps m=H(seed); SS=SHAKE-256(K̄‖H(c)). 90s: G=SHA-512, H/KDF=SHA-256, PRF/XOF=AES-256-CTR. ML-KEM seed SK (64 B); R3/90s KAT SK is expanded. `full` only. KATs: ACVP 75+75; `kyber_kat.vec` 25/instance R3+90s.
- ML-DSA / Dilithium R3 / Dilithium-AES → `ml_dsa.d`. FIPS 204 ML-DSA-4x4/6x5/8x7 plus Dilithium Round 3 modern and AES (`Dilithium-{4x4,6x5,8x7}{-AES,}-r3`). ML-DSA OIDs `2.16.840.1.101.3.4.3.{17,18,19}`; R3 `1.3.6.1.4.1.25258.1.9.{1,2,3}`; AES `1.3.6.1.4.1.25258.1.10.{1,2,3}`. AES uses AES-256-CTR for ExpandA/ExpandS/y (key = first 32 of seed, 12-byte LE nonce IV). `full` only. KATs: `ml_dsa_verify.vec` 221; `dilithium_kat.vec` hashed R3+AES.
- SLH-DSA / SPHINCS+ → `slh_dsa.d`. FIPS 205 SHAKE+SHA2 128/192/256 s/f + HashSLH-DSA pre-hash (`0x01‖ctx‖PH.OID‖PH(M)`) + SPHINCS+ r3.1 (`SphincsPlus-{shake,sha2}-*`; empty prefix; FORS LSB-first). `algoName` is the mode string. SLH OIDs `2.16.840.1.101.3.4.3.{20–31}`; SPHINCS+ OIDs `1.3.6.1.4.1.25258.1.12.{1,2}.{1–6}`. SK is `SK.seed‖SK.prf‖PK.seed‖PK.root`. Deterministic sign uses PK.seed as `opt_rand`. `full` only. KATs: `slh_dsa_generic.vec` 2, `slh_dsa.vec` HashSigDet 128f, `sphincsplus.vec` HashSigRand 128f, HashSLH pairwise.
- XMSS → `xmss.d`. RFC 8391 / NIST SP 800-208 verify + keygen + sign (no BDS; auth path is recomputed). `algoName` is `"XMSS"`. OID `0.4.0.127.0.15.1.1.13.0`. Raw PK is 4-byte BE param id + n root + n seed. SK is PK + idx + PRF + SK_SEED + WOTS method (NIST=2 / Botan2x=1). `PKSigner`/`PKVerifier` with `"Raw"`. `full` only. KATs: `xmss_verify.vec` 63, `xmss_invalid.vec` 336, `xmss_sig.vec` SHA2_10_256, `xmss_keygen_reference.vec` SHA2_10_256.
- HSS-LMS → `hss_lms.d`. RFC 8554 / draft-fluhrer-lms-more-parm-sets verify + keygen + sign (SECRET_METHOD 2; no BDS). `algoName` is `"HSS-LMS"`. OID `1.2.840.113549.1.9.16.3.17`. `full` only. KATs: `hss_lms_verify.vec` 5, `hss_lms_invalid.vec` 4, `hss_lms_sig.vec` 2.
- Hybrid KEM → `hybrid_kem.d`. Hybrid-ML-KEM-768-X25519; SS = SHA-3-256(ss_mlkem ‖ ss_x25519). OID `1.3.6.1.4.1.25258.1.21`. `full` only. Pairwise + factory.
- FrodoKEM → `frodo_kem.d`. SHAKE and AES-A 640/976/1344 + eFrodo. OIDs `1.3.6.1.4.1.25258.1.{14,15,16,17}.{1,2,3}`. `full` only. Pairwise 12. KATs: `frodokem_kat.vec` CTR_DRBG (SHAKE-256(128) of PK/SK/CT; SS raw); 640 all 25, 976/1344 first.
- Classic McEliece → `classic_mceliece.d`. NIST R4 + ISO draft (16 names, `f`/`pc`). `algoName` is `ClassicMcEliece_*`. OIDs `1.3.6.1.4.1.22554.5.1.{1–10}` and pc `1.3.6.1.4.1.25258.1.18.{1–6}`. Encaps/decaps on the key (`cmceEncaps` / `cmceDecaps`); implicit reject via `s`. SK is `δ‖c‖g‖α-control‖s`. `full` only. KATs: `cmce_kat_hashed.vec` 348864 + 348864f (SHAKE-256(512) of PK/SK).

`pk_algs.makePublicKey` / make-private (`pk_algs.d:32+`) is the **OID → type** factory used when decoding X.509 / PKCS#8. It `OIDS.lookup`s then `static if`s each algorithm.

### Operations

`pk_ops.d` defines `Encryption`, `Decryption`, `Signature`, `Verification`, `KeyAgreement`. `CoreEngine` returns the matching `*Operation` class (`RSAPrivateOperation`, `ECDSASignatureOperation`, `DHKAOperation`, `ECDHKAOperation`, `Curve25519KAOperation`, … — `core_engine.d:606–660`).

High-level wrappers in `pubkey.d`:

- `PKSigner` / `PKVerifier` — EMSA encode then `sign` / `verify`. Optional `ENABLE_FAULT_PROTECTION` allocates a verify op and checks the signature just produced (`pubkey.d:208–212, 282–306`).
- `PKEncryptorEME` / `PKDecryptorEME` — EME pad + encrypt.
- `PKKeyAgreement` — used by TLS (EC)DH (`messages.d:944`).

`PKSigner.this` walks `af.engines[]` in **registration order**, not provider weight (`pubkey.d:262–269`). First engine that understands the key wins. With `full_openssl` that is OpenSSL for RSA/DSA.

### Padding (`pk_pad/`)

`getEmsa` / `getEme` (`pk_pad/factory.d:36+`) parse SCAN names and pull hashes from the factory:

| Name | Role |
|---|---|
| `EMSA1(HASH)` | DSA/ECDSA (X9.62-style hash then sign) |
| `EMSA1_BSI` | BSI ECDSA variant |
| `EMSA_X931` | X9.31 |
| `EMSA_PKCS1` / `EMSA3(HASH)` | PKCS#1 v1.5 signatures (TLS RSA) |
| `PSSR` / `EMSA4` | PSS |
| `Raw` / `EMSA_RAW` | no hash |
| `EME-OAEP` / `EME1` | OAEP encrypt |
| `EME-PKCS1-v1_5` / `EME_PKCS1v15` | PKCS#1 v1.5 encrypt (TLS RSA kex) |
| `Raw` (`EME_RAW`) | **done** no pad; unpad strips leading zeros |

TLS picks these in `HandshakeState.understandSigFormat` / `chooseSigFormat` (`handshake_state.d:114–209`): RSA → `EMSA3(hash)`, RSA-PSS → `PSSR(hash)`, DSA/ECDSA → `EMSA1(hash)` with `DER_SEQUENCE` encoding of (r,s).

PBE (password-based encryption of PKCS#8) is `PBE_PKCSv20` + `constructs/pbes2.d`.

### Math

`botan.math.bigint.bigint` — arbitrary-precision `struct BigInt` on botan-math words (`mp_core.d` re-exports). Division in `bigint/divide.d`. Tests: `bigint/test.d`, `test_data/mp_valid.dat`.

`numbertheory/`: `pow_mod` (engine can override via `Engine.modExp`), `def_powm` (Montgomery / fixed-window — `core_engine.d:600–604`), `reducer`, `primes`, `numthry` (inverse, LCM, …). RSA keygen uses `randomPrime` + `inverseMod` (`rsa.d:137–147`).

`ec_gfp/`: `curve_gfp`, `curve_nistp`, `point_gfp`. Used by ECDSA/ECDH/GOST. Internals unread. `SKIP_EC_GFP_TEST` exists.

Blinding: `pubkey/blinding.d` (unread) used by RSA private ops.

`workfactor.d` — estimated strength. Unread.

### ASN.1

`source/botan/asn1/`: `DEREncoder` / `BERDecoder`, `OID` + `OIDS` registry (`oids.d`, defaults installed in `LibraryState.initialize` when PK is on), `AlgorithmIdentifier`, `X509DN`, strings, times, alt names, attributes. This is shared by PKCS#8, X.509, TLS session BER (`session.d:76–114`), and PK signatures in DER_SEQUENCE form (`pubkey.d:217–232`).

### X.509 and CVC

`source/botan/cert/x509/` (`version(X509)` / `BOTAN_HAS_X509_CERTIFICATES`):

- `X509Certificate` (`x509cert.d:41–57`) — `subjectPublicKey()` decodes via `x509_key.loadKey`.
- `x509path.d` — `x509PathValidate` used by default `TLSCredentialsManager.verifyCertificateChain` (`credentials_manager.d:68–91`).
- `x509_ca.d`, `pkcs10.d`, `x509self.d` — issue / request / self-sign. `examples/selfsigned` walks this: `X509CertOptions` → CA key/cert → PKCS#10 → signed leaf.
- `x509_crl.d`, `certstor.d`, `ocsp.d` / `ocsp_types.d` — CRL + OCSP. README TODO: OCSP stapling. OCSP internals **unread**.
- `nist_x509/test01`–`test76` are path-building vectors.

`source/botan/cert/cvc/` — card-verifiable / EAC certificates. **Unread.** `SKIP_CVC_TEST = true` with TODO “EAC11 ECDSA Key decoding”. `version(CVC)` is not in `full`.

### Encoding keys

- Public: `x509_key.BER_encode` / PEM (`x509_key.d:40–48`).
- Private: `pkcs8` module (`pkcs8.d`) — BER/PEM, optional PBES2 password.

## Loci

| Piece | File:line |
|---|---|
| PublicKey / PrivateKey | `source/botan/pubkey/pk_keys.d:25–150` |
| PKSigner | `source/botan/pubkey/pubkey.d:138–276` |
| PK ops interfaces | `source/botan/pubkey/pk_ops.d:24–119` |
| OID key factory | `source/botan/pubkey/pk_algs.d:32–80` |
| RSA keygen + Embed | `source/botan/pubkey/algo/rsa.d:90–159` |
| EMSA factory | `source/botan/pk_pad/factory.d:36–80` |
| TLS sig format | `source/botan/tls/handshake_state.d:114–209` |
| X.509 cert + SPKI | `source/botan/cert/x509/x509cert.d:41–57` |
| Path validate (TLS default) | `source/botan/tls/credentials_manager.d:68–91` |
| PKCS#8 header | `source/botan/pubkey/pkcs8.d:39–50` |
| BigInt | `source/botan/math/bigint/bigint.d:35` |
| mp re-export | `source/botan/math/mp/mp_core.d:13–18` |

## Invariants

- Do not weaken `const` on key types / `TLSCredentialsManager` to paper over `Embed.opEquals`.
- `genCheck` / `loadCheck` honor `RT_Test*` versions (`constants.d:122–127`); default `full` has them **off**.
- `PKSigner` first-engine-wins ≠ symmetric weight-wins.
- Minimum RSA keygen length is 1024 bits (`rsa.d:130–131`) — policy, not math.
- X.509 modules use `version(X509)` in some files (`x509cert.d:14`) and `BOTAN_HAS_X509_CERTIFICATES` in others (`x509_key.d:14`). Both are set by `version(X509)`.

## Extension points

- New PK algorithm: `PublicKey`/`PrivateKey` impl (or Embed struct), `*Operation` classes, `CoreEngine` arms, `pk_algs.make*`, OIDs, `version` flag, vectors under `test_data/pubkey/`.
- New padding: `getEmsa`/`getEme` arm + `version(EMSA_*)`.
- Custom trust: override `verifyCertificateChain`; default is already path-build + hostname.

## Unread

- `if_algo.d`, `dl_algo.d`, `ecc_key.d`, `ec_group.d`, `dl_group.d` bodies.
- Each `algo/*.d` beyond RSA’s constructor/Embed and engine dispatch names.
- `blinding.d`, `workfactor.d`, `rfc6979.d` (deterministic DSA/ECDSA; `version(RFC6979)` is in `full`).
- `ec_gfp/*` internals, NIST P-curve specializations.
- `asn1/oids.d` default table.
- `x509path.d` algorithm, `ocsp.d`, CRL matching.
- Entire `cert/cvc/` tree.
- `pubkey/test.d` driver.
