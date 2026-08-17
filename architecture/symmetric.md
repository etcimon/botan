# Symmetric crypto — block, stream, modes, hash, MAC, KDF, PBKDF, filters

## How it works

Symmetric objects share a small interface stack and the factory described in `libstate-factory.md`. Application code should stay on **names** + `lookup` / `Pipe`, not on concrete types (except when you need a specific hash in a tight loop, as `examples/hash` optionally does with `SHA256`).

### Interface stack

```
BufferedComputation          SymmetricAlgorithm         KeyedTransform / Transformation
        │                            │                              │
        ├─ HashFunction              ├─ BlockCipher ───────────────┤
        └─ MessageAuthenticationCode─┘                              │
                                     StreamCipher                   │
                                                                    CipherMode
                                                                    AEADMode
```

- `BufferedComputation` (`algo_base/buf_comp.d:23`): `update` / `finished` / `outputLength`. Hashes and MACs.
- `SymmetricAlgorithm` (`algo_base/sym_algo.d:21`): `keySpec`, `setKey`, min/max key length.
- `BlockCipher` (`block/block_cipher.d:20`): `blockSize`, `parallelism`, `encryptN` / `decryptN`.
- `HashFunction` (`hash/hash.d:19`): `clone`, `clear`, `hashBlockSize`.
- `MessageAuthenticationCode` (`mac/mac.d:21`): both buffered and keyed; `verifyMac`.
- `CipherMode` (`modes/cipher_mode.d:19`): `KeyedTransform`; `authenticated()` false by default.
- AEAD types live under `modes/aead/` (`aead.d` unread in detail). `getAead` is what TLS record uses.

`BOTAN_BLOCK_CIPHER_PAR_MULT = 4` (`constants.d:73`) scales `parallelBytes()`.

### Names and modes

`CoreEngine.getCipher` (`core_engine.d:131–186`) splits on `/`:

- 1 part, and it is a stream cipher → `StreamCipherFilter`.
- 2–3 parts: `CIPHER/MODE` or `CIPHER/MODE/PADDING`. Default padding is PKCS7 for CBC, NoPadding otherwise.
- 4+ parts → not this engine.

Examples: `"AES-256/CBC"`, `"AES-256/CBC/PKCS7"`, `"AES-128/GCM"`, `"ChaCha20Poly1305"`. AEAD is constructed inside `getCipherMode` / AEAD filters (`BOTAN_HAS_AEAD_*`). `lookup.getCipher` tries **every** engine’s `getCipher` and returns the first hit (this is **not** weight-based).

### Filters and Pipe

C++ Botan’s I/O story is preserved. `Filter` / `Filterable` (`filters/filter.d`) write bytes downstream. `KeyedFilter` adds `setKey` / `setIv`. `Pipe` (`filters/pipe.d:56`) is a Unix-pipe of filters: `Pipe(getCipher(...))`, `processMsg`, `readAll`. Mode KATs (`modes/cipher_mode.d:54–58`) use exactly that.

Also: `HexEncoder`/`Decoder`, `Base64*` (`BOTAN_HAS_CODEC_FILTERS` is hard-true), `AEADFilter`, `TransformFilter`. `fd_unix.d` exists but is commented out of `pipe.d`.

### Families (do not treat this as a per-file review)

**Block** (`source/botan/block/`, 37 files): AES (+ NI, SSSE3), ARIA, Blowfish, Camellia, CAST-128/256, Cascade, DES/DESX, GOST 28147, IDEA (+ SSE2), KASUMI, Kuznyechik, Lion, MARS, MISTY1, Noekeon (+ SIMD), RC2/5/6, SAFER-SK, SEED, Serpent (+ SIMD), SHACAL2, SM4, TEA, Twofish, Threefish-512 (+ AVX2), XTEA (+ SIMD). Each concrete type is `static if (BOTAN_HAS_*)` imported by `CoreEngine` / `SIMDEngine` / `AESISAEngine`.

**Stream** (`stream/`): RC4, ChaCha, Salsa20, SHAKE-128/256 (XOF as stream; no IV; `full` only), plus OFB/CTR wrappers (`ofb.d`, `ctr.d`) that turn a block cipher into a stream.

**Modes** (`modes/`): ECB, CBC, CFB, XTS, plus `mode_pad.d` (PKCS7, X9.23, OneAndZeros, **ESP** RFC 4303, NoPadding). AEAD: CCM, EAX, OCB, GCM (+ optional `GCM_CLMUL` on `full_openssl`), SIV (RFC 5297 CMAC), GCM-SIV (RFC 8452 POLYVAL), ChaCha20-Poly1305, Ascon-AEAD128 (NIST SP 800-232).

**Hash** (`hash/`): SHA-1 (`sha160.d` + SSE2 + x86_{32,64}), SHA-2 32/64, SHA-3, SHAKE (fixed-length hash), Keccak, Skein-512, BLAKE2b, BLAKE2s, SM3, Streebog-256/512, Ascon-Hash256, Truncated, Tiger, Whirlpool, RIPEMD-128/160, GOST 34.11, HAS-160, MD2/4/5, Parallel, Comb4P. Checksums Adler32/CRC24/CRC32 live under `checksum/` but register as hashes.

**XOF** (`xof/`): first-class absorb-then-squeeze. `getXof("SHAKE-128")` / `"SHAKE-256"` (no args), `getXof("Ascon-XOF128")`, cSHAKE-128/256 via `getXof("cSHAKE-128", name)`. SHAKE-128(n) hash SCAN is unchanged.

**MAC** (`mac/`): HMAC, CMAC, CBC-MAC, Poly1305, SSL3-MAC, ANSI X9.19, SipHash, GMAC (`MacStart` nonce), KMAC-128/256 (`MacStart` customization), BLAKE2bMAC (`retrieveMac("BLAKE2b")`).

**KDF / PRF** (`kdf/`, `prf/`): KDF1 (IEEE 1363), KDF1-18033 (ISO 18033-2), KDF2, X9.42 PRF, SSL3-PRF, TLS-PRF, TLS-12-PRF (HMAC-based), SP 800-108 Counter/Feedback/Pipeline, SP 800-56A one-step, SP 800-56C two-step, **HKDF / HKDF-Extract / HKDF-Expand** (`prf/hkdf.d`, `HKDF : KDF`). `expandMessageXmd` (RFC 9380) is a hash-to-curve helper, not a `getKdf` name. `getKdf` is a **direct** SCAN switch; returned objects are the concrete `KDF` subclass and can be `cast`. `deriveKey` accepts an optional label (HKDF uses it as RFC 5869 info; older KDFs ignore it).

**PBKDF** (`pbkdf/`): PBKDF1, PBKDF2, Argon2, Scrypt, Bcrypt-PBKDF, OpenPGP-S2K, PKCS12-KDF via `getPbkdf`. Passhash (bcrypt, passhash9) sits in `passhash/` and is a construct, not a PBKDF engine object.

**Constructs** (adjacent, not factory-cached): CryptoBox, CryptoBox-PSK, RFC 3394 key wrap, NIST KW/KWP (`constructs/nist_keywrap.d`; SP 800-38F / RFC 5649), FPE-FE1, SRP6, TSS, AONT, PBES2, HOTP/TOTP (RFC 4226/6238; `constructs/hotp.d`). Unread internals; examples exist for cryptobox/bcrypt.

### How a hash KAT uses the factory

`hashTest` (`hash/hash.d:48–106`) asks `af.providersOf(algo)`, clones each provider’s prototype, hashes the hex input, checks the digest, then `clear()` + re-hash to test reset. That is the pattern for block/mac/stream tests as well (same `BOTAN_HAS_TESTS` gate, vectors under `test_data/{block,hash,mac,stream,modes,aead,kdf,pbkdf}`).

## Loci

| Piece | File:line |
|---|---|
| Hash interface | `source/botan/hash/hash.d:19–36` |
| XOF interface / `getXof` | `source/botan/xof/xof.d` |
| Block interface | `source/botan/block/block_cipher.d:20–52` |
| MAC interface | `source/botan/mac/mac.d:21–40` |
| CipherMode | `source/botan/modes/cipher_mode.d:19–27` |
| getCipher lookup | `source/botan/libstate/lookup.d:114–166` |
| CoreEngine mode parse | `source/botan/engine/core_engine.d:131–186` |
| Pipe | `source/botan/filters/pipe.d:56` |
| StreamCipherFilter | `source/botan/filters/filters.d:37–59` |
| getKdf | `source/botan/kdf/kdf.d:139–178` |
| Hash KAT | `source/botan/hash/hash.d:48–126` |

## Invariants

- Clone prototypes. Do not `setKey` on a cached object.
- `"AES-128/CBC"` is a filter/mode, not a `BlockCipher`.
- `getCipher` (modes) is first-engine-wins; `retrieveHash` is weight-wins. Different policies.
- HMAC name is `HMAC(HASH)`, TLS-12-PRF is `TLS-12-PRF(HASH)` — both pull `makeMac`/`makeHashFunction` from the factory, so SIMD SHA-1 can back HMAC/PRF too.

## Extension points

- New block: implement `BlockCipher`, `version` + `BOTAN_HAS_*`, import in `CoreEngine.findBlockCipher`, add `test_data/block/foo.vec`.
- New mode: hook `getCipherMode` / AEAD factory; TLS `ciphersuite.d` is a separate table if you want it on the wire.
- Custom filter: subclass `Filter` and `Pipe.append`.

## Unread

- Individual algorithm files (AES-NI internals, GCM GHASH, Skein tweak, …).
- `modes/aead/aead.d` factory body.
- `prf/hkdf.d`.
- `passhash/bcrypt.d`, `passhash9.d`.
- `constructs/*` beyond names.
- `compression/*` (Zlib gated on x86_64 `full`).
- `simd/*` helpers (`simd_32.d` etc.).
- `checksum/*` beyond registration.
- `codec/*` beyond knowing hex/base64 filters exist.
