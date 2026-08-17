# Interface — what is actually public

## How it works

Botan-in-D does not have a single generated API header. The C++ original used `botan.h`; this tree keeps a similarly named `source/botan/all.d` that is **not** a complete export of the library. It only re-exports library state, lookup helpers, version/parsing, and the RNG:

```11:22:source/botan/all.d
module botan.all;

public import botan.libstate.init;
public import botan.libstate.lookup;
public import botan.libstate.libstate;
public import botan.utils.version_;
public import botan.utils.parsing;

public import botan.rng.rng;
import botan.constants;
static if (BOTAN_HAS_AUTO_SEEDING_RNG)
    public import botan.rng.auto_rng;
```

`all.d` is listed in `dub.json` `sourceFiles` (so it is always compiled) but examples **do not** import it. They import `botan.pubkey.algo.rsa`, `botan.tls.client`, `botan.hash.sha2_32`, `botan.libstate.lookup`, etc. That is the real style: pick a module, whose body is usually wrapped in `static if (BOTAN_HAS_*)`.

The **configuration surface** is the D `version` identifier list on each dub configuration. `source/botan/constants.d` maps almost every `version(Foo)` to `enum BOTAN_HAS_FOO = true/false`. Algorithm modules then compile to either a full implementation or an empty husk. Because `sourcePaths` lists every package, the compiler still parses the files; it just DCE’s the gated bodies. A `lite` or `hash` consumer therefore cannot name `TLSClient` or `RSAPrivateKey` even though those `.d` files sit on disk.

Two extra versions always apply (`dub.json` top-level): `Have_botan` and `Botan`. They are not feature flags.

`lookup.d` is the stringly-typed factory façade most application code should use for symmetric objects:

| Function | Returns |
|---|---|
| `retrieveBlockCipher` / `retrieveStreamCipher` / `retrieveHash` / `retrieveMac` | **prototype** (clone it) |
| `make*` on `AlgorithmFactory` | fresh instance |
| `getPbkdf` | fresh PBKDF |
| `getCipher(spec, key, iv, dir)` | `KeyedFilter` for `Pipe` (`"AES-256/CBC/PKCS7"`) |
| `haveAlgorithm` / `algorithmType` | existence / `"Block"`/`"Hash"`/… |

Public-key objects are **not** retrieved by SCAN name. You construct `RSAPrivateKey`, `ECDSAPrivateKey`, … and pass them to `PKSigner` / `PKVerifier` / `PKEncryptorEME` / `PKDecryptorEME` / `PKKeyAgreement` with a **padding** name (`"EMSA4(SHA-512)"`, `"EME-PKCS1-v1_5"`, `"EME1(SHA-256)"`, `"Raw"`). `getEmsa` / `getEme` / `getKdf` are the padding/KDF factories (`pk_pad/factory.d`, `kdf/kdf.d:139`).

TLS is a callback-driven endpoint API:

- `TLSClient` / `TLSServer` (`tls/client.d`, `tls/server.d`)
- `TLSPolicy`, `TLSCredentialsManager`, `TLSSessionManager`
- `TLSBlockingChannel` if you want a read/write loop
- `TLSSession`, `TLSAlert`, `TLSProtocolVersion`, `TLSCiphersuite`

Certificates: `X509Certificate` (alias of `RefCounted!X509CertificateImpl`, `x509cert.d:41`), `X509CA`, `PKCS10Request`, `x509self` for self-signed, `pkcs8` / `x509_key` for PEM/BER keys. Trust stores: `CertificateStore` / `CertificateStoreInMemory` (`addFromFile` loads a PEM bundle); `CertStore_Flatfile` → `CertificateStoreFlatfile` (self-signed CAs); `CertStore_System` → `CertificateStoreSystem` (OS trust, not installed by default). TLS 1.3 scheme names map to `certChain` algoName via `certChainAlgoName` (`tls/policy.d`).

Memory types that leak into the public API come from memutils, re-exported by `botan.utils.types`:

- `Vector!T`, `SecureVector!ubyte`, `Array!T`
- `Unique!T`, `RefCounted!T`
- `std.typecons.scoped` (examples wrap encryptors in `scoped!`)

Ownership convention: `retrieve*` returns a library-owned prototype; `clone()` / `make*` returns a caller-owned object. `Unique!` and `scoped!` are how examples dispose them. `PrivateKey` objects returned by `TLSCredentialsManager.privateKeyFor` remain owned by the credentials manager (`credentials_manager.d:156–157`).

Secret compares and CBC/ECB unpad use `botan.utils.ct` (`CTMask`, `constantTimeCompare`, `secureScrubMemory`). `sameMem` is early-out by default (`BOTAN_HAS_CT` is off, like algorithm flags). Compile with `--d-version=CT` for constant-time MAC verify, SPAKE2+, CryptoBox, PSS/OAEP, HMAC short-key, PKCS7 / X9.23 / OneAndZeros / **ESP** unpad, and Base32/Base58 Mask lookup. C++ still has Valgrind `CT::poison` and `strong_type` — not ported.

`LibraryInitializer` (`libstate/init.d`) exists for explicit init/shutdown. Lazy `globalState()` makes it optional; the comment still says you should deinitialize or memory might leak (`global_state.d:27–28`).

Internals that look public (they are `module botan.*` and importable) but should be treated as **package-private**:

- `botan.tls.handshake_state`, `handshake_io`, `messages`, `record`, `seq_numbers` (`package:` on several)
- `botan.engine.*` (unless you are adding an engine)
- `botan.algo_factory.algo_cache`
- `botan.math.mp.*` (re-exports botan-math)
- `botan.entropy.*` except through `LibraryState`
- `botan.selftest`, `botan.test` (test harness)

## Loci

| Surface | File:line |
|---|---|
| Umbrella import | `source/botan/all.d:11–22` |
| Version → `BOTAN_HAS_*` | `source/botan/constants.d:53–417` |
| Lookup façade | `source/botan/libstate/lookup.d:29–189` |
| Types / `CipherDir` | `source/botan/utils/types.d:13–28` |
| EMSA factory | `source/botan/pk_pad/factory.d:36` |
| KDF factory | `source/botan/kdf/kdf.d:139` |
| TLS client ctor | `source/botan/tls/client.d:51` |
| TLS server ctor | `source/botan/tls/server.d:50` |
| PKSigner ctor | `source/botan/pubkey/pubkey.d:254` |
| Public/Private key interfaces | `source/botan/pubkey/pk_keys.d:25–150` |
| Configurations | `dub.json:55–97` |
| sourcePaths + sourceFiles | `dub.json:15–53` |

## Invariants

- Feature flags are compile-time. There is no runtime “enable RSA”.
- `retrieve*` throws `AlgorithmNotFound` rather than returning null (`lookup.d:33–34`).
- Prototypes are not usable until `clone()`.
- `version(unittest)` sets `BOTAN_TEST`; `version(CanTest)` sets `BOTAN_HAS_TESTS`. Tests need **both** (`hash.d:108`: `static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest`).
- `all.d` will not give you TLS or RSA.

## Extension points

- New public algorithm: new `version` in `dub.json` + `constants.d` + `CoreEngine.find*` arm + interface impl.
- New SCAN alias: `SCANToken.setDefaultAliases()` (called from `LibraryState.initialize`).
- New TLS policy / credentials / session store: subclass the three TLS hooks.
- Preferred provider: `AlgorithmFactory.setPreferredProvider(spec, "simd")`.

## Open questions / unread

- No package.d / no `public` vs `package` audit of every module. Many “internal” modules are fully public D modules.
- `botan.utils.version_` unread beyond knowing `all.d` imports it.
- Wiki pages exist (2014–2015) but several fetches returned empty bodies; treat GitHub Pages + this note + vibe.0 imports as the observed contract. Remaining wiki prose unread in full: Getting Started, Low Level Interface, TLS, Public Key, X.509, Credentials, RNG, Pipe/Filter, AEAD, KDF, PBKDF, Password Hashing, OCSP, BigInt, Memory Container, Cryptobox, FPE, SRP.
- vibe.0 `source/vibe/stream/botan.d` **does** consume this API (`TLSBlockingChannel` ctors, `TLSPolicy` virtuals, `TLS_V12` default). That file is load-bearing.

## Configurations as API

| Config | What you can name |
|---|---|
| `full` (default) | Everything in the long versions list: TLS, X509, all PK, all block/hash/MAC/AEAD, SIMD/AES-NI/asm on x86_64, Self_Tests, CanTest |
| `full_openssl` | Same idea + `Engine_OPENSSL` + Windows `libeay32`/`ssleay32`; optional dub `openssl` `~>1.1.7+1.1.1d`. Note: **no** top-level `versions` key — only `versions-x86_64`. Non-x86_64 `full_openssl` is an empty-ish config. |
| `lite` | Hashes SHA-1/2 + MD4/5, HMAC, PBKDF1/2, CTR, KDFs/PRFs, RNGs/entropy. **No** TLS, X509, PUBKEY, block ciphers. |
| `pubkey` | RSA/DSA/ECDSA/DH/ECDH/… + X509 + a few hashes/HMAC/CBC/EME + entropy. No TLS, almost no block suite. |
| `hash` | SHA-1/2, MD4/5, CRC24, HMAC, Win32+RDRAND entropy. |

`examples/hash` uses `subConfigurations.botan = "hash"` and extra versions `Skein_512`, `Threefish`. `examples/pubkey` uses `"pubkey"`.

New algorithms added from C++ 3.x follow `feature-versions.md` and must not appear in this table as “always on”. They are selected with the **same** SCAN / `retrieve*` / `getCipher` / `getEmsa` / `OIDS`+`pk_algs` paths (`scan-asn1.md`), assembled by purpose (`"ARIA-128/GCM"`, `"Argon2id"`, `"GMAC(AES-128)"`, OID `"Ed25519"`). `version(TLS)` does not compile TLS 1.3. See `upgrade-randombit.md`.
