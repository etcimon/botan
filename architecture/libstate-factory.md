# libstate, AlgorithmFactory, engines, constants

## How it works

This is the spine of the library. Symmetric algorithms are never `new AES128` in application code. They are names, resolved at run time against a list of **engines**, cached as **prototypes**, and cloned per use. Public-key **operations** (sign, verify, encrypt, decrypt, key agreement, modexp) use the same engine list but are not cached in `AlgorithmFactory` — `PKSigner` walks engines per construction.

### `constants.d` is the feature switchboard

`source/botan/constants.d` is compiled first (it is in `sourceFiles` and imported everywhere via `import botan.constants`). It:

- Re-exports `botan_math.mp_types`.
- Sets C++-lineage version numbers (`BOTAN_VERSION_MAJOR=1`, `MINOR=12`, `PATCH=3`, datestamp `20151109`, VC revision `git:6661c489…`). The **D package** version is 1.13.9; do not confuse them.
- Defines buffer sizes, pool chunk, Karatsuba thresholds, RNG reseed limits (`BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED = 512`, `BOTAN_RNG_RESEED_POLL_BITS = 128`).
- Maps every `version(Foo)` used in `dub.json` to `BOTAN_HAS_*`.
- Hosts `LogLevel` and `logTrace`/`logInfo`/`logDebug`/`logError`. `LogLevel = Debug` currently, so initialize is chatty.
- `version(unittest)` → `BOTAN_TEST`; `version(CanTest)` → `BOTAN_HAS_TESTS`.

Some flags are **not** versions: `BOTAN_HAS_CIPHER_MODE_PADDING`, `BOTAN_HAS_AUTO_SEEDING_RNG`, `BOTAN_HAS_CODEC_FILTERS`, `BOTAN_HAS_HKDF` are hard `true` (`constants.d:80–84`).

### Global state

`LibraryState` (`libstate.d:72–234`) holds:

- `AlgorithmFactory m_algorithm_factory`
- `SerializedRNG m_prng`
- `Vector!EntropySource m_sources`
- `bool m_initialized`

It is stored in a **thread-local** `Unique!LibraryState` (`global_state.d:16`). First `globalState()` allocates and `initialize()`s. `setGlobalState` replaces it (used by `LibraryInitializer.deinitialize` to drop state). `LibraryInitializer` (`init.d:22–59`) is RAII around that; its `initialize()` has a typo in the error string (`"Library innullitialization failed"`).

`initialize()` engine order (`libstate.d:105–131`):

1. `GMPEngine` if `BOTAN_HAS_ENGINE_GNU_MP` — **not in full**; import path `botan.engine.gnump_engine` has **no matching file** under `engine/`.
2. `OpenSSLEngine` if `BOTAN_HAS_ENGINE_OPENSSL` — `full_openssl` only.
3. `AESISAEngine` if `BOTAN_HAS_ENGINE_AES_ISA` — AES-NI (`aes_ni.d`).
4. `SIMDEngine` if `BOTAN_HAS_ENGINE_SIMD` — SSSE3 AES, SSE2 SHA-1/IDEA, SIMD Serpent/XTEA/Noekeon.
5. `AssemblerEngine` if `BOTAN_HAS_ENGINE_ASSEMBLER` — x86/x86_64 hash/asm paths.
6. `CoreEngine` — **always**. Portable D implementations of everything gated on.

A special `modexpInit()` flag (`libstate.d:65–67, 88–104`) short-circuits to OpenSSL (optional) + CoreEngine only, skips aliases/OIDs/entropy/PRNG/selftests. Who calls it is unread.

After engines: entropy source list (see `rng-entropy.md`), `SerializedRNG`, optional `confirmStartupSelfTests`.

### AlgorithmFactory

`AlgorithmFactory` (`algo_factory.d:29–355`) owns `Vector!Engine` and five `AlgorithmCache!T` (block, stream, hash, MAC, PBKDF). Cipher **modes** are not cached here; `getCipher` asks each engine’s `getCipher` in order (`lookup.d:156–166`).

Lookup:

```391:416:source/botan/algo_factory/algo_factory.d
const(T) factoryPrototype(T)(...) {
    if (const T cache_hit = cache.get(algo_spec, provider))
        return cache_hit;
    SCANToken scan_name = SCANToken(algo_spec);
    if (scan_name.cipherMode() != "")
        return null; // "AES-128/CBC" is not a BlockCipher
    foreach (engine; engines[])
        if (provider == "" || engine.providerName() == provider)
            if (T impl = engineGetAlgo!T(engine, scan_name, af))
                cache.add(impl, algo_spec, engine.providerName());
    return cache.get(algo_spec, provider);
}
```

`SCANToken` (`algo_base/scan_token.d`) parses SCAN names (`HMAC(SHA-256)`, `AES-128`, aliases). Results are cached in a process-global `HashMap!(string, SCANToken)`.

`AlgorithmCache.get` (`algo_cache.d:56–92`) honors an explicit provider, else `setPreferredProvider`, else the highest `staticProviderWeight`:

| provider | weight |
|---|---|
| openssl | 9 |
| aes_isa | 8 |
| simd | 7 |
| asm | 6 |
| core | 5 |
| gmp | 1 |

Comment at `algo_cache.d:25–27` says the opposite about OpenSSL. Trust the numbers.

`addEngine` clears all caches (`algo_factory.d:45–49`).

### Engine interface

`Engine` (`engine/engine.d:35–150`) is a D interface. Default-looking methods are abstract; each concrete engine implements what it can and returns `null` otherwise. Hooks:

- `findBlockCipher` / `findStreamCipher` / `findHash` / `findMac` / `findPbkdf`
- `getCipher` (mode+padding filter)
- if `BOTAN_HAS_PUBLIC_KEY_CRYPTO`: `modExp`, `getKeyAgreementOp`, `getSignatureOp`, `getVerifyOp`, `getEncryptionOp`, `getDecryptionOp`

`CoreEngine` (`core_engine.d:126+`) is a giant `if (request.algoName == "AES-128") return new AES128;` switch, plus `getCipher` that splits `"CIPHER/MODE/PADDING"` (`core_engine.d:131–186`) and builds CBC/ECB/XTS/CFB/OFB/CTR/AEAD filters. PK ops dispatch on `key.algoName` (`core_engine.d:606–660`).

`SIMDEngine` (`simd_engine.d:31+`) additionally checks `CPUID.hasSsse3()` / `hasSse2()` / `SIMD32.enabled()` before returning a SIMD clone.

`dyn_engine.d` is a delegating wrapper (unread internals).

### CPUID

`botan.utils.cpuid` wraps `core.cpuid` plus a static ctor that snapshots x86 feature bits / AltiVec. SIMD engines consult it at **find** time, not at initialize time — so a prototype created on a machine without SSSE3 simply is not added.

## Loci

| Piece | File:line |
|---|---|
| Feature enums | `source/botan/constants.d` |
| Thread-local state | `source/botan/libstate/global_state.d:16–33` |
| initialize / engines | `source/botan/libstate/libstate.d:82–146` |
| Factory + prototype | `source/botan/algo_factory/algo_factory.d:29–416` |
| Weights | `source/botan/algo_factory/algo_cache.d:22–38` |
| Engine interface | `source/botan/engine/engine.d:35–150` |
| CoreEngine cipher parse | `source/botan/engine/core_engine.d:131–186` |
| CoreEngine PK ops | `source/botan/engine/core_engine.d:606–660` |
| SCAN parser | `source/botan/algo_base/scan_token.d:29–80` |
| CPUID | `source/botan/utils/cpuid.d:23–39` |

## Invariants

- `CoreEngine` is last in the vector but **not** last in preference (weight 5). Faster engines win if they registered a prototype under the same SCAN name.
- Mode names (`AES-128/GCM`) must not be resolved as block ciphers (`cipherMode() != ""` → null).
- `LibraryState` is per-thread; engines/caches are **not** shared across threads. Each thread that calls `globalState()` pays initialize + self-tests + a new HMAC_RNG.
- Prototypes in the cache are owned by the cache; callers `clone()`.

## Extension points

- `algorithmFactory().addEngine(new MyEngine)`.
- `addBlockCipher` / `addHashFunction` / … to inject a prototype without an engine.
- `setPreferredProvider("AES-128", "core")` to avoid AES-NI in tests.
- New `version` + `BOTAN_HAS_*` + `CoreEngine` arm whose `request.algoName` is the C++ SCAN `name()`. Nested uses (`HMAC(NEW)`, `NEW/GCM`) must work without a second factory. OID-bearing keys also get an `OIDS` + `pk_algs` arm (`scan-asn1.md`). Do not replace `SCANToken` or `OIDS`.

## Unread / open

- `dyn_engine.d` full behavior.
- `asm_engine.d` / `aes_isa_engine.d` beyond names.
- `gnump_engine` module missing from the tree.
- `SCANToken.setDefaultAliases` body unread.
- `modexpInit` callers.
- Whether thread-local factories duplicate large prototype heaps in a thread pool (TLS servers).
- `LogLevel = Debug` should probably be `Error` for production — not changed here.
