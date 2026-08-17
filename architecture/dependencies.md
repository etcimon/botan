# Dependencies

## How it works

`dub.json` declares two required D packages and a pile of OS libraries. There is no vendored C++ Botan, no CMake, no pkg-config for the core library.

```10:13:dub.json
    "dependencies": {
        "memutils": { "path": "../memutils" },
        "botan-math": { "version": "~>1.0.2" } 
    },
```

`dub.selections.json` (this clone):

- `memutils` **path `../memutils`** (sibling `E:\cva6\riscv-dev\memutils`, package 1.0.12)
- `botan-math` **1.0.4**

Do not let dub resolve memutils from another worktree or the public registry while developing. Local cache may still have 1.0.11; the path pin wins.

### memutils — the STL stand-in

`source/botan/utils/types.d` is the choke point:

```13:19:source/botan/utils/types.d
public import memutils.vector : Vector, Array, SecureVector, SecureArray;
public import memutils.utils;
public import memutils.refcounted;
public import memutils.unique;
public import botan.utils.exceptn;
public import std.typecons : scoped;
```

Used throughout:

- `Vector!T` / `SecureVector!ubyte` — handshake messages, keys, ciphertexts. Secure variants are intended to zero on free.
- `Unique!T` — engine ops inside `PKSigner`, handshake message pointers, `LibraryState` itself (`Unique!LibraryState`).
- `RefCounted!T` — `X509Certificate = RefCounted!X509CertificateImpl`.
- `HashMap` / `DictionaryList` — algorithm cache, TLS extensions, session maps, SCAN cache.
- `memutils.helpers.Embed` — **critical**. RSA/ECDSA/… public structs `mixin Embed!(m_priv, m_owned)` so a D struct can impersonate the `PrivateKey` / `PublicKey` interface (`rsa.d:81, 156`). `TLSCredentialsManager.channelPrivateKey` stores `ECDSAPrivateKey` in an AA, which instantiates `Embed.opEquals`.

Historical green fail (stale in the previous `AGENTS.md`): LDC 1.42 / frontend 2.112 could not call `Embed.opEquals` on a `const` object because `Object.opEquals` was not const. That was a **compiler + memutils + botan** interaction. The intended fix is const-correct `opEquals` on Embed (memutils v1.0.12 per known facts). **Do not** weaken TLS credential types to dodge it.

`dub.json` pins the sibling tree (`path: ../memutils`) so Botan always builds the 1.0.12 Embed/`DebugAllocator` sources next to this repo.

### botan-math — MPI kernels

`source/botan/math/mp/mp_core.d` re-exports the botan-math modules:

- `botan_math.mp_types`
- `botan_math.mp_bigint`
- `botan_math.mp_comba`
- `botan_math.mp_karatsuba`
- `botan_math.mp_monty`
- `botan_math.mp_word`

`constants.d:13` also `public import botan_math.mp_types`. `utils/mem_ops.d` re-exports `botan_math.mem_ops`.

`botan.math.bigint.bigint` is the D `struct BigInt` façade on top of those kernels (Karatsuba thresholds `BOTAN_KARAT_MUL_THRESHOLD = 32`, `BOTAN_KARAT_SQR_THRESHOLD = 32` in `constants.d:75–76`). Number theory (`numthry`, `pow_mod`, `reducer`, `primes`) and EC (`ec_gfp`) sit in this repo, not in botan-math.

There is a gated `Engine_GNU_MP` (`BOTAN_HAS_ENGINE_GNU_MP`) as an alternative modular-exp provider. It is **not** in `full`. Unread.

### Optional OpenSSL (`full_openssl`)

When configuration `full_openssl` is selected **on x86_64**:

- `version(Engine_OPENSSL)` → `BOTAN_HAS_ENGINE_OPENSSL` → `OpenSSLEngine` loaded first-ish (`libstate.d:110–113`, after optional GMP).
- dub extra dependency: `"openssl": { "version": "~>1.1.7+1.1.1d", "optional": true }`.
- Windows: `copyFiles` / `sourceFiles` for `lib/win-amd64/libeay32.dll|.lib` and `ssleay32`.
- Engine (`openssl_engine.d`) binds `deimos.openssl.*` and can supply RSA/DSA sign/verify, DH agreement, and (unread) EVP block/hash paths. Provider name `"openssl"`, weight **9** (highest).

`full` does **not** enable this engine.

### OS libraries

```52:53:dub.json
    "libs-posix": ["dl"],
    "libs-windows": ["advapi32", "user32"],
```

- `dl` — `dyn_engine` / `dyn_load` (unread) and possibly EGD/unix process entropy.
- `advapi32` — `Win32CAPIEntropySource` / CryptoAPI.
- `user32` — `Win32EntropySource` (GUI/timing jitter; unread internals).

Zlib is a `version(ZLib)` (`full` x86_64 has it) wrapping system zlib. Bzip2 / LZMA versions exist in `constants.d` but are not in `full`. Unread.

### What is *not* a dependency

- The C++ Botan library. This is a translation.
- Phobos digest/crypto (examples compare against `std.digest.sha` but the library does not use it).
- SQLite unless `version(SQLite)` (session_manager_sqlite, utils/sqlite3). Not in `full`.
- Network stack. TLS is transport-agnostic (you pass `void delegate(in ubyte[])`).

## Loci

| Dep | Where it enters |
|---|---|
| memutils vectors/unique | `source/botan/utils/types.d:13–16` |
| Embed mixin | `source/botan/pubkey/algo/rsa.d:25, 81, 156` |
| ChannelID ECDSA AA | `source/botan/tls/credentials_manager.d:248–257` |
| botan-math re-export | `source/botan/math/mp/mp_core.d:13–18` |
| OpenSSL engine | `source/botan/engine/openssl_engine.d:13–80` |
| Engine registration | `source/botan/libstate/libstate.d:95–131` |
| selections | `dub.selections.json` |

## Invariants

- Do not replace `Vector`/`SecureVector` with Phobos arrays in public signatures; the rest of the tree assumes memutils allocators and `.move()`.
- Do not “fix” Embed/const by changing `TLSCredentialsManager` / key structs to less-const types without a note.
- botan-math is the only MPI implementation on the default path.

## Extension points

- Path-local memutils override (dub `"path"`) to test Embed const-correctness.
- `full_openssl` when an OpenSSL 1.1.x is acceptable.
- GNU MP engine if someone enables `Engine_GNU_MP` and provides the D bindings module (`gnump_engine` is imported from `libstate.d:42` but the file was not listed under `engine/` — possible missing module; see open questions).

## Open questions / unread

- `engine/gnump_engine.d` is imported when `BOTAN_HAS_ENGINE_GNU_MP` but **does not appear** in `source/botan/engine/` listing (only aes_isa, asm, core, dyn, engine, openssl, simd). Enabling that version may not compile.
- memutils 1.0.11 (selections) vs claimed 1.0.12 fix.
- botan-math 1.0.4 internals unread (this note only sees the re-export).
- Whether `lib/win-amd64/*` OpenSSL blobs are still present / trustworthy: unread.
- RISC-V: both deps are portable D; no arch-specific botan-math kernel was inspected.
