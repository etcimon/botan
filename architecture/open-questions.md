# Open questions

## Pin / green (resolved vs leftover)

**Resolved in this clone (do not re-litigate as v1.13.8 facts):**

- Git: `460336f` “Fix auto/ref deprecations for LDC 1.42.”, tag `v1.13.9`, `dub.json` version `1.13.9`.
- `dub build --compiler=ldc2` is the recorded green. `build/botan.lib` is present. Deprecations were fixed **in botan**, not by weakening TLS types.
- Previous `AGENTS.md` claim of a current Embed.opEquals **build fail** is stale.

**Still open around green:**

1. `dub.selections.json` records `memutils` **1.0.11**. The Embed.opEquals const fix is attributed to memutils **1.0.12**. Local cache only has 1.0.11. Did green use 1.0.11 (already good enough?), a path-local memutils, or a later upgrade that was not saved? Isolate before changing Embed again.
2. `dub test --compiler=ldc2` (KAT + TLS in-process) was **not** re-run for this note set. Only build is recorded.
3. DMD reproduce of the old Embed fail: still not done (historical open item).
4. `LogLevel = Debug` makes initialize/self-test noisy; not a fail.

## Factory / engine mismatches

- `algo_cache.d:25–27` comment: “prefer anything over OpenSSL”. Weights give OpenSSL **9** (highest). Which is intended?
- `libstate.d` imports `botan.engine.gnump_engine` under `BOTAN_HAS_ENGINE_GNU_MP`, but `source/botan/engine/` has **no** `gnump_engine.d`. Enabling that version likely does not link.
- `full_openssl` sets versions only under `versions-x86_64`. Other archs selecting that configuration get almost no `BOTAN_HAS_*`.
- Symmetric lookup is weight-based; `getCipher` and `PKSigner` are first-engine-wins. Documented now; still easy to misuse.
- `modexpInit()` reduced boot: no caller found in the files read.

## TLS / PK

- ChannelID static AA (`credentials_manager.d:251`) lifetime vs thread-local `LibraryState`; fork; multi-hostname leak.
- DTLS retransmission / cookie path only sampled.
- TLS 1.3: absent. Any consumer expecting 1.3 must not use this pin.
- OCSP stapling is a README TODO; `ocsp.d` unread.
- CVC skipped (`SKIP_CVC_TEST`, EAC11 ECDSA decode TODO).
- RSA keygen allows 1024-bit keys; default TLS policy still lists RSA signatures. Policy vs modern floors.
- Fork-safety of `HMAC_RNG` / `SerializedRNG` unread (no atfork seen).

## RISC-V (latent)

This library is portable D + botan-math. There is **no** RISC-V engine, no RVV, no entropy source unique to SiFive/CVA6.

What would actually run if someone built `full` for RISC-V Linux:

- Portable `versions` only (no `versions-x86_64` SIMD/AES-NI/SHA1-asm/RDRAND).
- `CoreEngine` for every algorithm.
- Entropy: DevRand + UnixProc + ProcWalk + EGD.
- `dl` linked.

Unknowns: LDC RISC-V backend vs this codebase (inline `D_InlineAsm_X86*` is already gated). botan-math word size / endian. Whether `UnixEntropySource` exec-from-`/bin` is acceptable on the target. `BOTAN_TARGET_HAS_NATIVE_UINT128 = false` is hardcoded (`constants.d:68`).

Do not claim a RISC-V green. Do not add RISC-V versions without a cell.

## Unread subsystems (inventory)

Do not write as if these were reviewed:

| Area | Path |
|---|---|
| CVC / EAC | `source/botan/cert/cvc/*` |
| OCSP | `cert/x509/ocsp.d`, `ocsp_types.d` |
| X.509 path algorithm | `cert/x509/x509path.d` body |
| SQLite sessions | `tls/session_manager_sqlite.d`, `utils/sqlite3/` |
| TLS server FSM | `tls/server.d` past ctor |
| TLS extensions / DTLS IO / hash / seq / heartbeats / reader | `tls/extensions.d`, `handshake_io.d`, `handshake_hash.d`, `seq_numbers.d`, `heartbeats.d`, `reader.d` |
| dyn engine | `engine/dyn_engine.d` |
| asm / AES-ISA engines | `engine/asm_engine.d`, `aes_isa_engine.d` |
| GNU MP engine | missing file |
| SIMD helpers | `simd/*`, `utils/simd/*` |
| HKDF | `prf/hkdf.d` — **read** (now `HKDF : KDF` + factory) |
| Constructs | `constructs/*` (CryptoBox, SRP6, TSS, FPE, AONT, RFC3394, PBES2) |
| Passhash | `passhash/*` |
| Compression | `compression/*` |
| Entropy source bodies | `entropy/*.d` except the accumulator + registration |
| X9.31 RNG | `rng/x931_rng.d` |
| EC GFP / DL / IF scheme classes | `math/ec_gfp/*`, `pubkey/algo/{if,dl,ecc,ec_group,dl_group}.d` |
| Blinding, workfactor, RFC6979 | `pubkey/blinding.d`, `workfactor.d`, `algo/rfc6979.d` |
| ASN.1 OID table | `asn1/oids.d` |
| SCAN aliases | `SCANToken.setDefaultAliases` |
| http_util, datastor, dyn_load, asm_x86_* | `utils/` |
| Examples bcrypt / cryptobox / curve25519 | `examples/` |
| botan-math internals | external package 1.0.4 |
| OpenSSL blobs | `lib/win-amd64/` |

## Upgrade vs randombit/botan (2026-08-15)

Compare checkout: `../randombit-botan` @ `6931ef6fd` (described `3.13.0-24-g6931ef6fd`). Plan: `upgrade-randombit.md`. Companions: `feature-versions.md`, `copyright.md`, `AGENTS-upgrade.md`.

**Decided (do not re-litigate):**

- No Botan 3 API rebase (no `shared_ptr` callbacks, no engine removal).
- `latestTlsVersion()` stays 1.2; `TLS_13` is a separate identifier.
- Every increment ships KATs or a negative test; `SKIP_*` is not a landing strategy.
- Touched files take the newer C++ copyright years plus Etienne Cimon (2014–2026).

**Still open for the upgrade:**

- T0: `dub test --compiler=ldc2` on this pin.
- OCSP HTTP: **does** (`OnlineCheck` → `ocspHttpPost`). Transport is a
  delegate (`setHttpExchangeHandler`); no in-tree socket. S4: OCSP POST
  does not follow redirects. Staple emit (T13e) is still open.
- BER / DN / path must be read before S2/S3.
- Whether a `modern` dub configuration is added after several A-rows are green (not now).

## Process

- Notes live in `architecture/` and are untracked. Do not commit unless asked.
- Do not edit host-tracked scaffold outside this clone.
- Prefer fixing memutils Embed const-correctness over changing botan TLS types.
- Do not vendor `../randombit-botan` into `source/`.
