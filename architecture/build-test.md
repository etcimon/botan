# Build and test

## How it works

This is a dub static library. There is no Makefile in the clone root. `targetName` `botan`, `targetType` `staticLibrary`, `targetPath` `build` → `build/botan.lib` on Windows.

### What gets compiled

`sourcePaths` (`dub.json:15–45`) is an explicit list of **packages**, not `source/`:

`algo_base`, `algo_factory`, `asn1`, `block`, `cert`, `checksum`, `constructs`, `codec`, `engine`, `entropy`, `filters`, `hash`, `kdf`, `libstate`, `mac`, `math`, `modes`, `pbkdf`, `pk_pad`, `prf`, `pubkey`, `rng`, `selftest`, `simd`, `stream`, `utils`, `compression`, `passhash`, `tls`.

Plus `sourceFiles`: `constants.d`, `test.d`, `all.d`.

So `source/botan/*.d` that are not in that trio are **not** automatically compiled (there aren’t others). Tests live *inside* algorithm modules behind `static if (BOTAN_TEST)`.

Top-level versions: `Have_botan`, `Botan`. Configurations add the long feature lists. First configuration is `full` → implicit default for `dub build` / `dub test`.

Arch-specific extra versions (`full`):

- **x86_64 (all compilers):** `Engine_ASM`, `Entropy_Rdrand`, `Entropy_Rdseed`, `Entropy_HRTimer`, `ZLib`.
- **x86_64 + LDC** (`versions-x86_64-ldc`; DUB requires compiler last): `SHA1_x86_64`, `AES_NI`, `SIMD_SSE2`, `AES_SSSE3`, `IDEA_SSE2`, `SHA1_SSE2`, `SHA2_32_SSE2`, `SHA2_32_X86`, `ChaCha_SIMD`, `ChaCha_AVX2`, `SM4_HWAES`, `ARIA_HWAES`, `Camellia_HWAES`, `Engine_SIMD`. DMD SIGILL'd these at startup.
- **x86:** `Entropy_Rdrand`, `Entropy_HRTimer`, `MD4_x86_32`, `MD5_x86_32`, `SHA1_x86_32`, `Engine_ASM`.

A non-x86 target (including RISC-V, if someone ever builds this there) gets only the portable `versions` list: `CoreEngine`, device/Win32/proc entropy flags, no AES-NI/SSE. `Entropy_Rdrand` / `Entropy_HRTimer` are **not** in the portable list of `full` — they are arch extras — so RISC-V `full` would still have `Entropy_DevRand` / `Entropy_UnixProc` / `Entropy_ProcWalk` / `Entropy_EGD`.

Windows links `advapi32` + `user32`. Posix links `dl`.

### Green command

```
dub build --compiler=ldc2
```

Known-good cell: library debug, windows-x64, LDC 1.42.0 — PASS, **0** `Deprecation:` lines after `460336f` (`Fix auto/ref deprecations for LDC 1.42.`). That commit is the v1.13.9 tag.

Faster rebuilds: LDC `--cache=build/ldc-cache` + `--oq` in `dub.json` (one
`.o` per module inside `--combined`; see `scripts/inc-build.ps1` and
`incremental-build.md`). Do not use `--build-mode=singleFile` on this tree.

`README.md` claims testing on DMD 2.099.1+ / LDC 1.31.0+ (LDC 1.42+ for CI). GitHub Actions (`.github/workflows/ci.yml`) runs FocusTests on Ubuntu/Windows (`ldc-latest`, `ldc-beta`, `dmd-latest`, `dmd-beta` × x86/x86_64, Ubuntu x86 excluded) plus an Ubuntu LDC `full_openssl` job.

`dmd64_build_instructions.txt` is a historical note about 32-bit Windows host memory when targeting x86_64 with old DMD. Treat as unread/stale unless someone is still building that way.

### How tests actually run

Upgrade work is bound to this same cell. Do not add another harness; see `dub-test.md`.

There are **no** top-level `unittest {}` blocks that always compile. Two independent gates:

1. `version(unittest)` → `BOTAN_TEST = true` (`constants.d:86–87`). `dub test` sets this.
2. `version(CanTest)` → `BOTAN_HAS_TESTS = true` (`constants.d:53–54`). **`full` and `full_openssl` set `CanTest`; `lite` / `pubkey` / `hash` do not.**

A typical KAT driver (`hash/hash.d:108–126`):

```
static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest
{
    globalState();
    size_t fails = runTestsInDir("test_data/hash", test);
    testReport("hash", total_tests, fails);
}
```

So `dub test -c hash` compiles `BOTAN_TEST` but **skips** the vector unittests. `dub test` (default `full`) runs them.

`source/botan/test.d` is the harness (always compiled): `CHECK` / `CHECK_MESSAGE` mixins, `runTestsInDir` (walks `*.vec` in parallel via `std.parallelism`), `runTestsBb` (Botan-style `Key = Value` vector parser with `[section]` headers), `testReport`. Working directory is `"."` (`dub.json:14`), so `test_data/` is resolved from the clone root. `runTestsInDir` **asserts** if any file reports fails (`test.d:96–98`).

Per-suite skip switches live in `constants.d:16–51` (`SKIP_HASH_TEST`, `SKIP_TLS_TEST`, `SKIP_CVC_TEST`, …). CVC is skipped with a TODO (`EAC11 ECDSA Key decoding`).

Startup self-tests (`selftest/selftest.d`) are **not** unittests. They run inside `LibraryState.initialize` when `version(Self_Tests)` (`full` has it): hardcoded DES/3DES/AES-128 KATs via `cipherKat`. Failure throws `SelfTestFailure` at first use of `globalState()`.

`botan.tls.test` builds an in-process client/server with a test `TLSCredentialsManager` (self-signed RSA CA) when `BOTAN_TEST && BOTAN_HAS_TLS`.

### Vectors and extra trees

`test_data/` (not compiled):

- `aead/*.vec`, `block/*.vec`, `hash/*.vec`, `mac/*.vec`, `modes/*.vec`, `stream/*.vec`, `kdf/*.vec`, `pbkdf/*.vec`, `pubkey/*.vec`
- `hkdf.vec`, `hmac_drbg.vec`, `transform.vec`, `x931.vec`, `mp_valid.dat`
- `nist_x509/test01` … `test76` (NIST PKITS-style cert/CRL sets)
- `ecc/` CVC and EC PEM fixtures

### Examples

Under `examples/`, each is a **separate** dub project depending on `"botan": { "path": "../../" }` with a `subConfigurations` slice:

| Example | Config | What it shows |
|---|---|---|
| `hash/` | `hash` + extra `Skein_512` | `retrieveHash` vs Phobos |
| `pubkey/` | `pubkey` | RSA PKCS#1 encrypt/decrypt |
| `selfsigned/` | (default full, plus `version = X509` in source) | CA + PKCS#10 + signed cert |
| `bcrypt/` | unread | passhash |
| `cryptobox/` | unread | constructs/cryptobox |
| `curve25519/` | unread | X25519 |

These are manuals, not the `dub test` suite.

### Compiler notes

- LDC 1.42 required the `const auto ref` fix (`460336f`) — `auto const ref` is now a deprecation when `auto` and `ref` are not adjacent.
- Previous cell also hit memutils `Embed.opEquals` const. Fixed upstream in memutils 1.0.12 (claimed); selections still 1.0.11.
- `LogLevel = Debug` in `constants.d:14` means `logDebug` prints on every initialize/self-test during debug builds. Noisy, not fatal.

## Loci

| Item | File:line |
|---|---|
| sourcePaths / configs | `dub.json:15–97` |
| BOTAN_TEST / CanTest | `source/botan/constants.d:53–54, 86–87` |
| Skip flags | `source/botan/constants.d:16–51` |
| Vector harness | `source/botan/test.d:72–152` |
| Hash unittest shape | `source/botan/hash/hash.d:108–126` |
| Startup KATs | `source/botan/selftest/selftest.d:43+` |
| CI | `.github/workflows/ci.yml` (Ubuntu/Windows FocusTests + Ubuntu LDC `full_openssl`) |

## Invariants

- `dub build` (no `unittest`) does **not** compile KAT bodies; it still compiles `test.d` helpers.
- Vectors are required at **run** time for `dub test -c full`, relative to cwd.
- Do not add a new algorithm without a `test_data/**/*.vec` driver **and** a `BOTAN_HAS_TESTS` unittest that runs it. An explicit `SKIP_*` is only for a pre-existing known hole (CVC) and is not how an upgrade increment lands (`upgrade-randombit.md` test contract).
- Default configuration is `full`, including `Self_Tests` (startup cost / log noise).
- A feature-off compile (identifier absent) must still build; the new module is an empty husk.

## Extension points

- New configuration: copy a versions list; keep `constants.d` in sync or the version is a no-op.
- New KAT: drop a `.vec` into the **family** directory the existing unittest already walks, or add `SKIP_*` + the same `unittest` shape (`dub-test.md`).
- Green for any new algorithm is `dub test --compiler=ldc2` (default `full`). Only `dub build` is recorded as verified on this pin (T0 still open).

## Unread / open

- Whether `dub test --compiler=ldc2` currently PASSes on this machine was **not** re-run (only `build/botan.lib` observed).
- Appveyor vs GitHub Actions drift unread in detail.
- `examples/bcrypt`, `cryptobox`, `curve25519` source unread.
- `dmd64_build_instructions.txt` unread beyond the first lines.
- RISC-V: no CI cell; `full` x86_64 SIMD versions would need to stay off (they already do, via `versions-x86_64` only).
