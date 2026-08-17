# Incremental LDC build and focused tests

Day-to-day upgrade work should not recompile every module or run the full
KAT wall. The suite **architecture** is unchanged (`dub-test.md`): finish
still means `dub test --compiler=ldc2` on `full`. While iterating, use
per-module objects + LDC cache, and `FocusTests` so only the families you
touched actually execute.

## Incremental compile / link

This tree cannot use dub `--build-mode=singleFile`: X.509 `RefCounted` aliases
and circular modules fail when each `.d` is compiled alone. Incremental
rebuilds stay on **one LDC invocation** (`--combined`) that still writes
**one `.o` per module** (`--oq`) and **reuses unchanged objects** from
`--cache=build/ldc-cache` (`--cache-retrieval=hardlink` in `dub.json`
`dflags-ldc`).

Do **not** add `/INCREMENTAL` to the static-library link. The cache is the
reuse mechanism; the test exe is relinked from those `.o` files.

Wrapper (from the botan root, after `riscv-dev/setenv.ps1`):

```
.\scripts\inc-build.ps1              # dub build --combined (cached .o)
.\scripts\inc-build.ps1 test         # full suite, same cache
.\scripts\inc-build.ps1 test rsa,rng # FocusTests, only those families
```

Equivalent raw dub:

```
dub build --compiler=ldc2 --combined
dub test  --compiler=ldc2 --combined --d-version=FocusTests --d-version=Test_RSA
```

Constant-time helpers are **off by default** (`No_CT`). Enable with `--d-version=CT`
(`BOTAN_HAS_CT` in `constants.d` only). Do not add `CT` to `full` / `standard` unless
that config should pay the timing-safe cost.

`build/ldc-cache/` lives under `build/` (already gitignored).

## Focused tests (`version(FocusTests)`)

`constants.d` still owns every `SKIP_*_TEST`. Without `FocusTests` they stay
`false` (full suite). With `--d-version=FocusTests`, each skip is **true**
unless the matching `--d-version=Test_*` is also set.

| Script alias | `version` | Existing skip |
|---|---|---|
| `rsa` | `Test_RSA` | `SKIP_RSA_TEST` |
| `rng` | `Test_RNG` | `SKIP_RNG_TEST` |
| `tls` | `Test_TLS` | `SKIP_TLS_TEST` |
| `hash` / `xof` / `block` / `mac` / `aead` / `pbkdf` / `kdf` / `hkdf` | `Test_Hash` / `Test_XOF` … | same family |
| `ecdsa` / `dh` / `curve25519` / `ed25519` / `ed448` / `x448` / `sm2` / `ecgdsa` / `eckcdsa` / `ecies` / `hotp` / `base32` / `base58` / `codec` / `nist_keywrap` / `eme_raw` / `chacha_rng` / `spake2p` / `iso9796` / `tls` / `roughtime` / `system_rng` / … | `Test_ECDSA` … | pubkey / RNG / OTP / codec / wrap / pad / PAKE / TLS / Roughtime families |

Unittest **shape** is unchanged (`static if (BOTAN_HAS_TESTS && !SKIP_FOO_TEST)`).
Focus only flips the skip constants. Same `runTestsBb` / `test_data/`.

**Usual loop for an increment:** `inc-build.ps1 test rsa` (or whichever family)
while editing. **Finish** still requires a full `dub test --compiler=ldc2`
(`AGENTS-upgrade.md`). Focus is not a landing.

## Invariants

- No second harness. No C++ `botan-test`.
- `FocusTests` is a development `version`, not a dub configuration.
- Full `full`/`CanTest` green remains the recorded cell.
