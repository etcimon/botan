# botan — Upgrade pass (from randombit/botan)

How to land one increment from `architecture/upgrade-randombit.md` without breaking the wiki
API or shipping an untested algorithm.

Work on git branch **`feature/randombit-sync`**. That branch merges to **this repository’s
`master`** (etcimon/botan). Sync remotes first (`upgrade-randombit.md` git section).

Companion notes: `architecture/upgrade-randombit.md` (full increment table + test contract),
`architecture/dub-test.md` (`dub test` + constants + unittest format),
`architecture/inventory-randombit.md` (complete C++ vs D list),
`architecture/vibe-delegates.md` (frozen TLS aliases/ctors),
`architecture/feature-versions.md` (identifiers), `architecture/dub-configs.md` (`full` vs `standard`),
`architecture/cert-stores.md` (TLS 1.2/1.3 chains), `architecture/copyright.md` (headers),
`architecture/interface.md` (what callers may name), `AGENTS-development.md` (generic pass).

## Before writing code

1. Name the increment (`S1`, `A3`, …) from the rank table. One increment per pass.
2. Open the C++ counterpart under `../randombit-botan` and the D locus in the rank table.
   If the D area is marked unread (`architecture/open-questions.md`), write that note first.
3. State the API impact in one sentence: **none**, **new version identifier**, or **new
   optional argument with a default that preserves today’s behaviour**. Anything else stops
   the pass until the interface note is updated and a caller migration is written.
4. List the vectors you will copy from `../randombit-botan/src/tests/data/…` and the
   `unittest` that will run them. No list → no pass.

## During the pass

- Implement behind `version(Foo)` / `BOTAN_HAS_FOO` / `static if` (`feature-versions.md`
  checklist).
- Select it the existing way: C++ `name()` as SCAN / `algoName`, arm in
  `CoreEngine` or `getKdf`/`getEmsa`/`getPbkdf`/`pk_algs`+`OIDS` by **purpose**
  (`architecture/scan-asn1.md`). No second factory. Nested SCAN
  (`HMAC(SM3)`, `ARIA-128/GCM`) must work once the primitive arm exists.
- If the increment is an ASM/SIMD port: new ISA `version` only, code shaped
  like `aes_ni.d` / `utils/simd/wmmintrin.d` (LDC / GDC / `D_InlineAsm_*`),
  inspired by those files and the C++ impl, registered on
  `SIMDEngine`/`AssemblerEngine`/`AESISAEngine` under the **same** SCAN name
  (`architecture/asm-accel.md`). Same family `unittest` / `dub test`.
- Copy KATs into `test_data/` in `runTestsBb` syntax (`Key = Value`, `[section]`).
  Prefer an existing family dir so the existing `unittest` runs them
  (`architecture/dub-test.md`). Do not add C++ `botan-test` or a new runner.
- New family only: `SKIP_FOO_TEST` in `constants.d` +
  `static if (BOTAN_HAS_TESTS && !SKIP_FOO_TEST) unittest` in the same shape as
  `hash/hash.d:108–126` (`globalState`, `runTestsInDir` / `runTestsBb`,
  `testReport`).
- Security fixes: another unittest under the same constants, using `CHECK`.
- While iterating: `.\scripts\inc-build.ps1` / `inc-build.ps1 test <families>`
  (`architecture/incremental-build.md`). Finish still needs full `dub test`.
- Update copyright on every file whose body changed (`copyright.md`).
- Do not change `TLSClient` / `TLSBlockingChannel` / `TLSPolicy` virtuals / `retrieve*` /
  `latestTlsVersion()` defaults.
- Do not `git add` `../randombit-botan` into this package.

## Finished means

Recorded in `AGENTS-todo.md`, all actually run:

| Cell | Command | Must |
|---|---|---|
| existing library | `dub build --compiler=ldc2` | PASS (default `full`) |
| KATs + new unittests | `dub test --compiler=ldc2` | PASS on `full` / `CanTest` |
| (while editing) | `.\scripts\inc-build.ps1 test rsa` (etc.) | optional; **not** the landing cell (`incremental-build.md`) |
| feature-off | `dub build` of a config that does **not** list the new identifier | PASS; type not nameable |
| (if TLS) 1.2 still default | existing `tls/test.d` path | handshake at 1.2 |

If `dub test` is still unverified on this pin, the increment is **T0** and nothing else.

A `SKIP_*_TEST = true` landing is not finished.

## After

- Move the rank-table row to “done” in `upgrade-randombit.md` and
  `feature-versions.md`.
- Correct `interface.md` / `tls.md` / `symmetric.md` / `pubkey.md` only for the area you
  touched.
- Leave `BOTAN_VERSION_*` (C++ lineage 1.12.3) alone unless the pass is explicitly about
  that constant. The D package version stays `dub.json` `"version"`.
