# botan — Agent Guider (untracked-local)

```
id: botan
upstream: https://github.com/etcimon/botan.git
pin: master @ 460336f (tag v1.13.9)
compare: ../randombit-botan @ 6931ef6fd (3.13.0-24-g6931ef6fd, version.txt 3.14.0 unreleased)
work_branch: feature/randombit-sync  (merges to this repo's master)
vibe_branch: ../vibe.0 feature/botan-delegate-sync  (merges to vibe.0 master)
mechanism: nested-clone
purpose: Crypto + TLS in D (C++ Botan translation; memutils instead of STL)
green_command: dub build --compiler=ldc2
green_cell: library debug, windows-x64, LDC 1.42.0 — PASS (0 Deprecation lines; auto/ref fixed in 460336f)
green_verified: yes (focused x509/tls/pbkdf + hash/standard build 2026-08-15 CS1–CS3/H2/K1)
riscv_affinity: latent
persistence: untracked-local
authored_at: 2026-08-12
last_refresh: 2026-08-15
queue: AGENTS-todo.md (how to get current vs randombit/botan)
```

**Is:** large D crypto/TLS library under `source/botan/` (block, hash, pubkey, tls, asn1, …).  
**Is not:** the C++ Botan tree. C++ 3.x lives only as an analysis sibling at `../randombit-botan`.

**Deps:** `memutils ~>1.0.1` (selections still list 1.0.11; const `Embed.opEquals` lives in memutils **v1.0.12**), `botan-math ~>1.0.2` (selections: 1.0.4). libs-posix: `dl`. libs-windows: `advapi32`, `user32`. Optional `openssl` only in configuration `full_openssl`.

**Configurations:** `full` (default, include-all), `standard` (popular TLS/PKI), `full_openssl`, `lite`, `pubkey`, `hash`. Feature flags are D `version` identifiers mapped to `BOTAN_HAS_*` in `source/botan/constants.d`. Catalog: `architecture/feature-versions.md`.

**Green (current):** `460336f` + Train 0 + CS1/CS2/CS3/H2 + K1/K2 on `feature/randombit-sync`. Focused x509/tls/pbkdf PASS. Selections: memutils **1.0.12**.

## Notes

Start at `architecture/README.md`. Upgrade work is `architecture/upgrade-randombit.md` + `AGENTS-upgrade.md`.

| Intent | Open |
|---|---|
| Public promise (wiki, lookup, vibe.0) | `architecture/interface.md` |
| One TLS + pubkey walk | `architecture/overview.md` |
| Add/port an algorithm from C++ 3.x | `AGENTS-upgrade.md`, `architecture/upgrade-randombit.md` |
| What C++ has that we do not | `architecture/inventory-randombit.md` |
| Keep vibe.0 TLS delegates | `architecture/vibe-delegates.md` |
| SCAN + ASN.1 (how to select a new algo) | `architecture/scan-asn1.md` |
| How tests run (`dub test`, constants) | `architecture/dub-test.md` |
| Faster rebuilds / focused KATs | `architecture/incremental-build.md`, `scripts/inc-build.ps1` |
| dub `standard` vs `full` | `architecture/dub-configs.md` |
| Cert chain sources (1.2/1.3) | `architecture/cert-stores.md` |
| ASM/SIMD accel ports | `architecture/asm-accel.md` |
| New `version` identifier | `architecture/feature-versions.md` |
| Copyright on a touched file | `architecture/copyright.md` |
| Factory / engines / constants | `architecture/libstate-factory.md` |
| Build / KATs / configurations | `architecture/build-test.md` |
| What a pass is | `AGENTS-development.md` |
| Queue | `AGENTS-todo.md` |

## Invariants

- Wiki + GitHub Pages + vibe.0 signatures do not move. New behaviour is a new `version` or an optional argument whose default is today’s behaviour.
- ASN.1 (`ber_dec` / `OIDS` / `pk_algs`) and SCAN/`retrieve*`/`getCipher` selection stay as implemented. Missing algorithms are purpose-assembled strings (`scan-asn1.md`), not a new registry.
- Do not retire algorithms. `full` compiles all identifiers; `standard` is the useful/popular subset (`dub-configs.md`).
- Certificate chains stay `CertificateStore` + `TLSCredentialsManager`; 1.3 maps schemes to existing `algoName`s (`cert-stores.md`).
- ASM/SIMD ports are a separate `version` on `versions-<arch>`, written for LDC/GDC/`D_InlineAsm_*` after the existing D SIMD/engine style, tested with the same `dub test` KATs (`asm-accel.md`).
- Do not “fix” Embed/const by weakening TLS credential or key types; prefer const-correct `opEquals` on the Embed mixin.
- A new algorithm or security fix is not done without the test contract: **`dub test --compiler=ldc2`** on `full`, `constants.d` (`CanTest` / `BOTAN_HAS_TESTS` / `SKIP_*_TEST`), and a unittest of the same `runTestsBb` format (`architecture/dub-test.md`).
- `TLSProtocolVersion.latestTlsVersion()` stays TLS 1.2. `version(TLS)` does not imply `TLS_13`.
- `../randombit-botan` is never a dub dependency and is never vendored into `source/`.
- `BOTAN_VERSION_*` is the C++ lineage claim (1.12.3), not the D package version (1.13.9).

**Open:** S8/S2/S3/S4 need unread-file reads first; next increment **A1 / GMAC / KMAC** (GCM-SIV; GMAC needs MAC nonce/`start`). RISC-V unbuilt. See `AGENTS-todo.md`.
