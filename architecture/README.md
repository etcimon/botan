# botan architecture notes (untracked-local)

Pin: `master` `460336f848bf0dac878a250e8b9cf8e9da1dc432` / tag `v1.13.9` / `dub.json` version `1.13.9`.  
License: BSD 2-clause (`LICENSE.md`).  
This is a C++ Botan translation in D (C++ lineage ~1.12.3 per `BOTAN_VERSION_*` in `source/botan/constants.d`). It is **not** the C++ Botan tree. The analysis sibling `../randombit-botan` (`6931ef6fd`, 3.13-line) is for discrepancy work only. Containers and RAII come from [memutils](https://github.com/etcimon/memutils) instead of the C++ STL.

**Green (this cell):** `dub build --compiler=ldc2` — PASS. `build/botan.lib` present. Commit `460336f` rewrote `auto const ref` → `const auto ref` so LDC 1.42 / frontend 2.112 emit **0** `Deprecation:` lines. The older `memutils.helpers.Embed.opEquals` const failure (instantiated from `TLSCredentialsManager` / `ECDSAPrivateKey`) is attributed to memutils v1.0.12; this clone’s `dub.selections.json` still records `memutils` **1.0.11**. See `dependencies.md` and `open-questions.md`.

**Default build:** dub configuration `full` (first configuration, so implicit default), `targetType: staticLibrary`, `targetName: botan`, `targetPath: build`. Feature flags are D `version` identifiers listed per configuration in `dub.json`; `source/botan/constants.d` turns each into a `BOTAN_HAS_*` enum.

## Index

| Note | What it covers |
|---|---|
| [overview.md](overview.md) | One real TLS handshake + one pubkey sign/encrypt path, with file:line |
| [interface.md](interface.md) | `all.d`, public modules vs internals, version flags as the real API surface |
| [dependencies.md](dependencies.md) | memutils, botan-math, optional openssl, OS libs |
| [build-test.md](build-test.md) | sourcePaths, configurations, `test_data/`, selftest, examples, CanTest |
| [libstate-factory.md](libstate-factory.md) | `LibraryState`, `AlgorithmFactory`, engines, `constants.d` |
| [symmetric.md](symmetric.md) | block / stream / modes / hash / mac / kdf / pbkdf / filters |
| [pubkey.md](pubkey.md) | pubkey, pk_pad, math, asn1, cert/x509 |
| [tls.md](tls.md) | `tls/*`, credentials, session, record |
| [rng-entropy.md](rng-entropy.md) | RNG, HMAC_RNG, entropy sources |
| [open-questions.md](open-questions.md) | Unread, mismatches, RISC-V, residual green questions |
| [scan-asn1.md](scan-asn1.md) | **Design goal:** keep SCAN factory + ASN.1/OID; missing algos selected by purpose-assembled strings |
| [dub-test.md](dub-test.md) | **Design goal:** suite stays `dub test` + `constants.d` + same `unittest`/`runTestsBb` format |
| [incremental-build.md](incremental-build.md) | LDC per-`.o` cache + `FocusTests` for families you just added |
| [dub-configs.md](dub-configs.md) | `standard` (popular) vs `full` (include-all); nothing retired |
| [cert-stores.md](cert-stores.md) | Chain sources for TLS 1.2/1.3; same credentials virtuals |
| [asm-accel.md](asm-accel.md) | ISA/ASM ports: separate `version`, LDC/GDC/DMD-shaped, same `dub test` |
| [upgrade-randombit.md](upgrade-randombit.md) | Re-plan on `feature/randombit-sync`: complete increments, test contract, git sync |
| [inventory-randombit.md](inventory-randombit.md) | Every C++ `info.txt` algo vs this tree (same / D-only / missing) |
| [vibe-delegates.md](vibe-delegates.md) | vibe.0 `TLSBlockingChannel` delegate freeze (1.3 stays the same ctors) |
| [feature-versions.md](feature-versions.md) | `version` → `BOTAN_HAS_*` → `dub.json`; proposed identifiers |
| [copyright.md](copyright.md) | Headers when a file is copied forward from C++ Botan |

## How to read this tree

Do not treat `source/botan/all.d` as “the API”. The real surface is:

1. The D `version` list of the chosen dub configuration (`full`, `full_openssl`, `lite`, `pubkey`, `hash`).
2. The public types you import (`TLSClient`, `PKSigner`, `retrieveHash`, `AutoSeededRNG`, …).
3. String algorithm names parsed by `SCANToken` (`"AES-256/GCM"`, `"HMAC(SHA-256)"`, `"EMSA4(SHA-512)"`).

Algorithms that are not versioned in are compiled as empty modules (`static if (BOTAN_HAS_*)` around the body). The `.d` files still sit on `sourcePaths`.

## Unread (do not invent)

CVC (`cert/cvc/*`), compression backends, OCSP internals, SQLite session manager internals, `dyn_engine`, GNU MP engine, BeOS/CAPI entropy, `http_util`, `datastor` internals, SIMD helper headers, per-algorithm KATs beyond the factory path, `prf/hkdf.d` details, `utils/asm_*`, `tls/heartbeats.d` / `extensions.d` / `seq_numbers.d` beyond call sites. Marked unread in the relevant notes.
