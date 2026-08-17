# `dub test` — the suite stays this architecture

This is a **design goal**. New algorithms and security backports do not get a second
test runner. They bind to **`dub test`** (default configuration `full`), the
**constants** in `source/botan/constants.d`, and **unittests of the same format**
already used by hash/block/MAC/PBKDF/AEAD.

C++ Botan’s `botan-test` / `src/tests/` executable is a source of **vectors only**.
It is never the D harness.

## What `dub test` actually turns on

```
dub test --compiler=ldc2
```

Default configuration is `full` (`dub.json` first config). That cell sets
`version(CanTest)` and, because this is `dub test`, `version(unittest)`.

| Constant | Set by | Role |
|---|---|---|
| `BOTAN_TEST` | `version(unittest)` (`constants.d:86–87`) | D unittest compilation; TLS in-process suite uses this |
| `BOTAN_HAS_TESTS` | `version(CanTest)` (`constants.d:53–54`) | Vector KAT unittests |
| `SKIP_*_TEST` | enums in `constants.d:16–51`, default `false` | Per-family mute; **not** a way to land a feature |
| `BOTAN_HAS_FOO` | `version(Foo)` | Implementation present; KATs still need the two test constants |

`lite` / `pubkey` / `hash` do **not** set `CanTest`. `dub test -c hash` therefore
compiles `BOTAN_TEST` but **does not** run `BOTAN_HAS_TESTS` vector bodies.
Upgrade green is **`dub test` on `full`**, the same command CI already runs
(`.github/workflows/ci.yml`: `dub test --arch=$ARCH`).

While iterating, prefer incremental objects and **only the families you
changed**: `.\scripts\inc-build.ps1 test rsa,rng` (`incremental-build.md`).
That sets `version(FocusTests)` plus `Test_*`. It is not a substitute for
the full `full` cell at the end of an increment.

`dub build` does not compile those unittest bodies. That is intentional.

## Unittest format (copy this, do not invent)

Family KAT driver — `hash/hash.d:108–126` is the template:

```d
static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest
{
    globalState();
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        return runTestsBb(vec, "Hash", "Out", true,
            (ref HashMap!(string, string) m) {
                return hashTest(m["Hash"], m["In"], m["Out"]);
            });
    };
    size_t fails = runTestsInDir("test_data/hash", test);
    testReport("hash", total_tests, fails);
}
```

Same shape, different directory / key names:

| Family | Gate | Dir / file | SCAN field the `.vec` uses |
|---|---|---|---|
| Hash | `SKIP_HASH_TEST` | `test_data/hash/*.vec` | `Hash` |
| Block | `SKIP_BLOCK_TEST` | `test_data/block/*.vec` | cipher name |
| MAC | `SKIP_MAC_TEST` | `test_data/mac/*.vec` | MAC spec |
| Stream | `SKIP_STREAM_CIPHER_TEST` | `test_data/stream/*.vec` | stream name |
| Modes | `SKIP_CIPHER_MODE_TEST` | `test_data/modes/*.vec` | `CIPHER/MODE` |
| AEAD | `SKIP_AEAD_TEST` | `test_data/aead/*.vec` | AEAD name |
| PBKDF | `SKIP_PBKDF_TEST` | `test_data/pbkdf/*.vec` | `PBKDF2(…)` / new `"Argon2id"` |
| KDF | `SKIP_KDF_TEST` | `test_data/kdf/*.vec` | `KDF2(SHA-256)` |
| HKDF | `SKIP_HKDF_TEST` | `test_data/hkdf.vec` (RFC via `getKdf`) + `test_data/kdf/hkdf.vec` (factory Extract/Expand) | **H1b** |
| Pubkey | `SKIP_RSA_TEST` etc. | `test_data/pubkey/*.vec` | per-algo |
| TLS | `BOTAN_TEST && BOTAN_HAS_TLS` and `SKIP_TLS_TEST` | `tls/test.d` in-process + `test_data/tls_13/` + `test_data/tls/` + `hkdf_label.vec` | hello / 1.2 messages / Expand-Label |

Harness: `source/botan/test.d` — `runTestsBb` (Botan `Key = Value`, `[section]`,
`#` comments), `runTestsInDir` (`*.vec`), `CHECK` / `CHECK_MESSAGE`, `testReport`.
Working directory is the clone root (`dub.json` `"workingDirectory": "."`).

**Prefer dropping a `.vec` into an existing family directory** so the existing
unittest picks it up. A new hash does not get `unittest` in `blake2s.d` if
`hash/hash.d` already walks `test_data/hash`. A new block goes in
`test_data/block/` and `SKIP_BLOCK_TEST`.

Add a **new** `SKIP_*_TEST` + unittest only when there is no family driver
(new XOF dir, Argon2 *format* strings, RFC 8448 transcripts). The new block
must still be `static if (BOTAN_HAS_TESTS && !SKIP_FOO_TEST) unittest` and
still call `runTestsBb` / `runTestsInDir` / `testReport`.

After the vec walk, family drivers call `checkMemutilsRepeat` (`botan.test`):
warmup once, then a second Unique-wrapped probe of a popular algo. Growth of
`DebugAllocator` live bytes fails the family. Do not `.destroy` other GC
objects from a finalizer (`Unique!(T,void)` / `botanDestroyIfLive`). Classes
that hold `Unique!` (`HMAC_DRBG`, `HOTP`/`TOTP`, `ChaChaRNG`, `GCMMode`, …)
must be `Unique!`-wrapped in the probe. Covered: hash, block, mac, aead,
stream, xof, pbkdf, cipher_mode, hkdf/kdf, hotp, nist_keywrap, chacha_rng,
rng HMAC_DRBG, tls13 hello/record, tls 1.2 msg_kat, hkdf_label, rfc3394,
base64, polyval, rfc6979, fpe_fe1, cryptobox, spake2p, mode_pad, bcrypt,
passhash9, ecdh, ecdsa, dsa, rsa, elgamal. The 1.2 in-process handshake still
logs a fixed 548 B Lockless residue.

TLS 1.3 in-process tests extend `tls/test.d` under the same
`BOTAN_TEST && BOTAN_HAS_TLS` gate, plus `static if (BOTAN_HAS_TLS_13)` inside
so `!TLS_13` builds do not compile 1.3 cases. Packet fixtures (T13c hello
parse) use `runTestsBb` over `test_data/tls_13/` and the existing
`SKIP_TLS_TEST` (no separate `SKIP_TLS13_TEST`). T13d runs an in-process 1.3
handshake from `tls/test.d` (`TestPolicy` accepts 1.3; default policy does not).
Post-SH handshake and application records are AEAD-protected via
`TLS13RecordLayer`.

Negative tests (S1 RSA length, S5 RNG clear, S2 BER) are additional `unittest`
blocks with the **same constants**:

```d
static if (BOTAN_HAS_TESTS && !SKIP_RSA_TEST) unittest
{
    globalState();
    // constructed fixture; CHECK / CHECK_MESSAGE
}
```

They run under `dub test`, not a stand-alone `main`.

## Constants that must move together

When an increment adds a family that needs its own mute switch:

1. `enum SKIP_FOO_TEST = false;` next to the others in `constants.d`.
2. The unittest listed above.
3. `version(Foo)` → `BOTAN_HAS_FOO` (implementation) is **separate** from the
   skip. Do not reuse `SKIP_*` as a feature flag.
4. `CanTest` stays only on `full` / `full_openssl` unless a later pass
   deliberately documents otherwise.

Do not introduce `version(BotanTest)`, CMake `enable_testing`, or a
`dub.json` `"dflags-unittest"` runner that bypasses these enums.

## What is not the suite

| Thing | Role |
|---|---|
| `../randombit-botan/src/tests/` | Vector **source**. Copy `.vec` / fixtures; do not compile that tree |
| `selftest/selftest.d` + `version(Self_Tests)` | Startup KATs inside `globalState()`, not `dub test` |
| `examples/*` | Manuals (`subConfigurations`); not the suite |
| `SKIP_CVC_TEST` | Pre-existing hole (EAC11); do not add new skips to land features |

## Green cells (unchanged command)

| Cell | Command | What it proves |
|---|---|---|
| T0 / every increment | `dub test --compiler=ldc2` | default `full` + `CanTest` + `unittest` |
| library | `dub build --compiler=ldc2` | KATs not compiled; impl still builds |
| feature-off | `dub build` without the new `version` | husk; no type |
| family-off test | `dub test -c hash` | `BOTAN_HAS_TESTS` false; new KAT body not run (sanity) |

CI already is `dub test`. An increment that only “passes a handwritten main”
is not implemented.

ISA/ASM modules use this **same** suite (`asm-accel.md`): same `.vec` / SCAN
name; `full` on x86_64 may hit the accel provider; a portable-only build or
`setPreferredProvider(..., "core")` must still pass. No separate
`botan-test` / NASM harness.

## Invariants

- One harness: `botan.test` + in-module `unittest`.
- One invocation: `dub test` on `full`.
- Gates are the constants in `constants.d`, not a new file.
- `.vec` syntax stays `runTestsBb` (`Key = Value`, `[section]`). SCAN names
  in those keys match `scan-asn1.md`.
- `SKIP_*_TEST = true` is not a landing strategy.

## Loci

| Piece | Path |
|---|---|
| Skip + CanTest + unittest maps | `source/botan/constants.d:16–54, 86–87` |
| Harness | `source/botan/test.d` |
| Template KAT | `source/botan/hash/hash.d:108–126` |
| TLS in-process | `source/botan/tls/test.d` (`BOTAN_TEST && BOTAN_HAS_TLS`) |
| Config that sets `CanTest` | `dub.json` `full` / `full_openssl` |
| CI | `.github/workflows/ci.yml` `dub test --arch=$ARCH` |
