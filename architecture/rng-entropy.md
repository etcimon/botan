# RNG and entropy

## How it works

All randomness in botan goes through `RandomNumberGenerator` (`rng/rng.d:23`). The type is abstract: `randomize`, `randomVec`, `nextByte`, `isSeeded`, `clear`, `reseed`, `addEntropy`, `name`.

### What you actually get

`RandomNumberGenerator.makeRng()` (`rng.d:31–47`) builds:

```
HMAC_RNG(
    af.makeMac("HMAC(SHA-512)"),   // extractor
    af.makeMac("HMAC(SHA-256)"))   // PRF
```

then `reseed(256)`. That call requires `globalState()` → factory → CoreEngine HMAC + SHA-512/256. **RNG construction is what typically first initializes the library.**

`AutoSeededRNG` (`auto_rng.d:16–41`) is a thin owner of one `makeRng()` instance. Examples use `Unique!AutoSeededRNG`.

`HMAC_DRBG` holds `Unique!MAC` and `Unique!RNG` and **takes ownership** of both ctor arguments. Tests must `Unique!HMAC_DRBG` the DRBG itself and must **not** also `Unique!`-wrap the mac/prng they pass in (double-own). A GC-only `new HMAC_DRBG` leaks those Unique payloads when `gc_inFinalizer()` skips destroy. `rng/test.d` Unique-wraps and asserts `memutilsGrowth` 0 on a repeat.

`LibraryState` keeps a separate `SerializedRNG` (`rng.d:137–180`) as `globalRng()`: a mutex around another `makeRng()`. `PKSigner` uses **that** RNG, not the one you passed to `TLSClient`, unless you avoid `PKSigner`’s default path. TLS handshake IVs / ClientHello random use the RNG you passed into the client/server constructor.

`NullRNG` (`rng.d:120–132`) throws `PRNGUnseeded` on any output. Used where an API requires an RNG argument but generation must not happen.

### HMAC_RNG

`hmac_rng.d` implements Krawczyk extract-then-expand (not SP 800-90A). Two MACs: extractor (XTR) and PRF.

- `randomize` (`hmac_rng.d:39–68`): if unseeded, `reseed(256)`. Then HMAC-PRF with CTXinfo `"rng"`, copy half the PRF output, increment a counter. After `BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED` (512) bytes, `reseed(BOTAN_RNG_RESEED_POLL_BITS)` (128 bits).
- `isSeeded`: `m_collected_entropy_estimate >= 256`.
- `reseed` (`hmac_rng.d:98–154`):
  1. `EntropyAccumulator` feeds poll bytes into the extractor until `poll_bits` estimated entropy or the poll loop gives up.
  2. Forward-secure mix: PRF(`"rng"`) and PRF(`"reseed"`) are also extracted, so a bad poll cannot wipe a good state.
  3. New PRK = extractor.finished(); PRF key set to that; XTS salt = PRF(`"xts"`).

Poll dispatch is `LibraryState.pollAvailableSources` (`libstate.d:169–183`): up to 16 attempts, round-robin over `m_sources`, until `pollingGoalAchieved()`. If **no** sources were compiled in, it throws.

### Entropy sources

Built in `LibraryState.entropySources` (`libstate.d:186–228`). Each is `static if (BOTAN_HAS_ENTROPY_SRC_*)` **and** often `version(Posix)` / `version(Windows)`:

| Version flag | Class | Platform | What (from names + ctor args) |
|---|---|---|---|
| `Entropy_HRTimer` | `HighResolutionTimestamp` | all (in `full` only via x86 extras) | timing jitter |
| `Entropy_Rdrand` | `IntelRdrand` | x86 extras | `RDRAND` |
| `Entropy_DevRand` | `DeviceEntropySource` | Posix | `/dev/random`, `/dev/srandom`, `/dev/urandom` |
| `Entropy_CAPI` | `Win32CAPIEntropySource` | Windows | CryptoAPI (`advapi32`) — **in `lite`/`pubkey`, not in `full`’s portable list** |
| `Entropy_Win32` | `Win32EntropySource` | Windows | user32/timing (`user32`) |
| `Entropy_BEOS` | `BeOSEntropySource` | BeOS | unread; not in `full` |
| `Entropy_UnixProc` | `UnixProcessInfoEntropySource` + `UnixEntropySource` | Posix | process info; then exec of `/bin` `/sbin` `/usr/bin` `/usr/sbin` |
| `Entropy_ProcWalk` | `ProcWalkingEntropySource("/proc")` | Posix | `/proc` walk |
| `Entropy_EGD` | `EGDEntropySource` | Posix | `/var/run/egd-pool`, `/dev/egd-pool` |

`EntropyAccumulator` (`entropy_src.d:19–78`) is a callback + a reusable I/O buffer. Sources call `add(bytes, entropy_bits_per_byte)`.

On **Windows `full`**: Win32 + (x86) RDRAND + HRTimer. No CAPI unless you add `Entropy_CAPI`.  
On **Posix `full`**: DevRand + UnixProc + ProcWalk + EGD + (x86) RDRAND/HRTimer.  
On **RISC-V Linux** (hypothetical `full`): DevRand + UnixProc + ProcWalk + EGD. No RDRAND. That is enough for `HMAC_RNG` to seed from `/dev/urandom`.

### Other RNGs

- `HMAC_DRBG` (`hmac_drbg.d`) — SP 800-90A. `version(HMAC_DRBG)` is in `full`. Not the global default. Vectors: `test_data/hmac_drbg.vec`.
- `X931_RNG` (`x931_rng.d`) — ANSI X9.31. `version(X931_RNG)` in `full`. Vectors: `test_data/x931.vec`. Unread internals.
- `StatefulRNG` (`stateful_rng.d`) — reseed-interval + optional fork PID check. Spine for ChaCha_RNG (HMAC_DRBG not yet subclassed).
- `ChaChaRNG` (`chacha_rng.d`) — HMAC-SHA-256 + ChaCha20. `initializeWith` / `addEntropy` / `randomizeWithInput`. Vectors: `test_data/rng/chacha_rng.vec`.
- `System_RNG` (`system_rng.d`) — OS CSPRNG. Windows `RtlGenRandom` (`SystemFunction036`); Posix `/dev/urandom`. Always seeded; `addEntropy`/`reseed`/`clear` are no-ops. **Not** the `AutoSeededRNG` default.

`rng/test.d` — unread; gated by `SKIP_RNG_TEST`. `SKIP_SYSTEM_RNG_TEST` / `Test_System_RNG` covers the OS RNG smoke.

## Loci

| Piece | File:line |
|---|---|
| RNG interface + makeRng | `source/botan/rng/rng.d:23–47` |
| SerializedRNG / NullRNG | `source/botan/rng/rng.d:120–180` |
| AutoSeededRNG | `source/botan/rng/auto_rng.d:16–41` |
| HMAC_RNG generate / reseed | `source/botan/rng/hmac_rng.d:39–68, 98–154` |
| Poll loop | `source/botan/libstate/libstate.d:169–183` |
| Source list | `source/botan/libstate/libstate.d:186–228` |
| Accumulator | `source/botan/entropy/entropy_src.d:19–78` |
| HMAC_DRBG | `source/botan/rng/hmac_drbg.d:25–40` |
| Reseed constants | `source/botan/constants.d:77–78` |

## Invariants

- Do not use `NullRNG` for keygen.
- Global RNG and TLS ctor RNG are **different instances**.
- `makeRng` requires HMAC + SHA-256/512 compiled in (`full`, `lite`, `pubkey` have them; a hypothetical config without HMAC cannot `makeRng`).
- Zero sources ⇒ `pollAvailableSources` throws; `HMAC_RNG.reseed` then fails `isSeeded` if it cannot collect 256 bits.
- Unix process entropy **runs other binaries**. That is inherited from C++ Botan; treat as a sandbox concern.

## Extension points

- Implement `RandomNumberGenerator` and pass it to TLS / keygen.
- Implement `EntropySource` and push into `m_sources` (no public adder today — would need a `LibraryState` hook; currently the list is private and filled only in `initialize`).
- Use `HMAC_DRBG` explicitly when SP 800-90A is required.

## Unread

- Bodies of `dev_random.d`, `rdrand.d`, `hres_timer.d`, `es_win32.d`, `es_capi.d`, `es_egd.d`, `unix_procs.d`, `proc_walk.d`, `es_beos.d`.
- `x931_rng.d` internals.
- `rng/test.d`.
- Entropy **estimates** per source (whether `/dev/urandom` is credited conservatively enough).
- Fork safety: no `pthread_atfork` / PID check was seen in the files read. HMAC_RNG state after `fork` is an open correctness question.
