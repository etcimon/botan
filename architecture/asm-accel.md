# ASM / SIMD accelerations — separate constants, compiler-shaped

Design goal: any port of an ASM or SIMD optimization (for an algorithm this
tree already has, or a new one from `inventory-randombit.md`) is **inspired by**
the current D helpers and the C++ reference, **expressed in what DMD / LDC /
GDC can compile**, gated by a **separate `version`**, and **tested the same
`dub test` way** as the portable implementation.

It is not a dump of C++ `asm volatile` or a new runner.

## What already exists (copy this shape)

| Layer | How it works |
|---|---|
| Feature flag | Own identifier: `AES_NI`, `AES_SSSE3`, `SHA1_SSE2`, `SHA2_32_SSE2`, `SHA2_32_X86`, `ChaCha_SIMD`, `ChaCha_AVX2`, `SM4_HWAES`, `ARIA_HWAES`, `Camellia_HWAES`, `SHA1_x86_64`, `MD5_x86_32`, `Serpent_SIMD`, `Engine_ASM`, `Engine_SIMD`, … (`constants.d` → `BOTAN_HAS_*`) |
| dub placement | **`versions-x86_64` / `versions-x86` only**, never the portable `versions` list (`dub.json:61–66`) |
| Module | `static if (BOTAN_HAS_AES_NI)` around `aes_ni.d`; portable `aes.d` stays `version(AES)` |
| Engine | `AESISAEngine` / `SIMDEngine` / `AssemblerEngine` register the same **SCAN name** (`"AES-128"`) with a higher provider weight; `CPUID.hasSsse3()` etc. at **find** time (`simd_engine.d:38–44`) |
| Intrinsics | `utils/simd/{emmintrin,tmmintrin,wmmintrin,immintrin}.d` — **`version(GDC)` builtins**, **`version(D_InlineAsm_X86_64)`** / DMD-style asm, **LDC** via `core.simd` / LLVM (`wmmintrin.d:31+`) |
| LDC 64×64→128 | `utils/mul128.d` `BotanLdcX64Asm` GCC-style `mulq`. `donna128 * ulong` is a full `(h:l)*y` via `mul64x64_128` (release used to multiply only `l` and `assert h==0`, which `-b release` strips — TLS 1.3 X25519 SS started with 8 zero bytes). `DonnaLdcX64` `fmul`/`fsquareTimes` stay off until re-checked against OpenSSL EE. `botan-math` `word_add`/`word_sub` stay portable `pragma(inline, true)` (LDC `%b1` → LLVM `$b1` is invalid). |
| P-256 Solinas | `ec_gfp/curve_nistp.d` `CurveGFpP256` (not a `version`; identity field rep). Botan 1.11 `redc_p256` column sums + in-place P-sub on a `word[8]` product (`comba_mul4`/`sqr4`). `chooseRepr` matches the secp256r1 prime by limbs. Replaces Montgomery `monty_redc`/`monty_cios4` on the ECDSA P-256 TLS 1.3 path. |
| Compiler detect | `D_InlineAsm_X86` / `D_InlineAsm_X86_64` → `BOTAN_HAS_DMD_X86_*_INLINE_ASM` (`constants.d:89–94`) |

Portable `CoreEngine` must keep working when every accel `version` is off
(RISC-V, `standard` without `versions-x86_64`, `dub build --arch=…` portable).

## How to port an optimization

1. **Read the current D path first** (`aes.d`, `aes_ni.d`, the matching
   `utils/simd/*` wrapper, `SIMDEngine` / `AssemblerEngine`). New accel code
   should look like those modules, not like a C file with `asm`.
2. **Use C++ `../randombit-botan` as the algorithm source** (round counts,
   shuffle masks, bitslice steps) — `src/lib/block/aes/aes_ni`,
   `sha1/sha1_x86`, AVX-512 variants, etc. Translate the **math**, not the
   assembler syntax.
3. **Emit compiler-specific bodies**:
   - **LDC:** `core.simd`, `ldc.gccbuiltins_*` / LLVM intrinsics, same style as
     existing `cpuid.d` `version(LDC)` and donna128.
   - **GDC:** `__builtin_ia32_*` as in `wmmintrin.d`.
   - **DMD:** `version(D_InlineAsm_X86_64)` / `D_InlineAsm_X86` only where
     that compiler actually has the instruction; do not assume DMD equals LDC.
   Shared wrappers go in `utils/simd/` (or a new sibling) so algorithm files
   stay one call sequence.
4. **Separate constant** — never fold AES-NI into `version(AES)`. Examples:
   `AES_NI`, `SHA2_32_x86`, `ChaCha_SIMD`, `ARIA_AESNI`, `SM4_x86`. Map in
   `constants.d`. Put the identifier on `versions-x86_64` (or `versions-x86`,
   later `versions-aarch64` / `versions-riscv64` when a cell exists).
5. **Same SCAN name** as the portable type (`scan-asn1.md`). Factory + weights
   pick `aes_isa` / `simd` / `asm` vs `core`. Callers still write `"AES-256/GCM"`.
6. **Do not retire** the portable module. Accel off ⇒ `CoreEngine` only.

Do not enable a new ISA flag on the portable `full`/`standard` `versions` list.
Do not require YASM/NASM or C++ object files in `dub.json`.

## Tests (same architecture as `dub-test.md`)

Accelerations do **not** get a second harness.

| What | How |
|---|---|
| Correctness | Same family `.vec` and `static if (BOTAN_HAS_TESTS && !SKIP_BLOCK_TEST)` (or hash/MAC) unittest. SCAN name is identical, so `runTestsBb` already exercises the **preferred** provider when the accel `version` is on. |
| Portable still green | `dub test` on a build **without** the ISA versions (or `setPreferredProvider("AES-128", "core")` inside a unittest) must pass the same vectors. |
| Accel compiled | Record a cell: `dub test --compiler=ldc2` on `full` (this host is windows-x64, so `AES_NI` / `SIMD_SSE2` already compile). Note LDC vs GDC vs DMD if more than one compiler is run. |
| Accel off | `dub build` without `AES_NI` (portable `versions` only) still builds. |
| Optional | `haveAlgorithm("AES-128")` true; `algorithmFactory` provider list contains `"aes_isa"` only when `BOTAN_HAS_AES_NI` and CPUID allows. |

`SKIP_*_TEST` stays the **family** skip (`SKIP_BLOCK_TEST`), not a new
`SKIP_AES_NI_TEST`, unless the accel has unique KATs that cannot live in
`test_data/block/aes.vec`. Prefer one vector file, two providers.

Green command remains **`dub test --compiler=ldc2`**. An increment that only
“looks faster” without that cell is not done.

## Where new C++ accels would land

C++ 3.13 has many `*_avx2` / `*_avx512` / `*_armv8` / `*_hwaes` `info.txt`
rows (`inventory-randombit.md` *accel*). Each is its own D `version` when
ported (e.g. `AES_VAES`, `SHA2_32_AVX2`, `ChaCha_AVX2`). Priority follows
usefulness (`dub-configs.md`): AES-NI / SSE2 / SHA-NI-class first; AVX-512
later. ARMv8 / RISC-V only with a recorded compiler cell.

`Engine_SIMD` / `Engine_ASM` / `Engine_AES_ISA` stay the registration points
unless a new ISA engine is justified (then a new `Engine_*` version, same
pattern).

## Invariants

- One portable implementation per algorithm; accel is additive and optional.
- One `version` per ISA flavour; listed only under `versions-<arch>`.
- Intrinsics go through D compiler conditionals (LDC / GDC / `D_InlineAsm_*`).
- Same SCAN name; same `dub test` / `BOTAN_HAS_TESTS` / `runTestsBb` suite.
- No C++ assembler objects, no retiring portable code.

## Loci

| Piece | Path |
|---|---|
| ISA versions | `dub.json` `versions-x86_64` / `versions-x86` |
| Flag map | `source/botan/constants.d` (`AES_NI`, `SIMD_SSE2`, `D_InlineAsm_*`) |
| SIMDEngine / ASM engine | `source/botan/engine/simd_engine.d`, `asm_engine.d` |
| AES-NI | `source/botan/block/aes_ni.d` |
| Compiler split (model) | `source/botan/utils/simd/wmmintrin.d` |
| CPUID at find | `source/botan/utils/cpuid.d`, `simd_engine.d:38` |
