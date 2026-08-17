# dub configurations — popularity vs include-all

Design goal: **do not retire algorithms**. Historic and niche identifiers stay
in the package (`feature-versions.md` existing list + every new row). What
changes is **which configuration compiles them**.

Selection is still D `version` strings in `dub.json`. Callers cherry-pick with
`subConfigurations` or extra `"versions": ["MARS"]`.

## Configurations

| Name | Role | First in `dub.json`? |
|---|---|---|
| `full` | **Include all** compiled identifiers (today’s long list + every green increment). Implicit default while it remains first. | yes (now) |
| `standard` | **Useful / popular** TLS + PKI + modern primitives. Intended for vibe.0 and new apps. Does **not** delete identifiers; it simply does not list MARS/RC4/MD2/… | **added (H2)**; not first |
| `lite` / `pubkey` / `hash` | Existing slices | unchanged |
| `full_openssl` | `full` + OpenSSL engine (still x86_64-only versions — separate hygiene) | unchanged |

`full` is the “option to include all”. A consumer that wants every historic
cipher keeps `full` (the default today) or sets `"subConfigurations": { "botan": "full" }`.

`standard` is usefulness/popularity:

**Always (portable):** `CanTest` only if that config is used for `dub test`
(default test cell stays `full`). For library use: `SHA2_32`, `SHA2_64`,
`SHA3`, `Shake`, `BLAKE2B`, `HMAC`, `POLY1305`, `AES`, `ChaCha`, `Serpent`,
`AEAD_GCM`, `AEAD_CHACHA20_POLY1305`, `CBC`, `CTR_BE`, `GCM`/`AEAD_FILTER`,
`PBKDF2`, `HKDF` (after H1), `TLS_V12_PRF`, `HMAC_DRBG`, `PUBKEY`, `RSA`,
`ECDSA`, `ECDH`, `Curve25519`, `EMSA_PSSR`, `EMSA_PKCS1`, `EMSA1`, `EME_OAEP`,
`EME_PKCS1v15`, `TLS`, `X509`, `CertStore_Flatfile` (after CS1), portable
entropy (`Entropy_DevRand`, `Entropy_UnixProc`, `Entropy_Win32`,
`Entropy_ProcWalk`), `Auto_Seeding_RNG` (after H1).

**When green, also `standard`:** `Ed25519`, `Ed448`, `X448`, `Argon2`, `Scrypt`, `System_RNG`,
`AEAD_GCM_SIV`, `AEAD_ASCON128`, `Ascon_Hash256`, `Ascon_XOF`, `SHAKE_XOF`, `Truncated_Hash`, `BLAKE2S`, `GMAC`/`KMAC`/`BLAKE2BMAC`, `SP800_108`, `PGP_S2K`, `PKCS12_KDF`, `HOTP`, `SPAKE2P`, `Base32`, `Base58`, `NIST_Keywrap`, `EME_RAW`, `Stateful_RNG`, `ChaCha_RNG`. `CSHAKE_XOF` / `SP800_56A` / `SP800_56C` / `PBKDF_BCrypt` stay `full` only. `TLS_13` is on **`full` / `full_openssl` only** (not `standard`, not implied by `TLS`).
`versions` entry on the app (not implied by `standard`), same as `full`.

**Stay in `full` only (not retired, not in `standard`):** RC2/5/6, MARS, TEA,
XTEA, SAFER, KASUMI, MISTY1, CAST-256, DESX, MD2, MD4, RIPEMD-128, HAS-160,
Tiger, CBC-MAC, SSL3_MAC, SSL_V3_PRF, X931_RNG, RW, Nyberg_Rueppel, SEED,
GOST_*, national extras (SM2/SM3/SM4, Kuznyechik) until a caller asks,
ECGDSA/ECKCDSA/ECIES, ISO9796 (C++ deprecated), SHAKE_Cipher (C++ deprecated), PQC (`ML_KEM` …) until T13p/V1 need them, CVC,
engines ASM/SIMD unless
`versions-<arch>` on `standard` for AES-NI/SSE2 (those are useful on x86_64).

**`standard` x86_64 extras (useful, not historic):** `AES_NI`, `SIMD_SSE2`,
`AES_SSSE3`, `Engine_AES_ISA`, `Engine_SIMD`, `Entropy_Rdrand` — same idea as
today’s `full` arch extras, minus ISA toys that only back retired ciphers.
New ASM ports follow `asm-accel.md`: own constant, `versions-<arch>` only,
LDC/GDC/DMD-shaped, same `dub test` vectors as the portable algo.

## Adding a new algorithm

| Popularity | Put the `version` in |
|---|---|
| Useful for TLS/PKI/passwords (table above) | `standard` **and** `full` |
| Niche / national / PQC / deprecated-in-C++ | `full` only; extra `"versions"` for others |
| Historic already in tree | remain on `full`; never removed from `constants.d` |

Never delete a `version` identifier because C++ 3.13 deprecated it. Policy
(`TLSPolicy.allowedCiphers`) is what stops offering RC4, not `dub.json`.

## Default / vibe.0

While `full` is first, `dub build` and vibe.0 (no `subConfigurations`) compile
**all** current flags — no surprise shrink. After `standard` exists and
vibe.0 on `feature/botan-delegate-sync` can set
`"subConfigurations": { "botan": "standard" }` (or keep `full`), a later
release may move `standard` first. That move is its own pass and must keep
TLS + X509 + cert stores + AES-GCM + ChaCha20-Poly1305 + RSA/ECDSA/X25519.

`dub test` green remains **`full`** (`dub-test.md`) so historic KATs still run.
`dub build -c standard` is the H2 cell (proves the popular set links).

`standard` also lists a few identifiers that TLS/X.509 source names
unconditionally even when policy does not offer them: `MD5` and
`TLS_V10_PRF` (compiled PRF modules), `AEAD_CCM` (`AEADFilter` is gated
on CCM), `Diffie_Hellman` (`tls/messages.d` imports `dh`), `CryptoBox`
(session tickets), `CRC24` (OpenPGP codec), `PBE_PKCSv20` (PKCS#8).
Policy still does not *offer* FFDH or RC4.

## Invariants

- No algorithm identifier is removed from `constants.d` or from `full`.
- `standard` is a shorter **list**, not a different API.
- Extra `"versions": ["MD5"]` on an app still turns that husk on when using
  `standard`.
- Certificate stores needed for TLS (`X509`, `CertStore_Flatfile`) are in
  `standard` (`cert-stores.md`).
