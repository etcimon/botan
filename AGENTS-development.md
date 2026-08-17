# botan — What a pass is

A pass names one thesis, changes this tree in this tree’s idiom (D modules, `static if
(BOTAN_HAS_*)`, SCAN names, memutils containers), corrects the `architecture/` note for the
area it touched, runs a named green cell, and records the outcome in `AGENTS-todo.md`.

## Finished

- The thesis is either done or blocked on a fact (command + output), not on a guess.
- Interface-visible movement is stated in `architecture/interface.md` or did not happen.
  Callers (wiki, GitHub Pages, `examples/`, vibe.0 `source/vibe/stream/botan.d`) cannot be
  re-tested from inside this package; accidental signature drift is the defect to avoid.
- Cryptographic or security work additionally satisfies `AGENTS-upgrade.md` (vectors +
  `dub test` + feature-off build). A feature without those tests is not implemented.
- Copyright headers on touched files follow `architecture/copyright.md`.

## Scale

One boundary, one identifier, or one failing test per pass. TLS 1.3, PQC, and BER hardening
are sequences of green steps, not one diff. Prefer the change the C++ maintainers would
recognise (their vectors, their algorithm names) shaped as this D tree already shapes AES and
RSA.

## Green cells this tree actually has

| Cell | Command | What it covers |
|---|---|---|
| library debug, windows-x64, LDC 1.42 | `dub build --compiler=ldc2` | default `full`; recorded PASS on `460336f` |
| KATs + in-process TLS | `dub test --compiler=ldc2` | `CanTest` + `unittest`; **not yet re-verified** on this pin |
| example slices | `dub build` in `examples/hash`, `examples/pubkey` | `subConfigurations` `hash` / `pubkey` |

A pass that only builds has not tested an algorithm.

## What this file is not

It does not replace `AGENTS.md` (navigation) or `AGENTS-upgrade.md` (randombit increments).
It does not import a parent scaffold.
