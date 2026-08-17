# Copyright on updated files (D port of Botan)

This note is the rule for license headers when a pass touches a source file. It exists because
the D tree is a translation of C++ Botan (Simplified BSD) and later increments copy newer
`randombit/botan` files into that translation.

## Who holds what

- **C++ Botan** is Simplified BSD. Current upstream notice (`../randombit-botan/license.txt`)
  is `Copyright (C) 1999-2026 The Botan Authors`.
- **This D port** is the same license (`LICENSE.md`) with an aggregated 1999–2015 Jack Lloyd
  list plus **2014–2015 Etienne Cimon** as the port’s license holder.
- New D text written in an increment is still Simplified BSD and is attributed to the port
  holder **in addition to** the C++ authors whose file was copied or followed.

Nothing here changes the license text (the two numbered BSD clauses and the disclaimer stay
verbatim). Only the **year ranges and names** on a file move.

## Rule when a file is updated

Treat the D file as if it were a **copy of the newer randombit/botan file**, then record the
port.

1. Open the C++ counterpart under `../randombit-botan/src/lib/…` (or `license.txt` if the C++
   file has collapsed to “The Botan Authors”).
2. Copy that author/year list into the D header’s `Copyright:` block.
3. Add or extend `(C) 2014-YYYY Etienne Cimon` where `YYYY` is the year of the edit (this
   workspace: 2026). If the file already has `2014-2015 Etienne Cimon`, widen it; do not add a
   second Cimon line.
4. Keep `License: Botan is released under the Simplified BSD License (see LICENSE.md)`.
5. Do not delete Jack Lloyd, The Botan Authors, or any other name still present on the C++ file.
6. Do not put C++ include-guard comments or `license.txt` filenames into D modules.

If there is no C++ counterpart (pure D glue: `constants.d` version map, dub-only comments),
still widen Etienne Cimon’s years on that file when it is edited, and keep existing Jack Lloyd
years if he authored the original translation of that file.

## Header idiom (match existing D files)

```d
/**
* Short title
*
* Copyright:
* (C) 1999-2026 The Botan Authors
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.example;
```

Some files still use the C++-style `* (C) 2010,2016 Jack Lloyd` block without a `Copyright:`
label (`hash/sha3.d`). When updating such a file, either keep that shape and append a Cimon
line, or convert to the `Copyright:` / `License:` shape used by `tls/client.d`. Do not mix both
in one file.

## `LICENSE.md` aggregate notice

Update `LICENSE.md`’s year list in the **same pass** as the first file that would otherwise
make the aggregate stale (Jack Lloyd’s end year, Etienne Cimon’s end year, or the introduction
of “The Botan Authors”). Do not edit `LICENSE.md` in a docs-only pass.

## What a pass must not do

- Relicense a file.
- Replace the BSD notice with SPDX-only (this tree’s files use the prose header).
- Attribute the port to a name that is not the license holder of the port.
- Copy a C++ file’s header and forget Cimon — that would present the D text as if it were
  unmodified upstream.
- Update every file’s year because one algorithm changed. Years follow the file.

## Loci

| Notice | Path |
|---|---|
| D aggregate | `LICENSE.md` |
| C++ aggregate | `../randombit-botan/license.txt` |
| Typical D module header | `source/botan/tls/client.d:1–10` |
| Already-newer cherry-pick header | `source/botan/hash/sha3.d:1–8` |

## Invariants

- Every shipped `.d` file keeps a Simplified BSD header.
- A file whose body was brought in line with 3.x carries 3.x (or “Botan Authors”) years **and**
  Etienne Cimon.

## Open questions

- Whether to collapse `LICENSE.md`’s long individual list toward “The Botan Authors” the way
  3.x did. Not required for an increment; if done, it is its own pass and must keep Cimon.
