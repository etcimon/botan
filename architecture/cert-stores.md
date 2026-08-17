# Certificate chain sources (TLS 1.2 and 1.3)

Design goal: trust anchors and server/client chains stay on the **existing**
`CertificateStore` + `TLSCredentialsManager` virtuals. TLS 1.3 uses the same
hooks. New store *implementations* are version-gated modules. Nothing here
replaces ASN.1 / `x509PathValidate` (`scan-asn1.md`) or the vibe.0 delegate
ctors (`vibe-delegates.md`).

## What exists today

`CertificateStore` (`cert/x509/certstor.d`) is an interface:
`findCert(subject_dn, key_id)`, `findCrlFor`, `allSubjects`,
`certificateKnown`. Concrete types:

- `CertificateStoreInMemory` — list of certs; a ctor walks a **directory**
  of files (each file may now be a PEM bundle via `addFromFile`).
- `CertificateStoreFlatfile` (`CertStore_Flatfile`) — one PEM/DER **file**
  of self-signed CAs (C++ `Flatfile_Certificate_Store`).

`TLSCredentialsManager` (`tls/credentials_manager.d`) is what TLS calls:

| Virtual | Role (1.2 today, 1.3 must keep) |
|---|---|
| `trustedCertificateAuthorities(type, context)` | `Vector!CertificateStore` used as trust anchors and (server) CA advertisement |
| `verifyCertificateChain(type, hostname, chain)` | default: `x509PathValidate` against those stores + `matchesDnsName` |
| `certChain(cert_key_types, type, context)` | leaf-to-root chain whose leaf `algoName` is in `cert_key_types` (`"RSA"`, `"ECDSA"`, …) |
| `privateKeyFor(cert, type, context)` | key for that leaf |

vibe.0 `CustomTLSCredentials` implements those. `useTrustedCertificateFile`
builds a **one-certificate** `CertificateStoreInMemory`. `useCertificateChainFile`
sets a single `m_server_cert`. Comments already name Linux bundle paths
(`/etc/ssl/certs/ca-certificates.crt`) that this one-cert parse cannot load.
`trustedCertificateAuthorities` has a TODO: “Check machine stores for client mode”.

C++ 3.13 adds `certstor_flatfile` (PEM bundle), `certstor_system` (+ Windows /
macOS), SQL/SQLite stores. Those are the missing **sources**, not a new TLS API.

## Compatibility rule (1.2 and 1.3)

Handshake code (1.2 now, 1.3 later) may only:

1. Ask `certChain` with a list of **key-type strings**.
2. Ask `trustedCertificateAuthorities` for stores.
3. Call `verifyCertificateChain` (or the default path validator).

TLS 1.3 signature schemes (`rsa_pss_rsae_sha256`, `ecdsa_secp256r1_sha256`,
`ed25519`, …) must be **mapped to existing `algoName` tokens** (`"RSA"`,
`"ECDSA"`, `"Ed25519"`) before `certChain` is invoked. vibe.0’s loop
`cert_key_type == m_key.algoName` then keeps working without a ctor change.

Do **not**:

- Add a 1.3-only `certChain13` virtual that `CustomTLSCredentials` would miss.
- Change `Vector!CertificateStore` / `Vector!X509Certificate` signatures.
- Require C++ 3.13 `DNSName` to verify hostnames (keep `matchesDnsName` until
  an additive helper exists).
- Retire DSA/RSA chain selection. Policy may stop *offering* them; the store
  and `certChain` still accept those `algoName`s when the versions are compiled.

`TLSPolicy` stays the veto: `allowedSignatureMethods`, `allowedEccCurves`,
`allowedCiphers`. New 1.3 hooks are **new methods with defaults** (e.g.
`allowedSignatureSchemes()` defaulting to a mapping of the 1.2 lists plus
Ed25519 when `BOTAN_HAS_ED25519`). `CustomTLSPolicy` compiles unchanged.

## Sources to implement (version-gated)

| ID | `version` / type | What it loads | TLS use |
|---|---|---|---|
| CS1 **done** | `CertStore_Flatfile` → `CertificateStoreFlatfile` | One PEM/DER **bundle file** (many `CERTIFICATE` blocks). Matches C++ `Flatfile_Certificate_Store` and vibe.0’s documented CA paths. | `trustedCertificateAuthorities`; also intermediate lookup during path build |
| (extend) | keep `CertificateStoreInMemory` | Memory list; **add** `addFromFile` / PEM-bundle parse so a single file with many certs works without a new type | existing vibe.0 `useTrustedCertificateFile` can call this and load a bundle **without** a vibe.0 signature change |
| CS2 **done** | `CertStore_System` | OS trust: Windows `CertOpenSystemStore` (`Root`+`CA`); POSIX well-known bundle paths | client default when the app did not add files |
| (exists) | `SQLite` | `session_manager_sqlite` / unread SQL certstor | optional |
| CS3 **done** | policy helper only | Map 1.3 scheme names → `algoName` for `certChain` | `TLSChannel` 1.2 and 1.3 |

Directory-of-PEMs already works (`CertificateStoreInMemory.this(dir)`). CS1 is
the missing **file-of-PEMs** case.

Implementation stays behind `version(X509)` (already forced by vibe.0
`version = X509`). Flatfile/system are extra identifiers so `lite` does not
pull OS stores.

### Path validation

`verifyCertificateChain` continues to call `x509PathValidate(chain,
restrictions, trusted_CAs)`. Restrictions (`maxCertChainLength`) already
exist and vibe.0 sets them. S3 (nameConstraint) and S2 (BER) patch this
path; they do not replace the store interface.

OCSP staple (**T13e**, `OCSP_Staple`) is a `status_request` on the TLS 1.3
CertificateEntry (RFC 8446 4.4.2.1 / RFC 6066 CertificateStatus). The server
emits it only if the client offered the extension and
`TLSCredentialsManager.ocspStaple` returns DER (default empty). **S4:** online
fetch for path validation uses `setHttpExchangeHandler` / `ocspHttpPost` (zero
redirects). With no handler, `OnlineCheck` skips instead of throwing.

## vibe.0 follow-up (other branch)

After CS1: `useTrustedCertificateFile` should treat a regular file as a PEM
bundle (Flatfile or `addFromFile`) and a directory as today. Method
signature unchanged. `feature/botan-delegate-sync`.

System store (CS2) can satisfy the “machine stores” TODO in
`trustedCertificateAuthorities` when `CertStore_System` is compiled and the
app did not install a custom store — default off or behind an explicit
`useSystemTrustStore()` so tests stay deterministic.

## Tests (`dub-test.md`)

- CS1: `test_data/` PEM bundle with two CAs; `findCert` hits both; path
  validate a leaf signed by one. `SKIP_X509_TEST` unittest, `runTestsBb` or
  fixture files already used by `cert/x509/test.d`.
- CS1b: `CertificateStoreInMemory.addFromFile` on a multi-cert PEM.
- CS2: compile-only on this Windows cell unless a recorded store is present;
  Linux cell later.
- CS3: `certChain(["RSA"], "tls-server", …)` and
  `certChain(["ECDSA"], …)` plus, with `TLS_13`, mapping
  `rsa_pss_rsae_sha256` → `"RSA"` so the same credentials object answers.
- Existing `tls/test.d` in-process handshake still passes (test creds that
  ignore verify stay valid).

## Loci

| Piece | Path |
|---|---|
| Store interface + in-memory | `source/botan/cert/x509/certstor.d` |
| Path validate | `source/botan/cert/x509/x509path.d` |
| Credentials virtuals | `source/botan/tls/credentials_manager.d:47–114` |
| Policy allow-lists | `source/botan/tls/policy.d:65–180` |
| vibe.0 file helpers | `../vibe.0/source/vibe/stream/botan.d:588–627, 804–875` |
| C++ flatfile / system | `../randombit-botan/src/lib/x509/certstor_*` |

## Invariants

- No new TLS credentials virtual required for 1.3.
- `cert_key_types` remain `algoName` strings (`"RSA"`, `"ECDSA"`, `"Ed25519"`).
- Stores are `CertificateStore`; path validation stays `x509PathValidate`.
- Algorithms used on certificates (RSA, ECDSA, Ed25519, SHA-2) are **not**
  retired; policy only decides what a handshake *offers*.
