# vibe.0 attachment — delegates are the TLS API

This note is the architectural constraint every TLS increment (including 1.3) must preserve.
The consumer is `../vibe.0` on branch `feature/botan-delegate-sync` (`7b77638`), which will
merge to etcimon/vibe.0 `master`. That tree’s own write-up is `../vibe.0/architecture/tls-crypto.md`.

## What vibe.0 actually compiles

`vibe.stream.botan` is **not** behind `version(Botan)` — importing the module is the opt-in.
It does force `version = X509` so botan’s certificate modules compile in that translation unit.

Other vibe.0 Botan gates:

| Site | Gate | Role |
|---|---|---|
| `vibe.stream.botan` | implicit (import) + `version = X509` | TLS stream + context |
| `vibe.stream.bufcomp` | `version(Botan)` | `BufferedComputation` + `SHA256` |
| `vibe.stream.tls.createTLSContext` | Botan factory honours `TLSVersion` | `any`/`tls1_2` offer 1.2; `tls1_3` offers 1.3 |
| `vibe.stream.tls.createTLSStreamFL` | always Botan | `RefCounted!BotanTLSStream` |
| HTTP / pgsql / examples | import `vibe.stream.botan` | ALPN `"h2"` path |

Today `TLSVersion.tls1_3` installs **OpenSSL**, because this botan pin has no 1.3. That is a
vibe.0 factory choice, not a botan API. Once `version(TLS_13)` exists **and**
`TLSBlockingChannel` still accepts the same delegates, vibe.0 can offer Botan for 1.3
without a second stream type.

## The delegate contract (do not change signatures)

`TLSChannel` / `TLSClient` / `TLSServer` / `TLSBlockingChannel` are a **callback endpoint**.
There is no socket in botan. vibe.0 owns I/O.

```
TCPConnection
    ▲  onRead  : ubyte[] delegate(ubyte[])     alias DataReader
    │  onWrite : void delegate(in ubyte[])     alias DataWriter
    │
BotanTLSStream  (vibe.stream.botan)
    │  TLSBlockingChannel(read_fn, write_fn, alert_cb, hs_cb, …)
    │
TLSBlockingChannel  (botan.tls.blocking)
    │  new TLSClient / TLSServer(
    │        write_fn,          // DataWriter  — ciphertext to the wire
    │        &dataCb,           // OnClearData — plaintext to the app
    │        &alertCb,          // OnAlert
    │        &handshakeCb,      // OnHandshakeComplete
    │        session_manager, creds, policy, rng, …)
    │
TLSClient / TLSServer : TLSChannel
```

Exact aliases (`channel.d:39–42`, `blocking.d:28`, `server.d:27–28`):

| Alias | Type | vibe.0 member |
|---|---|---|
| `DataWriter` | `void delegate(in ubyte[])` | `BotanTLSStream.onWrite` |
| `DataReader` | `ubyte[] delegate(ubyte[])` | `BotanTLSStream.onRead` |
| `OnClearData` | `void delegate(in ubyte[])` | internal `TLSBlockingChannel.dataCb` |
| `OnAlert` | `void delegate(in TLSAlert, in ubyte[])` | `onAlert` / `m_alert_cb` |
| `OnHandshakeComplete` | `bool delegate(in TLSSession)` | `onHandhsakeComplete` / `m_handshake_complete` |
| `NextProtocolHandler` | `string delegate(in Vector!string)` | `BotanTLSContext.nextProtocolHandler` (ALPN) |
| `SNIHandler` | `SNIContextSwitchInfo delegate(string)` | `BotanTLSContext.sniHandler` |

Those seven aliases stay frozen. OCSP/CRL HTTP is a **separate, optional** attach
(`setHttpExchangeHandler`) — not a `TLSBlockingChannel` argument:

| Alias | Type | vibe.0 attach |
|---|---|---|
| `HttpExchangeHandler` | `HTTPResponse delegate(method, url, content_type, body)` | `requestHTTP` with `maxRedirects = 0` (S4) |

Set once at process start (`setHttpExchangeHandler`). Botan never opens a
socket and does not follow `Location`. The existing `tcp_message_handler`
(hostname + raw HTTP/1.0) remains a fallback. Sketch:

```d
import botan.utils.http_util.http_util;
import vibe.http.client;
setHttpExchangeHandler((method, url, ct, body) {
    HTTPClientSettings st;
    st.maxRedirects = 0;
    uint code = 0;
    string msg;
    string reply_body;
    requestHTTP(url, (scope req) {
        req.method = method == "POST" ? HTTPMethod.POST : HTTPMethod.GET;
        if (ct.length) req.headers["Content-Type"] = ct;
        if (body.length) req.writeBody(cast(ubyte[]) body);
    }, (scope res) {
        code = res.statusCode;
        msg = httpStatusText(res.statusCode);
        reply_body = res.bodyReader.readAllUTF8();
    }, st);
    return HTTPResponse(code, msg, reply_body, HashMapRef!(string,string).init);
});
```

libasync can implement the same delegate with its TCP client; the URL (scheme,
host, path) is already parsed by the app, not by Botan.

Client `TLSBlockingChannel` ctor (`blocking.d:40–50`) also takes:

`TLSSessionManager`, `TLSCredentialsManager`, `TLSPolicy`, `RandomNumberGenerator`,
`TLSServerInformation`, `TLSProtocolVersion offer_version` (default `latestTlsVersion()`),
`Vector!string next_protocols`.

Server ctor (`blocking.d:63–74`) takes the same four objects plus `NextProtocolHandler`,
`SNIHandler`, `is_datagram`, `io_buf_sz`.

vibe.0 calls those two ctors verbatim (`botan.d:95` client, `botan.d:111` server).
`BotanTLSContext` subclasses nothing in botan except it **holds** a `TLSPolicy` /
`TLSCredentialsManager` / `TLSSessionManager` that *are* botan types. `CustomTLSPolicy`
overrides `acceptableProtocolVersion`, `ciphersuiteList`, `allowedEccCurves`,
`chooseCurve`, `minimumDhGroupSize`, `sessionTicketLifetime` — those virtuals stay.

C++ 3.x replaced this with `std::shared_ptr<TLS::Callbacks>` and a virtual class
(`tls_callbacks.h`). **That shape is not imported.** Internally a 1.3 record/handshake
module may exist (`tls/tls13/*`) the way C++ split `tls12`/`tls13`, but it must be
reached only from `TLSChannel` after `offer_version` is inspected. T13c parse
types (`TLS13SupportedVersions`, `TLS13KeyShare`, …) are not public API.
vibe.0 never constructs a 1.3-specific type.

## What “same way as currently” means for new features

- New algorithms: factory SCAN names + `version` flags (`scan-asn1.md`). vibe.0 does
  not name them unless a `CustomTLSPolicy` allow-list is extended. Adding
  `"AES-256/GCM-SIV"` or `"Ed25519"` must not change `TLSClient.this` or the
  seven aliases. TLS suites keep putting SCAN strings in `cipher`/`mac`/`prf`.
- Certificate files: after CS1, `useTrustedCertificateFile` may load a PEM
  **bundle** through `CertificateStoreInMemory.addFromFile` / Flatfile
  (`cert-stores.md`). `certChain` still matches `m_key.algoName` against
  `"RSA"` / `"ECDSA"` / `"Ed25519"` — 1.3 schemes are mapped before the call.
- TLS 1.3: add `TLSProtocolVersion.TLS_V13 = 0x0304` **without** changing
  `latestTlsVersion()` (stays 1.2). vibe.0 already has `defaultProtocolOffer` and
  `TLSVersion.tls1_3`. Wiring Botan for 1.3 is a **vibe.0** factory change on
  `feature/botan-delegate-sync`: if botan compiled `TLS_13`, `createTLSContext(tls1_3)`
  may return `BotanTLSContext` and set `defaultProtocolOffer = TLS_V13`. The stream
  class stays `BotanTLSStream`.
- Policy virtuals: new hooks (e.g. 1.3 ciphersuites, PQC groups) are **new methods
  with defaults** on `TLSPolicy`. `CustomTLSPolicy` keeps compiling without edits.
  Do not remove or reorder existing virtuals.
- `TLSSession` fields vibe.0 reads in `onHandhsakeComplete`: `sessionId()`,
  `ciphersuite()`, `startTime()`, `Version()`, `peerCerts()`. Adding 1.3 fields is
  fine; renaming or dropping these is not.
- `underlyingChannel().applicationProtocol()` is how ALPN is read. Keep it on
  `TLSChannel` for 1.3.
- `LibraryState` thread-local + `static ~this` `setGlobalState(null)` in vibe.0
  remains the lifetime model. Do not switch to C++ process-global state.

## Internal 1.2 / 1.3 split (allowed)

C++ uses `Channel_Impl` + `tls_client_impl_13`. D may do the same **behind**
`TLSClient`/`TLSServer`:

```
TLSChannel.receivedData / send
        │
        ├─ HandshakeState 1.2   (existing)
        └─ static if (BOTAN_HAS_TLS_13) Tls13Handshake   (new files)
```

`TLSBlockingChannel.doHandshake` already loops `read_fn` → `channel.receivedData`
until `isActive()`. A 1.3 handshake that becomes active through the same
`isActive()` / `receivedData` / `send` surface needs **no** vibe.0 change except
offer version.

## vibe.0 follow-up (other repo, other branch)

Tracked on `../vibe.0` `feature/botan-delegate-sync`:

1. **V1 landed:** `createTLSContext(tls1_3)` builds `BotanTLSContext` and sets
   `defaultProtocolOffer = TLS_V13`. Stream remains `BotanTLSStream` + the same
   four delegates. OpenSSL remains available via `setTLSContextFactory`.
2. **V2 landed:** factory honours every `TLSVersion`; PEM bundles + system store
   + OCSP `requestHTTP` (`maxRedirects = 0`). `any` still does not offer 1.3.
3. `peerCertificate` on `BotanTLSStream` still `assert`s; that is a vibe.0 interface
   gap, not a botan increment.

## Invariants

- The seven aliases and both `TLSBlockingChannel` ctors are frozen.
- `TLSPolicy` / `TLSCredentialsManager` / `TLSSessionManager` remain subclassable
  with the virtuals vibe.0 already overrides.
- `latestTlsVersion()` remains 1.2 until a documented, opt-in vibe.0 change asks
  otherwise — and even then the **default** on the botan type stays 1.2 so
  `createTLSContext(TLSVersion.any)` does not silently offer 1.3.
- C++ `TLS::Callbacks` is never a D public type.

## Loci

| Piece | File:line |
|---|---|
| Aliases | `source/botan/tls/channel.d:39–42` |
| Client blocking ctor | `source/botan/tls/blocking.d:40–60` |
| Server blocking ctor | `source/botan/tls/blocking.d:63–84` |
| Client offer + delegates | `source/botan/tls/client.d:51–71` |
| Server ALPN/SNI | `source/botan/tls/server.d:27–68` |
| vibe.0 stream attach | `../vibe.0/source/vibe/stream/botan.d:80–126, 312–371` |
| vibe.0 factory | `../vibe.0/source/vibe/stream/tls.d:81–98` |
