# TLS

## How it works

`version(TLS)` → `BOTAN_HAS_TLS`. The implementation is a **callback-driven** TLS 1.0–1.2 / DTLS 1.0–1.2 endpoint. `version(TLS)` does **not** imply 1.3. **T13a:** `version(TLS_13)` → `BOTAN_HAS_TLS_13` defines `TLS_V13 = 0x0304` and `knownVersion()`; **`latestTlsVersion()` stays 1.2**; default `TLSPolicy.acceptableProtocolVersion` rejects 1.3 until T13d. There is no socket: you supply `void delegate(in ubyte[])` for ciphertext out and you push ciphertext in via `receivedData`. Application plaintext arrives on another delegate. This is how vibe.d / http2-botan (mentioned in `README.md`) can own the I/O. vibe.0 subclasses `TLSPolicy` and defaults `m_min_ver = TLS_V12`.

`TLSChannel` (`channel.d:47`) is the generic endpoint. `TLSClient` and `TLSServer` subclass it and implement handshake message handling. `TLSBlockingChannel` (`blocking.d:33`) layers a `DataReader` on top for apps that want `read`/`write` instead of callbacks.

### Objects you actually construct

1. **`TLSPolicy`** (`policy.d:35`) — allowed ciphers, MAC, kex, sigs, ECC curves, extensions, versions, renegotiation, heartbeats, time-in-random. Defaults prefer AEAD + ECDHE + x25519/secp/brainpool; SHA-1/MD5/3DES/RC4/static-RSA are commented out (`policy.d:65–156`). Compression is never negotiated (`policy.d:189–192`, comment: “Compression is not currently supported”).
2. **`TLSCredentialsManager`** (`credentials_manager.d:33`) — trust anchors, chain verify, client/server certs, private keys, SRP, PSK, ChannelID. Defaults: empty trust store, empty cert chain, `verifyCertificateChain` via `x509PathValidate`, ChannelID = cached `ECDSAPrivateKey(secp256r1)` per hostname (`credentials_manager.d:248–257`).
3. **`TLSSessionManager`** (`session_manager.d:36`) — save/load by session id or `TLSServerInformation`. In-memory implementation is in the same module (unread beyond the interface). `session_manager_sqlite.d` is `version(SQLite)` — **unread**, not in `full`.
4. **`RandomNumberGenerator`** — typically `AutoSeededRNG`.
5. **`TLSClient` / `TLSServer`**.

Client ctor (`client.d:51–71`) immediately sends ClientHello (resume if the manager has a session for that server). Server ctor (`server.d:50–68`) waits; it also takes ALPN chooser and SNI callback (`SNIHandler` can swap session manager / creds / policy per hostname — `server.d:28–37`).

### Record layer

`record.d` owns:

- `readRecord` — parse header, decrypt, authenticate, enforce fragment size (`channel.d:83–118` uses it).
- `ConnectionCipherState` (`record.d:44–79`) — per epoch, per direction. Pulls client/server keys from `TLSSessionKeys`. If `getAead(cipher_algo)` succeeds, AEAD (`AES-GCM`, `AES-CCM`, ChaCha20-Poly1305) with `cipher_key ‖ mac_key`. Else classic MAC-then-encrypt (CBC or stream) via factory MAC + cipher.

`tls_cbc.d` is the C++-3 `TLS_CBC_HMAC_AEAD_*` record transform (MAC-then-encrypt / EtM). The MAC-then-encrypt failure path runs Lucky13 extra HMAC compressions (`performAdditionalCompressions`) so a bad pad/MAC always burns the same number of hash blocks as a max-pad record. `checkTlsCbcPadding` walks with `CTMask`.

`tls_null.d` (`version(TLS_NULL)` → `BOTAN_HAS_TLS_NULL`, `full` only) is RFC 5246 GenericStreamCipher: HMAC only, no confidentiality. KATs in `test_data/tls/tls_null.vec`. Not on `standard`. The live 1.12 record path still rejects a missing stream/block cipher (`"NULL cipher not supported"`); the AEAD object is the C++-3 equivalent used by the KATs.

**T13f:** handshake type `KEY_UPDATE` (24) + `TLS13KeyUpdate` (RFC 8446 4.6.3). `TLS13CipherState.updateWriteKeys` / `updateReadKeys` apply `HKDF-Expand-Label(..., "traffic upd")` and reset the sequence. `TLSChannel` emits one unprotected dummy CCS (`14 03 03 00 01 01`) before the first protected 1.3 record (RFC 8446 D.4).

Epoch 0 is plaintext (handshake until CCS). `changeCipherSpecWriter` / `Reader` bump epoch and install a new cipher state. DTLS sequence numbers pack epoch in the high 16 bits (`channel.d:135`).

`seq_numbers.d` — unread beyond that use. `magic.d` — handshake type constants, extension types, `NO_COMPRESSION`. `alert.d` — alert descriptions.

### Handshake

`HandshakeState` (`handshake_state.d`) stores every parsed message as `Unique!T`, a running `HandshakeHash`, version, suite, session keys, and the expecting/received bitmasks (see `overview.md`).

`HandshakeIO` (`handshake_io.d:39`) serializes messages into records and reassembles fragments. TLS and DTLS have different implementations (DTLS has flights / cookies). Internals unread.

`messages.d` is the large handshake-message file: `ClientHello`, `ServerHello`, `Certificate`, `ServerKeyExchange`, `ClientKeyExchange`, `CertificateVerify`, `Finished`, `HelloRequest`, `HelloVerifyRequest`, `NewSessionTicket`, `ChannelID`, `ChangeCipherSpec`. `ClientKeyExchange` PMS derivation is the crypto heart (`messages.d:823–970`, Bleichenbacher dummy PMS for RSA).

**T13c:** with `BOTAN_HAS_TLS_13`, `ClientHello.deserialize` / `ServerHello.deserialize` also parse RFC 8446 4.2 hello extensions via `tls/tls13/hello_ext.d` (`supported_versions` 0x002b, `key_share` 0x0033, `cookie` 0x002c, `psk_key_exchange_modes` 0x002d, `record_size_limit` 0x001c). A ClientHello is TLS 1.3 when `legacy_version` is not ≥ 0x0304 **and** `supported_versions` lists 0x0304 (then `m_version` becomes `TLS_V13`; NULL compression is required). ServerHello selected version is the first listed `supported_versions` entry. `ServerHello.isHelloRetryRequest()` matches the RFC 8446 HRR random.

**T13d (in-process `isActive` at 1.3 with record protection):** offering `TLS_V13` (and a policy that accepts it) writes **legacy 0x0303**, `supported_versions` [1.3, 1.2], x25519 `key_share` (0x001d), and suites 0x1301/02/03 first. After ServerHello both sides install handshake traffic keys on `TLS13RecordLayer`. EncryptedExtensions, Certificate, CertificateVerify, and Finished are AEAD-wrapped as outer `application_data` (RFC 8446 5.2). After the server Finished is in the transcript, application traffic secrets (`c ap` / `s ap`) replace the handshake keys (write and read switch independently). Default `TLSPolicy` still rejects 1.3; `latestTlsVersion()` stays 1.2. `TestPolicy` accepts 1.3 so `tls/test.d` runs an in-process 1.3 handshake.

**T13p:** `version(TLS_13_PQC)` → `BOTAN_HAS_TLS_13_PQC` (asserts `TLS_13`+`ML_KEM`+`Curve25519`), `full` only. Groups: X25519MLKEM768 `0x11EC` (ML-KEM first), SecP256r1MLKEM768 `0x11EB` / SecP384r1MLKEM1024 `0x11ED` (ECDH first), pure ML-KEM-512/768/1024 `0x0200`/`0x0201`/`0x0202`, and libOQS eFrodo `0xFE00`–`0xFE0F` (pure + x25519/x448/secp256/384/521 hybrids; classical first) when `FrodoKEM` is on. Handshake IKM is concat into HKDF (not SHA-3-256). `offerTls13PqcHybrid()` default false offers `0x11EC`; `offerTls13PqcExtraGroup()` names one Frodo/OQS group. x25519 remains the fallback share.

`ciphersuite.d` is a giant `switch(suite id)` mapping IANA numbers to `(sig, kex, cipher, keylen, nonce, mac, prf)` (`ciphersuite.d:35–100` shows the pattern). `TLSCiphersuite.byId`. Policy filters this list when building ClientHello.

`session_key.d` derives master secret + key block via `protocolSpecificPrf()` (`handshake_state.d:223–238` → `getKdf("TLS-12-PRF(…)")` or `"TLS-PRF"`). Extended master secret is supported (`session_key.d:48, 73–77`).

`TLSSession` (`session.d:37`) is the resumable blob: id, ticket, master secret, original handshake hash (ChannelID resumption), version, suite, certs, SNI, SRP, EMS flag. BER-encodable (`session.d:76–114`) and optionally CryptoBox-PSK wrapped (import of `constructs.cryptobox_psk`).

`extensions.d` — SNI, ALPN, EMS, session ticket, sigalgs, ECC, ChannelID, SRP, heartbeat, max fragment, status_request (`OCSP_Staple`). NPN and SCT remain listed but commented out of the default offer.

`handshake_hash.d` — transcript hash / SSL3-style MD5+SHA1 for old versions. Unread internals; `flushInto(version, prfAlgo)` is what EMS and Finished consume.

`version_.d` — `TLS_V10/11/12/13`, `DTLS_V10/12`. Latest TLS is **1.2** (`latestTlsVersion()`). `TLS_V13` is known only when `BOTAN_HAS_TLS_13`. SSLv3 is **not** in the known-version list. PRF/MAC modules still contain SSL3 names for old suites. Record/handshake 1.3 is T13b–d (T13c = hello parse only); they must **not** change `latestTlsVersion()`.

### Server path (shorter)

`TLSServer` waits for ClientHello, picks version/suite via policy, may resume, otherwise sends ServerHello + optional Certificate + ServerKeyExchange + CertificateRequest + ServerHelloDone. SNI handler can swap credentials mid-handshake. Server-side `ClientKeyExchange.this` (`messages.d:834`) decrypts RSA or completes (EC)DH. **Unread** in detail past the constructor and `getPeerCertChain`.

### Credentials and ChannelID

`TLSCredentialsManager` is the integration surface for real apps (file-backed CAs, PKCS#11, …). Default ChannelID (`channelPrivateKey`, `credentials_manager.d:248–257`) generates a process-lifetime `ECDSAPrivateKey` per hostname and stores it in a static AA — this is the `Embed.opEquals` instantiation site that used to fail on LDC 1.42 + old memutils.

Client finished-path also reloads ChannelID on **resumption** from `session.originalHandshakeHash` (`client.d:429–444`).

### Tests

`tls/test.d` (`BOTAN_TEST && BOTAN_HAS_TLS`): in-process client↔server, test creds that **ignore** verify failures (`test.d:68–78`). `SKIP_TLS_TEST` can disable. T13a policy checks live here. T13b record KATs are `tls/tls13/record_layer.d`. T13c hello parse KATs are `tls/tls13/hello.d` (`module botan.tls.hello13`) over `test_data/tls_13/{client,server}_hello.vec`. TLS 1.2 message decode KATs (`alert`, `hello_request`, `hello_verify`, `new_session_ticket`, `cert_verify`, `cert_status`) live in `tls/msg_kat.d` over `test_data/tls/*.vec`. CBC+HMAC KATs are `tls/tls_cbc.d` (`tls_cbc_kat.vec` / `tls_cbc.vec`); NULL+HMAC KATs are `tls/tls_null.d` (`tls_null.vec`) when `TLS_NULL` is on. `CertificateStatus` is the RFC 6066 handshake message (type 22); 1.3 staple remains the CertificateEntry `status_request` extension. HKDF-Expand-Label KATs are `test_data/hkdf_label.vec` in `tls13/cipher_state.d`.

T13 objects under test are `Unique!`-wrapped so `Unique!(T,void)` runs `.destroy` **outside** a GC finalizer (`Unique` skips payload destroy when `gc_inFinalizer()`). `HandshakeExtensions` / `TLS13KeyShare` follow the same gate via `botanDestroyIfLive`. After `globalState()`, `takeMemutilsSnap` / `memutilsGrowth` (`botan.test`) read `DebugAllocator.bytesAllocated`. Hello parse repeat and AEAD wrap must not grow. A warm 1.2 handshake still leaves a fixed 548 B Lockless residue (logged, not failed). Process shutdown now reports 0 CryptoSafe bytes (was ~36 KiB before Unique wrap).

## Loci

| Piece | File:line |
|---|---|
| Client ctor + hello | `source/botan/tls/client.d:51–135` |
| Client FSM | `source/botan/tls/client.d:140–487` |
| Server ctor / SNI | `source/botan/tls/server.d:28–68` |
| Channel I/O | `source/botan/tls/channel.d:51–150` |
| Record cipher state | `source/botan/tls/record.d:44–79` |
| Handshake FSM + PRF | `source/botan/tls/handshake_state.d:56–97, 223–238` |
| PMS | `source/botan/tls/messages.d:823–970` |
| Master / key block | `source/botan/tls/session_key.d:43–99` |
| Suites | `source/botan/tls/ciphersuite.d:35` |
| Policy defaults | `source/botan/tls/policy.d:35–192` |
| Credentials + ChannelID | `source/botan/tls/credentials_manager.d:33–272` |
| Session BER | `source/botan/tls/session.d:37–114` |
| Versions | `source/botan/tls/version_.d:26–47` |
| Blocking façade | `source/botan/tls/blocking.d:33` |
| TLS 1.3 hello extensions | `source/botan/tls/tls13/hello_ext.d` |
| TLS 1.3 hello KATs | `source/botan/tls/tls13/hello.d`, `test_data/tls_13/` |
| TLS 1.2 message KATs | `source/botan/tls/msg_kat.d`, `test_data/tls/` |
| HKDF-Expand-Label | `source/botan/tls/tls13/cipher_state.d`, `test_data/hkdf_label.vec` |

## Invariants

- T13b adds `tls/tls13/record_layer.d` + `cipher_state.d` and suite ids `0x1301`/`0x1302`/`0x1303`. AEAD is `getAead("AES-128/GCM")`. Not attached to `TLSChannel` until T13d. `latestTlsVersion()` stays 1.2.
- T13c parses 1.3 ClientHello/ServerHello (and HRR) through existing `messages.d` + new hello extensions. The 1.2 default ctor path (`latestTlsVersion()`) still does not emit 1.3. Offer `TLS_V13` to emit legacy 0x0303 + `supported_versions` + `key_share`. `latestTlsVersion()` stays 1.2.
- T13d in-process `isActive` at 1.3 when both policies accept 1.3. Post-SH handshake and application records use `TLS13RecordLayer` + handshake then application traffic keys. `latestTlsVersion()` stays 1.2.
- GC-allocated objects that hold `Vector`/`Unique` must be `Unique!`-destroyed (or `botanDestroyIfLive`) on the stack path. Do not `.destroy` other GC objects from a finalizer (`Unique!(T,void)` rule).
- Same gate on `GCMMode.~this` (CTR before GHASH), `Pipe.destruct`, and `SecureQueue.destroy`. `HashMap.clear`/`remove` `.destroy` struct values (`Array`/`RefCounted`) instead of `Value.init` (Embed/`defaultInit` leak).
- Classes with `Unique!` members (`HMAC_DRBG`, `ConnectionCipherState`, `HandshakeState`, `GCMMode`, `AutoSeededRNG`, …) leak their payloads if only GC-collected. Tests must `Unique!`-wrap them. `takeMemutilsSnap` after `globalState()`; hello/record/HKDF/HMAC_DRBG repeats must not grow.
- Policy is the only suite filter; `ciphersuite.d` still contains many historical suites (3DES, RC4, SEED) that default policy will not offer.
- Expecting-mask is single-shot (see overview).
- RSA kex **must** use the dummy-PMS path (`messages.d:869–888`); do not “simplify” the catch.
- Credentials retain ownership of `privateKeyFor` keys.
- Do not weaken ChannelID / ECDSA types to fix Embed.

## Extension points

- Subclass `TLSPolicy`, `TLSCredentialsManager`, `TLSSessionManager`.
- SNI callback on the server to host multiple certs.
- ALPN via `next_protocols` (client) / `NextProtocolHandler` (server).
- New suite: add `byId` arm + policy allow-list + matching AEAD/cipher/MAC in the factory.

## Unread

- `tls/server.d` handshake switch (everything after line ~80).
- `tls/extensions.d`, `handshake_io.d` TLS vs DTLS classes, `handshake_hash.d`, `seq_numbers.d`, `heartbeats.d`, `reader.d`, `exceptn.d`, `server_info.d`, `alert.d` internals.
- In-memory `TLSSessionManager` implementation body.
- `session_manager_sqlite.d`.
- DTLS cookie / retransmission correctness.
- ChannelID spec match vs Chrome (this tree has extra resumption hash plumbing).
- Whether SSLv3 can still be forced through policy despite `knownVersion`.
