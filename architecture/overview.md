# Overview — a real journey through botan

Two walks, both live in this tree. The first is a TLS 1.2 client handshake that actually exercises libstate, the factory, engines, the RNG, credentials, X.509, and pubkey ops. The second is the smaller pubkey encrypt example under `examples/pubkey/`. Together they are the representative path; per-algorithm files are not documented individually.

## 0. Before anything runs: thread-local `LibraryState`

Almost every high-level call eventually does `globalState()`. That function lives in `source/botan/libstate/global_state.d` and is **thread-local** (`private Unique!LibraryState g_lib_state`, comment at line 15: “Thread-Local, no locks needed”).

```22:33:source/botan/libstate/global_state.d
LibraryState globalState()
{
    if (!g_lib_state) { 

        g_lib_state = new LibraryState;
        /* Lazy initialization. Botan still needs to be deinitialized later
            on or memory might leak.
        */
        g_lib_state.initialize();
    }
    return *g_lib_state;
}
```

`LibraryState.initialize()` (`libstate.d:82–146`) then:

1. Installs SCAN aliases and default OIDs (`SCANToken.setDefaultAliases()`, `OIDS.setDefaults()`), unless `modexpInit()` was used for a reduced “just modular exponentiation” boot.
2. Constructs `AlgorithmFactory`.
3. Pushes engines **in this order** (each gated by a `BOTAN_HAS_ENGINE_*` version): GNU MP → OpenSSL → AES-ISA → SIMD → Assembler → **always** `CoreEngine`.
4. Builds the entropy-source list (`entropySources()`, `libstate.d:186–228`).
5. Creates a process-wide `SerializedRNG` wrapping `HMAC_RNG(HMAC(SHA-512), HMAC(SHA-256))`.
6. Optionally runs `confirmStartupSelfTests` if `Self_Tests` is on (`full` has it).
7. Sets `m_initialized`.

After this, `retrieveHash("SHA-256")`, `PKSigner(...)`, and TLS record crypto all go through the same factory.

`botan.all` (`source/botan/all.d`) is a convenience umbrella: it re-exports `libstate.init`, `lookup`, `libstate`, `version_`, `parsing`, `rng`, and (when `BOTAN_HAS_AUTO_SEEDING_RNG`) `auto_rng`. Real applications usually import the modules they need, as the examples do.

## 1. TLS client handshake (the long path)

### 1.1 Construction

`TLSClient.this` (`source/botan/tls/client.d:51–71`) takes:

- four callbacks: socket output, application data, alert, handshake-complete;
- a `TLSSessionManager`, a `TLSCredentialsManager`, a `TLSPolicy`, a `RandomNumberGenerator`;
- optional `TLSServerInformation` (SNI hostname), offered version (default `TLSProtocolVersion.latestTlsVersion()` = TLS 1.2, `version_.d:39–42`), ALPN list.

It calls `TLSChannel.this` (`channel.d:51–73`) then immediately `createHandshakeState` + `sendClientHello`.

The client hello is built in `sendClientHello` (`client.d:89–135`):

- If the session manager can `loadFromServerInfo` and we are not forcing a full renegotiation, a **resumption** `ClientHello` is sent and `state.resume_master_secret` is stashed (`client.d:100–118`).
- Otherwise a fresh `ClientHello` is constructed with policy, RNG, SNI hostname, optional SRP identifier, and ALPN (`client.d:121–132`).

`TLSPolicy` (`policy.d:35–`) is the application’s algorithm veto. Default preference is AES-GCM / ChaCha20-Poly1305, SHA-256+, AEAD MACs, ECDHE (RSA/ECDSA), and curves starting at `x25519` then brainpool/secp (`policy.d:65–179`). Compression is advertised as `NO_COMPRESSION` only (`policy.d:189–192`). Secure renegotiation is required (`allowInsecureRenegotiation` is false, `policy.d:224`).

### 1.2 Bytes on the wire, then the state machine

Inbound bytes enter `TLSChannel.receivedData` (`channel.d:80+`). That loop calls `readRecord` (`record.d`) which decrypts under the current epoch’s `ConnectionCipherState` (epoch 0 is plaintext). Handshake / CCS records are fed into `HandshakeIO`; application data goes to `m_data_cb`.

`HandshakeState` (`handshake_state.d:33–439`) is a bitmask FSM:

- `setExpectedNext` ORs a type into `m_hand_expecting_mask`.
- `confirmTransitionTo` requires overlap, then **clears** the expecting mask so the next message is illegal unless the handler sets a new expectation (`handshake_state.d:68–87`).

Client-side dispatch is `TLSClient.processHandshakeMsg` (`client.d:140–487`). The full-handshake sequence this code expects:

| Peer message | What botan does | Next expected |
|---|---|---|
| `SERVER_HELLO` (`client.d:182–281`) | Parse; reject unknown suite / compression / extra extensions; set version; if session-id matches, **resume** and jump to CCS/ticket | CERTIFICATE or SERVER_KEX or SERVER_HELLO_DONE depending on kex |
| `CERTIFICATE` (`client.d:283–317`) | `m_creds.verifyCertificateChain("tls-client", hostname, chain)` then `subjectPublicKey()` | SERVER_KEX or CERTIFICATE_REQUEST / SERVER_HELLO_DONE |
| `SERVER_KEX` (`client.d:318–336`) | Parse; if suite has a sig algo, `ServerKeyExchange.verify(server_key, state)` | CERTIFICATE_REQUEST (opt), SERVER_HELLO_DONE |
| `CERTIFICATE_REQUEST` (`client.d:337–341`) | Stash acceptable types | SERVER_HELLO_DONE |
| `SERVER_HELLO_DONE` (`client.d:342–399`) | See next paragraph | NEW_SESSION_TICKET or CCS |
| `NEW_SESSION_TICKET` | Store ticket | CCS |
| `HANDSHAKE_CCS` | `changeCipherSpecReader(CLIENT)` | FINISHED |
| `FINISHED` (`client.d:414–484`) | Verify server Finished; save `TLSSession`; `activateSession()` | — |

### 1.3 ClientKeyExchange, session keys, client Finished

On `SERVER_HELLO_DONE` the client:

1. Optionally sends a client certificate chain from `m_creds.certChain(...)` (`client.d:346–353`).
2. Builds `ClientKeyExchange` (`client.d:355–361`) with policy, credentials, the server public key, hostname, and RNG. That class (`messages.d:823+`) produces the **pre-master secret**:
   - RSA kex: `PKEncryptorEME` with PKCS#1 v1.5 (server side uses a Bleichenbacher dummy PMS, `messages.d:854–888`).
   - (EC)DH: `PKKeyAgreement` with `"Raw"` (`messages.d:931–964`).
   - PSK / DHE_PSK / ECDHE_PSK / SRP: credentials + optional DH.
3. `state.computeSessionKeys()` (`handshake_state.d:388–391`) → `TLSSessionKeys.this` (`session_key.d:43–99`):
   - `protocolSpecificPrf()` (`handshake_state.d:223–238`) returns `getKdf("TLS-12-PRF(SHA-256|suite.prf)")` or `"TLS-PRF"` for TLS 1.0/1.1.
   - Master secret: either resume the old one, or `PRF(pre_master, "master secret" ‖ crandom ‖ srandom)` / extended-master-secret variant hashing the handshake so far (`session_key.d:73–86`).
   - Key block: `PRF(master, "key expansion" ‖ srandom ‖ crandom)` sliced into client/server MAC keys, cipher keys, IVs.
4. If a client cert was sent, `CertificateVerify` is produced with `m_creds.privateKeyFor(...)` (`client.d:365–374`). That is a `PKSigner` under the hood (EMSA3/EMSA1 chosen by `understandSigFormat` / `chooseSigFormat`, `handshake_state.d:114–209`).
5. CCS is written, `changeCipherSpecWriter(CLIENT)` installs a `ConnectionCipherState` (`record.d:44–79`) that pulls AES-GCM / ChaCha-Poly / CBC+HMAC from the factory via `getAead` / MAC / block cipher.
6. Optional ChannelID (`client.d:381–388`) uses `TLSCredentialsManager.channelPrivateKey` (default: a cached `ECDSAPrivateKey` on secp256r1, `credentials_manager.d:248–257`).
7. Client `Finished` is sent; after the server Finished verifies, a `TLSSession` is built (`client.d:457–469`) and `sessionManager().save` is called if the handshake callback returns true.

### 1.4 Where algo_factory + engine + rng + credentials actually fire

- **Factory / engine:** every hash, HMAC, AEAD, block cipher, and the TLS-12-PRF HMAC is `AlgorithmFactory.make*` → `factoryPrototype` (`algo_factory.d:391–416`) → each `Engine.find*`. Default provider weights (`algo_cache.d:22–38`): openssl 9, aes_isa 8, simd 7, asm 6, core 5, gmp 1. (Comment above those weights is stale — it claims OpenSSL is last.)
- **RNG:** constructor argument, **and** `globalState().globalRng()` inside `PKSigner.this` (`pubkey.d:260`). `SerializedRNG` (`rng.d:137–180`) mutex-wraps `HMAC_RNG`. Reseed polls `LibraryState.pollAvailableSources` (`libstate.d:169–183`).
- **Credentials:** abstract `TLSCredentialsManager` (`credentials_manager.d:33–272`). Default `verifyCertificateChain` runs `x509PathValidate` against `trustedCertificateAuthorities`. Client certs and the signing key come from `certChain` / `privateKeyFor`. ChannelID default allocates an ECDSA key via `Embed` mixin on `ECDSAPrivateKey` — this is the historical `opEquals` instantiation.

### 1.5 After the handshake

`activateSession()` promotes pending handshake state to active. Application writes go through `TLSChannel` → `ConnectionCipherState` (AEAD or CBC+MAC) → `m_output_fn`. Renegotiation is a new `HandshakeState` with RFC 5746 checks (`client.d:148–165`). DTLS adds `HELLO_VERIFY_REQUEST` and epoch-based retransmit (`channel.d:123–146`).

A blocking façade `TLSBlockingChannel` (`tls/blocking.d`) wraps the callback API with a `DataReader`.

## 2. Pubkey encrypt / sign (the short path)

`examples/pubkey/source/app.d` is the documented small journey:

```10:26:examples/pubkey/source/app.d
void main() {
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
	// ...
	auto privkey = RSAPrivateKey(*rng, 1024);
	auto pubkey = RSAPublicKey(privkey);
	auto enc = scoped!PKEncryptorEME(pubkey, "EME-PKCS1-v1_5");
	auto dec = scoped!PKDecryptorEME(privkey, "EME-PKCS1-v1_5");
	Vector!ubyte encrypted_message = enc.encrypt(message.ptr, message.length, *rng);
	SecureVector!ubyte decrypted_message = dec.decrypt(encrypted_message);
}
```

What that actually does:

1. `AutoSeededRNG.this` (`auto_rng.d:35–38`) → `RandomNumberGenerator.makeRng()` (`rng.d:31–47`) → `HMAC_RNG` + `reseed(256)` via `globalState()` (lazy init).
2. `RSAPrivateKey(rng, 1024)` (`algo/rsa.d:128–152`) draws two primes, computes `d = e⁻¹ mod λ(n)`, wraps `IFSchemePrivateKey`, `genCheck`.
3. `mixin Embed!(m_priv, m_owned)` (`rsa.d:156`) makes the struct look like a `PrivateKey` interface.
4. `PKEncryptorEME` / `PKDecryptorEME` (in `pubkey.d`, same file as `PKSigner`) ask every engine for `getEncryptionOp` / `getDecryptionOp`. `CoreEngine.getSignatureOp` / encrypt ops (`core_engine.d:626+`) match `key.algoName == "RSA"` and return `RSAPrivateOperation` / `RSAPublicOperation`.
5. Padding name `"EME-PKCS1-v1_5"` is resolved by `getEme` in `pk_pad/factory.d` (EME siblings of `getEmsa` at `factory.d:36+`).

A **sign** is the same factory walk with more surface:

```254:276:source/botan/pubkey/pubkey.d
    this(in PrivateKey key, in string emsa_name,
         SignatureFormat format = IEEE_1363,
         FaultProtection prot = DISABLE_FAULT_PROTECTION)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();
        foreach (Engine engine; af.engines[]) {
            if (!m_op)
                m_op = engine.getSignatureOp(key, rng);
            // ...
        }
        m_emsa = getEmsa(emsa_name);
        m_sig_format = format;
    }
```

`signMessage` → `EMSA.encodingOf` → `Signature.sign` → optional self-test via `getVerifyOp` if `ENABLE_FAULT_PROTECTION`. TLS `CertificateVerify` and X.509 CA signing use this exact constructor.

`examples/hash/source/hash.d` is the symmetric counterpart: `retrieveHash("SHA-256").clone()` (`lookup.d:61–68`) → factory prototype → `HashFunction.update` / `finished`.

## 3. What this journey does **not** go through

- `full_openssl` / `OpenSSLEngine` (only if that configuration is selected).
- GNU MP engine (`Engine_GNU_MP` is not in `full`).
- CVC / EAC certificates (`SKIP_CVC_TEST`, `BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES` off by default).
- TLS 1.3 (does not exist here). SSLv3 constants linger in PRF/MAC names.
- RISC-V-specific engines — there are none. On a non-x86 target the SIMD / AES-NI / RDRAND versions stay off; `CoreEngine` + `/dev/urandom` (Posix) is the path.

## Loci

| Step | File:line |
|---|---|
| Lazy global state | `source/botan/libstate/global_state.d:22` |
| Engine + entropy + PRNG boot | `source/botan/libstate/libstate.d:82–146` |
| Factory prototype search | `source/botan/algo_factory/algo_factory.d:391–416` |
| Provider weights | `source/botan/algo_factory/algo_cache.d:22–38` |
| TLS client ctor + first hello | `source/botan/tls/client.d:51–135` |
| Handshake FSM | `source/botan/tls/handshake_state.d:56–97` |
| Client message switch | `source/botan/tls/client.d:140–487` |
| PMS / RSA-DH-PSK | `source/botan/tls/messages.d:823–970` |
| Master secret / key block | `source/botan/tls/session_key.d:43–99` |
| Record cipher state | `source/botan/tls/record.d:44–79` |
| Credentials + ChannelID ECDSA | `source/botan/tls/credentials_manager.d:68–91, 248–257` |
| PKSigner engine walk | `source/botan/pubkey/pubkey.d:254–276` |
| CoreEngine RSA/ECDSA ops | `source/botan/engine/core_engine.d:606–660` |
| HMAC_RNG factory | `source/botan/rng/rng.d:40–47` |

## Invariants

- One `LibraryState` per thread; `SerializedRNG` is the only internally locked RNG.
- Handshake expecting-mask is single-shot: handlers must call `setExpectedNext` again.
- Session keys are never derived until PMS (or resume master) exists.
- `PKSigner` / encryptors own engine ops via `Unique!`; they do not cache across keys.
- String names are SCAN names, not D type names (`"AES-128/GCM"`, `"EMSA3(SHA-256)"`, `"TLS-12-PRF(SHA-256)"`).

## Extension points

- Subclass `TLSPolicy` to change suites, curves, versions.
- Subclass `TLSCredentialsManager` for real trust stores and keys (do not weaken types to dodge `Embed.opEquals`).
- Implement `TLSSessionManager` (in-memory exists; SQLite is optional / `version(SQLite)`).
- `AlgorithmFactory.addEngine` / `addBlockCipher` / `setPreferredProvider`.
- New algorithms: implement the interface, `static if (BOTAN_HAS_FOO)` it into `CoreEngine.find*`, add a `version` in `dub.json` + `constants.d`.

## Open questions

- `algo_cache` comment vs openssl weight 9 — which preference is intended?
- ChannelID default key cache (`pkey_saved`) is a process-lifetime static AA; lifetime vs `LibraryState` is unclear.
- DTLS cookie / retransmission path only partially read (`channel.d` datagram branch).
- `modexpInit()` reduced boot is unused by TLS/examples; who calls it?
