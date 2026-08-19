/**
* TLS 1.3 handshake key schedule (RFC 8446 7.1)
*
* Copyright:
* (C) 2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.handshake;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.tls.tls13.cipher_state;
import botan.tls.tls13.hello_ext;
import botan.tls.messages;
import botan.tls.magic;
import botan.tls.policy;
import botan.tls.version_;
import botan.tls.exceptn;
import botan.tls.alert;
import botan.kdf.kdf;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.utils.types;
import botan.utils.mem_ops;
static if (BOTAN_HAS_CURVE25519) import botan.pubkey.algo.curve25519;
static if (BOTAN_HAS_TLS_13_PQC) import botan.pubkey.algo.ml_kem;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_FRODOKEM) import botan.pubkey.algo.frodo_kem;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_X448) import botan.pubkey.algo.x448;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_ECDH)
{
    import botan.pubkey.algo.ecdh;
    import botan.pubkey.algo.ec_group;
}
import botan.rng.rng;
import botan.mac.mac;
import botan.pubkey.pubkey;
import botan.pubkey.pk_keys;
import botan.pubkey.algo.ecc_key;

/// Digest length without cloning a HashFunction every call.
size_t tls13HashLen(string hash_name)
{
    if (hash_name == "SHA-256") return 32;
    if (hash_name == "SHA-384") return 48;
    if (hash_name == "SHA-512") return 64;
    Unique!HashFunction h = retrieveHash(hash_name).clone();
    return h.outputLength;
}

/// HKDF-Extract(salt, ikm) → Hash.length bytes. SCAN: HKDF-Extract(hash).
SecureVector!ubyte tls13HkdfExtract(string hash_name,
                                    const(ubyte)* salt, size_t salt_len,
                                    const(ubyte)* ikm, size_t ikm_len)
{
    static KDF cached;
    static string cached_hash;
    if (cached is null || cached_hash != hash_name)
    {
        Unique!KDF u = getKdf("HKDF-Extract(" ~ hash_name ~ ")");
        cached = u.release();
        cached_hash = hash_name.idup;
    }
    const size_t n = tls13HashLen(hash_name);
    return cached.deriveKey(n, ikm, ikm_len, salt, salt_len);
}

/// Derive-Secret(secret, label, messages) = HKDF-Expand-Label(..., Hash(messages)).
SecureVector!ubyte tls13DeriveSecret(string hash_name,
                                     const(ubyte)* secret, size_t secret_len,
                                     string label,
                                     const(ubyte)* messages, size_t messages_len)
{
    Unique!HashFunction h = retrieveHash(hash_name).clone();
    const size_t n = tls13HashLen(hash_name);
    if (messages_len)
        h.update(messages, messages_len);
    auto ctx = h.finished();
    return tls13HkdfExpandLabel(hash_name, secret, secret_len, label,
                                ctx.ptr, ctx.length, n);
}

/**
* Handshake traffic secrets after ECDHE (empty early PSK).
* `shared` is the x25519 agreement or TLS hybrid concat(ss_mlkem‖ss_x25519);
* `hello_hash` is Hash(CH || SH).
*/
struct TLS13HandshakeSecrets
{
    SecureVector!ubyte handshake_secret;
    SecureVector!ubyte client_handshake_traffic;
    SecureVector!ubyte server_handshake_traffic;
}

TLS13HandshakeSecrets tls13HandshakeSecrets(string hash_name,
                                            const(ubyte)* ecdhe, size_t ecdhe_len,
                                            const(ubyte)* hello_hash, size_t hello_hash_len)
{
    const size_t n = tls13HashLen(hash_name);
    auto zeros = SecureVector!ubyte(n);
    auto early = tls13HkdfExtract(hash_name, zeros.ptr, zeros.length, zeros.ptr, zeros.length);
    auto derived = tls13DeriveSecret(hash_name, early.ptr, early.length, "derived", null, 0);
    TLS13HandshakeSecrets outp;
    outp.handshake_secret = tls13HkdfExtract(hash_name, derived.ptr, derived.length, ecdhe, ecdhe_len);
    outp.client_handshake_traffic = tls13DeriveSecret(hash_name,
        outp.handshake_secret.ptr, outp.handshake_secret.length,
        "c hs traffic", hello_hash, hello_hash_len);
    outp.server_handshake_traffic = tls13DeriveSecret(hash_name,
        outp.handshake_secret.ptr, outp.handshake_secret.length,
        "s hs traffic", hello_hash, hello_hash_len);
    return outp;
}

/// Application traffic secrets after the server Finished is in the transcript.
struct TLS13AppSecrets
{
    SecureVector!ubyte client_application_traffic;
    SecureVector!ubyte server_application_traffic;
}

TLS13AppSecrets tls13AppSecrets(string hash_name,
                                const(ubyte)* handshake_secret, size_t handshake_len,
                                const(ubyte)* messages, size_t messages_len)
{
    auto derived = tls13DeriveSecret(hash_name, handshake_secret, handshake_len, "derived", null, 0);
    auto zeros = SecureVector!ubyte(tls13HashLen(hash_name));
    auto master = tls13HkdfExtract(hash_name, derived.ptr, derived.length, zeros.ptr, zeros.length);
    TLS13AppSecrets outp;
    outp.client_application_traffic = tls13DeriveSecret(hash_name,
        master.ptr, master.length, "c ap traffic", messages, messages_len);
    outp.server_application_traffic = tls13DeriveSecret(hash_name,
        master.ptr, master.length, "s ap traffic", messages, messages_len);
    return outp;
}

string tls13AeadName(in TLSCiphersuite suite)
{
    return suite.cipherAlgo();
}

/// Highest mutually acceptable version. Offering 1.3 with a 1.2-only
/// policy falls back to 1.2 (ClientHello always lists both).
TLSProtocolVersion tls13SelectVersion(TLSProtocolVersion client_ver, in TLSPolicy policy)
{
    if (client_ver == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
    {
        if (policy.acceptableProtocolVersion(client_ver))
            return client_ver;
        auto v12 = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
        if (policy.acceptableProtocolVersion(v12))
            return v12;
    }
    return client_ver;
}

/// First of 0x1301 / 0x1302 / 0x1303 that the client offered, else 0.
ushort tls13ChooseSuite(in ClientHello ch)
{
    if (ch.offeredSuite(0x1301))
        return 0x1301;
    if (ch.offeredSuite(0x1302))
        return 0x1302;
    if (ch.offeredSuite(0x1303))
        return 0x1303;
    return 0;
}

static if (BOTAN_HAS_CURVE25519)
{
    /// Server share + secret from the client's key_share (x25519 or X25519MLKEM768).
    struct TLS13X25519Agreement
    {
        ushort group;
        Vector!ubyte server_public;
        SecureVector!ubyte shared_secret;

        TLS13X25519Agreement move()
        {
            TLS13X25519Agreement r;
            r.group = group;
            r.server_public = server_public.move();
            r.shared_secret = shared_secret.move();
            return r;
        }
    }

    TLS13KeyShareEntry tls13FindShare(TLS13KeyShare ks, ushort group, size_t expect_len)
    {
        foreach (e; ks.entries()[])
            if (e.group == group && e.key_exchange.length == expect_len)
                return e;
        return null;
    }

    SecureVector!ubyte tls13Concat2(const(ubyte)* a, size_t al, const(ubyte)* b, size_t bl)
    {
        auto ss = SecureVector!ubyte(al + bl);
        ss[0 .. al] = a[0 .. al];
        ss[al .. $] = b[0 .. bl];
        return ss.move();
    }

    static if (BOTAN_HAS_TLS_13_PQC)
    {
        TLS13X25519Agreement tls13AgreePureMlkem(MLKEMMode mode, size_t pk_len, size_t ct_len,
                                                 ushort group, const(ubyte)* pk_bits,
                                                 RandomNumberGenerator rng)
        {
            Unique!MLKEMPublicKey pk = new MLKEMPublicKey(mode, pk_bits, pk_len);
            ubyte[32] ss;
            auto ct = new ubyte[ct_len];
            mlkemEncaps(pk.raw(), rng, ss.ptr, ct.ptr);
            TLS13X25519Agreement a;
            a.group = group;
            a.server_public = Vector!ubyte(ct_len);
            a.server_public[] = ct[0 .. ct_len];
            a.shared_secret = SecureVector!ubyte(32);
            a.shared_secret[] = ss[];
            return a.move();
        }
    }

    static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_ECDH)
    {
        SecureVector!ubyte tls13EcdhAgree(const ref ECDHPrivateKey sk, const(ubyte)* peer, size_t n)
        {
            import botan.pubkey.pubkey : PKKeyAgreement;
            import std.typecons : scoped;
            Vector!ubyte pub = Vector!ubyte(n);
            foreach (i; 0 .. n)
                pub[i] = peer[i];
            auto ka = scoped!PKKeyAgreement(sk, "Raw");
            auto derived = ka.deriveKey(0, pub);
            auto bits = derived.bitsOf();
            auto ss = SecureVector!ubyte(bits.length);
            ss[] = bits[];
            return ss.move();
        }

        TLS13X25519Agreement tls13AgreeEcdhMlkem(MLKEMMode mode, size_t pk_len, size_t ct_len,
                                                 size_t ecdh_len, string curve, ushort group,
                                                 const(ubyte)* ch_share, RandomNumberGenerator rng)
        {
            Unique!MLKEMPublicKey pk = new MLKEMPublicKey(mode, ch_share + ecdh_len, pk_len);
            ubyte[32] ss_ml;
            auto ct = new ubyte[ct_len];
            mlkemEncaps(pk.raw(), rng, ss_ml.ptr, ct.ptr);
            auto grp = ECGroup(curve);
            auto eph = ECDHPrivateKey(rng, grp);
            auto ss_ec = tls13EcdhAgree(eph, ch_share, ecdh_len);
            auto eph_pub = eph.publicValue();
            if (eph_pub.length != ecdh_len)
                throw new TLSException(TLSAlert.INTERNAL_ERROR, "ECDH public length mismatch");
            TLS13X25519Agreement a;
            a.group = group;
            a.server_public = Vector!ubyte(ecdh_len + ct_len);
            a.server_public[0 .. ecdh_len] = eph_pub[];
            a.server_public[ecdh_len .. $] = ct[0 .. ct_len];
            a.shared_secret = tls13Concat2(ss_ec.ptr, ss_ec.length, ss_ml.ptr, 32);
            return a.move();
        }
    }

    static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_FRODOKEM)
    {
        TLS13X25519Agreement tls13AgreeFrodoOqs(const ref Tls13FrodoOqsGroup spec,
                                                const(ubyte)* ch_share,
                                                RandomNumberGenerator rng)
        {
            Unique!FrodoPublicKey pk = new FrodoPublicKey(spec.frodo,
                ch_share + spec.classical_pub, spec.frodo_pk);
            auto ss_f = new ubyte[spec.frodo_ss];
            auto ct = new ubyte[spec.frodo_ct];
            frodoEncaps(pk.raw(), rng, ss_f.ptr, ct.ptr);
            TLS13X25519Agreement a;
            a.group = spec.id;
            if (spec.isPure())
            {
                a.server_public = Vector!ubyte(spec.frodo_ct);
                a.server_public[] = ct[0 .. spec.frodo_ct];
                a.shared_secret = SecureVector!ubyte(spec.frodo_ss);
                a.shared_secret[] = ss_f[0 .. spec.frodo_ss];
                return a.move();
            }
            a.server_public = Vector!ubyte(spec.shLen());
            if (spec.classical == TLS13_FRODO_CLASSICAL_X25519)
            {
                auto xsk = Curve25519PrivateKey(rng);
                auto xpub = xsk.publicValue();
                auto ss_x = xsk.agree(ch_share, spec.classical_pub);
                a.server_public[0 .. spec.classical_pub] = xpub[];
                a.server_public[spec.classical_pub .. $] = ct[0 .. spec.frodo_ct];
                a.shared_secret = tls13Concat2(ss_x.ptr, ss_x.length, ss_f.ptr, spec.frodo_ss);
                return a.move();
            }
            static if (BOTAN_HAS_X448)
            {
                if (spec.classical == TLS13_FRODO_CLASSICAL_X448)
                {
                    auto xsk = X448PrivateKey(rng);
                    auto xpub = xsk.publicValue();
                    auto ss_x = xsk.agree(ch_share, spec.classical_pub);
                    a.server_public[0 .. spec.classical_pub] = xpub[];
                    a.server_public[spec.classical_pub .. $] = ct[0 .. spec.frodo_ct];
                    a.shared_secret = tls13Concat2(ss_x.ptr, ss_x.length, ss_f.ptr, spec.frodo_ss);
                    return a.move();
                }
            }
            static if (BOTAN_HAS_ECDH)
            {
                if (spec.classical == TLS13_FRODO_CLASSICAL_P256 ||
                    spec.classical == TLS13_FRODO_CLASSICAL_P384 ||
                    spec.classical == TLS13_FRODO_CLASSICAL_P521)
                {
                    auto grp = ECGroup(spec.classical);
                    auto eph = ECDHPrivateKey(rng, grp);
                    auto ss_ec = tls13EcdhAgree(eph, ch_share, spec.classical_pub);
                    auto eph_pub = eph.publicValue();
                    if (eph_pub.length != spec.classical_pub)
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "ECDH public length mismatch");
                    a.server_public[0 .. spec.classical_pub] = eph_pub[];
                    a.server_public[spec.classical_pub .. $] = ct[0 .. spec.frodo_ct];
                    a.shared_secret = tls13Concat2(ss_ec.ptr, ss_ec.length, ss_f.ptr, spec.frodo_ss);
                    return a.move();
                }
            }
            throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Unsupported Frodo/OQS hybrid");
        }

        SecureVector!ubyte tls13ClientFrodoOqsSecret(in ClientHello ch, TLS13KeyShareEntry e,
                                                     const ref Tls13FrodoOqsGroup spec)
        {
            if (e.key_exchange.length != spec.shLen())
                throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad Frodo/OQS ServerHello share");
            if (!ch.hasTls13Frodo(spec.frodo))
                throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost eFrodo share");
            auto ss_f = new ubyte[spec.frodo_ss];
            frodoDecaps(ch.tls13Frodo(spec.frodo).raw(),
                        e.key_exchange.ptr + spec.classical_pub, spec.frodo_ct, ss_f.ptr);
            if (spec.isPure())
            {
                auto outp = SecureVector!ubyte(spec.frodo_ss);
                outp[] = ss_f[0 .. spec.frodo_ss];
                return outp.move();
            }
            if (spec.classical == TLS13_FRODO_CLASSICAL_X25519)
            {
                if (!ch.hasTls13X25519())
                    throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost x25519 share");
                auto ss_x = ch.tls13X25519().agree(e.key_exchange.ptr, spec.classical_pub);
                return tls13Concat2(ss_x.ptr, ss_x.length, ss_f.ptr, spec.frodo_ss);
            }
            static if (BOTAN_HAS_X448)
            {
                if (spec.classical == TLS13_FRODO_CLASSICAL_X448)
                {
                    if (!ch.hasTls13X448())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost x448 share");
                    auto ss_x = ch.tls13X448().agree(e.key_exchange.ptr, spec.classical_pub);
                    return tls13Concat2(ss_x.ptr, ss_x.length, ss_f.ptr, spec.frodo_ss);
                }
            }
            static if (BOTAN_HAS_ECDH)
            {
                if (spec.classical == TLS13_FRODO_CLASSICAL_P256)
                {
                    if (!ch.hasTls13P256())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost P-256 share");
                    auto ss_ec = tls13EcdhAgree(ch.tls13P256(), e.key_exchange.ptr, spec.classical_pub);
                    return tls13Concat2(ss_ec.ptr, ss_ec.length, ss_f.ptr, spec.frodo_ss);
                }
                if (spec.classical == TLS13_FRODO_CLASSICAL_P384)
                {
                    if (!ch.hasTls13P384())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost P-384 share");
                    auto ss_ec = tls13EcdhAgree(ch.tls13P384(), e.key_exchange.ptr, spec.classical_pub);
                    return tls13Concat2(ss_ec.ptr, ss_ec.length, ss_f.ptr, spec.frodo_ss);
                }
                if (spec.classical == TLS13_FRODO_CLASSICAL_P521)
                {
                    if (!ch.hasTls13P521())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost P-521 share");
                    auto ss_ec = tls13EcdhAgree(ch.tls13P521(), e.key_exchange.ptr, spec.classical_pub);
                    return tls13Concat2(ss_ec.ptr, ss_ec.length, ss_f.ptr, spec.frodo_ss);
                }
            }
            throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Unsupported Frodo/OQS hybrid");
        }
    }

    TLS13X25519Agreement tls13AgreeFromClientShare(TLS13KeyShare client_ks, RandomNumberGenerator rng,
                                                   in TLSPolicy policy = null)
    {
        if (client_ks is null)
            throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "ClientHello missing key_share");
        static if (BOTAN_HAS_TLS_13_PQC)
        {
        const bool want_pqc = policy !is null && (
            policy.offerTls13PqcHybrid() ||
            policy.offerTls13Secp256Mlkem() ||
            policy.offerTls13Secp384Mlkem() ||
            policy.offerTls13Mlkem512() ||
            policy.offerTls13Mlkem768() ||
            policy.offerTls13Mlkem1024() ||
            policy.offerTls13PqcExtraGroup().length != 0);
        if (want_pqc)
        {
            if (auto e = tls13FindShare(client_ks, TLS13_GROUP_X25519_MLKEM768, TLS13_HYBRID_CH_SHARE_LEN))
            {
                Unique!MLKEMPublicKey pk = new MLKEMPublicKey(
                    MLKEMMode.Kem768, e.key_exchange.ptr, TLS13_MLKEM768_PK_LEN);
                ubyte[32] ss_ml;
                ubyte[TLS13_MLKEM768_CT_LEN] ct;
                mlkemEncaps(pk.raw(), rng, ss_ml.ptr, ct.ptr);
                auto xsk = Curve25519PrivateKey(rng);
                auto xpub = xsk.publicValue();
                auto ss_x = xsk.agree(e.key_exchange.ptr + TLS13_MLKEM768_PK_LEN,
                                      TLS13_X25519_SHARE_LEN);
                TLS13X25519Agreement a;
                a.group = TLS13_GROUP_X25519_MLKEM768;
                a.server_public = Vector!ubyte(TLS13_HYBRID_SH_SHARE_LEN);
                a.server_public[0 .. TLS13_MLKEM768_CT_LEN] = ct[];
                a.server_public[TLS13_MLKEM768_CT_LEN .. $] = xpub[];
                a.shared_secret = tls13Concat2(ss_ml.ptr, 32, ss_x.ptr, ss_x.length);
                return a.move();
            }
            static if (BOTAN_HAS_ECDH)
            {
                if (auto e = tls13FindShare(client_ks, TLS13_GROUP_SECP256R1_MLKEM768, TLS13_P256_HYBRID_CH_LEN))
                    return tls13AgreeEcdhMlkem(MLKEMMode.Kem768, TLS13_MLKEM768_PK_LEN,
                                               TLS13_MLKEM768_CT_LEN, TLS13_SECP256R1_PUB_LEN,
                                               "secp256r1", TLS13_GROUP_SECP256R1_MLKEM768,
                                               e.key_exchange.ptr, rng);
                if (auto e = tls13FindShare(client_ks, TLS13_GROUP_SECP384R1_MLKEM1024, TLS13_P384_HYBRID_CH_LEN))
                    return tls13AgreeEcdhMlkem(MLKEMMode.Kem1024, TLS13_MLKEM1024_PK_LEN,
                                               TLS13_MLKEM1024_CT_LEN, TLS13_SECP384R1_PUB_LEN,
                                               "secp384r1", TLS13_GROUP_SECP384R1_MLKEM1024,
                                               e.key_exchange.ptr, rng);
            }
            if (auto e = tls13FindShare(client_ks, TLS13_GROUP_MLKEM768, TLS13_MLKEM768_PK_LEN))
                return tls13AgreePureMlkem(MLKEMMode.Kem768, TLS13_MLKEM768_PK_LEN,
                                           TLS13_MLKEM768_CT_LEN, TLS13_GROUP_MLKEM768,
                                           e.key_exchange.ptr, rng);
            if (auto e = tls13FindShare(client_ks, TLS13_GROUP_MLKEM1024, TLS13_MLKEM1024_PK_LEN))
                return tls13AgreePureMlkem(MLKEMMode.Kem1024, TLS13_MLKEM1024_PK_LEN,
                                           TLS13_MLKEM1024_CT_LEN, TLS13_GROUP_MLKEM1024,
                                           e.key_exchange.ptr, rng);
            if (auto e = tls13FindShare(client_ks, TLS13_GROUP_MLKEM512, TLS13_MLKEM512_PK_LEN))
                return tls13AgreePureMlkem(MLKEMMode.Kem512, TLS13_MLKEM512_PK_LEN,
                                           TLS13_MLKEM512_CT_LEN, TLS13_GROUP_MLKEM512,
                                           e.key_exchange.ptr, rng);
            static if (BOTAN_HAS_FRODOKEM)
            {
                foreach (ref spec; TLS13_FRODO_OQS_GROUPS)
                {
                    if (auto e = tls13FindShare(client_ks, spec.id, spec.chLen()))
                        return tls13AgreeFrodoOqs(spec, e.key_exchange.ptr, rng);
                }
            }
        }
        }
        foreach (e; client_ks.entries()[])
        {
            if (e.group == TLS13_GROUP_X25519 && e.key_exchange.length == TLS13_X25519_SHARE_LEN)
            {
                TLS13X25519Agreement a;
                a.group = TLS13_GROUP_X25519;
                auto sk = Curve25519PrivateKey(rng);
                a.server_public = sk.publicValue();
                a.shared_secret = sk.agree(e.key_exchange.ptr, e.key_exchange.length);
                return a.move();
            }
        }
        throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "No usable key_share from client");
    }

    /// Client shared secret from ServerHello key_share (classic, hybrid concat, or pure ML-KEM).
    SecureVector!ubyte tls13ClientSecretFromServerShare(in ClientHello ch, TLS13KeyShare server_ks)
    {
        if (server_ks is null || server_ks.entries().empty)
            throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "ServerHello missing key_share");
        auto e = server_ks.entries()[0];
        static if (BOTAN_HAS_TLS_13_PQC)
        {
            if (e.group == TLS13_GROUP_X25519_MLKEM768)
            {
                if (e.key_exchange.length != TLS13_HYBRID_SH_SHARE_LEN)
                    throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad X25519MLKEM768 ServerHello share");
                if (!ch.hasTls13Mlkem() || !ch.hasTls13X25519())
                    throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost hybrid shares");
                ubyte[32] ss_ml;
                mlkemDecaps(ch.tls13Mlkem().raw(), e.key_exchange.ptr, TLS13_MLKEM768_CT_LEN, ss_ml.ptr);
                auto ss_x = ch.tls13X25519().agree(e.key_exchange.ptr + TLS13_MLKEM768_CT_LEN,
                                                   TLS13_X25519_SHARE_LEN);
                return tls13Concat2(ss_ml.ptr, 32, ss_x.ptr, ss_x.length);
            }
            static if (BOTAN_HAS_ECDH)
            {
                if (e.group == TLS13_GROUP_SECP256R1_MLKEM768)
                {
                    if (e.key_exchange.length != TLS13_P256_HYBRID_SH_LEN)
                        throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad SecP256r1MLKEM768 share");
                    if (!ch.hasTls13P256() || !ch.hasTls13Mlkem())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost P-256 hybrid shares");
                    auto ss_ec = tls13EcdhAgree(ch.tls13P256(), e.key_exchange.ptr, TLS13_SECP256R1_PUB_LEN);
                    ubyte[32] ss_ml;
                    mlkemDecaps(ch.tls13Mlkem().raw(), e.key_exchange.ptr + TLS13_SECP256R1_PUB_LEN,
                                TLS13_MLKEM768_CT_LEN, ss_ml.ptr);
                    return tls13Concat2(ss_ec.ptr, ss_ec.length, ss_ml.ptr, 32);
                }
                if (e.group == TLS13_GROUP_SECP384R1_MLKEM1024)
                {
                    if (e.key_exchange.length != TLS13_P384_HYBRID_SH_LEN)
                        throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad SecP384r1MLKEM1024 share");
                    if (!ch.hasTls13P384() || !ch.hasTls13Mlkem1024())
                        throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost P-384 hybrid shares");
                    auto ss_ec = tls13EcdhAgree(ch.tls13P384(), e.key_exchange.ptr, TLS13_SECP384R1_PUB_LEN);
                    ubyte[32] ss_ml;
                    mlkemDecaps(ch.tls13Mlkem1024().raw(), e.key_exchange.ptr + TLS13_SECP384R1_PUB_LEN,
                                TLS13_MLKEM1024_CT_LEN, ss_ml.ptr);
                    return tls13Concat2(ss_ec.ptr, ss_ec.length, ss_ml.ptr, 32);
                }
            }
            if (e.group == TLS13_GROUP_MLKEM768)
            {
                if (e.key_exchange.length != TLS13_MLKEM768_CT_LEN || !ch.hasTls13Mlkem())
                    throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad ML-KEM-768 share");
                ubyte[32] ss;
                mlkemDecaps(ch.tls13Mlkem().raw(), e.key_exchange.ptr, TLS13_MLKEM768_CT_LEN, ss.ptr);
                auto outp = SecureVector!ubyte(32);
                outp[] = ss[];
                return outp.move();
            }
            if (e.group == TLS13_GROUP_MLKEM1024)
            {
                if (e.key_exchange.length != TLS13_MLKEM1024_CT_LEN || !ch.hasTls13Mlkem1024())
                    throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad ML-KEM-1024 share");
                ubyte[32] ss;
                mlkemDecaps(ch.tls13Mlkem1024().raw(), e.key_exchange.ptr, TLS13_MLKEM1024_CT_LEN, ss.ptr);
                auto outp = SecureVector!ubyte(32);
                outp[] = ss[];
                return outp.move();
            }
            if (e.group == TLS13_GROUP_MLKEM512)
            {
                if (e.key_exchange.length != TLS13_MLKEM512_CT_LEN || !ch.hasTls13Mlkem512())
                    throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad ML-KEM-512 share");
                ubyte[32] ss;
                mlkemDecaps(ch.tls13Mlkem512().raw(), e.key_exchange.ptr, TLS13_MLKEM512_CT_LEN, ss.ptr);
                auto outp = SecureVector!ubyte(32);
                outp[] = ss[];
                return outp.move();
            }
            static if (BOTAN_HAS_FRODOKEM)
            {
                if (auto spec = tls13FrodoOqsById(e.group))
                    return tls13ClientFrodoOqsSecret(ch, e, *spec);
            }
        }
        if (e.group != TLS13_GROUP_X25519)
            throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Unsupported ServerHello key_share group");
        if (!ch.hasTls13X25519())
            throw new TLSException(TLSAlert.INTERNAL_ERROR, "Client lost x25519 share");
        return ch.tls13X25519().agree(e.key_exchange.ptr, e.key_exchange.length);
    }
}

SecureVector!ubyte tls13TranscriptHash(string hash_name, const(ubyte)* messages, size_t messages_len)
{
    Unique!HashFunction h = retrieveHash(hash_name).clone();
    if (messages_len)
        h.update(messages, messages_len);
    return h.finished();
}

SecureVector!ubyte tls13CertificateVerifyTbs(ConnectionSide side, const(ubyte)* th, size_t th_len)
{
    SecureVector!ubyte msg;
    msg.reserve(64 + 40 + 1 + th_len);
    foreach (i; 0 .. 64)
        msg.pushBack(0x20);
    immutable ctx = (side == SERVER) ? "TLS 1.3, server CertificateVerify"
                                     : "TLS 1.3, client CertificateVerify";
    msg ~= cast(const(ubyte)[]) ctx;
    msg.pushBack(0);
    if (th_len)
        msg ~= th[0 .. th_len];
    return msg.move();
}

/// EMSA + IANA SignatureScheme + wire encoding for TLS 1.3 CertificateVerify.
/// RFC 8446 4.4.3 + 4.2.3: ECDSA is DER ECDSA-Sig-Value (RFC 4492 5.4);
/// RSA-PSS and Ed25519/Ed448 are IEEE 1363 / raw. Ephemeral ECDH
/// (key_share) is independent of this.
struct TLS13CvParams
{
    ushort scheme;
    string emsa;
    SignatureFormat format;
}

TLS13CvParams tls13CvParamsForKey(PrivateKey key)
{
    const string algo = key.algoName;
    if (algo == "RSA")
        return TLS13CvParams(TLS13_RSA_PSS_RSAE_SHA256, "PSSR(SHA-256)", IEEE_1363);
    if (algo == "ECDSA")
    {
        string oid;
        if (auto ec = cast(ECPrivateKey) key)
            oid = ec.domain().getOid();
        if (oid == "1.3.132.0.34" || oid == "secp384r1")
            return TLS13CvParams(TLS13_ECDSA_SECP384R1_SHA384, "EMSA1(SHA-384)", DER_SEQUENCE);
        if (oid == "1.3.132.0.35" || oid == "secp521r1")
            return TLS13CvParams(TLS13_ECDSA_SECP521R1_SHA512, "EMSA1(SHA-512)", DER_SEQUENCE);
        return TLS13CvParams(TLS13_ECDSA_SECP256R1_SHA256, "EMSA1(SHA-256)", DER_SEQUENCE);
    }
    static if (BOTAN_HAS_ED25519)
        if (algo == "Ed25519")
            return TLS13CvParams(TLS13_ED25519, "Raw", IEEE_1363);
    static if (is(typeof(BOTAN_HAS_ED448)) && BOTAN_HAS_ED448)
        if (algo == "Ed448")
            return TLS13CvParams(TLS13_ED448, "Raw", IEEE_1363);
    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                           "TLS 1.3 CertificateVerify: unsupported key " ~ algo);
}

TLS13CvParams tls13CvParamsForScheme(ushort scheme)
{
    switch (scheme)
    {
        case TLS13_RSA_PSS_RSAE_SHA256:
            return TLS13CvParams(scheme, "PSSR(SHA-256)", IEEE_1363);
        case TLS13_ECDSA_SECP256R1_SHA256:
            return TLS13CvParams(scheme, "EMSA1(SHA-256)", DER_SEQUENCE);
        case TLS13_ECDSA_SECP384R1_SHA384:
            return TLS13CvParams(scheme, "EMSA1(SHA-384)", DER_SEQUENCE);
        case TLS13_ECDSA_SECP521R1_SHA512:
            return TLS13CvParams(scheme, "EMSA1(SHA-512)", DER_SEQUENCE);
        case TLS13_ED25519:
            return TLS13CvParams(scheme, "Raw", IEEE_1363);
        case TLS13_ED448:
            return TLS13CvParams(scheme, "Raw", IEEE_1363);
        default:
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER,
                                   "TLS 1.3 CertificateVerify scheme not supported");
    }
}

Vector!ubyte tls13SignCertificateVerify(PrivateKey key,
                                        ConnectionSide side,
                                        string hash_name,
                                        const(ubyte)* messages, size_t messages_len,
                                        RandomNumberGenerator rng,
                                        ref ushort scheme)
{
    auto p = tls13CvParamsForKey(key);
    scheme = p.scheme;
    auto th = tls13TranscriptHash(hash_name, messages, messages_len);
    auto tbs = tls13CertificateVerifyTbs(side, th.ptr, th.length);
    // One PKSigner per leaf key: EMSA + engine walk is a large
    // fraction of ECDSA reconnect. Single-threaded event loops reuse it.
    static PKSigner* cached;
    static PrivateKey cached_key;
    static string cached_emsa;
    static SignatureFormat cached_fmt;
    if (cached is null || cached_key !is key || cached_emsa != p.emsa || cached_fmt != p.format)
    {
        cached = new PKSigner(key, p.emsa, p.format);
        cached_key = key;
        cached_emsa = p.emsa;
        cached_fmt = p.format;
    }
    return cached.signMessage(tbs, rng);
}

bool tls13VerifyCertificateVerify(PublicKey key,
                                  ConnectionSide side,
                                  string hash_name,
                                  const(ubyte)* messages, size_t messages_len,
                                  ushort scheme,
                                  const(ubyte)* sig, size_t sig_len)
{
    auto p = tls13CvParamsForScheme(scheme);
    auto th = tls13TranscriptHash(hash_name, messages, messages_len);
    auto tbs = tls13CertificateVerifyTbs(side, th.ptr, th.length);
    PKVerifier verifier = PKVerifier(key, p.emsa, p.format);
    return verifier.verifyMessage(tbs.ptr, tbs.length, sig, sig_len);
}

Vector!ubyte tls13FinishedMac(string hash_name,
                              const(ubyte)* traffic_secret, size_t traffic_len,
                              const(ubyte)* messages, size_t messages_len)
{
    const size_t n = tls13HashLen(hash_name);
    auto fin_key = tls13HkdfExpandLabel(hash_name, traffic_secret, traffic_len, "finished", null, 0, n);
    auto th = tls13TranscriptHash(hash_name, messages, messages_len);
    Unique!MessageAuthenticationCode hmac = retrieveMac("HMAC(" ~ hash_name ~ ")").clone();
    hmac.setKey(fin_key.ptr, fin_key.length);
    hmac.update(th.ptr, th.length);
    return unlock(hmac.finished());
}

/**
* RFC 8446 4.6.3 KeyUpdate (handshake type 24). One byte: 0 = update_not_requested, 1 = update_requested.
*/
final class TLS13KeyUpdate
{
public:
    this(bool request_peer_update)
    {
        m_update_requested = request_peer_update;
    }

    this(const(ubyte)* buf, size_t len)
    {
        if (len != 1)
            throw new TLSException(TLSAlert.DECODE_ERROR, "malformed key_update");
        if (buf[0] > 1)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "unexpected key_update parameter");
        m_update_requested = buf[0] == 1;
    }

    HandshakeType type() const { return KEY_UPDATE; }

    Vector!ubyte serialize() const
    {
        return Vector!ubyte(cast(ubyte[])[m_update_requested ? 1 : 0]);
    }

    bool expectsReciprocation() const { return m_update_requested; }

private:
    bool m_update_requested;
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.pubkey.algo.curve25519;
    import botan.rng.auto_rng;
    auto gs = globalState();
    size_t fails;
    {
        Unique!TLS13KeyUpdate a = new TLS13KeyUpdate(true);
        Unique!TLS13KeyUpdate b = new TLS13KeyUpdate(false);
        auto sa = a.serialize();
        auto sb = b.serialize();
        if (sa.length != 1 || sa[0] != 1)
            ++fails;
        if (sb.length != 1 || sb[0] != 0)
            ++fails;
        Unique!TLS13KeyUpdate pa = new TLS13KeyUpdate(sa.ptr, sa.length);
        Unique!TLS13KeyUpdate pb = new TLS13KeyUpdate(sb.ptr, sb.length);
        if (!pa.expectsReciprocation() || pb.expectsReciprocation())
            ++fails;
        bool threw;
        ubyte[1] badv = [2];
        try { Unique!TLS13KeyUpdate bad = new TLS13KeyUpdate(badv.ptr, 1); } catch (TLSException) { threw = true; }
        if (!threw)
            ++fails;
        threw = false;
        try { Unique!TLS13KeyUpdate bad = new TLS13KeyUpdate(null, 0); } catch (TLSException) { threw = true; }
        if (!threw)
            ++fails;
    }
    static if (BOTAN_HAS_CURVE25519 && BOTAN_HAS_HKDF && BOTAN_HAS_AUTO_SEEDING_RNG)
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto a = Curve25519PrivateKey(*rng);
        auto b = Curve25519PrivateKey(*rng);
        auto a_pub = a.publicValue();
        auto b_pub = b.publicValue();
        auto ab = a.agree(b_pub.ptr, b_pub.length);
        auto ba = b.agree(a_pub.ptr, a_pub.length);
        if (ab.length != 32 || ab[] != ba[])
            ++fails;
        ubyte[32] th;
        auto sa = tls13HandshakeSecrets("SHA-256", ab.ptr, ab.length, th.ptr, th.length);
        auto sb = tls13HandshakeSecrets("SHA-256", ba.ptr, ba.length, th.ptr, th.length);
        if (sa.client_handshake_traffic[] != sb.client_handshake_traffic[])
            ++fails;
        if (sa.server_handshake_traffic[] != sb.server_handshake_traffic[])
            ++fails;
        if (sa.client_handshake_traffic[] == sa.server_handshake_traffic[])
            ++fails;
    }
    else
        ++fails;

    {
        import botan.tls.policy;
        class Offer13Policy : TLSPolicy
        {
            override bool acceptableProtocolVersion(TLSProtocolVersion v) const
            {
                return !v.isDatagramProtocol() &&
                    (v == TLSProtocolVersion(TLSProtocolVersion.TLS_V12) ||
                     v == TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
            }
        }
        Unique!TLSPolicy def = new TLSPolicy;
        Unique!Offer13Policy offer = new Offer13Policy;
        auto v13 = TLSProtocolVersion(TLSProtocolVersion.TLS_V13);
        auto v12 = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
        if (tls13SelectVersion(v13, *def) != v12)
            ++fails;
        if (tls13SelectVersion(v13, *offer) != v13)
            ++fails;
        if (tls13SelectVersion(v12, *def) != v12)
            ++fails;
    }

    static if (BOTAN_HAS_CURVE25519 && BOTAN_HAS_HKDF && BOTAN_HAS_AUTO_SEEDING_RNG)
    {
        import botan.tls.handshake_io;
        import botan.tls.handshake_hash;
        import botan.tls.policy;
        class Offer13Policy2 : TLSPolicy
        {
            override bool acceptableProtocolVersion(TLSProtocolVersion v) const
            {
                return !v.isDatagramProtocol() &&
                    (v == TLSProtocolVersion(TLSProtocolVersion.TLS_V12) ||
                     v == TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
            }
        }
        Unique!Offer13Policy2 pol = new Offer13Policy2;
        Unique!AutoSeededRNG rng2 = new AutoSeededRNG;
        {
            Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            HandshakeHash hh;
            Unique!ClientHello ch = new ClientHello(io, hh,
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                *pol, *rng2, Vector!ubyte(), Vector!string(), "server", "");
            if (tls13ChooseSuite(*ch) != 0x1301)
                ++fails;
            static if (BOTAN_HAS_OCSP_STAPLE)
                if (!ch.supportsStatusRequest())
                    ++fails;
            auto agr = tls13AgreeFromClientShare(ch.tls13KeyShare(), *rng2);
            if (agr.server_public.length != 32 || agr.shared_secret.length != 32)
                ++fails;
            static if (BOTAN_HAS_CURVE25519)
            {
                if (!ch.hasTls13X25519())
                    ++fails;
                else
                {
                    auto client_ss = ch.tls13X25519().agree(agr.server_public.ptr, agr.server_public.length);
                    if (client_ss[] != agr.shared_secret[])
                        ++fails;
                    ubyte[32] th_hello;
                    auto sc = tls13HandshakeSecrets("SHA-256", client_ss.ptr, client_ss.length, th_hello.ptr, th_hello.length);
                    auto ss = tls13HandshakeSecrets("SHA-256", agr.shared_secret.ptr, agr.shared_secret.length, th_hello.ptr, th_hello.length);
                    if (sc.client_handshake_traffic[] != ss.client_handshake_traffic[])
                        ++fails;
                }
            }
        }
        fails += checkMemutilsRepeat("tls13 sh/ee exchange", {
            Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            HandshakeHash hh;
            Unique!ClientHello ch = new ClientHello(io, hh,
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                *pol, *rng2, Vector!ubyte(), Vector!string(), "server", "");
            auto agr = tls13AgreeFromClientShare(ch.tls13KeyShare(), *rng2);
            HandshakeHash shh;
            Unique!ServerHello sh = new ServerHello(io, shh, *pol,
                Vector!ubyte(),
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                0x1301, 0, 0, false, false, Vector!ubyte(),
                false, false, "", false, *rng2,
                TLS13_GROUP_X25519, agr.server_public[]);
            Unique!TLS13EncryptedExtensions ee = new TLS13EncryptedExtensions(*ch);
            auto eew = ee.serialize();
            Unique!TLS13EncryptedExtensions parsed = new TLS13EncryptedExtensions(eew);
        });
    }

    static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_HKDF && BOTAN_HAS_AUTO_SEEDING_RNG)
    {
        import botan.tls.handshake_io;
        import botan.tls.handshake_hash;
        class Offer13PqcPolicy : TLSPolicy
        {
            override bool acceptableProtocolVersion(TLSProtocolVersion v) const
            {
                return !v.isDatagramProtocol() &&
                    (v == TLSProtocolVersion(TLSProtocolVersion.TLS_V12) ||
                     v == TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
            }
            override bool offerTls13PqcHybrid() const { return true; }
        }
        Unique!Offer13PqcPolicy pqc = new Offer13PqcPolicy;
        Unique!AutoSeededRNG rngp = new AutoSeededRNG;
        {
            Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            HandshakeHash hh;
            Unique!ClientHello ch = new ClientHello(io, hh,
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                *pqc, *rngp, Vector!ubyte(), Vector!string(), "server", "");
            auto ks = ch.tls13KeyShare();
            if (ks is null || ks.entries().length < 1)
                ++fails;
            else
            {
                bool saw_hy;
                bool saw_x;
                foreach (e; ks.entries()[])
                {
                    if (e.group == TLS13_GROUP_X25519_MLKEM768 &&
                        e.key_exchange.length == TLS13_HYBRID_CH_SHARE_LEN)
                        saw_hy = true;
                    if (e.group == TLS13_GROUP_X25519 &&
                        e.key_exchange.length == TLS13_X25519_SHARE_LEN)
                        saw_x = true;
                }
                if (!saw_hy || !saw_x)
                    ++fails;
                auto curves = ch.supportedEccCurves();
                bool named;
                foreach (c; curves[])
                    if (c == TLS13_GROUP_X25519_MLKEM768_NAME)
                        named = true;
                if (!named)
                    ++fails;
            }
            if (!ch.hasTls13Mlkem() || !ch.hasTls13X25519())
                ++fails;
            else
            {
                auto agr = tls13AgreeFromClientShare(ks, *rngp, *pqc);
                if (agr.group != TLS13_GROUP_X25519_MLKEM768 ||
                    agr.server_public.length != TLS13_HYBRID_SH_SHARE_LEN ||
                    agr.shared_secret.length != TLS13_HYBRID_SS_LEN)
                    ++fails;
                else
                {
                    auto e = new TLS13KeyShareEntry;
                    e.group = agr.group;
                    foreach (bb; agr.server_public[])
                        e.key_exchange.pushBack(bb);
                    Vector!TLS13KeyShareEntry ents;
                    ents.pushBack(e);
                    Unique!TLS13KeyShare shks = new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move());
                    auto client_ss = tls13ClientSecretFromServerShare(*ch, shks);
                    if (client_ss[] != agr.shared_secret[])
                        ++fails;
                }
            }
        }
        fails += checkMemutilsRepeat("tls13 pqc hybrid share", {
            Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            HandshakeHash hh;
            Unique!ClientHello ch = new ClientHello(io, hh,
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                *pqc, *rngp, Vector!ubyte(), Vector!string(), "server", "");
            auto agr = tls13AgreeFromClientShare(ch.tls13KeyShare(), *rngp, *pqc);
            auto e = new TLS13KeyShareEntry;
            e.group = agr.group;
            foreach (bb; agr.server_public[])
                e.key_exchange.pushBack(bb);
            Vector!TLS13KeyShareEntry ents;
            ents.pushBack(e);
            Unique!TLS13KeyShare shks = new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move());
            auto css = tls13ClientSecretFromServerShare(*ch, shks);
            if (css[] != agr.shared_secret[])
                throw new Exception("hybrid ss mismatch");
        });
        {
            Unique!TLSPolicy def = new TLSPolicy;
            if (def.offerTls13PqcHybrid())
                ++fails;
        }

        class OfferNamedPqcPolicy : TLSPolicy
        {
            string group_name;
            this(string n) { group_name = n; }
            override bool acceptableProtocolVersion(TLSProtocolVersion v) const
            {
                return !v.isDatagramProtocol() &&
                    (v == TLSProtocolVersion(TLSProtocolVersion.TLS_V12) ||
                     v == TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
            }
            override bool offerTls13PqcHybrid() const { return false; }
            override bool offerTls13Secp256Mlkem() const { return group_name == TLS13_GROUP_SECP256R1_MLKEM768_NAME; }
            override bool offerTls13Secp384Mlkem() const { return group_name == TLS13_GROUP_SECP384R1_MLKEM1024_NAME; }
            override bool offerTls13Mlkem512() const { return group_name == TLS13_GROUP_MLKEM512_NAME; }
            override bool offerTls13Mlkem768() const { return group_name == TLS13_GROUP_MLKEM768_NAME; }
            override bool offerTls13Mlkem1024() const { return group_name == TLS13_GROUP_MLKEM1024_NAME; }
            override string offerTls13PqcExtraGroup() const
            {
                return tls13IsFrodoOqsName(group_name) ? group_name : "";
            }
        }

        void checkPqcGroup(string name, ushort group, size_t ch_len, size_t sh_len, size_t ss_len)
        {
            Unique!OfferNamedPqcPolicy pol = new OfferNamedPqcPolicy(name);
            Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            HandshakeHash hh;
            Unique!ClientHello ch = new ClientHello(io, hh,
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                pol, *rngp, Vector!ubyte(), Vector!string(), "server", "");
            auto ks = ch.tls13KeyShare();
            if (ks is null)
            {
                logError("pqc ", name, " missing key_share");
                ++fails;
            }
            else if (tls13FindShare(ks, group, ch_len) is null)
            {
                foreach (ent; ks.entries()[])
                    logError("pqc ", name, " got group ", ent.group, " len ", ent.key_exchange.length,
                             " want ", group, "/", ch_len);
                ++fails;
            }
            else
            {
                auto agr = tls13AgreeFromClientShare(ks, *rngp, *pol);
                if (agr.group != group || agr.server_public.length != sh_len ||
                    agr.shared_secret.length != ss_len)
                {
                    logError("pqc ", name, " agree group ", agr.group, " sh ", agr.server_public.length,
                             " ss ", agr.shared_secret.length, " want ", group, "/", sh_len, "/", ss_len);
                    ++fails;
                }
                else
                {
                    auto e = new TLS13KeyShareEntry;
                    e.group = agr.group;
                    foreach (bb; agr.server_public[])
                        e.key_exchange.pushBack(bb);
                    Vector!TLS13KeyShareEntry ents;
                    ents.pushBack(e);
                    Unique!TLS13KeyShare shks = new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move());
                    auto css = tls13ClientSecretFromServerShare(*ch, shks);
                    if (css[] != agr.shared_secret[])
                    {
                        logError("pqc ", name, " ss mismatch client ", css.length, " server ", agr.shared_secret.length);
                        ++fails;
                    }
                }
            }
        }

        checkPqcGroup(TLS13_GROUP_MLKEM768_NAME, TLS13_GROUP_MLKEM768,
                      TLS13_MLKEM768_PK_LEN, TLS13_MLKEM768_CT_LEN, 32);
        checkPqcGroup(TLS13_GROUP_MLKEM512_NAME, TLS13_GROUP_MLKEM512,
                      TLS13_MLKEM512_PK_LEN, TLS13_MLKEM512_CT_LEN, 32);
        checkPqcGroup(TLS13_GROUP_MLKEM1024_NAME, TLS13_GROUP_MLKEM1024,
                      TLS13_MLKEM1024_PK_LEN, TLS13_MLKEM1024_CT_LEN, 32);
        static if (BOTAN_HAS_ECDH)
        {
            checkPqcGroup(TLS13_GROUP_SECP256R1_MLKEM768_NAME, TLS13_GROUP_SECP256R1_MLKEM768,
                          TLS13_P256_HYBRID_CH_LEN, TLS13_P256_HYBRID_SH_LEN, TLS13_P256_HYBRID_SS_LEN);
            checkPqcGroup(TLS13_GROUP_SECP384R1_MLKEM1024_NAME, TLS13_GROUP_SECP384R1_MLKEM1024,
                          TLS13_P384_HYBRID_CH_LEN, TLS13_P384_HYBRID_SH_LEN, TLS13_P384_HYBRID_SS_LEN);
            fails += checkMemutilsRepeat("tls13 p256 hybrid share", {
                Unique!OfferNamedPqcPolicy pol = new OfferNamedPqcPolicy(TLS13_GROUP_SECP256R1_MLKEM768_NAME);
                Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
                HandshakeHash hh;
                Unique!ClientHello ch = new ClientHello(io, hh,
                    TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                    pol, *rngp, Vector!ubyte(), Vector!string(), "server", "");
                auto agr = tls13AgreeFromClientShare(ch.tls13KeyShare(), *rngp, *pol);
                auto e = new TLS13KeyShareEntry;
                e.group = agr.group;
                foreach (bb; agr.server_public[])
                    e.key_exchange.pushBack(bb);
                Vector!TLS13KeyShareEntry ents;
                ents.pushBack(e);
                Unique!TLS13KeyShare shks = new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move());
                auto css = tls13ClientSecretFromServerShare(*ch, shks);
                if (css[] != agr.shared_secret[])
                    throw new Exception("p256 hybrid ss mismatch");
            });
        }
        static if (BOTAN_HAS_FRODOKEM)
        {
            checkPqcGroup(TLS13_GROUP_EFRODO_640_SHAKE_NAME, TLS13_GROUP_EFRODO_640_SHAKE,
                          TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN);
            checkPqcGroup(TLS13_GROUP_EFRODO_640_AES_NAME, TLS13_GROUP_EFRODO_640_AES,
                          TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN);
            checkPqcGroup(TLS13_GROUP_X25519_EFRODO_640_SHAKE_NAME, TLS13_GROUP_X25519_EFRODO_640_SHAKE,
                          TLS13_X25519_SHARE_LEN + TLS13_EFRODO_640_PK_LEN,
                          TLS13_X25519_SHARE_LEN + TLS13_EFRODO_640_CT_LEN,
                          TLS13_X25519_SHARE_LEN + TLS13_EFRODO_640_SS_LEN);
            static if (BOTAN_HAS_ECDH)
            {
                checkPqcGroup(TLS13_GROUP_SECP256_EFRODO_640_SHAKE_NAME, TLS13_GROUP_SECP256_EFRODO_640_SHAKE,
                              TLS13_SECP256R1_PUB_LEN + TLS13_EFRODO_640_PK_LEN,
                              TLS13_SECP256R1_PUB_LEN + TLS13_EFRODO_640_CT_LEN,
                              TLS13_SECP256R1_SS_LEN + TLS13_EFRODO_640_SS_LEN);
            }
            static if (BOTAN_HAS_X448)
            {
                checkPqcGroup(TLS13_GROUP_X448_EFRODO_976_SHAKE_NAME, TLS13_GROUP_X448_EFRODO_976_SHAKE,
                              TLS13_X448_SHARE_LEN + TLS13_EFRODO_976_PK_LEN,
                              TLS13_X448_SHARE_LEN + TLS13_EFRODO_976_CT_LEN,
                              TLS13_X448_SHARE_LEN + TLS13_EFRODO_976_SS_LEN);
            }
            fails += checkMemutilsRepeat("tls13 x25519/efrodo-640-shake", {
                Unique!OfferNamedPqcPolicy pol = new OfferNamedPqcPolicy(TLS13_GROUP_X25519_EFRODO_640_SHAKE_NAME);
                Unique!StreamHandshakeIO io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
                HandshakeHash hh;
                Unique!ClientHello ch = new ClientHello(io, hh,
                    TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                    pol, *rngp, Vector!ubyte(), Vector!string(), "server", "");
                auto agr = tls13AgreeFromClientShare(ch.tls13KeyShare(), *rngp, *pol);
                auto e = new TLS13KeyShareEntry;
                e.group = agr.group;
                foreach (bb; agr.server_public[])
                    e.key_exchange.pushBack(bb);
                Vector!TLS13KeyShareEntry ents;
                ents.pushBack(e);
                Unique!TLS13KeyShare shks = new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move());
                auto css = tls13ClientSecretFromServerShare(*ch, shks);
                if (css[] != agr.shared_secret[])
                    throw new Exception("x25519/efrodo ss mismatch");
            });
        }
    }

    {
        Unique!TLS13Certificate empty_c = new TLS13Certificate(Vector!X509Certificate());
        auto raw = empty_c.serialize();
        if (raw.length != 4 || raw[0] != 0 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0)
            ++fails;
        Unique!TLS13Certificate parsed_c = new TLS13Certificate(raw, CLIENT);
        if (!parsed_c.empty)
            ++fails;
        Vector!ubyte cvbuf;
        cvbuf.pushBack(0x08);
        cvbuf.pushBack(0x04);
        cvbuf.pushBack(0);
        cvbuf.pushBack(2);
        cvbuf.pushBack(0xaa);
        cvbuf.pushBack(0xbb);
        Unique!TLS13CertificateVerify parsed_cv = new TLS13CertificateVerify(cvbuf);
        if (parsed_cv.scheme() != TLS13_RSA_PSS_RSAE_SHA256 || parsed_cv.signature().length != 2)
            ++fails;
        ubyte[32] sec_a = 0x11;
        ubyte[16] msgs = 0x22;
        auto fa = tls13FinishedMac("SHA-256", sec_a.ptr, sec_a.length, msgs.ptr, msgs.length);
        auto fb = tls13FinishedMac("SHA-256", sec_a.ptr, sec_a.length, msgs.ptr, msgs.length);
        if (fa[] != fb[] || fa.length != 32)
            ++fails;
        ubyte[32] sec_b = 0x33;
        auto fc = tls13FinishedMac("SHA-256", sec_b.ptr, sec_b.length, msgs.ptr, msgs.length);
        if (fa[] == fc[])
            ++fails;
        auto hs = tls13HandshakeSecrets("SHA-256", sec_a.ptr, sec_a.length, msgs.ptr, msgs.length);
        auto ap = tls13AppSecrets("SHA-256", hs.handshake_secret.ptr, hs.handshake_secret.length,
                                  msgs.ptr, msgs.length);
        if (ap.client_application_traffic[] == hs.client_handshake_traffic[])
            ++fails;
        if (ap.client_application_traffic[] == ap.server_application_traffic[])
            ++fails;
    }

    static if (BOTAN_HAS_OCSP_STAPLE)
    {
        import botan.tls.reader;
        import botan.tls.extensions;
        Vector!ubyte staple;
        staple.pushBack(0x30);
        staple.pushBack(0x03);
        staple.pushBack(0x02);
        staple.pushBack(0x01);
        staple.pushBack(0x00);
        Unique!StatusRequest sr = new StatusRequest(staple.clone);
        auto srw = sr.serialize();
        if (srw.length < 5 || srw[0] != 1)
            ++fails;
        TLSDataReader rdr = TLSDataReader("staple", srw);
        Unique!StatusRequest parsed_sr = new StatusRequest(rdr, cast(ushort) srw.length, CERTIFICATE);
        if (parsed_sr.ocspResponse()[] != staple[])
            ++fails;
    }

    testReport("tls13_handshake", 32, fails);
    assert(fails == 0);
}
