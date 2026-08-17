/**
* Ed25519 signatures (RFC 8032 / RFC 8410). Pure + Ed25519ph + hashed.
*
* Copyright:
* (C) 2017 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ed25519;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ED25519):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.rng.rng;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.exceptn;
import memutils.helpers;
import botan.pubkey.algo.ed25519_fe;
import botan.pubkey.algo.ed25519_sc;
import botan.pubkey.algo.ed25519_ge;

struct Ed25519PublicKey
{
public:
    enum algoName = "Ed25519";

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_pub = new Ed25519PublicKeyImpl(alg_id, key_bits);
    }

    this(const ref Vector!ubyte pub)
    {
        m_owned = true;
        m_pub = new Ed25519PublicKeyImpl(pub);
    }

    this(PrivateKey pkey) { m_pub = cast(Ed25519PublicKeyImpl) pkey; }
    this(PublicKey pkey) { m_pub = cast(Ed25519PublicKeyImpl) pkey; }

    mixin Embed!(m_pub, m_owned);
    bool m_owned;
    Ed25519PublicKeyImpl m_pub;
}

struct Ed25519PrivateKey
{
public:
    enum algoName = "Ed25519";

    this(RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new Ed25519PrivateKeyImpl(rng);
    }

    this(const ref SecureVector!ubyte seed)
    {
        m_owned = true;
        m_priv = new Ed25519PrivateKeyImpl(seed);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new Ed25519PrivateKeyImpl(alg_id, key_bits, rng);
    }

    this(PrivateKey pkey) { m_priv = cast(Ed25519PrivateKeyImpl) pkey; }

    mixin Embed!(m_priv, m_owned);
    bool m_owned;
    Ed25519PrivateKeyImpl m_priv;
}

class Ed25519PublicKeyImpl : PublicKey
{
public:
    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        if (key_bits.length != 32)
            throw new DecodingError("Invalid size for Ed25519 public key");
        m_public = unlock(key_bits);
    }

    this(const ref Vector!ubyte pub)
    {
        if (pub.length != 32)
            throw new DecodingError("Invalid size for Ed25519 public key");
        m_public = pub.clone();
    }

    this() {}

    final override @property string algoName() const { return "Ed25519"; }
    final override size_t maxInputBits() const { return size_t.max / 2; }
    final override size_t messagePartSize() const { return 0; }
    final override size_t messageParts() const { return 1; }

    final override AlgorithmIdentifier algorithmIdentifier() const
    {
        auto empty = Vector!ubyte();
        return AlgorithmIdentifier(getOid(), empty);
    }

    final override Vector!ubyte x509SubjectPublicKey() const
    {
        return m_public.clone();
    }

    Vector!ubyte publicValue() const { return m_public.clone(); }

    override bool checkKey(RandomNumberGenerator, bool) const
    {
        if (m_public.length != 32)
            return false;
        ubyte[32] identity = 0;
        identity[0] = 1;
        ubyte acc = 0;
        foreach (i; 0 .. 32)
            acc |= m_public[i] ^ identity[i];
        if (acc == 0)
            return false;
        ubyte[32] ncid = 0;
        ncid[0] = 1;
        ncid[31] = 0x80;
        acc = 0;
        foreach (i; 0 .. 32)
            acc |= m_public[i] ^ ncid[i];
        if (acc == 0)
            return false;
        ubyte[32] pkcopy = m_public[];
        pkcopy[31] ^= 0x80;
        static immutable ubyte[32] order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        ];
        ubyte[32] zero = 0;
        return signatureCheck(pkcopy.ptr, order.ptr, identity.ptr, zero.ptr);
    }

    override size_t estimatedStrength() const { return 128; }

    Vector!ubyte m_public;
}

final class Ed25519PrivateKeyImpl : Ed25519PublicKeyImpl, PrivateKey
{
public:
    this(RandomNumberGenerator rng)
    {
        super();
        auto seed = rng.randomVec(32);
        expandSeed(seed);
        genCheck(rng);
    }

    this(const ref SecureVector!ubyte seed)
    {
        super();
        if (seed.length != 32)
            throw new DecodingError("Ed25519 seed must be 32 bytes");
        expandSeed(seed);
    }

    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        super();
        SecureVector!ubyte bits;
        BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING).discardRemaining();
        if (bits.length != 32)
            throw new DecodingError("Invalid size for Ed25519 private key");
        expandSeed(bits);
        loadCheck(rng);
    }

    override bool checkKey(RandomNumberGenerator, bool) const
    {
        ubyte[32] pk;
        ubyte[64] sk;
        ed25519GenKeypair(pk.ptr, sk.ptr, m_private.ptr);
        if (pk[] != m_public[])
            return false;
        return true;
    }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        SecureVector!ubyte bits = SecureVector!ubyte(m_private.ptr[0 .. 32]);
        return DEREncoder().encode(bits, ASN1Tag.OCTET_STRING).getContents();
    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const
    {
        return super.algorithmIdentifier();
    }

    const(ubyte)* expandedPtr() const { return m_private.ptr; }

private:
    void expandSeed(const ref SecureVector!ubyte seed)
    {
        ubyte[32] pk;
        m_private = SecureVector!ubyte(64);
        ed25519GenKeypair(pk.ptr, m_private.ptr, seed.ptr);
        m_public = Vector!ubyte(pk[]);
    }

    SecureVector!ubyte m_private;
}

/// RFC 8032 §5.1: "SigEd25519 no Ed25519 collisions" || phflag=1 || ctxlen=0
immutable ubyte[34] ED25519_PH_DOM = [
    0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E,
    0x6F, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F,
    0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x01, 0x00
];

bool ed25519IsPureParams(in string params)
{
    return params.length == 0 || params == "Raw" || params == "Identity" || params == "Pure";
}

bool ed25519IsPhParams(in string params)
{
    return params == "Ed25519ph";
}

Signature ed25519TrySignatureOp(in PrivateKey key, in string params)
{
    if (key.algoName != "Ed25519" || ed25519IsPureParams(params))
        return null;
    return new Ed25519SignatureOperation(key, params);
}

Verification ed25519TryVerificationOp(in PublicKey key, in string params)
{
    if (key.algoName != "Ed25519" || ed25519IsPureParams(params))
        return null;
    return new Ed25519VerificationOperation(key, params);
}

void ed25519Prehash(in string hash_name, const(ubyte)* msg, size_t msg_len, ref SecureVector!ubyte ph)
{
    Unique!HashFunction h = retrieveHash(hash_name).clone();
    if (!h)
        throw new LookupError("Ed25519 hashed mode needs " ~ hash_name);
    if (msg_len)
        h.update(msg, msg_len);
    ph = h.finished();
}

void ed25519SignParams(ubyte* sig, const(ubyte)* msg, size_t msg_len,
                       const(ubyte)* sk, in string params)
{
    if (ed25519IsPureParams(params))
    {
        ed25519Sign(sig, msg, msg_len, sk, null, 0);
        return;
    }
    const bool rfc = ed25519IsPhParams(params);
    const string hn = rfc ? "SHA-512" : params;
    SecureVector!ubyte ph;
    ed25519Prehash(hn, msg, msg_len, ph);
    if (rfc)
        ed25519Sign(sig, ph.ptr, ph.length, sk, ED25519_PH_DOM.ptr, ED25519_PH_DOM.length);
    else
        ed25519Sign(sig, ph.ptr, ph.length, sk, null, 0);
}

bool ed25519VerifyParams(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig,
                         const(ubyte)* pk, in string params)
{
    if (ed25519IsPureParams(params))
        return ed25519Verify(msg, msg_len, sig, pk, null, 0);
    const bool rfc = ed25519IsPhParams(params);
    const string hn = rfc ? "SHA-512" : params;
    SecureVector!ubyte ph;
    ed25519Prehash(hn, msg, msg_len, ph);
    if (rfc)
        return ed25519Verify(ph.ptr, ph.length, sig, pk, ED25519_PH_DOM.ptr, ED25519_PH_DOM.length);
    return ed25519Verify(ph.ptr, ph.length, sig, pk, null, 0);
}

final class Ed25519SignatureOperation : Signature
{
public:
    this(in PrivateKey pkey)
    {
        this(pkey, "Pure");
    }

    this(in PrivateKey pkey, in string params)
    {
        m_key = cast(Ed25519PrivateKeyImpl) pkey;
        m_params = params.idup;
    }

    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        auto sig = SecureVector!ubyte(64);
        ed25519SignParams(sig.ptr, msg, msg_len, m_key.expandedPtr(), m_params);
        return sig.move;
    }

private:
    const Ed25519PrivateKeyImpl m_key;
    string m_params;
}

final class Ed25519VerificationOperation : Verification
{
public:
    this(in PublicKey pkey)
    {
        this(pkey, "Pure");
    }

    this(in PublicKey pkey, in string params)
    {
        m_key = cast(Ed25519PublicKeyImpl) pkey;
        m_params = params.idup;
    }

    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }

    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        if (sig_len != 64)
            return false;
        return ed25519VerifyParams(msg, msg_len, sig, m_key.m_public.ptr, m_params);
    }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("Ed25519 has no message recovery");
    }

private:
    const Ed25519PublicKeyImpl m_key;
    string m_params;
}

void ed25519GenKeypair(ubyte* pk, ubyte* sk, const(ubyte)* seed)
{
    ubyte[64] az;
    sha512(az, seed, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;
    ed25519BasepointMul(pk, az.ptr);
    sk[0 .. 32] = seed[0 .. 32];
    sk[32 .. 64] = pk[0 .. 32];
}

void ed25519Sign(ubyte* sig, const(ubyte)* m, size_t mlen,
                 const(ubyte)* sk, const(ubyte)* domain_sep, size_t domain_sep_len)
{
    ubyte[64] az;
    ubyte[64] nonce;
    ubyte[64] hram;
    sha512(az, sk, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    sha512Parts(nonce, domain_sep, domain_sep_len, az.ptr + 32, 32, m, mlen);
    scReduce(nonce.ptr);
    ed25519BasepointMul(sig, nonce.ptr);

    sha512Parts(hram, domain_sep, domain_sep_len, sig, 32, sk + 32, 32, m, mlen);
    scReduce(hram.ptr);
    scMuladd(sig + 32, hram.ptr, az.ptr, nonce.ptr);
}

bool ed25519Verify(const(ubyte)* m, size_t mlen, const(ubyte)* sig,
                   const(ubyte)* pk, const(ubyte)* domain_sep, size_t domain_sep_len)
{
    if ((sig[63] & 0xE0) != 0)
        return false;

    ubyte[32] identity = 0;
    identity[0] = 1;
    ubyte acc = 0;
    foreach (i; 0 .. 32)
        acc |= pk[i] ^ identity[i];
    if (acc == 0)
        return false;

    immutable ulong[4] ORDER = [
        0x1000000000000000UL,
        0x0000000000000000UL,
        0x14def9dea2f79cd6UL,
        0x5812631a5cf5d3edUL,
    ];
    const ulong[4] ss = [
        load4(sig + 32 + 24) | (cast(ulong) load4(sig + 32 + 28) << 32),
        load4(sig + 32 + 16) | (cast(ulong) load4(sig + 32 + 20) << 32),
        load4(sig + 32 + 8) | (cast(ulong) load4(sig + 32 + 12) << 32),
        load4(sig + 32 + 0) | (cast(ulong) load4(sig + 32 + 4) << 32),
    ];
    foreach (i; 0 .. 4)
    {
        if (ss[i] > ORDER[i])
            return false;
        if (ss[i] < ORDER[i])
            break;
        if (i == 3)
            return false;
    }

    ubyte[64] h;
    sha512Parts(h, domain_sep, domain_sep_len, sig, 32, pk, 32, m, mlen);
    scReduce(h.ptr);
    return signatureCheck(pk, h.ptr, sig, sig + 32);
}

private:

void sha512(ref ubyte[64] outbuf, const(ubyte)* input, size_t len)
{
    Unique!HashFunction h = retrieveHash("SHA-512").clone();
    if (len)
        h.update(input, len);
    h.flushInto(outbuf.ptr);
}

void sha512Parts(ref ubyte[64] outbuf,
                 const(ubyte)* a, size_t al,
                 const(ubyte)* b, size_t bl,
                 const(ubyte)* c, size_t cl)
{
    Unique!HashFunction h = retrieveHash("SHA-512").clone();
    if (al) h.update(a, al);
    if (bl) h.update(b, bl);
    if (cl) h.update(c, cl);
    h.flushInto(outbuf.ptr);
}

void sha512Parts(ref ubyte[64] outbuf,
                 const(ubyte)* a, size_t al,
                 const(ubyte)* b, size_t bl,
                 const(ubyte)* c, size_t cl,
                 const(ubyte)* d, size_t dl)
{
    Unique!HashFunction h = retrieveHash("SHA-512").clone();
    if (al) h.update(a, al);
    if (bl) h.update(b, bl);
    if (cl) h.update(c, cl);
    if (dl) h.update(d, dl);
    h.flushInto(outbuf.ptr);
}

static if (BOTAN_HAS_TESTS && !SKIP_ED25519_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import botan.pubkey.pubkey;
    import botan.pubkey.pk_algs;
    import botan.asn1.oids;
    import botan.rng.auto_rng;
    import memutils.hashmap;
    import std.stdio : File;

    auto state = globalState();
    logDebug("Testing ed25519.d ...");

    size_t extra = 0;
    {
        const OID oid = OIDS.lookup("Ed25519");
        if (oid.toString() != "1.3.101.112")
            ++extra;
        if (OIDS.lookup(oid) != "Ed25519")
            ++extra;
    }

    File vec = File("test_data/pubkey/ed25519.vec", "r");
    size_t fails = runTests(vec, "Algo", "Signature", false,
        (ref HashMap!(string, string) m)
        {
            const string algo = m["Algo"];
            if (!ed25519IsPureParams(algo) && algo != "Ed25519ph" && algo != "SHA-256")
                return m["Signature"];

            auto seed = hexDecodeLocked(m["Privkey"]);
            auto pub = hexDecode(m["Pubkey"]);
            Vector!ubyte msg;
            if (auto mp = "Msg" in m)
            {
                if ((*mp).length)
                    msg = hexDecode(*mp);
            }
            auto priv = Ed25519PrivateKey(seed);
            if (priv.publicValue() != pub)
                return "PUBKEY_MISMATCH";
            ubyte[64] raw_sig;
            ed25519SignParams(raw_sig.ptr, msg.ptr, msg.length, priv.expandedPtr(), algo);
            if (!ed25519VerifyParams(msg.ptr, msg.length, raw_sig.ptr, pub.ptr, algo))
                return "VERIFY_FAIL";
            return hexEncode(raw_sig.ptr, 64, false);
        });

    {
        File vfy = File("test_data/pubkey/ed25519_verify.vec", "r");
        fails += runTestsBb(vfy, "Algo", "Signature", false,
            (ref HashMap!(string, string) m)
            {
                if (m["Algo"] != "Pure")
                    return 0;
                bool expect = true;
                if (auto vp = "Valid" in m)
                    expect = (*vp) != "0";
                auto pub = hexDecode(m["Pubkey"]);
                Vector!ubyte msg;
                if (auto mp = "Msg" in m)
                {
                    if ((*mp).length)
                        msg = hexDecode(*mp);
                }
                auto sig = hexDecode(m["Signature"]);
                if (sig.length != 64 || pub.length != 32)
                    return expect ? 1 : 0;
                bool ok = ed25519Verify(msg.ptr, msg.length, sig.ptr, pub.ptr, null, 0);
                return (ok == expect) ? 0 : 1;
            });
    }

    {
        File kv = File("test_data/pubkey/ed25519_key_valid.vec", "r");
        fails += runTestsBb(kv, "Group", "Pubkey", true,
            (ref HashMap!(string, string) m)
            {
                const bool expect = m["Group"] == "Valid";
                auto pub = hexDecode(m["Pubkey"]);
                try
                {
                    auto k = Ed25519PublicKey(pub);
                    const bool ok = k.checkKey(globalState().globalRng(), false);
                    return (ok == expect) ? 0 : 1;
                }
                catch (Exception)
                {
                    return expect ? 1 : 0;
                }
            });
    }

    {
        Unique!AutoSeededRNG arng = new AutoSeededRNG;
        auto k = Ed25519PrivateKey(*arng);
        auto signer = PKSigner(k, "Raw");
        ubyte[5] hello = ['h', 'e', 'l', 'l', 'o'];
        auto sig = signer.signMessage(hello.ptr, hello.length, *arng);
        auto verifier = PKVerifier(k, "Raw");
        if (!verifier.verifyMessage(hello.ptr, hello.length, sig.ptr, sig.length))
            ++extra;

        auto signer_ph = PKSigner(k, "Ed25519ph");
        auto sig_ph = signer_ph.signMessage(hello.ptr, hello.length, *arng);
        auto verifier_ph = PKVerifier(k, "Ed25519ph");
        if (!verifier_ph.verifyMessage(hello.ptr, hello.length, sig_ph.ptr, sig_ph.length))
            ++extra;
        if (verifier.verifyMessage(hello.ptr, hello.length, sig_ph.ptr, sig_ph.length))
            ++extra;

        auto bits = k.pkcs8PrivateKey();
        auto loaded = Ed25519PrivateKey(k.algorithmIdentifier(), bits, *arng);
        if (loaded.publicValue() != k.publicValue())
            ++extra;
        auto pub_bits = SecureVector!ubyte(k.publicValue()[]);
        Unique!PublicKey via_factory = makePublicKey(k.algorithmIdentifier(), pub_bits);
        if (!via_factory || via_factory.algoName != "Ed25519")
            ++extra;
    }

    fails += extra;
    testReport("ed25519", 0, fails);
    assert(fails == 0);
}
