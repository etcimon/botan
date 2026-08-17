/**
* ECKCDSA (ISO/IEC 14888-3 / TTAK.KO-12.0015)
*
* Copyright:
* (C) 2016 René Korthaus, Sirrix AG
* (C) 2018,2024 Jack Lloyd
* (C) 2023 Philippe Lieser - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.eckcdsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECKCDSA):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.pubkey.algo.keypair;
import botan.pubkey.pk_ops;
import botan.math.ec_gfp.point_gfp;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;
import botan.math.bigint.bigint;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import memutils.helpers : Embed;

struct ECKCDSAOptions
{
    enum algoName = "ECKCDSA";
    enum msgParts = 1;

    static bool checkKey(in ECPrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.publicPoint().onTheCurve())
            return false;
        if (!strong)
            return true;
        return signatureConsistencyCheck(rng, privkey, "Raw");
    }
}

struct ECKCDSAPublicKey
{
public:
    alias Options = ECKCDSAOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in ECGroup dom_par, in PointGFp public_point)
    {
        m_owned = true;
        m_pub = new ECPublicKey(Options(), dom_par, public_point);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_pub = new ECPublicKey(Options(), alg_id, key_bits);
    }

    this(in PublicKey pkey) { m_pub = cast(ECPublicKey) pkey; }
    this(in PrivateKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    mixin Embed!(m_pub, m_owned);
    bool m_owned;
    ECPublicKey m_pub;
}

struct ECKCDSAPrivateKey
{
public:
    alias Options = ECKCDSAOptions;
    __gshared immutable string algoName = Options.algoName;

    this(const ref AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits, true);
    }

    this()(RandomNumberGenerator rng, const auto ref ECGroup domain)
    {
        m_owned = true;
        auto zero = BigInt(0);
        m_priv = new ECPrivateKey(Options(), rng, domain, zero, true);
    }

    this()(RandomNumberGenerator rng, const auto ref ECGroup domain, const auto ref BigInt x)
    {
        m_owned = true;
        m_priv = new ECPrivateKey(Options(), rng, domain, x, true);
    }

    this(in PrivateKey pkey) { m_priv = cast(ECPrivateKey) pkey; }

    mixin Embed!(m_priv, m_owned);
    bool m_owned;
    ECPrivateKey m_priv;
}

void eckcdsaTruncateHash(ref Vector!ubyte digest, size_t order_bytes)
{
    if (digest.length > order_bytes)
    {
        auto tail = Vector!ubyte(digest[digest.length - order_bytes .. $]);
        digest = tail.move();
    }
}

Vector!ubyte eckcdsaPrefix(const ref PointGFp pub, size_t block)
{
    const size_t p_bytes = pub.getCurve().getP().bytes();
    auto x = pub.getAffineX();
    auto y = pub.getAffineY();
    auto xb = BigInt.encode1363(&x, p_bytes);
    auto yb = BigInt.encode1363(&y, p_bytes);
    auto prefix = Vector!ubyte(block);
    size_t off = 0;
    auto take = (const(ubyte)* p, size_t n)
    {
        const size_t room = (off < block) ? block - off : 0;
        const size_t use = (n < room) ? n : room;
        if (use)
            prefix[off .. off + use] = p[0 .. use];
        off += use;
    };
    take(xb.ptr, xb.length);
    take(yb.ptr, yb.length);
    return prefix.move();
}

Vector!ubyte eckcdsaHashMsg(in string hash_name, const ref PointGFp pub,
                            const(ubyte)* msg, size_t msg_len)
{
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    auto prefix = eckcdsaPrefix(pub, hash.hashBlockSize);
    hash.update(prefix.ptr, prefix.length);
    if (msg_len)
        hash.update(msg, msg_len);
    auto d = unlock(hash.finished());
    return d.move();
}

SecureVector!ubyte eckcdsaSignWithK(const ref ECGroup group, const ref BigInt x,
                                    const ref PointGFp pub, in string hash_name,
                                    const(ubyte)* msg, size_t msg_len, const ref BigInt k)
{
    const size_t olen = group.getOrder().bytes();
    auto H = eckcdsaHashMsg(hash_name, pub, msg, msg_len);
    eckcdsaTruncateHash(H, olen);

    PointGFp kG = group.getBasePoint() * &k;
    auto kx = kG.getAffineX();
    const size_t p_bytes = group.getCurve().getP().bytes();
    auto xb = BigInt.encode1363(&kx, p_bytes);
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    hash.update(xb.ptr, xb.length);
    auto r = unlock(hash.finished());
    eckcdsaTruncateHash(r, olen);

    auto c = Vector!ubyte(r.length);
    c[] = r[];
    xorBuf(c.ptr, H.ptr, c.length);
    ModularReducer mod_n = ModularReducer(group.getOrder());
    BigInt w = mod_n.reduce(BigInt(c.ptr, c.length));
    BigInt kmw = k.clone;
    kmw -= w;
    kmw = mod_n.reduce(kmw.move());
    BigInt s = mod_n.multiply(&x, &kmw);
    if (s == 0)
        throw new InternalError("During ECKCDSA signature generation created zero s");

    auto output = SecureVector!ubyte(r.length + olen);
    output[0 .. r.length] = r[];
    s.binaryEncode(&output[r.length + olen - s.bytes()]);
    return output.move();
}

bool eckcdsaVerify(const ref ECGroup group, const ref PointGFp pub, in string hash_name,
                   const(ubyte)* msg, size_t msg_len,
                   const(ubyte)* sig, size_t sig_len)
{
    const size_t olen = group.getOrder().bytes();
    auto H = eckcdsaHashMsg(hash_name, pub, msg, msg_len);
    eckcdsaTruncateHash(H, olen);
    const size_t size_r = H.length;
    if (sig_len != size_r + olen)
        return false;

    auto r = sig[0 .. size_r];
    BigInt s = BigInt(sig + size_r, olen);
    const BigInt* n = &group.getOrder();
    if (s <= 0 || s >= *n)
        return false;

    auto c = Vector!ubyte(size_r);
    c[] = r[];
    xorBuf(c.ptr, H.ptr, size_r);
    ModularReducer mod_n = ModularReducer(*n);
    BigInt w = mod_n.reduce(BigInt(c.ptr, c.length));
    PointGFp Q = PointGFp.multiExponentiate(group.getBasePoint(), &w, pub, &s);
    if (Q.isZero())
        return false;
    auto qx = Q.getAffineX();
    const size_t p_bytes = group.getCurve().getP().bytes();
    auto xb = BigInt.encode1363(&qx, p_bytes);
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    hash.update(xb.ptr, xb.length);
    auto v = unlock(hash.finished());
    eckcdsaTruncateHash(v, olen);
    if (v.length != size_r)
        return false;
    return v[] == r[];
}

final class ECKCDSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { this(cast(ECPrivateKey) pkey); }
    this(in ECKCDSAPrivateKey pkey) { this(pkey.m_priv); }
    this(in ECPrivateKey key)
    {
        assert(key.algoName == ECKCDSAPublicKey.algoName);
        m_key = key;
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        const BigInt* n = &m_key.domain().getOrder();
        BigInt k;
        do
        {
            k.randomize(rng, n.bits());
        } while (k == 0 || k >= *n);
        return eckcdsaSignWithK(m_key.domain(), m_key.privateValue(), m_key.publicPoint(),
                                "SHA-256", msg, msg_len, k);
    }

    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }

private:
    const ECPrivateKey m_key;
}

final class ECKCDSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { this(cast(ECPublicKey) pkey); }
    this(in ECKCDSAPublicKey pkey) { this(pkey.m_pub); }
    this(in ECPublicKey key)
    {
        assert(key.algoName == ECKCDSAPublicKey.algoName);
        m_key = key;
    }

    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }

    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return eckcdsaVerify(m_key.domain(), m_key.publicPoint(), "SHA-256",
                             msg, msg_len, sig, sig_len);
    }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("ECKCDSA has no message recovery");
    }

private:
    const ECPublicKey m_key;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import botan.libstate.global_state;
import botan.asn1.oids;
import botan.pubkey.pk_algs;
import memutils.hashmap;
import std.stdio : File;

string botanHashName(string h)
{
    if (h == "SHA-1")
        return "SHA-160";
    return h;
}

static if (BOTAN_HAS_TESTS && !SKIP_ECKCDSA_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing eckcdsa.d ...");
    size_t fails = 0;

    {
        const OID oid = OIDS.lookup("ECKCDSA");
        if (oid.toString() != "1.0.14888.3.0.5")
            ++fails;
        if (OIDS.lookup(oid) != "ECKCDSA")
            ++fails;
    }

    File vec = File("test_data/pubkey/eckcdsa.vec", "r");
    fails += runTestsBb(vec, "ECKCDSA Signature", "Signature", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Signature" in m) || !("X" in m) || !("Group" in m))
                return 0;
            auto group = ECGroup(m["Group"]);
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto x = BigInt(m["X"]);
            auto priv = ECKCDSAPrivateKey(*rng, group, x);
            auto msg = hexDecode(m["Msg"]);
            auto nonce = m["Nonce"];
            auto k = BigInt((nonce.length >= 2 && nonce[0] == '0' && (nonce[1] == 'x' || nonce[1] == 'X'))
                            ? nonce : "0x" ~ nonce);
            const string hash = botanHashName(m["Hash"]);
            auto got = eckcdsaSignWithK(priv.domain(), priv.privateValue(), priv.publicPoint(),
                                        hash, msg.ptr, msg.length, k);
            auto exp = hexDecode(m["Signature"]);
            if (got[] != exp[])
                return 1;
            if (!eckcdsaVerify(priv.domain(), priv.publicPoint(), hash,
                               msg.ptr, msg.length, got.ptr, got.length))
                return 1;
            return 0;
        });

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto k = ECKCDSAPrivateKey(*rng, ECGroup("secp256r1"));
        auto signer = PKSigner(k, "Raw");
        ubyte[5] hello = ['h', 'e', 'l', 'l', 'o'];
        auto sig = signer.signMessage(hello.ptr, hello.length, *rng);
        auto verifier = PKVerifier(k, "Raw");
        if (!verifier.verifyMessage(hello.ptr, hello.length, sig.ptr, sig.length))
            ++fails;
        auto bits = SecureVector!ubyte(k.x509SubjectPublicKey()[]);
        Unique!PublicKey via = makePublicKey(k.algorithmIdentifier(), bits);
        if (!via || via.algoName != "ECKCDSA")
            ++fails;
    }

    testReport("eckcdsa", 0, fails);
    assert(fails == 0);
}
