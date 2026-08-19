/**
* ECGDSA (BSI TR-03111)
*
* Copyright:
* (C) 2016 René Korthaus
* (C) 2018,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ecgdsa;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECGDSA):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.pubkey.algo.keypair;
import botan.pubkey.pk_ops;
import botan.math.ec_gfp.point_gfp;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;
import botan.math.bigint.bigint;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;
import memutils.helpers : Embed;

struct ECGDSAOptions
{
    enum algoName = "ECGDSA";
    enum msgParts = 2;

    static bool checkKey(in ECPrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.publicPoint().onTheCurve())
            return false;
        if (!strong)
            return true;
        return signatureConsistencyCheck(rng, privkey, "EMSA1(SHA-256)");
    }
}

/**
* ECGDSA public key (ISO 14888-3)
*/
struct ECGDSAPublicKey
{
public:
    alias Options = ECGDSAOptions;
    __gshared immutable string algoName = Options.algoName;

    /**
    * Params:
    *  dom_par = curve domain
    *  public_point = public point
    */
    this(in ECGroup dom_par, in PointGFp public_point)
    {
        m_owned = true;
        m_pub = new ECPublicKey(Options(), dom_par, public_point);
    }

    /**
    * Decode X.509 SubjectPublicKeyInfo
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = encoded point
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_pub = new ECPublicKey(Options(), alg_id, key_bits);
    }

    /// Wrap an existing key object (does not take Unique ownership).
    this(in PublicKey pkey) { m_pub = cast(ECPublicKey) pkey; }
    /// ditto
    this(in PrivateKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    mixin Embed!(m_pub, m_owned);
    bool m_owned;
    ECPublicKey m_pub;
}

/**
* ECGDSA private key (ISO 14888-3)
*/
struct ECGDSAPrivateKey
{
public:
    alias Options = ECGDSAOptions;
    __gshared immutable string algoName = Options.algoName;

    /**
    * Decode PKCS #8
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = encoded scalar
    */
    this(const ref AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits, true);
    }

    /**
    * Generate a random key
    * Params:
    *  rng = random number generator
    *  domain = curve domain
    */
    this()(RandomNumberGenerator rng, const auto ref ECGroup domain)
    {
        m_owned = true;
        auto zero = BigInt(0);
        m_priv = new ECPrivateKey(Options(), rng, domain, zero, true);
    }

    /**
    * Params:
    *  rng = random number generator
    *  domain = curve domain
    *  x = private scalar
    */
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

BigInt ecgdsaFromBytesTrunc(const(ubyte)* msg, size_t msg_len, const ref BigInt n)
{
    ModularReducer mod_n = ModularReducer(n);
    const size_t order_bits = n.bits();
    const size_t bit_length = 8 * msg_len;
    if (bit_length < order_bits)
        return mod_n.reduce(BigInt(msg, msg_len));

    const size_t shift = bit_length - order_bits;
    const size_t new_length = msg_len - (shift / 8);
    const size_t bit_shift = shift % 8;
    if (bit_shift == 0)
        return mod_n.reduce(BigInt(msg, new_length));

    auto sbytes = Vector!ubyte(new_length);
    ubyte carry = 0;
    foreach (i; 0 .. new_length)
    {
        const ubyte w = msg[i];
        sbytes[i] = cast(ubyte)((w >> bit_shift) | carry);
        carry = cast(ubyte)(w << (8 - bit_shift));
    }
    return mod_n.reduce(BigInt(sbytes.ptr, new_length));
}

SecureVector!ubyte ecgdsaSignWithK(const ref ECGroup group, const ref BigInt x,
                                   const(ubyte)* msg, size_t msg_len, const ref BigInt k)
{
    ModularReducer mod_n = ModularReducer(group.getOrder());
    auto m = ecgdsaFromBytesTrunc(msg, msg_len, group.getOrder());
    PointGFp kG = group.getBasePoint() * &k;
    auto kx = kG.getAffineX();
    BigInt r = mod_n.reduce(kx.move());
    BigInt kr = mod_n.multiply(&k, &r);
    BigInt krm = kr.move();
    krm -= m;
    krm = mod_n.reduce(krm.move());
    BigInt s = mod_n.multiply(&x, &krm);
    if (r == 0 || s == 0)
        throw new InternalError("During ECGDSA signature generated zero r/s");

    const size_t olen = group.getOrder().bytes();
    auto output = SecureVector!ubyte(2 * olen);
    r.binaryEncode(&output[olen - r.bytes()]);
    s.binaryEncode(&output[2 * olen - s.bytes()]);
    return output.move();
}

bool ecgdsaVerify(const ref ECGroup group, const ref PointGFp pub,
                  const(ubyte)* msg, size_t msg_len,
                  const(ubyte)* sig, size_t sig_len)
{
    const size_t olen = group.getOrder().bytes();
    if (sig_len != 2 * olen)
        return false;
    BigInt r = BigInt(sig, olen);
    BigInt s = BigInt(sig + olen, olen);
    const BigInt* n = &group.getOrder();
    if (r <= 0 || r >= *n || s <= 0 || s >= *n)
        return false;

    ModularReducer mod_n = ModularReducer(*n);
    auto m = ecgdsaFromBytesTrunc(msg, msg_len, *n);
    BigInt w = inverseMod(&r, n);
    BigInt wm = mod_n.multiply(&w, &m);
    BigInt ws = mod_n.multiply(&w, &s);
    PointGFp R = PointGFp.multiExponentiate(group.getBasePoint(), &wm, pub, &ws);
    if (R.isZero())
        return false;
    return mod_n.reduce(R.getAffineX()) == r;
}

final class ECGDSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { this(cast(ECPrivateKey) pkey); }
    this(in ECGDSAPrivateKey pkey) { this(pkey.m_priv); }
    this(in ECPrivateKey key)
    {
        assert(key.algoName == ECGDSAPublicKey.algoName);
        m_key = key;
        m_order = &m_key.domain().getOrder();
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        BigInt k;
        do
        {
            k.randomize(rng, m_order.bits());
        } while (k == 0 || k >= *m_order);
        return ecgdsaSignWithK(m_key.domain(), m_key.privateValue(), msg, msg_len, k);
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

private:
    const ECPrivateKey m_key;
    const BigInt* m_order;
}

final class ECGDSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { this(cast(ECPublicKey) pkey); }
    this(in ECGDSAPublicKey pkey) { this(pkey.m_pub); }
    this(in ECPublicKey key)
    {
        assert(key.algoName == ECGDSAPublicKey.algoName);
        m_key = key;
        m_order = &m_key.domain().getOrder();
    }

    override size_t maxInputBits() const { return m_order.bits(); }
    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override bool withRecovery() const { return false; }

    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return ecgdsaVerify(m_key.domain(), m_key.publicPoint(), msg, msg_len, sig, sig_len);
    }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("ECGDSA has no message recovery");
    }

private:
    const ECPublicKey m_key;
    const BigInt* m_order;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import botan.hash.hash;
import botan.libstate.lookup;
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

static if (BOTAN_HAS_TESTS && !SKIP_ECGDSA_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing ecgdsa.d ...");
    size_t fails = 0;

    {
        const OID oid = OIDS.lookup("ECGDSA");
        if (oid.toString() != "1.3.36.3.3.2.5.2.1")
            ++fails;
        if (OIDS.lookup(oid) != "ECGDSA")
            ++fails;
    }

    File vec = File("test_data/pubkey/ecgdsa.vec", "r");
    fails += runTestsBb(vec, "ECGDSA Signature", "Signature", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Signature" in m) || !("X" in m) || !("Group" in m))
                return 0;
            auto group = ECGroup(m["Group"]);
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto x = BigInt(m["X"]);
            auto priv = ECGDSAPrivateKey(*rng, group, x);
            Unique!HashFunction hash = retrieveHash(botanHashName(m["Hash"])).clone();
            auto msg = hexDecode(m["Msg"]);
            hash.update(msg);
            auto digest = hash.finished();
            auto nonce = m["Nonce"];
            auto k = BigInt((nonce.length >= 2 && nonce[0] == '0' && (nonce[1] == 'x' || nonce[1] == 'X'))
                            ? nonce : "0x" ~ nonce);
            auto got = ecgdsaSignWithK(priv.domain(), priv.privateValue(),
                                       digest.ptr, digest.length, k);
            auto exp = hexDecode(m["Signature"]);
            if (got[] != exp[])
                return 1;
            if (!ecgdsaVerify(priv.domain(), priv.publicPoint(),
                              digest.ptr, digest.length, got.ptr, got.length))
                return 1;
            return 0;
        });

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto k = ECGDSAPrivateKey(*rng, ECGroup("secp256r1"));
        auto signer = PKSigner(k, "EMSA1(SHA-256)");
        ubyte[5] hello = ['h', 'e', 'l', 'l', 'o'];
        auto sig = signer.signMessage(hello.ptr, hello.length, *rng);
        auto verifier = PKVerifier(k, "EMSA1(SHA-256)");
        if (!verifier.verifyMessage(hello.ptr, hello.length, sig.ptr, sig.length))
            ++fails;
        auto bits = SecureVector!ubyte(k.x509SubjectPublicKey()[]);
        Unique!PublicKey via = makePublicKey(k.algorithmIdentifier(), bits);
        if (!via || via.algoName != "ECGDSA")
            ++fails;
    }

    testReport("ecgdsa", 0, fails);
    assert(fails == 0);
}
