/**
* X448 key agreement (RFC 7748 / RFC 8410)
*
* Copyright:
* (C) 2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.x448;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_X448):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.rng.rng;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import memutils.helpers;
import botan.pubkey.algo.curve448_gf;

enum size_t X448_LEN = 56;

/**
* X448 public key (RFC 7748 / RFC 8410)
*/
struct X448PublicKey
{
public:
    enum algoName = "X448";

    /**
    * Decode X.509 SubjectPublicKeyInfo
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = 56-byte public key (u-coordinate)
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_pub = new X448PublicKeyImpl(alg_id, key_bits);
    }

    /**
    * Params:
    *  pub = 56-byte public key
    */
    this(const ref Vector!ubyte pub)
    {
        m_owned = true;
        m_pub = new X448PublicKeyImpl(pub);
    }

    /// ditto
    this(const ref SecureVector!ubyte pub)
    {
        m_owned = true;
        m_pub = new X448PublicKeyImpl(pub);
    }

    /// Wrap an existing key object (does not take Unique ownership).
    this(PrivateKey pkey) { m_pub = cast(X448PublicKeyImpl) pkey; }
    /// ditto
    this(PublicKey pkey) { m_pub = cast(X448PublicKeyImpl) pkey; }

    mixin Embed!(m_pub, m_owned);
    bool m_owned;
    X448PublicKeyImpl m_pub;
}

/**
* X448 private key (RFC 7748 / RFC 8410)
*/
struct X448PrivateKey
{
public:
    enum algoName = "X448";

    /**
    * Generate a random key
    * Params:
    *  rng = random number generator
    */
    this(RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new X448PrivateKeyImpl(rng);
    }

    /**
    * Params:
    *  secret = 56-byte scalar
    */
    this(const ref SecureVector!ubyte secret)
    {
        m_owned = true;
        m_priv = new X448PrivateKeyImpl(secret);
    }

    /**
    * Decode PKCS #8
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = 56-byte scalar
    *  rng = used for the load-time self-test
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new X448PrivateKeyImpl(alg_id, key_bits, rng);
    }

    /// Wrap an existing key object (does not take Unique ownership).
    this(PrivateKey pkey) { m_priv = cast(X448PrivateKeyImpl) pkey; }

    mixin Embed!(m_priv, m_owned);
    bool m_owned;
    X448PrivateKeyImpl m_priv;
}

class X448PublicKeyImpl : PublicKey
{
public:
    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        if (key_bits.length != X448_LEN)
            throw new DecodingError("Invalid size for X448 public key");
        m_public = unlock(key_bits);
    }

    this(const ref Vector!ubyte pub)
    {
        if (pub.length != X448_LEN)
            throw new DecodingError("Invalid size for X448 public key");
        m_public = pub.clone();
    }

    this(const ref SecureVector!ubyte pub)
    {
        if (pub.length != X448_LEN)
            throw new DecodingError("Invalid size for X448 public key");
        m_public = unlock(pub);
    }

    this() {}

    final override @property string algoName() const { return "X448"; }
    final override size_t maxInputBits() const { return 448; }
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

    override bool checkKey(RandomNumberGenerator, bool) const { return true; }

    override size_t estimatedStrength() const { return 224; }

    Vector!ubyte m_public;
}

final class X448PrivateKeyImpl : X448PublicKeyImpl, PrivateKey, PKKeyAgreementKey
{
public:
    this(RandomNumberGenerator rng)
    {
        super();
        m_private = rng.randomVec(X448_LEN);
        m_public = x448Basepoint(m_private);
        genCheck(rng);
    }

    this(const ref SecureVector!ubyte secret)
    {
        super();
        if (secret.length != X448_LEN)
            throw new DecodingError("Invalid size for X448 private key");
        m_private = secret.clone();
        m_public = x448Basepoint(m_private);
    }

    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        super();
        SecureVector!ubyte bits;
        BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING).discardRemaining();
        if (bits.length != X448_LEN)
            throw new DecodingError("Invalid size for X448 private key");
        m_private = bits.move();
        m_public = x448Basepoint(m_private);
        loadCheck(rng);
    }

    override bool checkKey(RandomNumberGenerator, bool) const
    {
        return x448Basepoint(m_private) == m_public;
    }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder().encode(m_private, ASN1Tag.OCTET_STRING).getContents();
    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const
    {
        return super.algorithmIdentifier();
    }

    override Vector!ubyte publicValue() const { return super.publicValue(); }

    SecureVector!ubyte agree(const(ubyte)* w, size_t w_len) const
    {
        if (w_len != X448_LEN)
            throw new DecodingError("Invalid size for X448 public key");
        auto shared_secret = x448(m_private, w);
        ubyte acc = 0;
        foreach (b; shared_secret[])
            acc |= b;
        if (acc == 0)
            throw new InvalidArgument("X448 public point appears to be of low order");
        return shared_secret.move();
    }

private:
    SecureVector!ubyte m_private;
}

final class X448KAOperation : KeyAgreement
{
public:
    this(in PrivateKey pkey)
    {
        this(cast(X448PrivateKeyImpl) pkey);
    }
    this(in X448PrivateKeyImpl pkey)
    {
        m_key = pkey;
    }
    this(in X448PrivateKey pkey)
    {
        this(pkey.m_priv);
    }

    SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
    {
        return m_key.agree(w, w_len);
    }

private:
    const X448PrivateKeyImpl m_key;
}

void decodeScalar(ref ubyte[X448_LEN] buf, const(ubyte)* secret)
{
    buf[] = secret[0 .. X448_LEN];
    buf[0] &= 0xfc;
    buf[55] |= 0x80;
}

SecureVector!ubyte x448(const ref SecureVector!ubyte secret, const(ubyte)* pubval)
{
    ubyte[X448_LEN] k;
    decodeScalar(k, secret.ptr);
    auto outbuf = SecureVector!ubyte(X448_LEN);
    x448Ladder(outbuf.ptr, k, pubval);
    return outbuf.move();
}

Vector!ubyte x448Basepoint(const ref SecureVector!ubyte secret)
{
    ubyte[X448_LEN] k;
    decodeScalar(k, secret.ptr);
    ubyte[X448_LEN] u = 0;
    u[0] = 5;
    Vector!ubyte ret = Vector!ubyte(X448_LEN);
    x448Ladder(ret.ptr, k, u.ptr);
    return ret.move();
}

/// RFC 7748 §5 Montgomery ladder. `k` is already clamped.
void x448Ladder(ubyte* dest, const ref ubyte[X448_LEN] k, const(ubyte)* u)
{
    const Gf448Elem x1 = Gf448Elem.fromBytes(u[0 .. X448_LEN]);
    Gf448Elem x2 = Gf448Elem.one();
    Gf448Elem z2 = Gf448Elem.zero();
    Gf448Elem x3 = Gf448Elem.fromBytes(u[0 .. X448_LEN]);
    Gf448Elem z3 = Gf448Elem.one();
    ulong swap = 0;

    for (int t = 447; t >= 0; --t)
    {
        const ulong kt = (k[t / 8] >> (t % 8)) & 1;
        const ulong kt_mask = 0UL - kt;
        swap ^= kt_mask;
        x2.ctCondSwap(swap, x3);
        z2.ctCondSwap(swap, z3);
        swap = kt_mask;

        const auto A = x2 + z2;
        const auto AA = square(A);
        const auto B = x2 - z2;
        const auto BB = square(B);
        const auto E = AA - BB;
        const auto C = x3 + z3;
        const auto D = x3 - z3;
        const auto DA = D * A;
        const auto CB = C * B;
        x3 = square(DA + CB);
        z3 = x1 * square(DA - CB);
        x2 = AA * BB;
        z2 = E * (AA + mulA24(E));
    }

    x2.ctCondSwap(swap, x3);
    z2.ctCondSwap(swap, z3);
    const auto res = x2 / z2;
    res.toBytes(dest[0 .. X448_LEN]);
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.pubkey.pk_algs;
import botan.codec.hex;
import botan.libstate.global_state;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t x448ScalarKat(string secret_h, string basepoint_h, string out_h)
{
    atomicOp!"+="(total_tests, 1);
    Vector!ubyte secret = hexDecode(secret_h);
    Vector!ubyte basepoint = hexDecode(basepoint_h);
    Vector!ubyte output = hexDecode(out_h);
    if (secret.length != X448_LEN || basepoint.length != X448_LEN)
        return 1;
    ubyte[X448_LEN] k;
    decodeScalar(k, secret.ptr);
    auto got = Vector!ubyte(X448_LEN);
    x448Ladder(got.ptr, k, basepoint.ptr);
    if (got != output)
        return 1;
    return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_X448_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing x448.d ...");
    size_t fails = 0;

    {
        const OID oid = OIDS.lookup("X448");
        if (oid.toString() != "1.3.101.111")
            ++fails;
        if (OIDS.lookup(oid) != "X448")
            ++fails;
    }

    File vec = File("test_data/pubkey/x448.vec", "r");
    fails += runTestsBb(vec, "X448", "K", true,
        (ref HashMap!(string, string) m) {
            return x448ScalarKat(m["Secret"], m["CounterKey"], m["K"]);
        });

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto a = X448PrivateKey(*rng);
        auto b = X448PrivateKey(*rng);
        auto a_ka = scoped!PKKeyAgreement(a, "KDF2(SHA-256)");
        auto b_ka = scoped!PKKeyAgreement(b, "KDF2(SHA-256)");
        auto a_key = a_ka.deriveKey(32, b.publicValue());
        auto b_key = b_ka.deriveKey(32, a.publicValue());
        if (a_key != b_key)
            ++fails;

        auto bits = a.pkcs8PrivateKey();
        auto loaded = X448PrivateKey(a.algorithmIdentifier(), bits, *rng);
        if (loaded.publicValue() != a.publicValue())
            ++fails;
        auto pub_bits = SecureVector!ubyte(a.publicValue()[]);
        Unique!PublicKey via_factory = makePublicKey(a.algorithmIdentifier(), pub_bits);
        if (!via_factory || via_factory.algoName != "X448")
            ++fails;
    }

    testReport("x448", total_tests, fails);
    assert(fails == 0);
}
