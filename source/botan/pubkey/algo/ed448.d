/**
* Ed448 signatures (RFC 8032 / RFC 8410). Pure + Ed448ph (SHAKE-256(512)).
*
* Copyright:
* (C) 2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ed448;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ED448):

static assert(BOTAN_HAS_SHAKE_XOF, "Ed448 requires SHAKE_XOF");

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
import botan.xof.xof;
import botan.libstate.lookup;
import botan.pubkey.algo.curve448_gf;
import botan.pubkey.algo.curve448_scalar;

enum size_t ED448_LEN = 57;

struct Ed448PublicKey
{
public:
    enum algoName = "Ed448";

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_owned = true;
        m_pub = new Ed448PublicKeyImpl(alg_id, key_bits);
    }

    this(const ref Vector!ubyte pub)
    {
        m_owned = true;
        m_pub = new Ed448PublicKeyImpl(pub);
    }

    this(PrivateKey pkey) { m_pub = cast(Ed448PublicKeyImpl) pkey; }
    this(PublicKey pkey) { m_pub = cast(Ed448PublicKeyImpl) pkey; }

    mixin Embed!(m_pub, m_owned);
    bool m_owned;
    Ed448PublicKeyImpl m_pub;
}

struct Ed448PrivateKey
{
public:
    enum algoName = "Ed448";

    this(RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new Ed448PrivateKeyImpl(rng);
    }

    this(const ref SecureVector!ubyte seed)
    {
        m_owned = true;
        m_priv = new Ed448PrivateKeyImpl(seed);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        m_owned = true;
        m_priv = new Ed448PrivateKeyImpl(alg_id, key_bits, rng);
    }

    this(PrivateKey pkey) { m_priv = cast(Ed448PrivateKeyImpl) pkey; }

    mixin Embed!(m_priv, m_owned);
    bool m_owned;
    Ed448PrivateKeyImpl m_priv;
}

class Ed448PublicKeyImpl : PublicKey
{
public:
    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        if (key_bits.length != ED448_LEN)
            throw new DecodingError("Invalid length for Ed448 public key");
        m_public = unlock(key_bits);
    }

    this(const ref Vector!ubyte pub)
    {
        if (pub.length != ED448_LEN)
            throw new DecodingError("Invalid length for Ed448 public key");
        m_public = pub.clone();
    }

    this() {}

    final override @property string algoName() const { return "Ed448"; }
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
        if (m_public.length != ED448_LEN)
            return false;
        try
        {
            ubyte[ED448_LEN] enc;
            enc[] = m_public[];
            Ed448Point.decode(enc);
            return true;
        }
        catch (DecodingError)
        {
            return false;
        }
    }

    override size_t estimatedStrength() const { return 224; }

    Vector!ubyte m_public;
}

final class Ed448PrivateKeyImpl : Ed448PublicKeyImpl, PrivateKey
{
public:
    this(RandomNumberGenerator rng)
    {
        super();
        auto seed = rng.randomVec(ED448_LEN);
        expandSeed(seed);
        genCheck(rng);
    }

    this(const ref SecureVector!ubyte seed)
    {
        super();
        if (seed.length != ED448_LEN)
            throw new DecodingError("Ed448 seed must be 57 bytes");
        expandSeed(seed);
    }

    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng)
    {
        super();
        SecureVector!ubyte bits;
        BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING).discardRemaining();
        if (bits.length != ED448_LEN)
            throw new DecodingError("Invalid size for Ed448 private key");
        expandSeed(bits);
        loadCheck(rng);
    }

    override bool checkKey(RandomNumberGenerator, bool) const
    {
        ubyte[ED448_LEN] pk;
        createPkFromSk(pk, m_private.ptr);
        return pk[] == m_public[];
    }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        SecureVector!ubyte bits = SecureVector!ubyte(m_private.ptr[0 .. ED448_LEN]);
        return DEREncoder().encode(bits, ASN1Tag.OCTET_STRING).getContents();
    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const
    {
        return super.algorithmIdentifier();
    }

    const(ubyte)* seedPtr() const { return m_private.ptr; }

private:
    void expandSeed(const ref SecureVector!ubyte seed)
    {
        ubyte[ED448_LEN] pk;
        m_private = seed.clone();
        createPkFromSk(pk, m_private.ptr);
        m_public = Vector!ubyte(pk[]);
    }

    SecureVector!ubyte m_private;
}

bool ed448IsPureParams(in string params)
{
    return params.length == 0 || params == "Raw" || params == "Identity" ||
           params == "Pure" || params == "Ed448";
}

bool ed448IsPhParams(in string params)
{
    return params == "Ed448ph" || params == "SHAKE-256(512)";
}

Signature ed448TrySignatureOp(in PrivateKey key, in string params)
{
    if (key.algoName != "Ed448" || ed448IsPureParams(params))
        return null;
    return new Ed448SignatureOperation(key, params);
}

Verification ed448TryVerificationOp(in PublicKey key, in string params)
{
    if (key.algoName != "Ed448" || ed448IsPureParams(params))
        return null;
    return new Ed448VerificationOperation(key, params);
}

void ed448Prehash(const(ubyte)* msg, size_t msg_len, ref ubyte[64] ph)
{
    Unique!XOF x = getXof("SHAKE-256");
    if (msg_len)
        x.update(msg, msg_len);
    x.output(ph[]);
}

void ed448SignParams(ubyte* sig, const(ubyte)* msg, size_t msg_len,
                     const(ubyte)* sk, const(ubyte)* pk, in string params)
{
    if (ed448IsPureParams(params))
    {
        ed448Sign(sig, msg, msg_len, sk, pk, false);
        return;
    }
    if (!ed448IsPhParams(params))
        throw new InvalidArgument("Unknown Ed448 signature params: " ~ params);
    ubyte[64] ph;
    ed448Prehash(msg, msg_len, ph);
    ed448Sign(sig, ph.ptr, ph.length, sk, pk, true);
}

bool ed448VerifyParams(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig,
                       const(ubyte)* pk, in string params)
{
    if (ed448IsPureParams(params))
        return ed448Verify(msg, msg_len, sig, pk, false);
    if (!ed448IsPhParams(params))
        return false;
    ubyte[64] ph;
    ed448Prehash(msg, msg_len, ph);
    return ed448Verify(ph.ptr, ph.length, sig, pk, true);
}

final class Ed448SignatureOperation : Signature
{
public:
    this(in PrivateKey pkey)
    {
        this(pkey, "Pure");
    }

    this(in PrivateKey pkey, in string params)
    {
        m_key = cast(Ed448PrivateKeyImpl) pkey;
        m_params = params.idup;
    }

    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        auto sig = SecureVector!ubyte(2 * ED448_LEN);
        ed448SignParams(sig.ptr, msg, msg_len, m_key.seedPtr(), m_key.m_public.ptr, m_params);
        return sig.move;
    }

private:
    const Ed448PrivateKeyImpl m_key;
    string m_params;
}

final class Ed448VerificationOperation : Verification
{
public:
    this(in PublicKey pkey)
    {
        this(pkey, "Pure");
    }

    this(in PublicKey pkey, in string params)
    {
        m_key = cast(Ed448PublicKeyImpl) pkey;
        m_params = params.idup;
    }

    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }

    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        if (sig_len != 2 * ED448_LEN)
            return false;
        try
        {
            return ed448VerifyParams(msg, msg_len, sig, m_key.m_public.ptr, m_params);
        }
        catch (DecodingError)
        {
            return false;
        }
    }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("Ed448 has no message recovery");
    }

private:
    const Ed448PublicKeyImpl m_key;
    string m_params;
}

struct Ed448Point
{
public:
    this(Gf448Elem x, Gf448Elem y, Gf448Elem z)
    {
        m_x = x;
        m_y = y;
        m_z = z;
    }

    this(Gf448Elem x, Gf448Elem y)
    {
        m_x = x;
        m_y = y;
        m_z = Gf448Elem.one();
    }

    static Ed448Point identity()
    {
        return Ed448Point(Gf448Elem.zero(), Gf448Elem.one());
    }

    static Ed448Point basePoint()
    {
        static immutable ulong[WORDS_448] bx = [
            0x2626a82bc70cc05eUL,
            0x433b80e18b00938eUL,
            0x12ae1af72ab66511UL,
            0xea6de324a3d3a464UL,
            0x9e146570470f1767UL,
            0x221d15a622bf36daUL,
            0x4f1970c66bed0dedUL
        ];
        static immutable ulong[WORDS_448] by = [
            0x9808795bf230fa14UL,
            0xfdbd132c4ed7c8adUL,
            0x3ad3ff1ce67c39c4UL,
            0x87789c1e05a0c2d7UL,
            0x4bea73736ca39840UL,
            0x8876203756c9c762UL,
            0x693f46716eb6bc24UL
        ];
        ulong[WORDS_448] xw = bx;
        ulong[WORDS_448] yw = by;
        return Ed448Point(Gf448Elem(xw), Gf448Elem(yw));
    }

    static Ed448Point decode(const ref ubyte[ED448_LEN] enc)
    {
        if ((enc[ED448_LEN - 1] & 0x7F) != 0)
            throw new DecodingError("Ed448 point has unacceptable x-distinguisher");
        ubyte[ED448_LEN] identity_element = 0;
        identity_element[0] = 1;
        ubyte same = 0;
        foreach (i; 0 .. ED448_LEN)
            same |= enc[i] ^ identity_element[i];
        if (same == 0)
            throw new DecodingError("Ed448 point is the identity element");

        const bool x_distinguisher = enc[ED448_LEN - 1] != 0;
        if (!Gf448Elem.bytesAreCanonical(enc[0 .. 56]))
            throw new DecodingError("Ed448 y-coordinate is not smaller than p");
        const auto y = Gf448Elem.fromBytes(enc[0 .. 56]);

        const auto u = square(y) - Gf448Elem.one();
        const auto v = -mulA24(square(y)) - Gf448Elem.one();
        const auto maybe_x = (u * square(u)) * v * root((square(square(u)) * u) * square(v) * v);

        if (v * square(maybe_x) != u)
            throw new DecodingError("Ed448 square root does not exist");
        if (maybe_x.isZero() && x_distinguisher)
            throw new DecodingError("Ed448 square root of zero cannot be odd");

        const bool maybe_x_parity = maybe_x.isOdd();
        Gf448Elem x = maybe_x;
        if (maybe_x_parity != x_distinguisher)
            x = -maybe_x;
        return Ed448Point(x, y);
    }

    ubyte[ED448_LEN] encode() const
    {
        ubyte[ED448_LEN] res = 0;
        y().toBytes(res[0 .. 56]);
        res[ED448_LEN - 1] = cast(ubyte)(x().isOdd() ? 0x80 : 0);
        return res;
    }

    Ed448Point opBinary(string op)(Ed448Point other) const
        if (op == "+")
    {
        const Gf448Elem A = m_z * other.m_z;
        const Gf448Elem B = square(A);
        const Gf448Elem C = m_x * other.m_x;
        const Gf448Elem D = m_y * other.m_y;
        const Gf448Elem E = -mulA24(C * D);
        const Gf448Elem F = B - E;
        const Gf448Elem G = B + E;
        const Gf448Elem H = (m_x + m_y) * (other.m_x + other.m_y);
        const Gf448Elem X3 = A * F * (H - C - D);
        const Gf448Elem Y3 = A * G * (D - C);
        const Gf448Elem Z3 = F * G;
        return Ed448Point(X3, Y3, Z3);
    }

    Ed448Point doublePoint() const
    {
        const Gf448Elem B = square(m_x + m_y);
        const Gf448Elem C = square(m_x);
        const Gf448Elem D = square(m_y);
        const Gf448Elem E = C + D;
        const Gf448Elem H = square(m_z);
        const Gf448Elem J = E - (H + H);
        const Gf448Elem X3 = (B - E) * J;
        const Gf448Elem Y3 = E * (C - D);
        const Gf448Elem Z3 = E * J;
        return Ed448Point(X3, Y3, Z3);
    }

    Ed448Point scalarMul(Scalar448 s) const
    {
        Ed448Point[16] table;
        table[0] = Ed448Point.identity();
        table[1] = this;
        foreach (i; 2 .. 16)
        {
            if ((i & 1) == 0)
                table[i] = table[i / 2].doublePoint();
            else
                table[i] = table[i - 1] + this;
        }

        auto res = Ed448Point.identity();
        for (int window = 111; window >= 0; --window)
        {
            res = res.doublePoint();
            res = res.doublePoint();
            res = res.doublePoint();
            res = res.doublePoint();
            const ulong w = s.getWindow(cast(size_t) window * 4, 4);
            auto selected = Ed448Point.identity();
            foreach (i; 0 .. 16)
            {
                const ulong mask = 0UL - cast(ulong)(i == w);
                selected.ctCondAssign(mask, table[i]);
            }
            res = res + selected;
        }
        return res;
    }

    static Ed448Point basePointMul(Scalar448 scalar)
    {
        return Ed448Point.basePoint().scalarMul(scalar);
    }

    static Ed448Point doubleScalarMulVartime(Scalar448 s1,
                                             Ed448Point p1,
                                             Scalar448 s2,
                                             Ed448Point p2)
    {
        const auto p1x2 = p1.doublePoint();
        const auto p1x3 = p1x2 + p1;
        const auto p2x2 = p2.doublePoint();
        const auto p2x3 = p2x2 + p2;
        Ed448Point[15] table = [
            p1,
            p1x2,
            p1x3,
            p2,
            p1 + p2,
            p1x2 + p2,
            p1x3 + p2,
            p2x2,
            p1 + p2x2,
            p1x2 + p2x2,
            p1x3 + p2x2,
            p2x3,
            p1 + p2x3,
            p1x2 + p2x3,
            p1x3 + p2x3
        ];

        auto res = Ed448Point.identity();
        for (int window = 222; window >= 0; --window)
        {
            res = res.doublePoint();
            res = res.doublePoint();
            const size_t bit_pos = cast(size_t) window * 2;
            const size_t idx = s1.getWindow(bit_pos, 2) | (s2.getWindow(bit_pos, 2) << 2);
            if (idx > 0)
                res = res + table[idx - 1];
        }
        return res;
    }

    Ed448Point negate() const
    {
        return Ed448Point(-m_x, m_y, m_z);
    }

    Gf448Elem x() const { return m_x / m_z; }
    Gf448Elem y() const { return m_y / m_z; }

    bool opEquals(Ed448Point other) const
    {
        const auto lhs_x = m_x * other.m_z;
        const auto rhs_x = other.m_x * m_z;
        const auto lhs_y = m_y * other.m_z;
        const auto rhs_y = other.m_y * m_z;
        return lhs_x == rhs_x && lhs_y == rhs_y;
    }

    void ctCondAssign(ulong mask, Ed448Point other)
    {
        m_x.ctCondAssign(mask, other.m_x);
        m_y.ctCondAssign(mask, other.m_y);
        m_z.ctCondAssign(mask, other.m_z);
    }

private:
    Gf448Elem m_x;
    Gf448Elem m_y;
    Gf448Elem m_z;
}

void createPkFromSk(ref ubyte[ED448_LEN] pk, const(ubyte)* sk)
{
    Unique!XOF xof = getXof("SHAKE-256");
    xof.update(sk, ED448_LEN);
    const Scalar448 s = scalarFromXof(*xof);
    pk = Ed448Point.basePointMul(s).encode();
}

void ed448Sign(ubyte* sig, const(ubyte)* msg, size_t msg_len,
               const(ubyte)* sk, const(ubyte)* pk, bool ph = false)
{
    Unique!XOF xof = getXof("SHAKE-256");
    xof.update(sk, ED448_LEN);
    const Scalar448 s = scalarFromXof(*xof);
    ubyte[ED448_LEN] prefix;
    xof.output(prefix[]);

    ubyte[114] r_bytes;
    shakeDom(ph, null, [prefix[], msg[0 .. msg_len]], r_bytes[]);
    const Scalar448 r = Scalar448(r_bytes[]);
    const auto big_r = Ed448Point.basePointMul(r).encode();

    ubyte[114] k_bytes;
    shakeDom(ph, null, [big_r[], pk[0 .. ED448_LEN], msg[0 .. msg_len]], k_bytes[]);
    const Scalar448 k = Scalar448(k_bytes[]);
    const auto big_s = r + k * s;
    sig[0 .. ED448_LEN] = big_r[];
    big_s.toBytes(sig[ED448_LEN .. 2 * ED448_LEN]);
}

bool ed448Verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, const(ubyte)* pk, bool ph = false)
{
    ubyte[ED448_LEN] r_enc;
    ubyte[ED448_LEN] s_enc;
    r_enc[] = sig[0 .. ED448_LEN];
    s_enc[] = sig[ED448_LEN .. 2 * ED448_LEN];
    const auto big_r = Ed448Point.decode(r_enc);
    if (!Scalar448.bytesAreReduced(s_enc[]))
        throw new DecodingError("Ed448 signature has invalid S");
    const Scalar448 big_s = Scalar448(s_enc[]);

    ubyte[114] k_bytes;
    shakeDom(ph, null, [r_enc[], pk[0 .. ED448_LEN], msg[0 .. msg_len]], k_bytes[]);
    const Scalar448 k = Scalar448(k_bytes[]);

    ubyte[ED448_LEN] pk_enc;
    pk_enc[] = pk[0 .. ED448_LEN];
    const auto neg_A = Ed448Point.decode(pk_enc).negate();
    return Ed448Point.doubleScalarMulVartime(big_s, Ed448Point.basePoint(), k, neg_A) == big_r;
}

private:

Scalar448 scalarFromXof(XOF xof)
{
    ubyte[ED448_LEN] raw_s;
    xof.output(raw_s[]);
    raw_s[0] &= 0xFC;
    raw_s[55] |= 0x80;
    raw_s[56] = 0;
    return Scalar448(raw_s[]);
}

void shakeDom(bool f, const(ubyte)[] context, const(ubyte)[][] parts, ubyte[] dest)
{
    if (context.length >= 256)
        throw new InvalidArgument("Ed448 context is too long");
    Unique!XOF xof = getXof("SHAKE-256");
    immutable ubyte[8] tag = ['S', 'i', 'g', 'E', 'd', '4', '4', '8'];
    xof.update(tag[]);
    ubyte fx = f ? 1 : 0;
    xof.update(&fx, 1);
    ubyte clen = cast(ubyte) context.length;
    xof.update(&clen, 1);
    if (context.length)
        xof.update(context);
    foreach (p; parts)
    {
        if (p.length)
            xof.update(p);
    }
    xof.output(dest);
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.global_state;
import botan.pubkey.pubkey;
import botan.pubkey.pk_algs;
import botan.asn1.oids;
import botan.rng.auto_rng;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_ED448_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing ed448.d ...");

    size_t extra = 0;
    {
        const OID oid = OIDS.lookup("Ed448");
        if (oid.toString() != "1.3.101.113")
            ++extra;
        if (OIDS.lookup(oid) != "Ed448")
            ++extra;
    }

    File vec = File("test_data/pubkey/ed448.vec", "r");
    size_t fails = runTestsBb(vec, "Algo", "Signature", true,
        (ref HashMap!(string, string) m)
        {
            const string algo = m["Algo"];
            if (!ed448IsPureParams(algo) && !ed448IsPhParams(algo))
                return 0;

            bool expect = true;
            if (auto vp = "Valid" in m)
                expect = (*vp) != "0";

            if (!("PublicKey" in m) || !("Signature" in m))
                return 0;

            auto pub = hexDecode(m["PublicKey"]);
            Vector!ubyte msg;
            if (auto mp = "Msg" in m)
            {
                if ((*mp).length)
                    msg = hexDecode(*mp);
            }
            auto sig = hexDecode(m["Signature"]);

            if (expect)
            {
                if (!("PrivateKey" in m))
                    return 1;
                auto seed = hexDecodeLocked(m["PrivateKey"]);
                if (seed.length != ED448_LEN || pub.length != ED448_LEN || sig.length != 2 * ED448_LEN)
                    return 1;
                auto priv = Ed448PrivateKey(seed);
                if (priv.publicValue() != pub)
                    return 1;
                ubyte[2 * ED448_LEN] raw_sig;
                ed448SignParams(raw_sig.ptr, msg.ptr, msg.length, priv.seedPtr(), pub.ptr, algo);
                if (raw_sig[] != sig[])
                    return 1;
                if (!ed448VerifyParams(msg.ptr, msg.length, raw_sig.ptr, pub.ptr, algo))
                    return 1;
                return 0;
            }

            if (sig.length != 2 * ED448_LEN || pub.length != ED448_LEN)
                return 0;
            bool ok = false;
            try
            {
                ok = ed448VerifyParams(msg.ptr, msg.length, sig.ptr, pub.ptr, algo);
            }
            catch (Exception)
            {
                ok = false;
            }
            return ok ? 1 : 0;
        });

    {
        Unique!AutoSeededRNG arng = new AutoSeededRNG;
        auto k = Ed448PrivateKey(*arng);
        auto signer = PKSigner(k, "Raw");
        ubyte[5] hello = ['h', 'e', 'l', 'l', 'o'];
        auto sig = signer.signMessage(hello.ptr, hello.length, *arng);
        auto verifier = PKVerifier(k, "Raw");
        if (!verifier.verifyMessage(hello.ptr, hello.length, sig.ptr, sig.length))
            ++extra;

        auto signer_ph = PKSigner(k, "Ed448ph");
        auto sig_ph = signer_ph.signMessage(hello.ptr, hello.length, *arng);
        auto verifier_ph = PKVerifier(k, "Ed448ph");
        if (!verifier_ph.verifyMessage(hello.ptr, hello.length, sig_ph.ptr, sig_ph.length))
            ++extra;
        if (verifier.verifyMessage(hello.ptr, hello.length, sig_ph.ptr, sig_ph.length))
            ++extra;

        auto bits = k.pkcs8PrivateKey();
        auto loaded = Ed448PrivateKey(k.algorithmIdentifier(), bits, *arng);
        if (loaded.publicValue() != k.publicValue())
            ++extra;
        auto pub_bits = SecureVector!ubyte(k.publicValue()[]);
        Unique!PublicKey via_factory = makePublicKey(k.algorithmIdentifier(), pub_bits);
        if (!via_factory || via_factory.algoName != "Ed448")
            ++extra;
    }

    fails += extra;
    testReport("ed448", 0, fails);
    assert(fails == 0);
}
