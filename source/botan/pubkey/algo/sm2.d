/**
* SM2 signatures and encryption (GB/T 32918)
*
* Copyright:
* (C) 2017,2018 Ribose Inc
* (C) 2018,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.sm2;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_SM2):

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
import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.get_byte;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import memutils.helpers : Embed;

struct SM2Options
{
    enum algoName = "SM2";
    enum msgParts = 1;

    static bool checkKey(in ECPrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.publicPoint().onTheCurve())
            return false;
        if (privkey.privateValue() >= privkey.domain().getOrder() - 1)
            return false;
        if (!strong)
            return true;
        return signatureConsistencyCheck(rng, privkey, "Raw");
    }
}

/**
* SM2 public key (GB/T 32918)
*/
struct SM2PublicKey
{
public:
    alias Options = SM2Options;
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
    *  alg_id = algorithm identifier (includes the curve OID)
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
* SM2 private key (GB/T 32918). Private scalar must be in 1 .. n-2.
*/
struct SM2PrivateKey
{
public:
    alias Options = SM2Options;
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
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits);
        if (m_priv.privateValue() >= m_priv.domain().getOrder() - 1)
            throw new DecodingError("SM2 private key cannot equal n-1");
    }

    /**
    * Generate a random key (retries if x == n-1)
    * Params:
    *  rng = random number generator
    *  domain = curve domain
    */
    this()(RandomNumberGenerator rng, const auto ref ECGroup domain)
    {
        m_owned = true;
        auto zero = BigInt(0);
        for (;;)
        {
            m_priv = new ECPrivateKey(Options(), rng, domain, zero);
            if (m_priv.privateValue() < domain.getOrder() - 1)
                break;
        }
    }

    /**
    * Params:
    *  rng = random number generator
    *  domain = curve domain
    *  x = private scalar (must be < n-1)
    */
    this()(RandomNumberGenerator rng, const auto ref ECGroup domain, const auto ref BigInt x)
    {
        m_owned = true;
        if (x >= domain.getOrder() - 1)
            throw new InvalidArgument("SM2 private key cannot equal n-1");
        m_priv = new ECPrivateKey(Options(), rng, domain, x);
    }

    this(in PrivateKey pkey) { m_priv = cast(ECPrivateKey) pkey; }

    mixin Embed!(m_priv, m_owned);
    bool m_owned;
    ECPrivateKey m_priv;
}

Vector!ubyte sm2ComputeZa(in string hash_name, in string user_id,
                          const ref ECGroup group, const ref PointGFp pubkey)
{
    if (user_id.length >= 8192)
        throw new InvalidArgument("SM2 user id too long to represent");

    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    const ushort uid_len = cast(ushort)(8 * user_id.length);
    ubyte[2] entla;
    entla[0] = get_byte(0, uid_len);
    entla[1] = get_byte(1, uid_len);
    hash.update(entla.ptr, 2);
    if (user_id.length)
        hash.update(cast(const(ubyte)*) user_id.ptr, user_id.length);

    const size_t p_bytes = group.getCurve().getP().bytes();
    void putInt(const(BigInt)* v)
    {
        auto enc = BigInt.encode1363(v, p_bytes);
        hash.update(enc.ptr, enc.length);
    }
    putInt(&group.getCurve().getA());
    putInt(&group.getCurve().getB());
    auto gx = group.getBasePoint().getAffineX();
    auto gy = group.getBasePoint().getAffineY();
    auto px = pubkey.getAffineX();
    auto py = pubkey.getAffineY();
    putInt(&gx);
    putInt(&gy);
    putInt(&px);
    putInt(&py);
    return unlock(hash.finished());
}

BigInt sm2MessageHash(in string hash_name, in string user_id,
                      const ref ECGroup group, const ref PointGFp pubkey,
                      const(ubyte)* msg, size_t msg_len)
{
    ModularReducer mod_n = ModularReducer(group.getOrder());
    if (hash_name == "Raw")
        return mod_n.reduce(BigInt(msg, msg_len));

    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    auto za = sm2ComputeZa(hash_name, user_id, group, pubkey);
    hash.update(za.ptr, za.length);
    if (msg_len)
        hash.update(msg, msg_len);
    auto digest = hash.finished();
    return mod_n.reduce(BigInt(digest.ptr, digest.length));
}

SecureVector!ubyte sm2SignWithK(const ref ECGroup group, const ref BigInt x,
                                const ref PointGFp pub, in string user_id, in string hash_name,
                                const(ubyte)* msg, size_t msg_len, const ref BigInt k)
{
    auto e = sm2MessageHash(hash_name, user_id, group, pub, msg, msg_len);
    ModularReducer mod_n = ModularReducer(group.getOrder());
    PointGFp kG = group.getBasePoint() * &k;
    auto kx = kG.getAffineX();
    BigInt r = mod_n.reduce(kx + &e);
    auto one = BigInt(1);
    BigInt xp1 = x + &one;
    BigInt da_inv = inverseMod(&xp1, &group.getOrder());
    BigInt rx = mod_n.multiply(&r, &x);
    BigInt kmrx = k.clone;
    kmrx -= rx;
    kmrx = mod_n.reduce(kmrx.move());
    BigInt s = mod_n.multiply(&kmrx, &da_inv);
    BigInt rplus = r + &s;
    BigInt rs = mod_n.reduce(rplus.move());
    if (r == 0 || s == 0 || rs == 0)
        throw new InternalError("During SM2 signature generated zero r/s");

    const size_t olen = group.getOrder().bytes();
    auto output = SecureVector!ubyte(2 * olen);
    r.binaryEncode(&output[olen - r.bytes()]);
    s.binaryEncode(&output[2 * olen - s.bytes()]);
    return output.move();
}

bool sm2Verify(const ref ECGroup group, const ref PointGFp pub,
               in string user_id, in string hash_name,
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
    BigInt rplus = r + &s;
    BigInt t = mod_n.reduce(rplus.move());
    if (t == 0)
        return false;

    auto e = sm2MessageHash(hash_name, user_id, group, pub, msg, msg_len);
    BigInt re = r.clone;
    re -= e;
    re = mod_n.reduce(re.move());

    PointGFp R = PointGFp.multiExponentiate(group.getBasePoint(), &s, pub, &t);
    if (R.isZero())
        return false;
    return mod_n.reduce(R.getAffineX()) == re;
}

SecureVector!ubyte sm2EncryptWithK(const ref ECGroup group, const ref PointGFp peer,
                                   in string hash_name, const(ubyte)* msg, size_t msg_len,
                                   const ref BigInt k)
{
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    Unique!KDF kdf = getKdf("KDF2(" ~ hash_name ~ ")");
    if (!kdf)
        throw new LookupError("SM2 encryption requires KDF2(" ~ hash_name ~ ")");

    PointGFp C1 = group.getBasePoint() * &k;
    PointGFp kPB = peer * &k;
    const size_t p_bytes = group.getCurve().getP().bytes();
    auto x2 = BigInt.encode1363(kPB.getAffineX(), p_bytes);
    auto y2 = BigInt.encode1363(kPB.getAffineY(), p_bytes);
    auto kdf_in = SecureVector!ubyte(x2.length + y2.length);
    kdf_in[0 .. x2.length] = x2[];
    kdf_in[x2.length .. $] = y2[];
    auto mask = kdf.deriveKey(msg_len, kdf_in.ptr, kdf_in.length);
    if (msg_len)
    {
        ubyte acc = 0;
        foreach (b; mask[])
            acc |= b;
        if (acc == 0)
            throw new InternalError("SM2 KDF produced an all-zero mask");
    }

    auto c2 = SecureVector!ubyte(msg[0 .. msg_len]);
    xorBuf(c2.ptr, mask.ptr, msg_len);

    hash.update(x2.ptr, x2.length);
    if (msg_len)
        hash.update(msg, msg_len);
    hash.update(y2.ptr, y2.length);
    auto c3 = hash.finished();

    return DEREncoder()
        .startCons(ASN1Tag.SEQUENCE)
        .encode(C1.getAffineX())
        .encode(C1.getAffineY())
        .encode(c3, ASN1Tag.OCTET_STRING)
        .encode(c2, ASN1Tag.OCTET_STRING)
        .endCons()
        .getContents();
}

SecureVector!ubyte sm2Decrypt(const ref ECGroup group, const ref BigInt x,
                              in string hash_name, const(ubyte)* ctext, size_t ctext_len)
{
    Unique!HashFunction hash = retrieveHash(hash_name).clone();
    Unique!KDF kdf = getKdf("KDF2(" ~ hash_name ~ ")");
    if (!kdf)
        throw new LookupError("SM2 decryption requires KDF2(" ~ hash_name ~ ")");

    BigInt x1, y1;
    SecureVector!ubyte c3, c2;
    try
    {
        BERDecoder(ctext, ctext_len)
            .startCons(ASN1Tag.SEQUENCE)
            .decode(x1)
            .decode(y1)
            .decode(c3, ASN1Tag.OCTET_STRING)
            .decode(c2, ASN1Tag.OCTET_STRING)
            .endCons()
            .verifyEnd();
    }
    catch (Exception)
    {
        throw new DecodingError("SM2 ciphertext is malformed");
    }

    if (c3.length != hash.outputLength)
        throw new DecodingError("SM2 ciphertext C3 has wrong length");

    PointGFp C1;
    try
    {
        C1 = PointGFp(group.getCurve(), &x1, &y1);
        if (!C1.onTheCurve())
            throw new DecodingError("SM2 C1 is not on the curve");
    }
    catch (Exception)
    {
        throw new DecodingError("SM2 C1 is not a valid point");
    }

    PointGFp dbC1 = C1 * &x;
    const size_t p_bytes = group.getCurve().getP().bytes();
    auto x2 = BigInt.encode1363(dbC1.getAffineX(), p_bytes);
    auto y2 = BigInt.encode1363(dbC1.getAffineY(), p_bytes);
    auto kdf_in = SecureVector!ubyte(x2.length + y2.length);
    kdf_in[0 .. x2.length] = x2[];
    kdf_in[x2.length .. $] = y2[];
    auto mask = kdf.deriveKey(c2.length, kdf_in.ptr, kdf_in.length);
    if (c2.length)
    {
        ubyte acc = 0;
        foreach (b; mask[])
            acc |= b;
        if (acc == 0)
            throw new DecodingError("SM2 KDF produced an all-zero mask");
    }
    xorBuf(c2.ptr, mask.ptr, c2.length);

    hash.update(x2.ptr, x2.length);
    if (c2.length)
        hash.update(c2.ptr, c2.length);
    hash.update(y2.ptr, y2.length);
    auto u = hash.finished();
    if (u[] != c3[])
        throw new DecodingError("SM2 ciphertext MAC check failed");
    return c2.move();
}

final class SM2SignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { this(cast(ECPrivateKey) pkey); }
    this(in SM2PrivateKey pkey) { this(pkey.m_priv); }
    this(in ECPrivateKey sm2)
    {
        assert(sm2.algoName == SM2PublicKey.algoName);
        m_key = sm2;
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        const BigInt* n = &m_key.domain().getOrder();
        BigInt k;
        do
        {
            k.randomize(rng, n.bits());
        } while (k == 0 || k >= *n);
        return sm2SignWithK(m_key.domain(), m_key.privateValue(), m_key.publicPoint(),
                            "", defaultHash(), msg, msg_len, k);
    }

    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }

private:
    const ECPrivateKey m_key;
}

final class SM2VerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { this(cast(ECPublicKey) pkey); }
    this(in SM2PublicKey pkey) { this(pkey.m_pub); }
    this(in ECPublicKey sm2)
    {
        assert(sm2.algoName == SM2PublicKey.algoName);
        m_key = sm2;
    }

    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }

    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return sm2Verify(m_key.domain(), m_key.publicPoint(), "", defaultHash(),
                         msg, msg_len, sig, sig_len);
    }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("SM2 has no message recovery");
    }

private:
    const ECPublicKey m_key;
}

final class SM2EncryptionOperation : Encryption
{
public:
    this(in PublicKey pkey) { this(cast(ECPublicKey) pkey); }
    this(in SM2PublicKey pkey) { this(pkey.m_pub); }
    this(in ECPublicKey sm2)
    {
        m_key = sm2;
    }

    override size_t maxInputBits() const { return 512; }

    override SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        const BigInt* n = &m_key.domain().getOrder();
        for (;;)
        {
            BigInt k;
            do
            {
                k.randomize(rng, n.bits());
            } while (k == 0 || k >= *n);
            try
            {
                return sm2EncryptWithK(m_key.domain(), m_key.publicPoint(),
                                       defaultHash(), msg, msg_len, k);
            }
            catch (InternalError)
            {
                continue;
            }
        }
    }

private:
    const ECPublicKey m_key;
}

final class SM2DecryptionOperation : Decryption
{
public:
    this(in PrivateKey pkey) { this(cast(ECPrivateKey) pkey); }
    this(in SM2PrivateKey pkey) { this(pkey.m_priv); }
    this(in ECPrivateKey sm2)
    {
        m_key = sm2;
    }

    override size_t maxInputBits() const { return 512; }

    override SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len)
    {
        return sm2Decrypt(m_key.domain(), m_key.privateValue(), defaultHash(), msg, msg_len);
    }

private:
    const ECPrivateKey m_key;
}

private:

string defaultHash()
{
    static if (BOTAN_HAS_SM3)
        return "SM3";
    else
        return "SHA-256";
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import botan.asn1.oids;
import botan.pubkey.pk_algs;
import botan.libstate.global_state;
import memutils.hashmap;
import std.stdio : File;

ECGroup sm2GroupFromParams(string p_s, string a_s, string b_s,
                           string xg_s, string yg_s, string n_s, string oid)
{
    auto p = BigInt(p_s);
    auto a = BigInt(a_s);
    auto b = BigInt(b_s);
    auto curve = CurveGFp(&p, &a, &b);
    auto gx = BigInt(xg_s);
    auto gy = BigInt(yg_s);
    auto G = PointGFp(curve, &gx, &gy);
    auto n = BigInt(n_s);
    auto h = BigInt(1);
    return ECGroup(curve, G, n, h, oid);
}

static if (BOTAN_HAS_TESTS && !SKIP_SM2_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing sm2.d ...");
    size_t fails = 0;

    {
        const OID oid = OIDS.lookup("SM2");
        if (oid.toString() != "1.2.156.10197.1.301.1")
            ++fails;
        if (OIDS.lookup(oid) != "SM2")
            ++fails;
        if (OIDS.lookup("sm2p256v1").toString() != "1.2.156.10197.1.301")
            ++fails;
    }

    File sigvec = File("test_data/pubkey/sm2_sig.vec", "r");
    fails += runTestsBb(sigvec, "SM2 Signature", "Signature", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Signature" in m) || !("x" in m) || !("P" in m))
                return 0;
            string hash = "SM3";
            if (auto hp = "Hash" in m)
                if ((*hp).length)
                    hash = *hp;
            string ident;
            if (auto ip = "Ident" in m)
                ident = *ip;
            auto group = sm2GroupFromParams(m["P"], m["A"], m["B"], m["xG"], m["yG"], m["Order"], m["Oid"]);
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto x = BigInt(m["x"]);
            auto priv = SM2PrivateKey(*rng, group, x);
            Vector!ubyte msg;
            if (auto mp = "Msg" in m)
                if ((*mp).length)
                    msg = hexDecode(*mp);
            auto k = BigInt(m["Nonce"].length >= 2 && (m["Nonce"][0] == '0' && (m["Nonce"][1] == 'x' || m["Nonce"][1] == 'X'))
                           ? m["Nonce"] : "0x" ~ m["Nonce"]);
            auto got = sm2SignWithK(priv.domain(), priv.privateValue(), priv.publicPoint(),
                                    ident, hash, msg.ptr, msg.length, k);
            auto exp = hexDecode(m["Signature"]);
            if (got[] != exp[])
                return 1;
            if (!sm2Verify(priv.domain(), priv.publicPoint(), ident, hash,
                           msg.ptr, msg.length, got.ptr, got.length))
                return 1;
            return 0;
        });

    File encvec = File("test_data/pubkey/sm2_enc.vec", "r");
    fails += runTestsBb(encvec, "SM2 Encryption", "Ciphertext", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Ciphertext" in m) || !("x" in m) || !("P" in m))
                return 0;
            string hash = "SM3";
            if (auto hp = "Hash" in m)
                if ((*hp).length)
                    hash = *hp;
            auto group = sm2GroupFromParams(m["P"], m["A"], m["B"], m["xG"], m["yG"], m["Order"], m["Oid"]);
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto x = BigInt(m["x"]);
            auto priv = SM2PrivateKey(*rng, group, x);
            Vector!ubyte msg;
            if (auto mp = "Msg" in m)
                if ((*mp).length)
                    msg = hexDecode(*mp);
            auto k = BigInt(m["Nonce"].length >= 2 && (m["Nonce"][0] == '0' && (m["Nonce"][1] == 'x' || m["Nonce"][1] == 'X'))
                           ? m["Nonce"] : "0x" ~ m["Nonce"]);
            auto got = sm2EncryptWithK(priv.domain(), priv.publicPoint(),
                                       hash, msg.ptr, msg.length, k);
            auto exp = hexDecode(m["Ciphertext"]);
            if (got[] != exp[])
                return 1;
            auto pt = sm2Decrypt(priv.domain(), priv.privateValue(), hash, got.ptr, got.length);
            if (pt[] != msg[])
                return 1;
            return 0;
        });

    File inv = File("test_data/pubkey/sm2_invalid.vec", "r");
    fails += runTestsBb(inv, "SM2 Invalid", "Ctext", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Ctext" in m) || !("Key" in m))
                return 0;
            auto group = ECGroup("sm2p256v1");
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto raw = hexDecode(m["Key"]);
            auto x = BigInt(raw.ptr, raw.length);
            auto priv = SM2PrivateKey(*rng, group, x);
            Vector!ubyte ctext;
            if (m["Ctext"].length)
                ctext = hexDecode(m["Ctext"]);
            try
            {
                auto pt = sm2Decrypt(priv.domain(), priv.privateValue(), "SM3",
                                     ctext.ptr, ctext.length);
                return 1;
            }
            catch (Exception)
            {
                return 0;
            }
        });

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto group = ECGroup("sm2p256v1");
        auto k = SM2PrivateKey(*rng, group);
        auto signer = PKSigner(k, "Raw");
        ubyte[5] hello = ['h', 'e', 'l', 'l', 'o'];
        auto sig = signer.signMessage(hello.ptr, hello.length, *rng);
        auto verifier = PKVerifier(k, "Raw");
        if (!verifier.verifyMessage(hello.ptr, hello.length, sig.ptr, sig.length))
            ++fails;

        auto bits = SecureVector!ubyte(k.x509SubjectPublicKey()[]);
        Unique!PublicKey via_factory = makePublicKey(k.algorithmIdentifier(), bits);
        if (!via_factory || via_factory.algoName != "SM2")
            ++fails;

        auto kk = BigInt("0x11");
        auto ct = sm2EncryptWithK(k.domain(), k.publicPoint(), defaultHash(),
                                  hello.ptr, hello.length, kk);
        auto pt = sm2Decrypt(k.domain(), k.privateValue(), defaultHash(), ct.ptr, ct.length);
        if (pt[] != hello[])
            ++fails;
    }

    testReport("sm2", 0, fails);
    assert(fails == 0);
}
