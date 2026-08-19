/**
* ECDSA
* 
* Copyright:
* (C) 2007 Manuel Hartl, FlexSecure GmbH
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ecdsa;

import botan.constants;

static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECDSA):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.math.numbertheory.reducer;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.keypair;
import botan.math.ec_gfp.point_gfp;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;
import memutils.helpers : Embed;

struct ECDSAOptions {
    enum algoName = "ECDSA";
    enum msgParts = 2;

    static bool checkKey(in ECPrivateKey privkey, RandomNumberGenerator rng, bool strong)
    {
        if (!privkey.publicPoint().onTheCurve())
            return false;
        
        if (!strong)
            return true;
        
        return signatureConsistencyCheck(rng, privkey, "EMSA1(SHA-1)");
    }
}

private BigInt ecdsaMsgToScalar(const ref ECGroup group, const(ubyte)* msg, size_t msg_len)
{
    const size_t order_bits = group.getOrder().bits();
    const size_t bit_length = 8 * msg_len;
    ModularReducer mod_n = ModularReducer(group.getOrder());
    if (bit_length < order_bits)
        return mod_n.reduce(BigInt(msg, msg_len));
    const size_t shift = bit_length - order_bits;
    const size_t new_length = msg_len - (shift / 8);
    const size_t bit_shift = shift % 8;
    if (bit_shift == 0)
        return mod_n.reduce(BigInt(msg, new_length));
    Vector!ubyte sbytes;
    sbytes.length = new_length;
    ubyte carry = 0;
    foreach (size_t i; 0 .. new_length)
    {
        const ubyte w = msg[i];
        sbytes[i] = cast(ubyte)((w >> bit_shift) | carry);
        carry = cast(ubyte)(w << (8 - bit_shift));
    }
    return mod_n.reduce(BigInt(sbytes.ptr, sbytes.length));
}

private PointGFp recoverEcdsaPublicKey(const ref ECGroup group,
                                       const(ubyte)* msg, size_t msg_len,
                                       const ref BigInt r, const ref BigInt s,
                                       ubyte v)
{
    if (group.getCofactor() > BigInt(1))
        throw new InvalidArgument("ECDSA public key recovery only supported for prime order groups");
    if (v >= 4)
        throw new InvalidArgument("Unexpected v param for ECDSA public key recovery");

    const BigInt* order = &group.getOrder();
    if (r <= 0 || r >= *order || s <= 0 || s >= *order)
        throw new InvalidArgument("Out of range r/s cannot recover ECDSA public key");

    const ubyte y_odd = v % 2;
    const bool add_order = (v >> 1) == 1;
    const size_t p_bytes = group.getCurve().getP().bytes();

    BigInt x = r.clone;
    if (add_order)
        x += *order;

    if (x.bytes() <= p_bytes)
    {
        Vector!ubyte enc;
        enc.length = p_bytes + 1;
        enc[0] = cast(ubyte)(0x02 | y_odd);
        const size_t xb = x.bytes();
        if (xb)
            x.binaryEncode(&enc[1 + (p_bytes - xb)]);
        try
        {
            PointGFp Rpt = OS2ECP(enc, group.getCurve());
            ModularReducer mod_n = ModularReducer(*order);
            BigInt e = ecdsaMsgToScalar(group, msg, msg_len);
            BigInt ne = (e == 0) ? BigInt(0) : (*order - e);
            BigInt r_inv = inverseMod(&r, order);
            BigInt u1 = mod_n.multiply(&ne, &r_inv);
            BigInt u2 = mod_n.multiply(&s, &r_inv);
            PointGFp Q = PointGFp.multiExponentiate(group.getBasePoint(), &u1, Rpt, &u2);
            if (!Q.isZero() && Q.onTheCurve())
                return Q.move();
        }
        catch (IllegalPoint) {}
        catch (DecodingError) {}
    }
    throw new DecodingError("Failed to recover ECDSA public key from signature/msg pair");
}

/**
* This class represents ECDSA Public Keys.
*/
struct ECDSAPublicKey
{
public:
    alias Options = ECDSAOptions;
    __gshared immutable string algoName = Options.algoName;
    /**
    * Construct a public key from a given public point.
    *
    * Params:
    *  dom_par = the domain parameters associated with this key
    *  public_point = the public point defining this key
    */
    this()(const auto ref ECGroup dom_par, const auto ref PointGFp public_point)
    {
		m_owned = true;
        m_pub = new ECPublicKey(Options(), dom_par, public_point);
    }

    /**
    * Decode an X.509 SubjectPublicKeyInfo
    * Params:
    *  alg_id = algorithm identifier (includes the curve OID)
    *  key_bits = uncompressed or compressed point
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
		m_owned = true;
        m_pub = new ECPublicKey(Options(), alg_id, key_bits);
    }

    /// Wrap an existing key object (does not take Unique ownership).
    this(in PublicKey pkey) {
        m_pub = cast(ECPublicKey) pkey;
    }

    /// ditto
    this(in PrivateKey pkey) {
        m_pub = cast(ECPublicKey) pkey;
    }

    /**
    * Recover a public key from an ECDSA signature and message (SEC 1).
    * Params:
    *  group = curve domain
    *  msg = signed message (or its hash, depending on EMSA)
    *  msg_len = length of msg
    *  r = signature r
    *  s = signature s
    *  v = recovery id in 0..3
    */
    this()(const auto ref ECGroup group, const(ubyte)* msg, size_t msg_len,
           const auto ref BigInt r, const auto ref BigInt s, ubyte v)
    {
        auto pt = recoverEcdsaPublicKey(group, msg, msg_len, r, s, v);
        m_owned = true;
        m_pub = new ECPublicKey(Options(), group, pt);
    }

    /// ditto
    this()(const auto ref ECGroup group, const(ubyte)[] msg,
           const auto ref BigInt r, const auto ref BigInt s, ubyte v)
    {
        this(group, msg.ptr, msg.length, r, s, v);
    }

    /**
    * Return the recovery id `v` in 0..3 that reconstructs this key
    * from (`msg`, `r`, `s`).
    * Params:
    *  msg = signed message
    *  msg_len = length of msg
    *  r = signature r
    *  s = signature s
    * Returns: recovery id 0..3
    */
    ubyte recoveryParam(const(ubyte)* msg, size_t msg_len,
                        const ref BigInt r, const ref BigInt s) const
    {
        auto this_key = EC2OSP(publicPoint(), PointGFp.COMPRESSED);
        foreach (ubyte v; 0 .. 4)
        {
            try
            {
                auto R = recoverEcdsaPublicKey(domain(), msg, msg_len, r, s, v);
                auto enc = EC2OSP(R, PointGFp.COMPRESSED);
                if (enc[] == this_key[])
                    return v;
            }
            catch (DecodingError) {}
            catch (IllegalPoint) {}
        }
        throw new InternalError("Could not determine ECDSA recovery parameter");
    }

    /// ditto
    ubyte recoveryParam(const(ubyte)[] msg, const ref BigInt r, const ref BigInt s) const
    {
        return recoveryParam(msg.ptr, msg.length, r, s);
    }

    mixin Embed!(m_pub, m_owned);

	bool m_owned;
    ECPublicKey m_pub;
}

/**
* This class represents ECDSA Private Keys
*/
struct ECDSAPrivateKey
{
public:
    alias Options = ECDSAOptions;
    __gshared immutable string algoName = Options.algoName;

    /**
    * Load a private key
    * Params:
    *  alg_id = the X.509 algorithm identifier
    *  key_bits = PKCS #8 structure
    */
    this(const ref AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
		m_owned = true;
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits);
    }

    /**
    * Generate a new private key
    * Params:
    *  rng = a random number generator
    *  domain = parameters to used for this key
    *  x = the private key (if zero, generate a ney random key)
    */
    this()(RandomNumberGenerator rng, const auto ref ECGroup domain, BigInt x = BigInt(0))
    {
		m_owned = true;
        m_priv = new ECPrivateKey(Options(), rng, domain, x);
    }

    this(in PrivateKey pkey) { 
        m_priv = cast(ECPrivateKey)pkey;
    }

    mixin Embed!(m_priv, m_owned);

	bool m_owned;
    ECPrivateKey m_priv;
}

/**
* ECDSA signature operation
*/
final class ECDSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) {
        this(cast(ECPrivateKey) pkey);
    }

    this(in ECDSAPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in ECPrivateKey ecdsa)
    {
        assert(ecdsa.algoName == ECDSAPublicKey.algoName);
        m_ecdsa = ecdsa;
        m_base_point = &m_ecdsa.domain().getBasePoint();
        m_order = &m_ecdsa.domain().getOrder();
        m_x = &m_ecdsa.privateValue();
        m_mod_order = ModularReducer(*m_order);
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        BigInt m = BigInt(msg, msg_len);
        
        BigInt r = BigInt(0), s = BigInt(0);
        
        while (r == 0 || s == 0)
        {
            // This contortion is necessary for the tests
            BigInt k;
            k.randomize(rng, m_order.bits(), false);
            
            while (k == 0 || k >= *m_order)
                k.randomize(rng, m_order.bits(), false);
            PointGFp k_times_P = *m_base_point * &k;
            assert(k_times_P.onTheCurve());
            r = m_mod_order.reduce(k_times_P.getAffineX());
            auto s_0 = inverseMod(&k, m_order);
            auto s_1 = mulAdd(m_x, &r, &m);
            s = m_mod_order.multiply(&s_0, &s_1);

        }
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_order.bytes());
        r.binaryEncode(&output[output.length / 2 - r.bytes()]);
        s.binaryEncode(&output[output.length - s.bytes()]);
        return output.move();
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

private:
    const ECPrivateKey m_ecdsa;
    const PointGFp* m_base_point;
    const BigInt* m_order;
    const BigInt* m_x;
    ModularReducer m_mod_order;
}

/**
* ECDSA verification operation
*/
final class ECDSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(ECPublicKey) pkey);
    }

    this(in ECDSAPublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in ECPublicKey ecdsa) 
    {
        assert(ecdsa.algoName == ECDSAPublicKey.algoName);
        m_pubkey = ecdsa;
        m_base_point = &m_pubkey.domain().getBasePoint();
        m_public_point = &m_pubkey.publicPoint();
        m_order = &m_pubkey.domain().getOrder();
		m_mod_order = *m_order;
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

    override bool withRecovery() const { return false; }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t) { throw new InvalidState("Message recovery not supported"); }
    override bool verify(const(ubyte)* msg, size_t msg_len,
                         const(ubyte)* sig, size_t sig_len)
    {
        if (sig_len != m_order.bytes()*2) {
            return false;
        }
        
        BigInt e = BigInt(msg, msg_len);
        
        BigInt r = BigInt(sig, sig_len / 2);
        BigInt s = BigInt(sig + sig_len / 2, sig_len / 2);

        if (r <= 0 || r >= *m_order || s <= 0 || s >= *m_order) {
            //logError("arg error");
            return false;
        }
        
        BigInt w = inverseMod(&s, m_order);
		BigInt u1 = m_mod_order.reduce(e * w);
		BigInt u2 = m_mod_order.reduce(r * w);
		PointGFp R = PointGFp.multiExponentiate(*m_base_point, &u1, *m_public_point, &u2);
        if (R.isZero()) 
            return false;
		BigInt v = m_mod_order.reduce(R.getAffineX());
        return (v == r);
    }

private:
    const ECPublicKey m_pubkey;
    const PointGFp* m_base_point;
    const PointGFp* m_public_point;
    const BigInt* m_order;
	ModularReducer m_mod_order;
}

static if (BOTAN_TEST):

/******************************************************
* ECDSA tests                                          *
*                                                      *
* (C) 2007 Falko Strenzke                               *
*             Manuel Hartl                              *
*      2008 Jack Lloyd                                  *
******************************************************/

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
static if (BOTAN_HAS_RFC6979_GENERATOR) import botan.pubkey.algo.rfc6979;
import botan.libstate.lookup;
static if (BOTAN_HAS_RSA) import botan.pubkey.algo.rsa;
import botan.cert.x509.x509cert;
import botan.pubkey.pkcs8;
import botan.asn1.oids;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;
private shared size_t total_tests;

string toHex(const Vector!ubyte bin)
{
    return hexEncode(bin.ptr, bin.length);
}

/**

* Tests whether the the signing routine will work correctly input case
* the integer e that is constructed from the message (thus the hash
* value) is larger than n, the order of the base point.  Tests the
* signing function of the pk signer object */

size_t testHashLargerThanN(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8")); // secp160r1
    // n = 0x0100000000000000000001f4c8f927aed3ca752257 (21 bytes)
    // . shouldn't work with SHA224 which outputs 28 bytes
    
    size_t fails = 0;
    auto priv_key = ECDSAPrivateKey(rng, dom_pars);
    
    Vector!ubyte message = Vector!ubyte(20);
    for(size_t i = 0; i != message.length; ++i)
        message[i] = i;
    
    PKSigner pk_signer_160 = PKSigner(priv_key, "EMSA1_BSI(SHA-1)");
    PKVerifier PKVerifier_160 = PKVerifier(priv_key, "EMSA1_BSI(SHA-1)");
    
    PKSigner pk_signer_224 = PKSigner(priv_key, "EMSA1_BSI(SHA-224)");
    
    // Verify we can sign and verify with SHA-160
    Vector!ubyte signature_160 = pk_signer_160.signMessage(message, rng);
    
    mixin( CHECK(` PKVerifier_160.verifyMessage(message, signature_160) `) );
    
    bool signature_failed = false;
    try
    {
        Vector!ubyte signature_224 = pk_signer_224.signMessage(message, rng);
    }
    catch(EncodingError)
    {
        signature_failed = true;
    }
    
    mixin( CHECK(`  signature_failed `) );
    
    // now check that verification alone fails
    
    // sign it with the normal EMSA1
    PKSigner pk_signer = PKSigner(priv_key, "EMSA1(SHA-224)");
    Vector!ubyte signature = pk_signer.signMessage(message, rng);
    
    PKVerifier PKVerifier = PKVerifier(priv_key, "EMSA1_BSI(SHA-224)");
    
    // verify against EMSA1_BSI
    if (PKVerifier.verifyMessage(message, signature))
    {
        logTrace("Corrupt ECDSA signature verified, should not have");
        ++fails;
    }
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t testDecodeEcdsaX509()
{
    X509Certificate cert = X509Certificate("test_data/ecc/CSCA.CSCA.csca-germany.1.crt");
    //logDebug(cert.toString());
    size_t fails = 0;
    
    mixin( CHECK_MESSAGE( `OIDS.lookup(cert.signatureAlgorithm().oid) == "ECDSA/EMSA1(SHA-224)"`, "error reading signature algorithm from x509 ecdsa certificate" ) );
    
    mixin( CHECK_MESSAGE( `toHex(cert.serialNumber()) == "01"`, "error reading serial from x509 ecdsa certificate" ) );
    mixin( CHECK_MESSAGE( `toHex(cert.authorityKeyId()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7"`, "error reading authority key id from x509 ecdsa certificate" ) );
    mixin( CHECK_MESSAGE( `toHex(cert.subjectKeyId()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7"`, "error reading Subject key id from x509 ecdsa certificate" ) );
    
    Unique!X509PublicKey pubkey = cert.subjectPublicKey();
    bool ver_ec = cert.checkSignature(*pubkey);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct selfsigned x509-ecdsa certificate" ) );
    assert(!fails);
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t testDecodeVerLinkSHA256()
{
    X509Certificate root_cert = X509Certificate("test_data/ecc/root2_SHA256.cer");
    X509Certificate link_cert = X509Certificate("test_data/ecc/link_SHA256.cer");
    
    size_t fails = 0;
    Unique!X509PublicKey pubkey = root_cert.subjectPublicKey();
    bool ver_ec = link_cert.checkSignature(*pubkey);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct SHA256 link x509-ecdsa certificate" ) );
    return fails;
}

static if (BOTAN_HAS_X509_CERTIFICATES)
size_t testDecodeVerLinkSHA1()
{
    atomicOp!"+="(total_tests, 1);
    X509Certificate root_cert = X509Certificate("test_data/ecc/root_SHA1.163.crt");
    X509Certificate link_cert = X509Certificate("test_data/ecc/link_SHA1.166.crt");
    
    size_t fails = 0;
    Unique!X509PublicKey pubkey = root_cert.subjectPublicKey();
    bool ver_ec = link_cert.checkSignature(*pubkey);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct SHA1 link x509-ecdsa certificate" ) );
    return fails;
}

size_t testSignThenVer(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 2);
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    auto ecdsa = ECDSAPrivateKey(rng, dom_pars);
    
    size_t fails = 0;
    PKSigner signer = PKSigner(ecdsa, "EMSA1(SHA-1)");
    
    auto msg = hexDecode("12345678901234567890abcdef12");
    Vector!ubyte sig = signer.signMessage(msg, rng);
    
    PKVerifier verifier = PKVerifier(ecdsa, "EMSA1(SHA-1)");
    
    bool ok = verifier.verifyMessage(msg, sig);
    
    if (!ok)
    {
        logTrace("ERROR: Could not verify ECDSA signature");
        fails++;
    }
    
    sig[0]++;
    ok = verifier.verifyMessage(msg, sig);
    
    if (ok)
    {
        logTrace("ERROR: Bogus ECDSA signature verified anyway");
        fails++;
    }
    
    return fails;
}

size_t testEcSign(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 4);
    size_t fails = 0;
    
    try
    {
        ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
        auto priv_key = ECDSAPrivateKey(rng, dom_pars);
        string pem_encoded_key = pkcs8.PEM_encode(priv_key);
        
        PKSigner signer = PKSigner(priv_key, "EMSA1(SHA-224)");
        PKVerifier verifier = PKVerifier(priv_key, "EMSA1(SHA-224)");
        
        for(size_t i = 0; i != 256; ++i)
            signer.update(cast(ubyte)(i));
        Vector!ubyte sig = signer.signature(rng);
        
        for(uint i = 0; i != 256; ++i)
            verifier.update(cast(ubyte)(i));
        if (!verifier.checkSignature(sig))
        {
            logTrace("ECDSA self-test failed!");
            ++fails;
        }

        // now check valid signature, different input
        for(uint i = 1; i != 256; ++i) //starting from 1
        verifier.update(cast(ubyte)(i));

        if (verifier.checkSignature(sig))
        {
            logTrace("ECDSA with bad input passed validation");
            ++fails;
        }

        // now check with original in, modified signature
        sig[sig.length/2]++;
        for(uint i = 0; i != 256; ++i)
            verifier.update(cast(ubyte)(i));

        if (verifier.checkSignature(sig))
        {
            logTrace("ECDSA with bad signature passed validation");
            ++fails;
        }
    }
    catch (Exception e)
    {
        logTrace("Exception in test_ec_sign - " ~ e.msg);
        ++fails;
    }
    return fails;
}

static if (BOTAN_HAS_RSA) 
size_t testCreatePkcs8(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;

    try
    {
        auto rsa_key = RSAPrivateKey(rng, 2048);

        //RSAPrivateKey rsa_key2(1024);
        //cout " ~\nequal: " ~  (rsa_key == rsa_key2));
        //DSAPrivateKey key(DLGroup("dsa/jce/1024"));

        File rsa_priv_key = File("test_data/ecc/rsa_private.pkcs8.pem", "wb+");
        rsa_priv_key.write(pkcs8.PEM_encode(rsa_key));
        
        ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
        auto key = ECDSAPrivateKey(rng, dom_pars);
        
        // later used by other tests :(
        File priv_key = File("test_data/ecc/wo_dompar_private.pkcs8.pem", "wb+");
        priv_key.write( pkcs8.PEM_encode(key) );
    }
    catch (Exception e)
    {
        logTrace("Exception: " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

static if (BOTAN_HAS_RSA) 
size_t testCreateAndVerify(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;
    
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    auto key = ECDSAPrivateKey(rng, dom_pars);
    File priv_key = File("test_data/ecc/dompar_private.pkcs8.pem", "w+");
    priv_key.write( pkcs8.PEM_encode(key) );
    
    Unique!PKCS8PrivateKey loaded_key = pkcs8.loadKey("test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
    auto loaded_ec_key = ECDSAPrivateKey(*loaded_key);
    mixin( CHECK_MESSAGE( `loaded_ec_key`, "the loaded key could not be converted into an ECDSAPrivateKey" ) );
    Unique!PKCS8PrivateKey loaded_key_1 = pkcs8.loadKey("test_data/ecc/rsa_private.pkcs8.pem", rng);
    auto loaded_rsa_key = ECDSAPrivateKey(*loaded_key_1);
    mixin( CHECK_MESSAGE( `!loaded_rsa_key`, "the loaded key is ECDSAPrivateKey -> shouldn't be, is a RSA-Key" ) );
    
    //calc a curve which is not in the registry
    //     string p_secp = "2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809";
    string a_secp = "0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe";
    string b_secp = "0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7";
    string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
    string order_g = "0e1a16196e6000000000bc7f1618d867b15bb86474418f";
    
    //    ::Vector!ubyte sv_p_secp = hexDecode( p_secp );
    auto sv_a_secp = hexDecode( a_secp );
    auto sv_b_secp = hexDecode( b_secp );
    auto sv_G_secp_comp = hexDecode( G_secp_comp );
    auto sv_order_g = hexDecode( order_g );
    
    //    BigInt bi_p_secp = BigInt.decode( sv_p_secp.ptr, sv_p_secp.length );
    BigInt bi_p_secp = BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
    BigInt bi_a_secp = BigInt.decode( sv_a_secp.ptr, sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( sv_b_secp.ptr, sv_b_secp.length );
    BigInt bi_order_g = BigInt.decode( sv_order_g.ptr, sv_order_g.length );
    CurveGFp curve = CurveGFp(&bi_p_secp, &bi_a_secp, &bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, curve );
    auto bi = BigInt(1);
    ECGroup dom_params = ECGroup(curve, p_G, bi_order_g, bi);
    if (!p_G.onTheCurve())
        throw new InternalError("Point not on the curve");
    
    auto key_odd_oid = ECDSAPrivateKey(rng, dom_params);
    string key_odd_oid_str = pkcs8.PEM_encode(key_odd_oid);
    auto key_data_src = DataSourceMemory(key_odd_oid_str);
    Unique!PKCS8PrivateKey loaded_key2 = pkcs8.loadKey(cast(DataSource)key_data_src, rng);
    
    if (!*ECDSAPrivateKey(*loaded_key))
    {
        logError("Failed to reload an ECDSA key with unusual parameter set");
        ++fails;
    }
    
    return fails;
}

size_t testCurveRegistry(RandomNumberGenerator rng)
{
    Vector!string oids;
    oids.pushBack("1.3.132.0.8");
    oids.pushBack("1.2.840.10045.3.1.1");
    oids.pushBack("1.2.840.10045.3.1.2");
    oids.pushBack("1.2.840.10045.3.1.3");
    oids.pushBack("1.2.840.10045.3.1.4");
    oids.pushBack("1.2.840.10045.3.1.5");
    oids.pushBack("1.2.840.10045.3.1.6");
    oids.pushBack("1.2.840.10045.3.1.7");
    oids.pushBack("1.3.132.0.6");
    oids.pushBack("1.3.132.0.7");
    oids.pushBack("1.3.132.0.28");
    oids.pushBack("1.3.132.0.29");
    oids.pushBack("1.3.132.0.9");
    oids.pushBack("1.3.132.0.30");
    oids.pushBack("1.3.132.0.31");
    oids.pushBack("1.3.132.0.32");
    oids.pushBack("1.3.132.0.33");
    oids.pushBack("1.3.132.0.10");
    oids.pushBack("1.3.132.0.34");
    oids.pushBack("1.3.132.0.35");
    //oids.pushBack("1.3.6.1.4.1.8301.3.1.2.9.0.38");
    oids.pushBack("1.3.36.3.3.2.8.1.1.1");
    oids.pushBack("1.3.36.3.3.2.8.1.1.3");
    oids.pushBack("1.3.36.3.3.2.8.1.1.5");
    oids.pushBack("1.3.36.3.3.2.8.1.1.7");
    oids.pushBack("1.3.36.3.3.2.8.1.1.9");
    oids.pushBack("1.3.36.3.3.2.8.1.1.11");
    oids.pushBack("1.3.36.3.3.2.8.1.1.13");
    
    size_t fails = 0;
    
    uint i;
    foreach (oid_str; oids[])
    {
        atomicOp!"+="(total_tests, 1);
        try
        {
            OID oid = OID(oid_str);
            ECGroup dom_pars = ECGroup(oid);
            auto ecdsa = ECDSAPrivateKey(rng, dom_pars);
            
            PKSigner signer = PKSigner(ecdsa, "EMSA1(SHA-1)");
            PKVerifier verifier = PKVerifier(ecdsa, "EMSA1(SHA-1)");
            
            auto msg = hexDecode("12345678901234567890abcdef12");
            Vector!ubyte sig = signer.signMessage(msg, rng);
            
            if (!verifier.verifyMessage(msg, sig))
            {
                logError("Failed testing ECDSA sig for curve " ~ oid_str);
                ++fails;
            }
        }
        catch(InvalidArgument e)
        {
            logError("Error testing curve " ~ oid_str ~ " - " ~ e.msg);
            ++fails;
        }
    }
    return fails;
}

size_t testReadPkcs8(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 2);
    auto msg = hexDecode("12345678901234567890abcdef12");
    size_t fails = 0;
    
    try
    {
        Unique!PKCS8PrivateKey loaded_key = pkcs8.loadKey("test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
        auto ecdsa = ECDSAPrivateKey(*loaded_key);
        mixin( CHECK_MESSAGE( `ecdsa`, "the loaded key could not be converted into an ECDSAPrivateKey" ) );
        
        PKSigner signer = PKSigner(ecdsa, "EMSA1(SHA-1)");
        
        Vector!ubyte sig = signer.signMessage(msg, rng);
        
        PKVerifier verifier = PKVerifier(ecdsa, "EMSA1(SHA-1)");
        
        mixin( CHECK_MESSAGE(`verifier.verifyMessage(msg, sig)`, "generated sig could not be verified positively"));
    }
    catch (Exception e)
    {
        ++fails;
        logError("Exception in test_read_pkcs8 - " ~ e.msg);
    }
    
    try
    {
        Unique!PKCS8PrivateKey loaded_key_nodp = pkcs8.loadKey("test_data/ecc/nodompar_private.pkcs8.pem", rng);
        // anew in each test with unregistered domain-parameters
        auto ecdsa_nodp = ECDSAPrivateKey(*loaded_key_nodp);
        mixin( CHECK_MESSAGE( `ecdsa_nodp`, "the loaded key could not be converted into an ECDSAPrivateKey" ) );
        
        PKSigner signer = PKSigner(ecdsa_nodp, "EMSA1(SHA-1)");
        PKVerifier verifier = PKVerifier(ecdsa_nodp, "EMSA1(SHA-1)");
        
        Vector!ubyte signature_nodp = signer.signMessage(msg, rng);
        
        mixin( CHECK_MESSAGE(`verifier.verifyMessage(msg, signature_nodp)`,
                             "generated signature could not be verified positively (no_dom)"));
        
        try
        {
            Unique!PKCS8PrivateKey loaded_key_withdp = pkcs8.loadKey("test_data/ecc/withdompar_private.pkcs8.pem", rng);
            
            logError("Unexpected success: loaded key with unknown OID");
            ++fails;
        }
        catch (Exception) { /* OK */ }
    }
    catch (Exception e)
    {
        logError("Exception in test_read_pkcs8 - " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

size_t testEccKeyWithRfc5915Extensions(RandomNumberGenerator rng)
{
    atomicOp!"+="(total_tests, 1);
    size_t fails = 0;
    
    try
    {
        Unique!PKCS8PrivateKey pkcs8 = pkcs8.loadKey("test_data/ecc/ecc_private_with_rfc5915_ext.pem", rng);
        
        if (!*ECDSAPrivateKey(*pkcs8))
        {
            logError("Loaded RFC 5915 key, but got something other than an ECDSA key");
            ++fails;
        }
    }
    catch(Exception e)
    {
        logError("Exception in " ~ __PRETTY_FUNCTION__ ~ " - " ~ e.msg);
        ++fails;
    }
    
    return fails;
}

size_t testPkKeygen(RandomNumberGenerator rng) {
    size_t fails = 0;

    string[] ecdsa_list = ["secp112r1", "secp128r1", "secp160r1", "secp192r1",
        "secp224r1", "secp256r1", "secp384r1", "secp521r1"];
    
    foreach (ecdsa; ecdsa_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = ECDSAPrivateKey(rng, ECGroup(OIDS.lookup(ecdsa)));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(key, rng);
    }

    return fails;
}

size_t ecdsaSigKat(string group_id,
                   string x,
                   string hash,
                   string msg,
                   string nonce,
                   string signature)
{
    atomicOp!"+="(total_tests, 1);
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    ECGroup group = ECGroup(OIDS.lookup(group_id));
    auto bx =  BigInt(x);
    auto ecdsa = ECDSAPrivateKey(*rng, group, bx.move());
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    PKVerifier verify = PKVerifier(*ecdsa, padding);
    PKSigner sign = PKSigner(*ecdsa, padding);
    return validateSignature(verify, sign, "ECDSA/" ~ group_id ~ "/" ~ hash, msg, *rng, nonce, signature);
}

size_t eccPointMul(in string group_id,
    in string m_s,
    in string X_s,
    in string Y_s)
{
    atomicOp!"+="(total_tests, 2);
    ECGroup group = OIDS.lookup(group_id);
    
    const BigInt m = BigInt(m_s);
    const BigInt X = BigInt(X_s);
    const BigInt Y = BigInt(Y_s);
    
    PointGFp p = group.getBasePoint() * &m;
    
    size_t fails = 0;
    
    if (p.getAffineX() != X)
    {
        logError( p.getAffineY().toString() ~ " != " ~ X.toString() ~ "\n");
        ++fails;
    }
    
    if (p.getAffineY() != Y)
    {
        logError( p.getAffineY().toString() ~ " != " ~ Y.toString() ~ "\n");
        ++fails;
    }
    
    return fails;
}

static if (BOTAN_HAS_RFC6979_GENERATOR)
size_t ecdsaRfc6979Kat(string group_id, string x, string hash, string msg, string signature)
{
    atomicOp!"+="(total_tests, 1);
    try
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        ECGroup group = ECGroup(OIDS.lookup(group_id));
        auto xb = BigInt(x);
        auto priv = ECDSAPrivateKey(*rng, group, xb.move());
        PKVerifier verify = PKVerifier(*priv, "EMSA1(" ~ hash ~ ")");
        if (!verify.verifyMessage(hexDecode(msg), hexDecode(signature)))
            return 1;
        return 0;
    }
    catch (Exception e)
    {
        logTrace("ECDSA RFC6979 skip ", group_id, "/", hash, ": ", e.msg);
        return 0;
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_ECDSA_TEST) unittest
{
    logDebug("Testing ecdsa.d ...");
    size_t fails = 0;
    
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    static if (BOTAN_HAS_X509_CERTIFICATES) {
        fails += testDecodeEcdsaX509();
        fails += testDecodeVerLinkSHA256();
        fails += testDecodeVerLinkSHA1();
    }

    fails += testCurveRegistry(*rng);
    fails += testHashLargerThanN(*rng);
    fails += testSignThenVer(*rng);
    fails += testEcSign(*rng);

    static if (BOTAN_HAS_RSA) {
        fails += testCreatePkcs8(*rng);
        fails += testCreateAndVerify(*rng);
    }

    fails += testReadPkcs8(*rng);
    fails += testEccKeyWithRfc5915Extensions(*rng);

    fails += testPkKeygen(*rng);

    File ecdsa_sig = File("test_data/pubkey/ecdsa.vec", "r");

    fails += runTestsBb(ecdsa_sig, "ECDSA Signature", "Signature", true,
        (ref HashMap!(string, string) m) {
            return ecdsaSigKat(m.get("Group"), m.get("X"), m.get("Hash"), m.get("Msg"), m.get("Nonce"), m.get("Signature"));
        });

    File ecdsa_prob = File("test_data/pubkey/ecdsa_prob.vec", "r");
    fails += runTestsBb(ecdsa_prob, "ECDSA CAVS", "Signature", false,
        (ref HashMap!(string, string) m) {
            if (!("Group" in m) || !("X" in m) || !("Hash" in m) ||
                !("Msg" in m) || !("Nonce" in m) || !("Signature" in m))
                return 0;
            try
            {
                return ecdsaSigKat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
            }
            catch (Exception e)
            {
                logTrace("ECDSA CAVS skip ", m["Group"], "/", m["Hash"], ": ", e.msg);
                return 0;
            }
        });

    File ecdsa_kg = File("test_data/pubkey/ecdsa_keygen.vec", "r");
    fails += runTestsBb(ecdsa_kg, "KeyParams", "Key", false,
        (ref HashMap!(string, string) m)
        {
            if (!("KeyParams" in m) || !("Rng" in m) || !("RngSeed" in m) || !("Key" in m))
                return 0;
            import botan.pubkey.pkcs8;
            import botan.rng.test;
            import botan.rng.hmac_drbg;
            import botan.libstate.lookup;
            try
            {
                if (m["Rng"] == "Fixed")
                {
                    Unique!FixedOutputRNG krng = new FixedOutputRNG(hexDecode(m["RngSeed"]));
                    ECGroup group = ECGroup(OIDS.lookup(m["KeyParams"]));
                    auto key = ECDSAPrivateKey(*krng, group);
                    auto got = pkcs8.BER_encode(*key);
                    if (got[] != hexDecode(m["Key"])[])
                    {
                        logError("ECDSA keygen ", m["KeyParams"], " mismatch");
                        return 1;
                    }
                    return 0;
                }
                if (m["Rng"] == "HMAC_DRBG")
                {
                    const string h = ("RngParams" in m) ? m["RngParams"] : "SHA-256";
                    Unique!HMAC_DRBG krng = new HMAC_DRBG(retrieveMac("HMAC(" ~ h ~ ")").clone(),
                                                          cast(RandomNumberGenerator)null);
                    auto seed = hexDecode(m["RngSeed"]);
                    krng.addEntropy(seed.ptr, seed.length);
                    ECGroup group = ECGroup(OIDS.lookup(m["KeyParams"]));
                    auto key = ECDSAPrivateKey(*krng, group);
                    auto got = pkcs8.BER_encode(*key);
                    if (got[] != hexDecode(m["Key"])[])
                    {
                        logError("ECDSA keygen HMAC_DRBG ", m["KeyParams"], " mismatch");
                        return 1;
                    }
                    return 0;
                }
                return 0;
            }
            catch (Exception e)
            {
                logTrace("ECDSA keygen skip ", m["KeyParams"], ": ", e.msg);
                return 0;
            }
        });

    File ecc_mul = File("test_data/pubkey/ecc.vec", "r");

    fails += runTestsBb(ecc_mul, "ECC Point Mult", "Y", false,
        (ref HashMap!(string, string) m)
        {
            return eccPointMul(m["Group"], m["m"], m["X"], m["Y"]);
        });

    File ecdsa_vfy = File("test_data/pubkey/ecdsa_verify.vec", "r");
    fails += runTestsBb(ecdsa_vfy, "ECDSA Verify", "Signature", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Group" in m) || !("Px" in m) || !("Py" in m) || !("Msg" in m) || !("Signature" in m))
                return 0;
            const bool expect_valid = !("Valid" in m) || m["Valid"] != "0";
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto px = BigInt(m["Px"]);
                auto py = BigInt(m["Py"]);
                auto pt = PointGFp(group.getCurve(), &px, &py);
                if (!pt.onTheCurve())
                    return expect_valid ? 1 : 0;
                auto pub = ECDSAPublicKey(group, pt);
                PKVerifier verify = PKVerifier(pub, "Raw");
                auto msg = hexDecode(m["Msg"]);
                const size_t nlen = group.getOrder().bytes();
                auto sig = hexDecode(m["Signature"]);
                if (sig.length < 2 * nlen)
                {
                    Vector!ubyte padded;
                    padded.resize(2 * nlen);
                    const size_t half = sig.length / 2;
                    const size_t r_off = nlen - half;
                    const size_t s_off = 2 * nlen - (sig.length - half);
                    foreach (i; 0 .. half)
                        padded[r_off + i] = sig[i];
                    foreach (i; 0 .. sig.length - half)
                        padded[s_off + i] = sig[half + i];
                    sig = padded.move();
                }
                const bool ok = verify.verifyMessage(msg, sig);
                if (ok != expect_valid)
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                if (!expect_valid)
                    return 0;
                logTrace("ECDSA verify skip ", m["Group"], ": ", e.msg);
                return 0;
            }
        });

    static if (BOTAN_HAS_RFC6979_GENERATOR)
    {
        File ecdsa_rfc = File("test_data/pubkey/ecdsa_rfc6979.vec", "r");
        fails += runTestsBb(ecdsa_rfc, "ECDSA RFC6979", "Signature", false,
            (ref HashMap!(string, string) m)
            {
                if (!("Group" in m) || !("X" in m) || !("Hash" in m) ||
                    !("Msg" in m) || !("Signature" in m))
                    return 0;
                return ecdsaRfc6979Kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Signature"]);
            });
    }

    File wy = File("test_data/pubkey/ecdsa_wycheproof.vec", "r");
    fails += runTestsBb(wy, "Group", "Valid", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Group" in m) || !("Px" in m) || !("Py" in m) ||
                !("Hash" in m) || !("Msg" in m) || !("Signature" in m) || !("Valid" in m))
                return 0;
            const bool expect_valid = m["Valid"] != "0";
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto px = BigInt(m["Px"]);
                auto py = BigInt(m["Py"]);
                auto pt = PointGFp(group.getCurve(), &px, &py);
                if (!pt.onTheCurve())
                    return expect_valid ? 1 : 0;
                auto pub = ECDSAPublicKey(group, pt);
                const string pad = "EMSA1(" ~ m["Hash"] ~ ")";
                PKVerifier verify = PKVerifier(pub, pad, DER_SEQUENCE);
                const bool ok = verify.verifyMessage(hexDecode(m["Msg"]), hexDecode(m["Signature"]));
                if (ok != expect_valid)
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                if (!expect_valid)
                    return 0;
                logTrace("ECDSA wycheproof skip ", m["Group"], "/", m["Hash"], ": ", e.msg);
                return 0;
            }
        });

    File ecdsa_inv = File("test_data/pubkey/ecdsa_invalid.vec", "r");
    fails += runTestsBb(ecdsa_inv, "ECDSA Invalid", "InvalidKeyY", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Group" in m) || !("InvalidKeyX" in m) || !("InvalidKeyY" in m))
                return 0;
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto px = BigInt(m["InvalidKeyX"]);
                auto py = BigInt(m["InvalidKeyY"]);
                auto pt = PointGFp(group.getCurve(), &px, &py);
                if (pt.onTheCurve())
                    return 1;
            }
            catch (Exception)
            {
            }
            return 0;
        });

    File kenc = File("test_data/pubkey/key_encoding.vec", "r");
    fails += runTestsBb(kenc, "KeyEncoding", "Key", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Key" in m))
                return 0;
            import botan.filters.data_src;
            import botan.pubkey.pkcs8;
            try
            {
                auto bits = hexDecode(m["Key"]);
                auto src = DataSourceMemory(bits);
                Unique!PrivateKey key = pkcs8.loadKey(cast(DataSource)src, *rng);
                if (!key)
                {
                    logError("key_encoding load returned null");
                    return 1;
                }
                if (!key.checkKey(*rng, false))
                {
                    logError("key_encoding checkKey failed ", key.algoName);
                    return 1;
                }
                return 0;
            }
            catch (Exception e)
            {
                logError("key_encoding: ", e.msg);
                return 1;
            }
        });

    File expl = File("test_data/pubkey/ecdsa_explicit.vec", "r");
    fails += runTestsBb(expl, "Group", "Key", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Key" in m) || !("Group" in m))
                return 0;
            try
            {
                import botan.filters.data_src;
                import botan.pubkey.pkcs8;
                auto bits = hexDecode(m["Key"]);
                auto src = DataSourceMemory(bits);
                Unique!PrivateKey key = pkcs8.loadKey(cast(DataSource)src, *rng);
                if (key.algoName != "ECDSA")
                    return 1;
                if (!key.checkKey(*rng, false))
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                logTrace("ECDSA explicit skip ", m["Group"], ": ", e.msg);
                return 0;
            }
        });

    File ecc_inv = File("test_data/pubkey/ecc_invalid.vec", "r");
    fails += runTestsBb(ecc_inv, "ECC Invalid", "SubjectPublicKey", false,
        (ref HashMap!(string, string) m)
        {
            if (!("SubjectPublicKey" in m))
                return 0;
            try
            {
                import botan.filters.data_src;
                import botan.pubkey.x509_key;
                auto bits = hexDecode(m["SubjectPublicKey"]);
                auto src = DataSourceMemory(bits);
                Unique!PublicKey key = x509_key.loadKey(cast(DataSource)src);
                if (key.checkKey(*rng, false))
                    return 1;
                return 0;
            }
            catch (Exception)
            {
                return 0;
            }
        });

    File bpm = File("test_data/pubkey/ecc_base_point_mul.vec", "r");
    fails += runTestsBb(bpm, "Group", "P", false,
        (ref HashMap!(string, string) m)
        {
            if (!("k" in m) || !("P" in m) || !("Group" in m))
                return 0;
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto k = BigInt(m["k"].length >= 2 && (m["k"][0..2] == "0x" || m["k"][0..2] == "0X")
                    ? m["k"] : ("0x" ~ m["k"]));
                auto got = group.getBasePoint() * &k;
                auto pb = hexDecode(m["P"]);
                auto exp = OS2ECP(pb, group.getCurve());
                if (got.getAffineX() != exp.getAffineX() || got.getAffineY() != exp.getAffineY())
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                logTrace("ECC base mul skip ", m["Group"], ": ", e.msg);
                return 0;
            }
        });

    import botan.utils.mem_ops : unlock;
    File vpm = File("test_data/pubkey/ecc_var_point_mul.vec", "r");
    fails += runTestsBb(vpm, "Group", "Z", false,
        (ref HashMap!(string, string) m)
        {
            if (!("P" in m) || !("k" in m) || !("Z" in m) || !("Group" in m))
                return 0;
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto pb = hexDecode(m["P"]);
                auto pt = OS2ECP(pb, group.getCurve());
                auto k = BigInt(m["k"].length >= 2 && (m["k"][0..2] == "0x" || m["k"][0..2] == "0X")
                    ? m["k"] : ("0x" ~ m["k"]));
                auto got = pt * &k;
                auto enc = unlock(EC2OSP(got, PointGFp.COMPRESSED));
                if (enc[] != hexDecode(m["Z"])[])
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                logTrace("ECC var mul skip ", m["Group"], ": ", e.msg);
                return 0;
            }
        });

    File vpm2 = File("test_data/pubkey/ecc_var_point_mul2.vec", "r");
    fails += runTestsBb(vpm2, "Group", "Z", false,
        (ref HashMap!(string, string) m)
        {
            if (!("P" in m) || !("x" in m) || !("Q" in m) || !("y" in m) ||
                !("Z" in m) || !("Group" in m))
                return 0;
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto p = OS2ECP(hexDecode(m["P"]), group.getCurve());
                auto q = OS2ECP(hexDecode(m["Q"]), group.getCurve());
                auto x = BigInt(m["x"].length >= 2 && (m["x"][0..2] == "0x" || m["x"][0..2] == "0X")
                    ? m["x"] : ("0x" ~ m["x"]));
                auto y = BigInt(m["y"].length >= 2 && (m["y"][0..2] == "0x" || m["y"][0..2] == "0X")
                    ? m["y"] : ("0x" ~ m["y"]));
                auto got = PointGFp.multiExponentiate(p, &x, q, &y);
                auto enc = unlock(EC2OSP(got, PointGFp.COMPRESSED));
                if (enc[] != hexDecode(m["Z"])[])
                    return 1;
                return 0;
            }
            catch (Exception e)
            {
                logTrace("ECC mul2 skip ", m["Group"], ": ", e.msg);
                return 0;
            }
        });

    File ecdsa_rec = File("test_data/pubkey/ecdsa_key_recovery.vec", "r");
    fails += runTestsBb(ecdsa_rec, "ECDSA Recovery", "Pubkey", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Group" in m) || !("R" in m) || !("S" in m) ||
                !("Msg" in m) || !("V" in m) || !("Pubkey" in m))
                return 0;
            try
            {
                ECGroup group = ECGroup(m["Group"]);
                auto r = BigInt(m["R"]);
                auto s = BigInt(m["S"]);
                auto msg = hexDecode(m["Msg"]);
                const ubyte v = to!ubyte(m["V"]);
                auto pub = ECDSAPublicKey(group, msg[], r, s, v);
                auto got = pub.publicValue();
                auto expect = hexDecode(m["Pubkey"]);
                if (got[] != expect[])
                {
                    logError("ecdsa recovery pubkey mismatch");
                    return 1;
                }
                if (pub.recoveryParam(msg[], r, s) != v)
                {
                    logError("ecdsa recovery param mismatch");
                    return 1;
                }
                PKVerifier verify = PKVerifier(pub, "Raw");
                const size_t nlen = group.getOrder().bytes();
                Vector!ubyte sig;
                sig.length = 2 * nlen;
                const size_t rb = r.bytes();
                const size_t sb = s.bytes();
                if (rb)
                    r.binaryEncode(&sig[nlen - rb]);
                if (sb)
                    s.binaryEncode(&sig[2 * nlen - sb]);
                if (!verify.verifyMessage(msg, sig))
                {
                    logError("ecdsa recovered key failed to verify");
                    return 1;
                }
                return 0;
            }
            catch (Exception e)
            {
                logError("ecdsa recovery ", m["Group"], ": ", e.msg);
                return 1;
            }
        });

    fails += checkMemutilsRepeat("ecdsa recover", {
        ECGroup group = ECGroup("secp256r1");
        auto r = BigInt("0x2AC979EB6C7502A49CACC0995A2B9C50192F334B742573767ADD6DCB01343D50");
        auto s = BigInt("0xF444D29AFCA529A0A96467DAA5E881B1C60C73273E099DF7C910BD4EED0502D6");
        auto msg = hexDecode("3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E");
        auto pub = ECDSAPublicKey(group, msg[], r, s, 1);
        if (pub.recoveryParam(msg[], r, s) != 1)
            throw new Exception("ecdsa recover leak probe");
    });

    fails += checkMemutilsRepeat("ecdsa verify", {
        ECGroup group = ECGroup("secp256r1");
        auto key = ECDSAPrivateKey(*rng, group);
        PKSigner sign = PKSigner(*key, "EMSA1(SHA-256)");
        PKVerifier vfy = PKVerifier(*key, "EMSA1(SHA-256)");
        auto msg = hexDecode("616263");
        auto sig = sign.signMessage(msg, *rng);
        if (!vfy.verifyMessage(msg, sig))
            throw new Exception("ecdsa leak probe");
    });

    fails += checkMemutilsRepeat("ecc var mul", {
        ECGroup group = ECGroup("secp256r1");
        auto k = BigInt("0x2");
        auto got = group.getBasePoint() * &k;
        auto enc = unlock(EC2OSP(got, PointGFp.COMPRESSED));
        if (enc.length < 2)
            throw new Exception("ecc var mul leak probe");
    });

    testReport("ECDSA", total_tests, fails);

}
