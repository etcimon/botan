/**
* ECDSA
* 
* Copyright:
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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
    this(in ECGroup dom_par, in PointGFp public_point) 
    {
        m_pub = new ECPublicKey(Options(), dom_par, public_point);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        m_pub = new ECPublicKey(Options(), alg_id, key_bits);
    }

    this(in PublicKey pkey) {
        m_pub = cast(ECPublicKey) pkey;
    }

    this(in PrivateKey pkey) {
        m_pub = cast(ECPublicKey) pkey;
    }

    mixin Embed!m_pub;

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
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits);
    }

    /**
    * Generate a new private key
    * Params:
    *  rng = a random number generator
    *  domain = parameters to used for this key
    *  x = the private key (if zero, generate a ney random key)
    */
    this()(RandomNumberGenerator rng, auto const ref ECGroup domain, BigInt x = 0)
    {
        m_priv = new ECPrivateKey(Options(), rng, domain, x);
    }

    this(in PrivateKey pkey) { 
        m_priv = cast(ECPrivateKey)pkey;
    }

    mixin Embed!m_priv;

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
        m_base_point = &ecdsa.domain().getBasePoint();
        m_order = &ecdsa.domain().getOrder();
        m_x = &ecdsa.privateValue();
        m_mod_order = ModularReducer(*m_order);
    }

    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        logTrace("ECDSA Sign operation");
        rng.addEntropy(msg, msg_len);
        
        BigInt m = BigInt(msg, msg_len);
        
        BigInt r = 0, s = 0;
        
        while (r == 0 || s == 0)
        {
            // This contortion is necessary for the tests
            BigInt k;
            k.randomize(rng, m_order.bits());
            
            while (k >= *m_order)
                k.randomize(rng, m_order.bits() - 1);
            PointGFp k_times_P = (*m_base_point) * k;
            assert(k_times_P.onTheCurve());
            r = m_mod_order.reduce(k_times_P.getAffineX());
            s = m_mod_order.multiply(inverseMod(k, *m_order), mulAdd(*m_x, r, m));

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
        m_base_point = &ecdsa.domain().getBasePoint();
        m_public_point = &ecdsa.publicPoint();
        m_order = &ecdsa.domain().getOrder();
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

    override bool withRecovery() const { return false; }

    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t) { throw new InvalidState("Message recovery not supported"); }
    override bool verify(const(ubyte)* msg, size_t msg_len,
                         const(ubyte)* sig, size_t sig_len)
    {
        logTrace("ECDSA Verification");
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
        
        BigInt w = inverseMod(s, *m_order);
        auto r_1 = PointGFp.multiExponentiate(*m_base_point, e, *m_public_point, r);
        assert(r_1.onTheCurve());
        PointGFp R = r_1 * w;
        assert(R.onTheCurve());
        if (R.isZero()) 
            return false;
        return (R.getAffineX() % (*m_order) == r);
    }

private:
    const PointGFp* m_base_point;
    const PointGFp* m_public_point;
    const BigInt* m_order;
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
    X509Certificate cert = X509Certificate("../test_data/ecc/CSCA.CSCA.csca-germany.1.crt");
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
    X509Certificate root_cert = X509Certificate("../test_data/ecc/root2_SHA256.cer");
    X509Certificate link_cert = X509Certificate("../test_data/ecc/link_SHA256.cer");
    
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
    X509Certificate root_cert = X509Certificate("../test_data/ecc/root_SHA1.163.crt");
    X509Certificate link_cert = X509Certificate("../test_data/ecc/link_SHA1.166.crt");
    
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
        RSAPrivateKey rsa_key = RSAPrivateKey(rng, 1024);

        //RSAPrivateKey rsa_key2(1024);
        //cout " ~\nequal: " ~  (rsa_key == rsa_key2));
        //DSAPrivateKey key(DLGroup("dsa/jce/1024"));

        File rsa_priv_key = File("../test_data/ecc/rsa_private.pkcs8.pem", "wb+");
        rsa_priv_key.write(pkcs8.PEM_encode(rsa_key));
        
        ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
        auto key = ECDSAPrivateKey(rng, dom_pars);
        
        // later used by other tests :(
        File priv_key = File("../test_data/ecc/wo_dompar_private.pkcs8.pem", "wb+");
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
    File priv_key = File("../test_data/ecc/dompar_private.pkcs8.pem", "w+");
    priv_key.write( pkcs8.PEM_encode(key) );
    
    Unique!PKCS8PrivateKey loaded_key = pkcs8.loadKey("../test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
    ECDSAPrivateKey loaded_ec_key = ECDSAPrivateKey(*loaded_key);
    mixin( CHECK_MESSAGE( `loaded_ec_key`, "the loaded key could not be converted into an ECDSAPrivateKey" ) );
    Unique!PKCS8PrivateKey loaded_key_1 = pkcs8.loadKey("../test_data/ecc/rsa_private.pkcs8.pem", rng);
    ECDSAPrivateKey loaded_rsa_key = ECDSAPrivateKey(*loaded_key_1);
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
    CurveGFp curve = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, curve );
    auto bi = BigInt(1);
    ECGroup dom_params = ECGroup(curve, p_G, bi_order_g, bi);
    if (!p_G.onTheCurve())
        throw new InternalError("Point not on the curve");
    
    auto key_odd_oid = ECDSAPrivateKey(rng, dom_params);
    string key_odd_oid_str = pkcs8.PEM_encode(key_odd_oid);
    auto key_data_src = DataSourceMemory(key_odd_oid_str);
    Unique!PKCS8PrivateKey loaded_key2 = pkcs8.loadKey(cast(DataSource)key_data_src, rng);
    
    if (!ECDSAPrivateKey(*loaded_key))
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
        Unique!PKCS8PrivateKey loaded_key = pkcs8.loadKey("../test_data/ecc/wo_dompar_private.pkcs8.pem", rng);
        ECDSAPrivateKey ecdsa = ECDSAPrivateKey(*loaded_key);
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
        Unique!PKCS8PrivateKey loaded_key_nodp = pkcs8.loadKey("../test_data/ecc/nodompar_private.pkcs8.pem", rng);
        // anew in each test with unregistered domain-parameters
        ECDSAPrivateKey ecdsa_nodp = ECDSAPrivateKey(*loaded_key_nodp);
        mixin( CHECK_MESSAGE( `ecdsa_nodp`, "the loaded key could not be converted into an ECDSAPrivateKey" ) );
        
        PKSigner signer = PKSigner(ecdsa_nodp, "EMSA1(SHA-1)");
        PKVerifier verifier = PKVerifier(ecdsa_nodp, "EMSA1(SHA-1)");
        
        Vector!ubyte signature_nodp = signer.signMessage(msg, rng);
        
        mixin( CHECK_MESSAGE(`verifier.verifyMessage(msg, signature_nodp)`,
                             "generated signature could not be verified positively (no_dom)"));
        
        try
        {
            Unique!PKCS8PrivateKey loaded_key_withdp = pkcs8.loadKey("../test_data/ecc/withdompar_private.pkcs8.pem", rng);
            
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
        Unique!PKCS8PrivateKey pkcs8 = pkcs8.loadKey("../test_data/ecc/ecc_private_with_rfc5915_ext.pem", rng);
        
        if (!ECDSAPrivateKey(*pkcs8))
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
    auto rng = AutoSeededRNG();
    
    ECGroup group = ECGroup(OIDS.lookup(group_id));
    auto bx =  BigInt(x);
    auto ecdsa = ECDSAPrivateKey(*rng, group, bx.move());
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier verify = PKVerifier(*ecdsa, padding);
    PKSigner sign = PKSigner(*ecdsa, padding);
    
    return validateSignature(verify, sign, "DSA/" ~ hash, msg, *rng, nonce, signature);
}

static if (!SKIP_ECDSA_TEST) unittest
{
    logDebug("Testing ecdsa.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    static if (BOTAN_HAS_X509_CERTIFICATES) {
        fails += testDecodeEcdsaX509();
        fails += testDecodeVerLinkSHA256();
        fails += testDecodeVerLinkSHA1();
    }

    fails += testCurveRegistry(rng);
    fails += testHashLargerThanN(rng);
    fails += testSignThenVer(rng);
    fails += testEcSign(rng);

    static if (BOTAN_HAS_RSA) {
        fails += testCreatePkcs8(rng);
        fails += testCreateAndVerify(rng);
    }

    fails += testReadPkcs8(rng);
    fails += testEccKeyWithRfc5915Extensions(rng);

    fails += testPkKeygen(rng);

    File ecdsa_sig = File("../test_data/pubkey/ecdsa.vec", "r");

    fails += runTestsBb(ecdsa_sig, "ECDSA Signature", "Signature", true,
        (ref HashMap!(string, string) m) {
            return ecdsaSigKat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
        });


    testReport("ECDSA", total_tests, fails);

}
