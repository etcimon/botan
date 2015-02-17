/**
* ECDH
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
module botan.pubkey.algo.ecdh;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECDH):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.math.bigint.bigint;
import memutils.helpers : Embed;

struct ECDHOptions {
    enum algoName = "ECDH";
    enum msgParts = 1;
}

/**
* This class represents ECDH Public Keys.
*/
struct ECDHPublicKey
{
public:
    alias Options = ECDHOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    { 
        m_pub = new ECPublicKey(Options(), alg_id, key_bits);
    }

    /**
    * Construct a public key from a given public point.
    *
    * Params:
    *  dom_par = the domain parameters associated with this key
    *  public_point = the public point defining this key
    */
    this()(auto const ref ECGroup dom_par, auto const ref PointGFp public_point) 
    {
        m_pub = new ECPublicKey(Options(), dom_par, public_point);
    }

    this(PrivateKey pkey) { m_pub = cast(ECPublicKey) pkey; }
    this(PublicKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    mixin Embed!m_pub;

    ECPublicKey m_pub;
}

/**
* This class represents ECDH Private Keys.
*/
struct ECDHPrivateKey
{
public:
    alias Options = ECDHOptions;
    __gshared immutable string algoName = Options.algoName;

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        m_priv = new ECPrivateKey(Options(), alg_id, key_bits);
    }

    /**
    * Generate a new private key
    * Params:
    *  rng = a random number generator
    *  domain = parameters to used for this key
    *  x = the private key; if zero, a new random key is generated
    */
    this(RandomNumberGenerator rng, const ref ECGroup domain, BigInt x = BigInt(0)) 
    {
        m_priv = new ECPrivateKey(Options(), rng, domain, x);
    }

    this(RandomNumberGenerator rng, const ref ECGroup domain) { auto bi = BigInt(0); this(rng, domain, bi.move()); }

    this(PrivateKey pkey) { m_priv = cast(ECPrivateKey) pkey; }

    mixin Embed!m_priv;

    ECPrivateKey m_priv;

}

/**
* ECDH operation
*/
final class ECDHKAOperation : KeyAgreement
{
public:
    this(in PrivateKey pkey) {
        this(cast(ECPrivateKey) pkey);
    }

    this(in ECDHPrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in ECPrivateKey key) 
    {
        m_curve = &key.domain().getCurve();
        m_cofactor = &key.domain().getCofactor();
        m_l_times_priv = inverseMod(*m_cofactor, key.domain().getOrder()) * key.privateValue();
    }

    override SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
    {
        PointGFp point = OS2ECP(w, w_len, *m_curve);
        
        PointGFp S = (point * (*m_cofactor)) * m_l_times_priv;

        assert(S.onTheCurve(), "ECDH agreed value was on the curve");
        
        return BigInt.encode1363(S.getAffineX(),
                                  m_curve.getP().bytes());
    }
private:
    const CurveGFp* m_curve;
    const BigInt* m_cofactor;
    BigInt m_l_times_priv;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.pubkey;
import botan.cert.x509.x509self;
import botan.asn1.der_enc;
import botan.rng.auto_rng;
import core.atomic : atomicOp;
shared(size_t) total_tests;

size_t testEcdhNormalDerivation(RandomNumberGenerator rng)
{
    size_t fails = 0;
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));


    ECDHPrivateKey private_a = ECDHPrivateKey(rng, dom_pars);
    
    ECDHPrivateKey private_b = ECDHPrivateKey(rng, dom_pars); //public_a.getCurve()
    
    auto ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
    auto kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
    
    SymmetricKey alice_key = ka.deriveKey(32, private_b.publicValue());
    SymmetricKey bob_key = kb.deriveKey(32, private_a.publicValue());
    // 1 test
    if (alice_key != bob_key)
    {
        logError("The two keys didn't match!");
        logDebug("Alice's key was: " ~ alice_key.toString());
        logDebug("Bob's key was: " ~ bob_key.toString());
        atomicOp!"+="(total_tests, cast(size_t)1);
        ++fails;
    }

    return fails;
}

size_t testEcdhSomeDp(RandomNumberGenerator rng)
{
    size_t fails = 0;
    
    Vector!string oids;
    oids.pushBack("1.2.840.10045.3.1.7");
    oids.pushBack("1.3.132.0.8");
    oids.pushBack("1.2.840.10045.3.1.1");
    // 3 tests
    foreach (oid_str; oids[])
    {
        OID oid = OID(oid_str);
        ECGroup dom_pars = ECGroup(oid);
        
        ECDHPrivateKey private_a = ECDHPrivateKey(rng, dom_pars);
        ECDHPrivateKey private_b = ECDHPrivateKey(rng, dom_pars);
        
        auto ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
        auto kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
        
        SymmetricKey alice_key = ka.deriveKey(32, private_b.publicValue());
        SymmetricKey bob_key = kb.deriveKey(32, private_a.publicValue());
        
        mixin( CHECK_MESSAGE( `alice_key == bob_key`, "different keys - Alice s key was: ` ~ alice_key.toString() ~ `, Bob's key was: ` ~ bob_key.toString() ~ `" ) );
    }
    
    return fails;
}

size_t testEcdhDerDerivation(RandomNumberGenerator rng)
{
    size_t fails = 0;
    
    Vector!string oids;
    oids.pushBack("1.2.840.10045.3.1.7");
    oids.pushBack("1.3.132.0.8");
    oids.pushBack("1.2.840.10045.3.1.1");
    // 3 tests
    foreach (oid_str; oids[])
    {
        OID oid = OID(oid_str);
        ECGroup dom_pars = ECGroup(oid);
        
        auto private_a = ECDHPrivateKey(rng, dom_pars);
        auto private_b = ECDHPrivateKey(rng, dom_pars);
        
        Vector!ubyte key_a = private_a.publicValue();
        Vector!ubyte key_b = private_b.publicValue();
        
        auto ka = scoped!PKKeyAgreement(private_a, "KDF2(SHA-1)");
        auto kb = scoped!PKKeyAgreement(private_b, "KDF2(SHA-1)");
        
        SymmetricKey alice_key = ka.deriveKey(32, key_b);
        SymmetricKey bob_key = kb.deriveKey(32, key_a);
        
        mixin( CHECK_MESSAGE( `alice_key == bob_key`, "different keys - Alice's key was: ` ~ alice_key.toString() ~ `, Bob's key was: ` ~ bob_key.toString() ~ `" ) );
        
    }
    
    return fails;
}

static if (!SKIP_ECDH_TEST) unittest
{
    logDebug("Testing ecdh.d ...");
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    fails += testEcdhNormalDerivation(rng);
    fails += testEcdhSomeDp(rng);
    fails += testEcdhDerDerivation(rng);
    
    testReport("ECDH", total_tests, fails);
}