/**
* IF Scheme
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.if_algo;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.pubkey.pubkey;
import botan.math.bigint.bigint;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IFSchemePublicKey : PublicKey
{
public:
    this(T)(in T options, in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        decodeOptions(options);
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_n)
                .decode(m_e)
                .verifyEnd()
                .endCons();
    }

    this(T)(in T options, auto ref BigInt n, auto ref BigInt e)
    {
        decodeOptions(options);
        m_n = n.move();
        m_e = e.move(); 
    }

    final void decodeOptions(T)(in T options) {
        static if (__traits(hasMember, T, "checkKey"))
            m_check_key = &options.checkKey;
        static if (__traits(hasMember, T, "algoName"))
            m_algo_name = options.algoName;
        else static assert(false, "No algoName found in " ~ T.stringof);
    }


    /// Used for object casting to the right type in the factory.
    final override @property string algoName() const {
        return m_algo_name;
    }

    /*
    * Check IF Scheme Public Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_n < 35 || m_n.isEven() || m_e < 2)
            return false;
        return true;
    }


    final AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(getOid(), AlgorithmIdentifierImpl.USE_NULL_PARAM);
    }

    final Vector!ubyte x509SubjectPublicKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(m_n)
                .encode(m_e)
                .endCons()
                .getContentsUnlocked();
    }

    /**
    * Returns: public modulus
    */
    final ref const(BigInt) getN() const { return m_n; }

    /**
    * Returns: public exponent
    */
    final ref const(BigInt) getE() const { return m_e; }

    final size_t maxInputBits() const { return (m_n.bits() - 1); }

    final override size_t messagePartSize() const {
        return 0;
    }

    final override size_t messageParts() const {
        return 1;
    }

    override final size_t estimatedStrength() const
    {
        return dlWorkFactor(m_n.bits());
    }

protected:
    BigInt m_n, m_e;

    // options
    string m_algo_name;
    bool function(in IFSchemePrivateKey, RandomNumberGenerator, bool) m_check_key;
}

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
final class IFSchemePrivateKey : IFSchemePublicKey, PrivateKey
{
public:
    this(T)(in T options, RandomNumberGenerator rng, 
            in AlgorithmIdentifier aid, const ref SecureVector!ubyte key_bits)
    {
        BigInt n, e;
        BERDecoder(key_bits).startCons(ASN1Tag.SEQUENCE)
            .decodeAndCheck!size_t(0, "Unknown PKCS #1 key format version")
            .decode(n)
            .decode(e)
            .decode(m_d)
            .decode(m_p)
            .decode(m_q)
            .decode(m_d1)
            .decode(m_d2)
            .decode(m_c)
            .endCons();
        
        super(options, n, e);

        loadCheck(rng);
    }

    this(T)(in T options,
            RandomNumberGenerator rng,
            BigInt prime1,
            BigInt prime2,
            BigInt exp,
            BigInt d_exp,
            BigInt mod)
    {
        m_p = prime1.move();
        m_q = prime2.move();
        BigInt n = mod.isNonzero() ? mod.move() : m_p * m_q;
        super(options, n.move(), exp.move()); // defines m_e and m_n

        m_d = d_exp.move();
        
        if (m_d == 0)
        {
            BigInt inv_for_d = lcm(m_p - 1, m_q - 1);
            if (m_e.isEven())
                inv_for_d >>= 1;
            
            m_d = inverseMod(m_e, inv_for_d);
        }
        
        m_d1 = m_d % (m_p - 1);
        m_d2 = m_d % (m_q - 1);
        m_c = inverseMod(m_q, m_p);

        loadCheck(rng);

    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return super.algorithmIdentifier(); }

    /*
    * Check IF Scheme Private Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_check_key) 
            return m_check_key(this, rng, strong);
        return checkKeyImpl(rng, strong);
    }

    final bool checkKeyImpl(RandomNumberGenerator rng, bool strong) const 
    {        
        if (m_n < 35 || m_n.isEven() || m_e < 2 || m_d < 2 || m_p < 3 || m_q < 3 || m_p*m_q != m_n)
            return false;
        
        if (m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverseMod(m_q, m_p))
            return false;
        
        const size_t prob = (strong) ? 56 : 12;
        
        if (!isPrime(m_p, rng, prob) || !isPrime(m_q, rng, prob))
            return false;
        return true;
    }

    /**
    * Get the first prime p.
    * Returns: prime p
    */
    ref const(BigInt) getP() const { return m_p; }

    /**
    * Get the second prime q.
    * Returns: prime q
    */
    ref const(BigInt) getQ() const { return m_q; }

    /**
    * Get d with exp * d = 1 mod (p - 1, q - 1).
    * Returns: d
    */
    ref const(BigInt) getD() const { return m_d; }

    ref const(BigInt) getC() const { return m_c; }
    ref const(BigInt) getD1() const { return m_d1; }
    ref const(BigInt) getD2() const { return m_d2; }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(cast(size_t)(0))
                .encode(m_n)
                .encode(m_e)
                .encode(m_d)
                .encode(m_p)
                .encode(m_q)
                .encode(m_d1)
                .encode(m_d2)
                .encode(m_c)
                .endCons()
                .getContents();
    }

protected:
    BigInt m_d, m_p, m_q, m_d1, m_d2, m_c;
}