/**
* DL Scheme
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.dl_algo;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.pubkey.algo.dl_group;
public import botan.pubkey.pubkey;
import botan.utils.mem_ops;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* This class represents discrete logarithm (DL) public keys.
*/
class DLSchemePublicKey : PublicKey
{
public:
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {    
        return (cast(DLSchemePublicKey)this).checkKey(rng, strong);
    }

    final bool checkKey(RandomNumberGenerator rng, bool strong)
    {
        if (m_y < 2 || m_y >= groupP())
            return false;
        if (!m_group.verifyGroup(rng, strong))
            return false;
        return true;
    }

    final void decodeOptions(T)(in T options) {
        static if (__traits(hasMember, T, "checkKey"))
            m_check_key = &options.checkKey;
        static if (__traits(hasMember, T, "msgParts"))
            m_msg_parts = options.msgParts;

        static if (__traits(hasMember, T, "format"))
            m_format = options.format;
        else static assert(false, "No format found in " ~ T.stringof);
    
        static if (__traits(hasMember, T, "algoName"))
            m_algo_name = options.algoName;
        else static assert(false, "No algoName found in " ~ T.stringof);

    }

    /// Used for object casting to the right type in the factory.
    final override @property string algoName() const {
        return m_algo_name;
    }

    final override size_t messageParts() const {
        return m_msg_parts;
    }

    final override size_t maxInputBits() const {
        if (m_msg_parts == 1 && algoName != "DH" && algoName != "ElGamal") 
            return 0;

        if (algoName == "NR" || algoName == "ElGamal")
            return groupQ().bits() - 1;

        return groupQ().bits();
    }

    final size_t messagePartSize() const { 
        if (m_msg_parts == 1) return 0; 
        return groupQ().bytes(); 
    }

    final AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(getOid(), m_group.DER_encode(m_format));
    }

    final Vector!ubyte x509SubjectPublicKey() const
    {
        return DEREncoder().encode(m_y).getContentsUnlocked();
    }

    /*
    * Return the public value for key agreement
    */
    Vector!ubyte publicValue() const
    {
        return unlock(BigInt.encode1363(getY(), groupP().bytes()));
    }

    /**
    * Get the DL domain parameters of this key.
    * Returns: DL domain parameters of this key
    */
    final ref const(DLGroup) getDomain() const { return m_group; }

    /**
    * Get the public value m_y with m_y = g^m_x mod p where m_x is the secret key.
    */
    final ref const(BigInt) getY() const { return m_y; }

    /**
    * Set the value m_y
    */
    final void setY(BigInt y) { m_y = y.move(); }

    /**
    * Get the prime p of the underlying DL m_group.
    * Returns: prime p
    */
    final ref const(BigInt) groupP() const { return m_group.getP(); }

    /**
    * Get the prime q of the underlying DL m_group.
    * Returns: prime q
    */
    final ref const(BigInt) groupQ() const { return m_group.getQ(); }

    /**
    * Get the generator g of the underlying DL m_group.
    * Returns: generator g
    */
    final ref const(BigInt) groupG() const { return m_group.getG(); }

    override final size_t estimatedStrength() const
    {
        return dlWorkFactor(m_group.getP().bits());
    }

    this(T)(in T options,
            in AlgorithmIdentifier alg_id, 
            auto const ref SecureVector!ubyte key_bits)
    {
        decodeOptions(options);
        m_group.BER_decode(alg_id.parameters, m_format);
        BERDecoder(key_bits).decode(m_y);
    }

    this(T)(in T options, DLGroup grp, BigInt y1)
    {
        decodeOptions(options);
        m_group = grp.move;
        m_y = y1.move;
    }

protected:
    /**
    * The DL public key
    */
    BigInt m_y;

    /**
    * The DL group
    */
    DLGroup m_group;

    /// options
    DLGroup.Format m_format;
    string m_algo_name;
    short m_msg_parts = 1;
    bool function(in DLSchemePrivateKey, RandomNumberGenerator, bool) m_check_key;
}

/**
* This class represents discrete logarithm (DL) private keys.
*/
final class DLSchemePrivateKey : DLSchemePublicKey, PrivateKey, PKKeyAgreementKey
{
public:

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return super.algorithmIdentifier(); }

    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_check_key)
            return m_check_key(this, rng, strong);

        return checkKeyImpl(rng, strong);
    }

    final bool checkKeyImpl(RandomNumberGenerator rng, bool strong) const 
    {
        const BigInt* p = &groupP();
        const BigInt* g = &groupG();
        if (m_y < 2 || m_y >= *p || m_x < 2 || m_x >= *p) {
            return false;
        }
        if (!m_group.verifyGroup(rng, strong)) {
            return false;
        }
        
        if (!strong)
            return true;
        
        if (m_y != powerMod(*g, m_x, *p)) 
        {        
            return false;
        }
        return true;
    }

    /**
    * Get the secret key m_x.
    * Returns: secret key
    */
    ref const(BigInt) getX() const { return m_x; }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder().encode(m_x).getContents();
    }

    this(T)(in T options, in AlgorithmIdentifier alg_id,
             const ref SecureVector!ubyte key_bits)
    {
        BERDecoder(key_bits).decode(m_x);
        DLGroup grp;
        grp.BER_decode(alg_id.parameters, options.format);
        BigInt y = powerMod(grp.getG(), m_x, grp.getP());
        super(options, grp.move, y.move);
    }

    this(T)(in T options, 
            DLGroup grp, 
            BigInt y1, BigInt x_arg)
    {
        //logTrace("grp: ", grp.toString());
        m_x = x_arg.move;
        //logTrace("x: ", m_x.toString());
        super(options, grp.move, y1.move);
    }

    /*
    * Return the public value for key agreement
    */
    override Vector!ubyte publicValue() const
    {
        return super.publicValue();
    }


package:
    /**
    * The DL private key
    */
    BigInt m_x;
}