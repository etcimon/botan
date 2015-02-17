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
module botan.pubkey.algo.ecc_key;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && (BOTAN_HAS_ECDH || BOTAN_HAS_ECDSA || BOTAN_HAS_GOST_34_10_2001)):

public import botan.pubkey.pubkey;
public import botan.pubkey.algo.ec_group;
public import botan.math.numbertheory.numthry;
public import botan.math.ec_gfp.curve_gfp;
public import botan.math.ec_gfp.point_gfp;
public import botan.pubkey.pk_keys;
public import botan.pubkey.x509_key;
import botan.rng.rng;
import botan.pubkey.pkcs8;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import memutils.vector;
import botan.utils.mem_ops;
import botan.utils.exceptn;

/**
* This class represents abstract ECC public keys. When encoding a key
* via an encoder that can be accessed via the corresponding member
* functions, the key will decide upon its internally stored encoding
* information whether to encode itself with or without domain
* parameters, or using the domain parameter oid. Furthermore, a public
* key without domain parameters can be decoded. In that case, it
* cannot be used for verification until its domain parameters are set
* by calling the corresponding member function.
*/
class ECPublicKey : PublicKey
{
public:
    this(T)(in T options, const ref ECGroup dom_par, const ref PointGFp pub_point) 
    {
        decodeOptions(options);

        m_domain_params = dom_par.dup;
        m_public_key = pub_point.dup;
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

        if (domain().getCurve() != publicPoint().getCurve())
            throw new InvalidArgument("ECPublicKey: curve mismatch in constructor");
    }

    this(T)(in T options, in AlgorithmIdentifier alg_id, 
        const ref SecureVector!ubyte key_bits) 
    {
        decodeOptions(options);

        m_domain_params = ECGroup(alg_id.parameters);
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        m_public_key = OS2ECP(key_bits, domain().getCurve());
    }

    protected this(T)(in T options, in AlgorithmIdentifier alg_id) 
    {
        decodeOptions(options);
        //logTrace("ECGroup with alg_id.parameters");
        m_domain_params = ECGroup(alg_id.parameters);
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
    }

    final void decodeOptions(T)(in T options) {
        static if (__traits(hasMember, T, "checkKey"))
            m_check_key = &options.checkKey;
        static if (__traits(hasMember, T, "algorithmIdentifier"))
            m_algorithm_identifier = &options.algorithmIdentifier;
        static if (__traits(hasMember, T, "x509SubjectPublicKey"))
            m_subject_public_key = &options.x509SubjectPublicKey;
        static if (__traits(hasMember, T, "msgParts"))
            m_msg_parts = options.msgParts;
        static if (__traits(hasMember, T, "algoName"))
            m_algo_name = options.algoName;
        else static assert(false, "No algoName found in " ~ T.stringof);
    }

    /// Used for object casting to the right type in the factory.
    final override @property string algoName() const {
        return m_algo_name;
    }

    /**
    * Get the public point of this key.
    * Throws: $(D InvalidState) is thrown if the
    * domain parameters of this point are not set
    * Returns: the public point of this key
    */
    final ref const(PointGFp) publicPoint() const { return m_public_key; }

    final override size_t maxInputBits() const { return domain().getOrder().bits(); }

    final override size_t messagePartSize() const { 
        if (m_msg_parts == 1) return 0;

        return domain().getOrder().bytes(); 
    }

    final override size_t messageParts() const { return m_msg_parts; }

    final override AlgorithmIdentifier algorithmIdentifier() const
    {
        if (m_algorithm_identifier)
            return m_algorithm_identifier(this);
        return AlgorithmIdentifier(getOid(), DER_domain());
    }

    final override Vector!ubyte x509SubjectPublicKey() const
    {
        if (m_subject_public_key)
            return m_subject_public_key(this);
        return unlock(EC2OSP(publicPoint(), PointGFp.COMPRESSED));
    }

    override bool checkKey(RandomNumberGenerator rng, bool b) const
    {
        return publicPoint().onTheCurve();
    }

    /**
    * Get the domain parameters of this key.
    * Throws: $(D InvalidState) is thrown if the domain parameters of this point are not set
    * Returns: the domain parameters of this key
    */
    final ref const(ECGroup) domain() const { return m_domain_params; }

    /**
    * Set the domain parameter encoding to be used when encoding this key.
    *
    * Params:
    *  enc = the encoding to use
    */
    final void setParameterEncoding(ECGroupEncoding form)
    {
        if (form != EC_DOMPAR_ENC_EXPLICIT && form != EC_DOMPAR_ENC_IMPLICITCA && form != EC_DOMPAR_ENC_OID)
            throw new InvalidArgument("Invalid encoding form for EC-key object specified");
        
        if ((form == EC_DOMPAR_ENC_OID) && (m_domain_params.getOid() == ""))
            throw new InvalidArgument("Invalid encoding form OID specified for "
                                       ~ "EC-key object whose corresponding domain "
                                       ~ "parameters are without oid");
        
        m_domain_encoding = form;
    }

    /**
    * Return the DER encoding of this keys domain in whatever format
    * is preset for this particular key
    */
    Vector!ubyte DER_domain() const { return domain().DER_encode(domainFormat()); }

    /**
    * Get the domain parameter encoding to be used when encoding this key.
    * Returns: the encoding to use
    */
    ECGroupEncoding domainFormat() const { return m_domain_encoding; }

    override size_t estimatedStrength() const
    {
        return domain().getCurve().getP().bits() / 2;
    }

    /**
    * Returns: public point value
    */
    Vector!ubyte publicValue() const
    { return unlock(EC2OSP(publicPoint(), PointGFp.UNCOMPRESSED)); }
protected:

    ECGroup m_domain_params;
    PointGFp m_public_key;
    ECGroupEncoding m_domain_encoding;

    string m_algo_name;
    short m_msg_parts = 1;
    bool function(in ECPrivateKey, RandomNumberGenerator, bool) m_check_key;
    Vector!ubyte function(in ECPublicKey) m_subject_public_key;
    AlgorithmIdentifier function(in ECPublicKey) m_algorithm_identifier;
}

/**
* This abstract class represents ECC private keys
*/
final class ECPrivateKey : ECPublicKey, PrivateKey, PKKeyAgreementKey
{
public:
    /**
    * ECPrivateKey constructor
    */
    this(T)(in T options, RandomNumberGenerator rng, const ref ECGroup ec_group, const ref BigInt private_key) 
    {
        if (private_key == 0) {
            auto bi = BigInt(1);
            m_private_key = BigInt.randomInteger(rng, bi, ec_group.getOrder());
        }
        else
            m_private_key = private_key.dup;

        PointGFp public_key = ec_group.getBasePoint() * m_private_key;
        
        assert(public_key.onTheCurve(), "Generated public key point was on the curve");

        // logTrace("private key: ", m_private_key.toString());
        super(options, ec_group, public_key);
    }

    this(T)(in T options, const ref AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
    {
        super(options, alg_id);
        PointGFp public_key;
        OID key_parameters = OID();

        SecureVector!ubyte public_key_bits;
        
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeAndCheck!size_t(1, "Unknown version code for ECC key")
                .decodeOctetStringBigint(m_private_key)
                .decodeOptional(key_parameters, (cast(ASN1Tag) 0), ASN1Tag.PRIVATE, key_parameters)
                .decodeOptionalString(public_key_bits, ASN1Tag.BIT_STRING, 1, ASN1Tag.PRIVATE)
                .endCons();
        if (!key_parameters.empty && key_parameters != alg_id.oid)
            throw new DecodingError("ECPrivateKey - inner and outer OIDs did not match");

        if (public_key_bits.empty)
        {
            m_public_key = domain().getBasePoint() * m_private_key;
            assert(m_public_key.onTheCurve(), "Public point derived from loaded key was on the curve");
        }
        else
        {
            m_public_key = OS2ECP(public_key_bits, m_domain_params.getCurve());
            // OS2ECP verifies that the point is on the curve
        }
    }

    override bool checkKey(RandomNumberGenerator rng, bool b) const
    {
        if (m_check_key)
            return m_check_key(this, rng, b);
        
        return super.checkKey(rng, b);
    }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(cast(size_t)(1))
                .encode(BigInt.encode1363(m_private_key, m_private_key.bytes()),
                        ASN1Tag.OCTET_STRING)
                .endCons()
                .getContents();
    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { 
        if (algoName() == "GOST-34.10")
            return AlgorithmIdentifier(getOid(), DER_domain());
        return super.algorithmIdentifier();
    }

    /**
    * Get the private key value of this key object.
    * Returns: the private key value of this key object
    */
    ref const(BigInt) privateValue() const
    {
        if (m_private_key == 0)
            throw new InvalidState("ECPrivateKey.private_value - uninitialized");
        
        return m_private_key;
    }

    override Vector!ubyte publicValue() const { return super.publicValue(); }

private:
    BigInt m_private_key;
}