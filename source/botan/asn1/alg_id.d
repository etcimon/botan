/**
* Algorithm Identifier
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.alg_id;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;

alias AlgorithmIdentifier = RefCounted!AlgorithmIdentifierImpl;

/**
* Algorithm Identifier
*/
final class AlgorithmIdentifierImpl : ASN1Object
{
public:
    alias EncodingOption = bool;
    enum : EncodingOption { USE_NULL_PARAM }

    /*
    * DER encode an AlgorithmIdentifier
    */
    override void encodeInto(ref DEREncoder codec) const
    {
        //logTrace("encoding OID: ", m_oid.toString());
        codec.startCons(ASN1Tag.SEQUENCE)
                .encode(m_oid)
                .rawBytes(m_parameters)
                .endCons();
    }

    /*
    * Decode a BER encoded AlgorithmIdentifier
    */
    override void decodeFrom(ref BERDecoder codec)
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .decode(m_oid)
                .rawBytes(m_parameters)
                .endCons();
    }

    this() { m_oid = OID(); }

    /*
    * Create an AlgorithmIdentifier
    */
    this(OID alg_id, EncodingOption option) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = alg_id;
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. 2];
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(string alg_id, EncodingOption option) {
        __gshared immutable ubyte[2] DER_NULL = [ 0x05, 0x00 ];
        
        m_oid = OIDS.lookup(alg_id);
        
        if (option == USE_NULL_PARAM)
            m_parameters ~= DER_NULL.ptr[0 .. 2];
    }
    
    /*
    * Create an AlgorithmIdentifier
    */
    this(OID alg_id, ref Vector!ubyte param)
    {
        m_oid = alg_id;
        m_parameters = Vector!ubyte(param[]);
    }

    /*
    * Create an AlgorithmIdentifier
    */
    this(in string alg_id, ref Vector!ubyte param) {
        m_oid = OIDS.lookup(alg_id);
        m_parameters = Vector!ubyte(param[]);
    }

    /*
     * Make a copy of another AlgorithmIdentifier
     */
    this(const ref AlgorithmIdentifier other) {
        m_oid = OID(other.m_oid);
        m_parameters = Vector!ubyte(other.m_parameters[]);
    }

    /*
    * Compare two AlgorithmIdentifiers
    */
    bool opEquals(in AlgorithmIdentifier a2) const
    {
        if (m_oid != a2.m_oid)
            return false;
        if (m_parameters != a2.m_parameters)
            return false;
        return true;
    }

    /*
    * Compare two AlgorithmIdentifiers
    */
    int opCmp(in AlgorithmIdentifier a2) const
    {
        if (this == a2) return 0;
        else return -1;
    }

    @property const(OID) oid() const {
        return m_oid;
    }

    @property Vector!ubyte parameters() const {
        return m_parameters.dup;
    }

    @property void oid(OID oid) {
        m_oid = oid;
    }

    @property void parameters()(auto ref Vector!ubyte param) {
        m_parameters = param.dup;
    }

    override string toString() const {
        return m_oid.toString() ~ " & param length: " ~ m_parameters.length.to!string;
    }

private:
    OID m_oid;
    Vector!ubyte m_parameters;
}