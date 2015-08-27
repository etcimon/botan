/**
* ASN.1 Attribute
* 
* Copyright:
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.asn1.asn1_attribute;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.utils.types;

alias Attribute = RefCounted!AttributeImpl;

/**
* Attribute
*/
final class AttributeImpl : ASN1Object
{
public:
    this() { }

    /*
    * Create an Attribute
    */
    this(OID attr_oid, ref Vector!ubyte attr_value)
    {
        oid = attr_oid;
        parameters = attr_value.dup;
    }
    
    /*
    * Create an Attribute
    */
    this(in string attr_oid, ref Vector!ubyte attr_value)
    {
        oid = OIDS.lookup(attr_oid);
        parameters = attr_value.dup;
    }
    
    /*
    * DER encode a Attribute
    */
    override void encodeInto(ref DEREncoder codec) const
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .encode(oid)
                .startCons(ASN1Tag.SET)
                .rawBytes(parameters)
                .endCons()
                .endCons();
    }
    
    /*
    * Decode a BER encoded Attribute
    */
    override void decodeFrom(ref BERDecoder codec)
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .decode(oid)
                .startCons(ASN1Tag.SET)
                .rawBytes(parameters)
                .endCons()
                .endCons();
    }

    OID oid;
    Vector!ubyte parameters;
}


