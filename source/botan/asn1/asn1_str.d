/**
* ASN.1 string type
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_str;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.charset;
import botan.utils.parsing;
import botan.utils.types;

alias ASN1String = RefCounted!ASN1StringImpl;

/**
* Simple String
*/
final class ASN1StringImpl : ASN1Object
{
public:

    /*
    * DER encode an ASN1String
    */
    override void encodeInto(ref DEREncoder encoder) const
    {
        string value = iso8859();
        if (tagging() == ASN1Tag.UTF8_STRING)
            value = transcode(value, LATIN1_CHARSET, UTF8_CHARSET);
        encoder.addObject(tagging(), ASN1Tag.UNIVERSAL, value);
    }

    /*
    * Decode a BER encoded ASN1String
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BERObject obj = source.getNextObject();
        CharacterSet charset_is;
        
        if (obj.type_tag == ASN1Tag.BMP_STRING)
            charset_is = UCS2_CHARSET;
        else if (obj.type_tag == ASN1Tag.UTF8_STRING)
            charset_is = UTF8_CHARSET;
        else
            charset_is = LATIN1_CHARSET;
        
        initialize(transcode(obj.toString(), 
                             charset_is, 
                             LOCAL_CHARSET),
                   obj.type_tag);
    }

    /*
    * Return this string in local encoding
    */
    string value() const
    {
        return transcode(m_iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
    }

    bool opEquals(in RefCounted!(ASN1StringImpl) other) const
    {
        if (m_tag != other.tagging()) return false;
        if (m_iso_8859_str != other.iso8859()) return false;
        return true;
    }

    /*
    * Return this string in ISO 8859-1 encoding
    */
    string iso8859() const
    {
        return m_iso_8859_str;
    }

    /*
    * Return the type of this string object
    */
    ASN1Tag tagging() const
    {
        return m_tag;
    }

    this(in string str, ASN1Tag t)
    {
        initialize(str, t);
    }

    this(in string str = "")
    {
        m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
        m_tag = chooseEncoding(m_iso_8859_str, "latin1");
    }


private:
    void initialize(in string str, ASN1Tag t) {
        m_tag = t;
        m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
        
        if (m_tag == ASN1Tag.DIRECTORY_STRING)
            m_tag = chooseEncoding(m_iso_8859_str, "latin1");
        
        if (m_tag != ASN1Tag.NUMERIC_STRING &&
            m_tag != ASN1Tag.PRINTABLE_STRING &&
            m_tag != ASN1Tag.VISIBLE_STRING &&
            m_tag != ASN1Tag.T61_STRING &&
            m_tag != ASN1Tag.IA5_STRING &&
            m_tag != ASN1Tag.UTF8_STRING &&
            m_tag != ASN1Tag.BMP_STRING)
            throw new InvalidArgument("ASN1String: Unknown string type " ~
                                       to!string(m_tag));
    }

    string m_iso_8859_str;
    ASN1Tag m_tag;
}

/*
* Choose an encoding for the string
*/
ASN1Tag chooseEncoding(in string str,
                         in string type)
{
    __gshared immutable bool[256] IS_PRINTABLE = [
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, true, false, false, false,
        false, false, false, false, true, true, false, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, false,
        false, true, false, true, false, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, false, false, false, false, false,
        false, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false ];
    
    foreach (immutable(char) c; str)
    {
        if (!IS_PRINTABLE[cast(size_t) c])
        {
            if (type == "utf8")    return ASN1Tag.UTF8_STRING;
            if (type == "latin1") return ASN1Tag.T61_STRING;
            throw new InvalidArgument("chooseEncoding: Bad string type " ~ type);
        }
    }
    return ASN1Tag.PRINTABLE_STRING;
}
