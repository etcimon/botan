/**
* Common ASN.1 Objects
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*     2007 Yves Jerschow
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_alt_name;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.asn1.asn1_obj;
import botan.asn1.asn1_str;
import botan.asn1.asn1_oid;
import botan.asn1.asn1_alt_name;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import memutils.dictionarylist;
import botan.utils.charset;
import botan.utils.parsing;
import botan.utils.loadstor;
import botan.utils.types;
import memutils.hashmap;

alias AlternativeName = RefCounted!AlternativeNameImpl;

/**
* Alternative Name
*/
final class AlternativeNameImpl : ASN1Object
{
public:
    /*
    * DER encode an AlternativeName extension
    */
    override void encodeInto(ref DEREncoder der) const
    {
        der.startCons(ASN1Tag.SEQUENCE);
        
        encodeEntries(der, m_alt_info, "RFC822", (cast(ASN1Tag)1));
        encodeEntries(der, m_alt_info, "DNS", (cast(ASN1Tag)2));
        encodeEntries(der, m_alt_info, "URI", (cast(ASN1Tag)6));
        encodeEntries(der, m_alt_info, "IP", (cast(ASN1Tag)7));

        foreach(const ref OID oid, const ref ASN1String asn1_str; m_othernames)
        {
            der.startExplicit(0)
               .encode(oid)
               .startExplicit(0)
               .encode(asn1_str)
               .endExplicit()
               .endExplicit();
        }
        
        der.endCons();
    }

    /*
    * Decode a BER encoded AlternativeName
    */
    override void decodeFrom(ref BERDecoder source)
    {
        BERDecoder names = source.startCons(ASN1Tag.SEQUENCE);
        
        while (names.moreItems())
        {
            BERObject obj = names.getNextObject();
            if ((obj.class_tag != ASN1Tag.CONTEXT_SPECIFIC) &&
                (obj.class_tag != (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED)))
                continue;
            
            const ASN1Tag tag = obj.type_tag;
            
            if (tag == 0)
            {
                auto othername = BERDecoder(obj.value);
                
                OID oid = OID();
                othername.decode(oid);
                if (othername.moreItems())
                {
                    BERObject othername_value_outer = othername.getNextObject();
                    othername.verifyEnd();
                    
                    if (othername_value_outer.type_tag != (cast(ASN1Tag) 0) ||
                        othername_value_outer.class_tag != (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED))
                        throw new DecodingError("Invalid tags on otherName value");
                    
                    auto othername_value_inner = BERDecoder(othername_value_outer.value);
                    
                    BERObject value = othername_value_inner.getNextObject();
                    othername_value_inner.verifyEnd();
                    
                    const ASN1Tag value_type = value.type_tag;
                    
                    if (isStringType(value_type) && value.class_tag == ASN1Tag.UNIVERSAL)
                        addOthername(oid, value.toString(), value_type);
                }
            }
            else if (tag == 1 || tag == 2 || tag == 6)
            {
                const string value = transcode(obj.toString(),
                                               LATIN1_CHARSET,
                                               LOCAL_CHARSET);
                
                if (tag == 1) addAttribute("RFC822", value);
                if (tag == 2) addAttribute("DNS", value);
                if (tag == 6) addAttribute("URI", value);
            }
            else if (tag == 7)
            {
                if (obj.value.length == 4)
                {
                    const uint ip = loadBigEndian!uint(obj.value.ptr, 0);
                    addAttribute("IP", ipv4ToString(ip));
                }
            }

        }
    }

    /*
    * Return all of the alternative names
    */
    DictionaryListRef!(string, string) contents() const
    {
        DictionaryListRef!(string, string) names;

        foreach(const ref string k, const ref string v; m_alt_info) {
            names.insert(k, v);
        }

        foreach(const ref OID oid, const ref ASN1String asn1_str; m_othernames) {
            names.insert(OIDS.lookup(oid), asn1_str.value());
        }

        return names;
    }
  
    /*
    * Add an attribute to an alternative name
    */
    void addAttribute(in string type, in string str)
    {
        if (type == "" || str == "")
            return;

        bool exists;
        void adder(in string val) { 
            if (val == str)
                exists = true;
        }
        m_alt_info.getValuesAt(type, &adder);

        if (!exists)
            m_alt_info.insert(type, str);
    }
    
    /*
    * Get the attributes of this alternative name
    */
    const(DictionaryListRef!(string, string)) getAttributes() const
    {
        return m_alt_info;
    }

    /*
    * Add an OtherName field
    */
    void addOthername(in OID oid, in string value, ASN1Tag type)
    {
        if (value == "")
            return;
        m_othernames.insert(oid, ASN1String(value, type));
    }

    /*
    * Get the otherNames
    */
    const(DictionaryListRef!(OID, ASN1String)) getOthernames() const
    {
        return m_othernames;
    }

    /*
    * Return if this object has anything useful
    */
    bool hasItems() const
    {
        return (m_alt_info.length > 0 || m_othernames.length > 0);
    }

    /*
    * Create an AlternativeName
    */
    this(in string email_addr = "",
         in string uri = "",
         in string dns = "",
         in string ip = "")
    {
        addAttribute("RFC822", email_addr);
        addAttribute("DNS", dns);
        addAttribute("URI", uri);
        addAttribute("IP", ip);
    }

private:
    DictionaryListRef!(string, string) m_alt_info;
    DictionaryListRef!(OID, ASN1String) m_othernames;
}



/*
* Check if type is a known ASN.1 string type
*/
bool isStringType(ASN1Tag tag)
{
    return (tag == ASN1Tag.NUMERIC_STRING ||
            tag == ASN1Tag.PRINTABLE_STRING ||
            tag == ASN1Tag.VISIBLE_STRING ||
            tag == ASN1Tag.T61_STRING ||
            tag == ASN1Tag.IA5_STRING ||
            tag == ASN1Tag.UTF8_STRING ||
            tag == ASN1Tag.BMP_STRING);
}


/*
* DER encode an AlternativeName entry
*/
void encodeEntries(ref DEREncoder encoder,
                   in DictionaryListRef!(string, string) attr,
                   string type, ASN1Tag tagging)
{
    void checker(in string alt_name) {
        
        if (type == "RFC822" || type == "DNS" || type == "URI")
        {
            ASN1String asn1_string = ASN1String(alt_name, ASN1Tag.IA5_STRING);
            encoder.addObject(tagging, ASN1Tag.CONTEXT_SPECIFIC, asn1_string.iso8859());
        }
        else if (type == "IP")
        {
            const uint ip = stringToIpv4(alt_name);
            ubyte[4] ip_buf;
            storeBigEndian(ip, &ip_buf);
            encoder.addObject(tagging, ASN1Tag.CONTEXT_SPECIFIC, ip_buf.ptr, 4);
        }
    }
    attr.getValuesAt(type, &checker);
}