/**
* X.509 Distinguished Name
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.x509_dn;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.asn1_obj;
public import botan.asn1.asn1_oid;
public import botan.asn1.asn1_str;
public import botan.asn1.x509_dn;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.utils.types;
import memutils.dictionarylist;
import botan.asn1.oids;
import memutils.hashmap;
import std.array : Appender;

alias X509DN = RefCounted!X509DNImpl;

/**
* Distinguished Name
*/
final class X509DNImpl : ASN1Object
{
public:
    /*
    * DER encode a DistinguishedName
    */
    override void encodeInto(ref DEREncoder der) const
    {
        auto dn_info = getAttributes();
        
        der.startCons(ASN1Tag.SEQUENCE);
        
        if (!m_dn_bits.empty)
            der.rawBytes(m_dn_bits);
        else
        {
            doAva(der, dn_info, ASN1Tag.PRINTABLE_STRING, "X520.Country");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.State");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.Locality");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.Organization");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.OrganizationalUnit");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.CommonName");
            doAva(der, dn_info, ASN1Tag.PRINTABLE_STRING, "X520.SerialNumber");
        }
        
        der.endCons();
    }

    /*
    * Decode a BER encoded DistinguishedName
    */
    override void decodeFrom(ref BERDecoder source)
    {
        Vector!ubyte bits;
        
        source.startCons(ASN1Tag.SEQUENCE)
            .rawBytes(bits)
                .endCons();
        
        BERDecoder sequence = BERDecoder(bits);
        
        while (sequence.moreItems())
        {
            BERDecoder rdn = sequence.startCons(ASN1Tag.SET);
            
            while (rdn.moreItems())
            {
                OID oid = OID();
                ASN1String str = ASN1String();
                
                rdn.startCons(ASN1Tag.SEQUENCE)
                        .decode(oid)
                        .decode(str)
                        .verifyEnd()
                        .endCons();
                
                addAttribute(oid, str.value());
            }
        }
        
        m_dn_bits = bits.dup;
    }

    /*
    * Get the attributes of this X509DN
    */
    DictionaryListRef!(OID, string) getAttributes() const
    {
        DictionaryListRef!(OID, string) retval;
        foreach (const ref OID oid, const ref ASN1String asn1_str; m_dn_info)
            retval.insert(oid, asn1_str.value());
        return retval;
    }

    /*
    * Get a single attribute type
    */
    Vector!string getAttribute(in string attr) const
    {
        const OID oid = OIDS.lookup(derefInfoField(attr));
        return getAttribute(oid);
    }

    private Vector!string getAttribute(in OID oid) const 
    {
        auto range = m_dn_info.getValuesAt(oid);
        
        Vector!string values;
        foreach (const ref ASN1String asn1_string; range[])
            values.pushBack(asn1_string.value());
        return values.move;
    }

    /*
    * Get the contents of this X.500 Name
    */
    DictionaryListRef!(string, string) contents() const
    {
        DictionaryListRef!(string, string) retval;
        foreach (const ref OID key, const ref ASN1String value; m_dn_info)
            retval.insert(OIDS.lookup(key), value.value());
        return retval;
    }


    /*
    * Add an attribute to a X509DN
    */
    void addAttribute(in string type, in string str)
    {
        logTrace("Add X509DN Attribute Type: ", type, ", Value: ", str);
        OID oid = OIDS.lookup(type);
        addAttribute(oid, str);
    }

    /*
    * Add an attribute to a X509DN
    */
    void addAttribute(in OID oid, in string str)
    {
        if (str == "")
            return;

        bool exists;
        void search_func(in ASN1String name) {
            //logTrace(name.value());
            if (name.value() == str) { 
                exists = true;
            }
        }
        m_dn_info.getValuesAt(oid, &search_func);
        if (!exists) {
            m_dn_info.insert(oid, ASN1String(str.idup));
            m_dn_bits.clear();
        }
    }

    /*
    * Deref aliases in a subject/issuer info request
    */
    static string derefInfoField(in string info)
    {
        if (info == "Name" || info == "CommonName")         return "X520.CommonName";
        if (info == "SerialNumber")                         return "X520.SerialNumber";
        if (info == "Country")                              return "X520.Country";
        if (info == "Organization")                         return "X520.Organization";
        if (info == "Organizational Unit" || info == "OrgUnit")
            return "X520.OrganizationalUnit";
        if (info == "Locality")                             return "X520.Locality";
        if (info == "State" || info == "Province")          return "X520.State";
        if (info == "Email")                                return "RFC822";
        return info;
    }

    /*
    * Return the BER encoded data, if any
    */
    ref const(Vector!ubyte) getBits() const
    {
        return m_dn_bits;
    }

    /*
    * Create an empty X509DN
    */
    this()
    {
    }
    
    /*
    * Create an X509DN
    */
    this(in DictionaryListRef!(OID, string) args)
    {
        foreach (const ref OID oid, const ref string val; args)
            addAttribute(oid, val);
    }
    
    /*
    * Create an X509DN
    */
    this(in DictionaryListRef!(string, string) args)
    {
        foreach (const ref string key, const ref string val; args)
            addAttribute(OIDS.lookup(key), val);
    }

    /*
    * Compare two X509DNs for equality
    */
    bool opEquals(in X509DN dn2) const
    {
        auto attr1 = getAttributes();
        auto attr2 = dn2.getAttributes();
        size_t i;
        foreach (oid, str; *attr1) {
            i++;
            bool found;
            size_t j;
            foreach (oid2, val; *attr2) {
                j++;
                if (j != i) continue;
                if (x500NameCmp(val, str)) 
                    found = true;

                break;
            }
            if (!found) return false;
        }
        return true;

    }

    /*
    * Compare two X509DNs for inequality
    */
    int opCmp(const X509DN dn2) const
    {
        if (this == dn2)
            return 0;
        else if (this.isSmallerThan(dn2))
            return -1;
        else
            return 1;
    }

    /*
    * Induce an arbitrary ordering on DNs
    */
    bool isSmallerThan(const X509DN dn2) const
    {
        const auto attr1 = getAttributes();
        const auto attr2 = dn2.getAttributes();
        
        if (attr1.length < attr2.length) return true;
        if (attr1.length > attr2.length) return false;

        foreach (const ref OID key, const ref string value; attr1) {
            const auto value2 = attr2.get(key);
            if (value2 == null) return false;
            if (value > value2) return false;
            if (value < value2) return true;
        }
        return false;
    }

    override string toString() const
    {
        return toVector()[].idup;
    }

    Vector!ubyte toVector() const
    {
        Vector!ubyte output;
        DictionaryListRef!(string, string) contents = contents();
        
        foreach(const ref string key, const ref string val; contents)
        {
            output ~= toShortForm(key);
            output ~= "=";
            output ~= val;
            output ~= ' ';
        }
        return output.move();
    }
    @property X509DN dup() const {
        return X509DN(getAttributes());
    }

private:
    DictionaryListRef!(OID, ASN1String) m_dn_info;
    Vector!ubyte m_dn_bits;
}

/*
* DER encode a RelativeDistinguishedName
*/
void doAva(ref DEREncoder encoder,
           in DictionaryListRef!(OID, string) dn_info,
           ASN1Tag string_type, in string oid_str,
           bool must_exist = false)
{
    const OID oid = OIDS.lookup(oid_str);
    const bool exists = (dn_info.get(oid) != null);

    if (!exists && must_exist)
        throw new EncodingError("X509DN: No entry for " ~ oid_str);
    if (!exists) return;

    dn_info.getValuesAt(oid, (in string val) {
                 encoder.startCons(ASN1Tag.SET)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(oid)
                .encode(ASN1String(val, string_type))
                .endCons()
                .endCons();

    });
}

string toShortForm(in string long_id)
{
    if (long_id == "X520.CommonName")
        return "CN";
    
    if (long_id == "X520.Organization")
        return "O";
    
    if (long_id == "X520.OrganizationalUnit")
        return "OU";
    
    return long_id;
}