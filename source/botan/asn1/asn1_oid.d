/**
* ASN.1 OID
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_oid;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.bit_ops;
import botan.utils.parsing;
import std.array;
import botan.utils.types;

alias OID = RefCounted!OIDImpl;

/**
* This class represents ASN.1 object identifiers.
*/
final class OIDImpl : ASN1Object
{
public:

    /*
    * DER encode an OBJECT IDENTIFIER
    */
    override void encodeInto(ref DEREncoder der) const
    {
        if (m_id.length < 2)
            throw new InvalidArgument("encodeInto: OID is invalid");
        
        Vector!ubyte encoding;
        encoding.pushBack(cast(ubyte) (40 * m_id[0] + m_id[1]));
        
        foreach (size_t i; 2 .. m_id.length)
        {
            if (m_id[i] == 0)
                encoding.pushBack(cast(ubyte)0);
            else
            {
                size_t blocks = highBit(m_id[i]) + 6;
                blocks = (blocks - (blocks % 7)) / 7;
                
                foreach (size_t j; 0 .. (blocks - 1))
                    encoding.pushBack(cast(ubyte) (0x80 | ((m_id[i] >> 7*(blocks-j-1)) & 0x7F)));
                encoding.pushBack(cast(ubyte) (m_id[i] & 0x7F));
            }
        }
        der.addObject(ASN1Tag.OBJECT_ID, ASN1Tag.UNIVERSAL, encoding);
    }


    /*
    * Decode a BER encoded OBJECT IDENTIFIER
    */
    override void decodeFrom(ref BERDecoder decoder)
    {
        BERObject obj = decoder.getNextObject();
        if (obj.type_tag != ASN1Tag.OBJECT_ID || obj.class_tag != ASN1Tag.UNIVERSAL)
            throw new BERBadTag("Error decoding OID, unknown tag", obj.type_tag, obj.class_tag);
        if (obj.value.length < 2)
            throw new BERDecodingError("OID encoding is too short");
        clear();
        m_id.pushBack(obj.value[0] / 40);
        m_id.pushBack(obj.value[0] % 40);
        
        size_t i = 0;
        while (i != obj.value.length - 1)
        {
            uint component = 0;
            while (i != obj.value.length - 1)
            {
                ++i;
                
                if (component >> (32-7))
                    throw new DecodingError("OID component overflow");
                
                component = (component << 7) + (obj.value[i] & 0x7F);
                
                if (!(obj.value[i] & 0x80))
                    break;
            }
            m_id.pushBack(component);
        }
        //import botan.asn1.oids : OIDS;
        //assert(OIDS.lookup(OID(this)) !is null, "Invalid OID: " ~ m_id[].to!string);
    }


    /**
    * Find out whether this OID is empty
    * Returns: true is no OID value is set
    */
    @property bool empty() const { return m_id.length == 0; }

    /**
    * Get this OID as list (vector) of its components.
    * Returns: vector representing this OID
    */
    ref const(Vector!uint) getId() const { return m_id; }

    /**
    * Get this OID as a string
    * Returns: string representing this OID
    */
    override string toString() const
    {
        return toVector()[].idup;
    }

    Vector!ubyte toVector() const {
        Vector!ubyte oid_str;
        foreach (size_t i; 0 .. m_id.length)
        {
            oid_str ~= to!string(m_id[i]);
            if (i != m_id.length - 1)
                oid_str ~= '.';
        }
        return oid_str.move();
    }

    /**
    * Compare two OIDs.
    * Returns: true if they are equal, false otherwise
    */
    bool opEquals(in OIDImpl oid) const
    {
        if ((!oid || oid.m_id.length == 0) && m_id.length == 0) return true;
        else if (!oid || oid.m_id.length == 0) return false;
        else if (m_id.length == 0) return false;
        
        if (m_id.length != oid.m_id.length)
            return false;
        
        if (m_id != oid.m_id) return false;
        return true;
    }

    /**
    * Reset this instance to an empty OID.
    */
    void clear()
    {
        m_id.clear();
    }

    /**
    * Append another component onto the OID.
    * 
    * Params:
    *  oid = the OID to add the new component to
    *  component = the new component to add
    */
    OID opBinary(string op)(in OID oid, uint component)
        if (op == "+")
    {
        OID new_oid = OID(oid);
        new_oid ~= component;
        return new_oid;
    }
    
    /**
    * Compare two OIDs.
    * 
    * Params:
    *  b = the second OID
    * 
    * Returns: true if a is not equal to b
    */
    int opCmp(in OID b) const
    {
        if (this == *b) return 0;
        else return -1;
    }
    
    /**
    * Compare two OIDs.
    * 
    * Params:
    *  b = the second OID
    * 
    * Returns: true if a is lexicographically smaller than b
    */
    bool opBinary(string op)(in OID b)
        if (op == "<")
    {
        const Vector!uint* oid1 = &getId();
        const Vector!uint* oid2 = &b.getId();
        
        if (oid1.length < oid2.length)
            return true;
        if (oid1.length > oid2.length)
            return false;
        foreach (const i, const oid; (*oid1)[])
        {
            if (oid < (*oid2)[i])
                return true;
            if (oid > (*oid2)[i])
                return false;
        }
        return false;
    }


    /**
    * Add a component to this OID.
    * 
    * Params:
    *  new_comp = the new component to add to the end of this OID
    * 
    * Returns: reference to this
    */
    void opOpAssign(string op)(uint new_comp)
        if (op == "~") 
    {
        m_id.pushBack(new_comp);
    }

    /**
    * Construct an OID from a string.
    * 
    * Params:
    *  oid_str = a string in the form "a.b.c" etc., where a,b,c are numbers
    */
    this(in string oid_str = "")
    {
        if (oid_str == "")
            return;
        //logTrace("Loading ", oid_str);
        try
        {
            m_id = parseAsn1Oid(oid_str);
        }
        catch (Throwable)
        {
            logError("parseAsn1Oid failure with '" ~ oid_str ~ "'");
            throw new InvalidOID(oid_str);
        }
        
        if (m_id.length < 2 || m_id[0] > 2) {
           // logTrace("Got m_id: ", m_id[]);
            throw new InvalidOID(oid_str);
        }
        if ((m_id[0] == 0 || m_id[0] == 1) && m_id[1] > 39)
            throw new InvalidOID(oid_str);
    }

    this(const ref OID other)
    {
        m_id = other.m_id.dup;
    }

    this(const OIDImpl other)
    {
        m_id = other.m_id.dup;
    }

    @property OID dup() const {
        OID oid = OID();
        oid.m_id = m_id.dup;
        return oid;
    }
private:
    Vector!uint m_id;
}