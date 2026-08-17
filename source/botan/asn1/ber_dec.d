/**
* BER Decoder
* 
* Copyright:
* (C) 1999-2008,2015,2017,2018,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.ber_dec;

import botan.constants;
public import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.math.bigint.bigint;
import botan.utils.get_byte;
import botan.utils.types;

public:
/**
* BER Decoding Object
*/
struct BERDecoder
{
public:
    /*
    * Return the BER encoding of the next object
    */
    BERObject getNextObject()
    {
        BERObject next;
        if (m_pushed.type_tag != ASN1Tag.NO_OBJECT)
        {
            next = m_pushed.clone;
            m_pushed.class_tag = m_pushed.type_tag = ASN1Tag.NO_OBJECT;
            return next.move();
        }
        decodeTag(m_source, next.type_tag, next.class_tag);

        if (next.type_tag == ASN1Tag.NO_OBJECT)
            return next.move();

        const bool constructed = (next.class_tag & ASN1Tag.CONSTRUCTED) != 0;
        size_t field_size;
        const size_t allow_indef = m_require_der ? 0 : DefaultMaxNestedIndef;
        size_t length = decodeLength(m_source, field_size, m_require_der, constructed, allow_indef);
        if (next.type_tag == ASN1Tag.EOC && next.class_tag == ASN1Tag.UNIVERSAL && length != 0)
            throw new BERDecodingError("EOC marker with non-zero length");
        enum size_t DefaultMaxObjectSize = 128 * 1024 * 1024;
        if (length > DefaultMaxObjectSize)
            throw new BERDecodingError("Encoded object exceeds maximum size");

        next.value.resize(length);
        if (m_source.read(next.value.ptr, length) != length)
            throw new BERDecodingError("Value truncated");
        // Indefinite BER: findEoc includes the trailing EOC. C++ 3's value
        // excludes it, so strip 00 00 and leave the terminator out of `value`.
        if (field_size == 1 && constructed && next.value.length >= 2 &&
            next.value[next.value.length - 2] == 0 && next.value[next.value.length - 1] == 0)
            next.value.length = next.value.length - 2;
        if (next.type_tag == ASN1Tag.EOC && next.class_tag == ASN1Tag.UNIVERSAL)
        {
            if (m_require_der)
                throw new BERDecodingError("Detected EOC marker in DER structure");
            return getNextObject();
        }
        return next.move();
    }

    Vector!ubyte getNextOctetString()
    {
        Vector!ubyte out_vec;
        decode(out_vec, ASN1Tag.OCTET_STRING);
        return out_vec.move();
    }
        
    /*
    * Push a object back into the stream
    */
    void pushBack()(auto ref BERObject obj)
    {
        if (m_pushed.type_tag != ASN1Tag.NO_OBJECT)
            throw new InvalidState("BERDecoder: Only one push back is allowed");
        m_pushed = obj.move();
    }

    
    /*
    * Check if more objects are there
    */
    bool moreItems() const
    {
        if (m_source.endOfData() && (m_pushed.type_tag == ASN1Tag.NO_OBJECT))
            return false;
        return true;
    }

    /*
    * Verify that no bytes remain in the m_source
    */
    ref BERDecoder verifyEnd() return
    {
        if (!m_source.endOfData() || (m_pushed.type_tag != ASN1Tag.NO_OBJECT))
            throw new InvalidState("verify_end called, but data remains");
        return this;
    }

    /*
    * Discard all the bytes remaining in the m_source
    */
    ref BERDecoder discardRemaining() return
    {
        ubyte buf;
        while (m_source.readByte(buf))
            continue;
        //logTrace("Discarded");
        return this;
    }

    /*
    * Begin decoding a ASN1Tag.CONSTRUCTED type
    */
    BERDecoder startCons(ASN1Tag type_tag,
                         ASN1Tag class_tag = ASN1Tag.UNIVERSAL)
    {
        BERObject obj = getNextObject();
        //logTrace("AssertIsA: ", (class_tag | ASN1Tag.CONSTRUCTED));
        obj.assertIsA(type_tag, class_tag | ASN1Tag.CONSTRUCTED);
        
        BERDecoder result = BERDecoder(obj.value.ptr, obj.value.length);
        result.m_parent = &this;
        result.m_require_der = m_require_der;
        return result.move();
    }

    /*
    * Finish decoding a ASN1Tag.CONSTRUCTED type
    */
    ref BERDecoder endCons()
    {
        if (!m_parent)
            throw new InvalidState("endCons called with NULL m_parent");
        if (!m_source.endOfData())
            throw new DecodingError("endCons called with data left");
        return *m_parent;
    }
    

    
    ref BERDecoder getNext(ref BERObject ber) return
    {
        ber = getNextObject();
        return this;
    }
        
    /*
    * Save all the bytes remaining in the m_source
    */
    ref BERDecoder rawBytes(T, ALLOC)(ref Vector!(T, ALLOC) output) return
    {
        output.clear();
        ubyte buf;
        while (m_source.readByte(buf))
            output.pushBack(buf);
        return this;
    }

    ref BERDecoder rawBytes(T, ALLOC)(ref RefCounted!(Vector!(T, ALLOC), ALLOC) output) return
    {
        output.clear();
        ubyte buf;
        while (m_source.readByte(buf))
            output.pushBack(buf);
        return this;
    }

    /*
    * Decode a BER encoded NULL
    */
    ref BERDecoder decodeNull() return
    {
        BERObject obj = getNextObject();
        obj.assertIsA(ASN1Tag.NULL_TAG, ASN1Tag.UNIVERSAL);
        if (obj.value.length)
            throw new BERDecodingError("NULL object had nonzero size");
        return this;
    }

    ref BERDecoder decode(T)(ref T obj) return
    {
        static if (is(T == class)) {
            if (!obj)
                obj = new T();
		} else static if (__traits(compiles, { T t = T(); }())) {
            if (obj is T.init) obj = T();
		}
        (cast()*obj).decodeFrom(this);
        return this;
    }
    
    /*
    * Request for an object to decode itself
    */
    ref BERDecoder decode(T)(auto ref T obj, ASN1Tag type, ASN1Tag tag) return
        if (__traits(compiles, { obj.decodeFrom(this); }()))
    {
        obj.decodeFrom(this);
        return this;
    }
    
    /*
    * Decode a BER encoded BOOLEAN
    */
    ref BERDecoder decode(ref bool output) return
    {
        return decode(output, ASN1Tag.BOOLEAN, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * Decode a small BER encoded INTEGER
    */
    ref BERDecoder decode(ref size_t output) return
    {
        return decode(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * Decode a BER encoded INTEGER
    */
    ref BERDecoder decode(ref BigInt output) return
    {
        return decode(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    
    /*
    * Decode a BER encoded BOOLEAN
    */
    ref BERDecoder decode(ref bool output,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (obj.value.length != 1)
            throw new BERDecodingError("BER boolean value had invalid size");
        const ubyte val = obj.value[0];
        if (m_require_der && val != 0x00 && val != 0xFF)
            throw new BERDecodingError("Detected non-canonical boolean encoding in DER structure");
        output = (val != 0) ? true : false;
        return this;
    }
    
    /*
    * Decode a small BER encoded INTEGER
    */
    ref BERDecoder decode(ref size_t output,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        BigInt integer;
        decode(integer, type_tag, class_tag);
        
        if (integer.bits() > 32)
            throw new BERDecodingError("Decoded integer value larger than expected");
        
        output = 0;
        foreach (size_t i; 0 .. 4)
            output = (output << 8) | integer.byteAt(3-i);
        
        logTrace("decode size_t: ", output);

        return this;
    }

    /*
    * Decode a BER encoded INTEGER
    */
    ref BERDecoder decode(ref BigInt output,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (obj.value.empty)
            throw new BERDecodingError("INTEGER encoding has no content octets");
        if (m_require_der && obj.value.length > 1)
        {
            if (obj.value[0] == 0x00 && (obj.value[1] & 0x80) == 0)
                throw new BERDecodingError("Detected non-minimal INTEGER encoding in DER structure");
            if (obj.value[0] == 0xFF && (obj.value[1] & 0x80) != 0)
                throw new BERDecodingError("Detected non-minimal INTEGER encoding in DER structure");
        }
        {
            const bool negative = (obj.value[0] & 0x80) ? true : false;
            
            if (negative)
            {
                for (size_t i = obj.value.length; i > 0; --i)
                    if (obj.value[i-1]--)
                        break;
                foreach (size_t i; 0 .. obj.value.length)
                    obj.value[i] = ~cast(int)obj.value[i];
            }
            output = BigInt(obj.value.ptr, obj.value.length);
            if (negative)
                output.flipSign();
        }
        // breaks here
        logTrace("decode BigInt: ", output.toString());
        return this;
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    ref BERDecoder decode(ref SecureVector!ubyte output, ASN1Tag real_type) return
    {
        return decode(output, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    ref BERDecoder decode(ref Vector!ubyte output, ASN1Tag real_type) return
    {
        return decode(output, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    ref BERDecoder decode(ref SecureVector!ubyte buffer,
                          ASN1Tag real_type,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        if (real_type != ASN1Tag.OCTET_STRING && real_type != ASN1Tag.BIT_STRING)
            throw new BERBadTag("Bad tag for {BIT,OCTET} STRING", real_type);
        
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (real_type == ASN1Tag.OCTET_STRING)
            buffer = obj.value.move;
        else
        {
			if (obj.value.empty())
				throw new BERDecodingError("Invalid BIT STRING");
            if (obj.value[0] >= 8)
                throw new BERDecodingError("Bad number of unused bits in BIT STRING");
            if (obj.value[0] > 0 && obj.value.length < 2)
                throw new BERDecodingError("Invalid BIT STRING");
            if (m_require_der && obj.value[0] > 0)
            {
                const ubyte last = obj.value[obj.value.length - 1];
                if ((last & ((1 << obj.value[0]) - 1)) != 0)
                    throw new BERDecodingError("Detected non-zero padding bits in BIT STRING in DER structure");
            }
            buffer.resize(obj.value.length - 1);
            if (obj.value.length > 1)
                copyMem(buffer.ptr, &obj.value[1], obj.value.length - 1);
        }

        //logTrace("decode SecureVector: ", buffer[]);

        return this;
    }
    
    ref BERDecoder decode(ref Vector!ubyte buffer,
                          ASN1Tag real_type,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        if (real_type != ASN1Tag.OCTET_STRING && real_type != ASN1Tag.BIT_STRING)
            throw new BERBadTag("Bad tag for {BIT,OCTET} STRING", real_type);
        
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (real_type == ASN1Tag.OCTET_STRING)
            buffer = unlock(obj.value);
        else
        {
			if (obj.value.empty())
				throw new BERDecodingError("Invalid BIT STRING");
            if (obj.value[0] >= 8)
                throw new BERDecodingError("Bad number of unused bits in BIT STRING");
            if (obj.value[0] > 0 && obj.value.length < 2)
                throw new BERDecodingError("Invalid BIT STRING");
            if (m_require_der && obj.value[0] > 0)
            {
                const ubyte last = obj.value[obj.value.length - 1];
                if ((last & ((1 << obj.value[0]) - 1)) != 0)
                    throw new BERDecodingError("Detected non-zero padding bits in BIT STRING in DER structure");
            }
            buffer.resize(obj.value.length - 1);
            if (obj.value.length > 1)
                copyMem(buffer.ptr, &obj.value[1], obj.value.length - 1);
        }
        //logTrace("decode Vector: ", buffer[]);
        return this;
    }

    /*
    * Decode a small BER encoded INTEGER
    */
    ulong decodeConstrainedInteger(ASN1Tag type_tag,
                                   ASN1Tag class_tag,
                                   size_t T_bytes)
    {
        if (T_bytes > 8)
            throw new BERDecodingError("Can't decode small integer over 8 bytes");
        
        BigInt integer;
        decode(integer, type_tag, class_tag);
        
        if (integer.bits() > 8*T_bytes)
            throw new BERDecodingError("Decoded integer value larger than expected");
        
        ulong output = 0;
        foreach (size_t i; 0 .. 8)
            output = (output << 8) | integer.byteAt(7-i);
        
        //logTrace("decode Integer: (64bit) ", output);

        return output;
    }
       
    ref BERDecoder decodeIntegerType(T)(ref T output) return
    {
        return decodeIntegerType!T(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    ref BERDecoder decodeIntegerType(T)(ref T output,
                                        ASN1Tag type_tag,
                                        ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        output = cast(T) decodeConstrainedInteger(type_tag, class_tag, (output).sizeof);
        return this;
    }

    /*
    * Decode an OPTIONAL or DEFAULT element
    */
    ref BERDecoder decodeOptional(T)(auto ref T output,
                                     ASN1Tag type_tag,
                                     ASN1Tag class_tag,
                                     T default_value = T.init) return
    {
        BERObject obj = getNextObject();
        
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            if ((class_tag & ASN1Tag.CONSTRUCTED) && (class_tag & ASN1Tag.CONTEXT_SPECIFIC))
                BERDecoder(obj.value).decode(output).verifyEnd();
            else
            {
                pushBack(obj);
                decode(output, type_tag, class_tag);
            }
        }
        else
        {
            static if (__traits(hasMember, T, "isRefCounted")) {
                if (default_value is T.init)
                    output = T();
                else output = default_value;
            }
            else 
                output = default_value;
            pushBack(obj);
        }

        /*
        static if (__traits(hasMember, T, "toString"))
            logTrace("decode Optional ", T.stringof, ": ", output.toString());
        else static if (__traits(compiles, { to!string(output); }()))
            logTrace("decode Optional ", T.stringof, ": ", output.to!string);
        else
            logTrace("decode Optional ", T.stringof);
        */

        return this;
    }
    
    /*
    * Decode an OPTIONAL or DEFAULT element
    */
    ref BERDecoder decodeOptionalImplicit(T)(ref T output,
                                             ASN1Tag type_tag,
                                             ASN1Tag class_tag,
                                             ASN1Tag real_type,
                                             ASN1Tag real_class,
                                             T default_value = T.init) return
    {
        BERObject obj = getNextObject();
        
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            obj.type_tag = real_type;
            obj.class_tag = real_class;
            pushBack(obj);
            decode(output, real_type, real_class);
        }
        else
        {
            output = default_value;
            pushBack(obj);
        }
        /*
        static if (__traits(hasMember, T, "toString"))
            logTrace("decode OptionalImplicit ", T.stringof, ": ", output.toString());
        else
            logTrace("decode OptionalImplicit ", T.stringof);
        */
        return this;
    }
    

    /*
    * Decode a list of homogenously typed values
    */
    ref BERDecoder decodeList(T, Alloc)(auto ref Vector!(T, Alloc) vec,
                                        ASN1Tag type_tag = ASN1Tag.SEQUENCE,
                                        ASN1Tag class_tag = ASN1Tag.UNIVERSAL) return
    {
        BERDecoder list = startCons(type_tag, class_tag);
        
        while (list.moreItems())
        {
            T value;
            list.decode(value);
            //logTrace("Decode List ", T.stringof);

            vec.pushBack(value);
        }
        
        list.endCons();
        
        return this;
    }

    /// ditto
    ref BERDecoder decodeList(T, Alloc)(auto ref RefCounted!(Vector!(T, Alloc), Alloc) vec,
                                            ASN1Tag type_tag = ASN1Tag.SEQUENCE,
                                            ASN1Tag class_tag = ASN1Tag.UNIVERSAL) return
    {
        return decodeList(*vec, type_tag, class_tag); 
    }

    ref BERDecoder decodeAndCheck(T)(in T expected,
                                     in string error_msg) return
    {
        T actual;
        decode(actual);
        
        if (actual != expected)
            throw new DecodingError(error_msg ~ " T " ~ T.stringof ~ " : " ~ actual.to!string ~ ", expected: " ~ expected.to!string);
        
        static if (__traits(hasMember, T, "toString"))
            logTrace("decode and check ", T.stringof, ": ", actual.toString());
        else
            logTrace("decode and check ", T.stringof);

        return this;
    }
    
    /*
        * Decode an OPTIONAL string type
        */
    ref BERDecoder decodeOptionalString(Alloc)(ref Vector!( ubyte, Alloc ) output,
                                               ASN1Tag real_type,
                                               ushort type_no,
                                               ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC) return
    {
        BERObject obj = getNextObject();
        ASN1Tag type_tag = cast(ASN1Tag)(type_no);
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            if ((class_tag & ASN1Tag.CONSTRUCTED) && (class_tag & ASN1Tag.CONTEXT_SPECIFIC)) {
                BERDecoder(obj.value).decode(output, real_type).verifyEnd();
            }
            else
            {
                pushBack(obj);
                decode(output, real_type, type_tag, class_tag);
            }
        }
        else
        {
            output.clear();
            pushBack(obj);
        }

        //logTrace("decode optional string ", output[]);

        
        return this;
    }
    
    //BERDecoder operator=(in BERDecoder);

    ref BERDecoder decodeOctetStringBigint(ref BigInt output) return
    {
        SecureVector!ubyte out_vec;
        decode(out_vec, ASN1Tag.OCTET_STRING);
        output = BigInt.decode(out_vec.ptr, out_vec.length);
        //logTrace("decode octet string BigInt (32bit): ", output.getSubstring(0,32));
        return this;
    }

    /*
    * BERDecoder Constructor
    */
    this(DataSource src)
    {
        m_pushed = BERObject.init;
        m_source = src;
        m_owns = false;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Constructor
    */
    this(const(ubyte)* data, size_t length)
    {
        m_pushed = BERObject.init;
        m_source = cast(DataSource) DataSourceMemory(data, length);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Constructor
    */
    this(T, ALLOC)(const auto ref Vector!(T, ALLOC) data)
    {
        m_pushed = BERObject.init;
        m_source = cast(DataSource) DataSourceMemory(data.ptr, data.length);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }

    /// ditto
    this(T, ALLOC)(const auto ref RefCounted!(Vector!(T, ALLOC), ALLOC) data)
    {
        m_pushed = BERObject.init;
        m_source = cast(DataSource) DataSourceMemory(data.ptr, data.length);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }

    this(ref BERDecoder other, BERObject pushed) {
        m_parent = other.m_parent;
        m_source = other.m_source;
        m_pushed = pushed.move();
        m_owns = other.m_owns;
    }

    @property BERDecoder move() {
        return BERDecoder(this, m_pushed.move());
    }

    @property BERDecoder clone() {
        return BERDecoder(this, m_pushed.clone());
    }
    @disable @property BERDecoder dup();

    @disable this(this);

    ref BERDecoder setRequireDer(bool v = true) return
    {
        m_require_der = v;
        return this;
    }

    bool requireDer() const { return m_require_der; }

private:

    BERDecoder* m_parent;
    DataSource m_source;
    BERObject m_pushed;
    bool m_owns;
    bool m_require_der;
}

private:
/*
* BER decode an ASN.1 type tag
*/
size_t decodeTag(DataSource ber, ref ASN1Tag type_tag, ref ASN1Tag class_tag)
{
    ubyte b;
    if (!ber.readByte(b))
    {
        type_tag = ASN1Tag.NO_OBJECT;
        class_tag = ASN1Tag.NO_OBJECT;
        return 0;
    }
    
    if ((b & 0x1F) != 0x1F)
    {
        type_tag = cast(ASN1Tag)(b & 0x1F);
        class_tag = cast(ASN1Tag)(b & 0xE0);
        if (type_tag == ASN1Tag.EOC && class_tag == ASN1Tag.CONSTRUCTED)
            throw new BERDecodingError("EOC tag with constructed encoding");
        return 1;
    }
    
    size_t tag_bytes = 1;
    class_tag = cast(ASN1Tag)(b & 0xE0);
    
    size_t tag_buf = 0;
    while (true)
    {
        if (!ber.readByte(b))
            throw new BERDecodingError("Long-form tag truncated");
        if ((tag_buf >> 25) != 0)
            throw new BERDecodingError("Long-form tag overflowed 32 bits");
        if (tag_bytes == 1 && (b & 0x7F) == 0)
            throw new BERDecodingError("Long form tag with leading zero");
        ++tag_bytes;
        tag_buf = (tag_buf << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
    }
    if (tag_buf <= 30)
        throw new BERDecodingError("Long-form tag encoding used for small tag value");
    type_tag = cast(ASN1Tag)(tag_buf);
    return tag_bytes;
}

enum size_t DefaultMaxNestedIndef = 16;

/*
* BER decode an ASN.1 length field
*/
size_t decodeLength(DataSource ber, ref size_t field_size,
                    bool require_der = false, bool constructed = true,
                    size_t allow_indef = DefaultMaxNestedIndef)
{
    ubyte b;
    if (!ber.readByte(b))
        throw new BERDecodingError("Length field not found");
    field_size = 1;
    if ((b & 0x80) == 0)
        return b;
    
    field_size += (b & 0x7F);
    if (field_size == 1)
    {
        if (require_der)
            throw new BERDecodingError("Detected indefinite-length encoding in DER structure");
        if (!constructed)
            throw new BERDecodingError("Indefinite-length encoding used with non-constructed type");
        if (allow_indef == 0)
            throw new BERDecodingError("Nested EOC markers too deep, rejecting to avoid stack exhaustion");
        return findEoc(ber, allow_indef - 1);
    }
    if (field_size > 5)
        throw new BERDecodingError("Length field is too large");
    
    size_t length = 0;
    
    foreach (size_t i; 0 .. (field_size - 1))
    {
        if (get_byte(0, length) != 0)
            throw new BERDecodingError("Field length overflow");
        if (!ber.readByte(b))
            throw new BERDecodingError("Corrupted length field");
        length = (length << 8) | b;
    }
    return length;
}

/*
* BER decode an ASN.1 length field
*/
size_t decodeLength(DataSource ber, bool require_der = false, bool constructed = true)
{
    size_t dummy;
    return decodeLength(ber, dummy, require_der, constructed);
}

/*
* Find the EOC marker
*/
size_t findEoc(DataSource ber, size_t allow_indef = DefaultMaxNestedIndef)
{
    SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
    SecureVector!ubyte data = SecureVector!ubyte();
    
    while (true)
    {
        const size_t got = ber.peek(buffer.ptr, buffer.length, data.length);
        if (got == 0)
            break;
        
        data ~= buffer[];
    }

    auto source = cast(DataSource) DataSourceMemory(&data);
    size_t length = 0;
    while (true)
    {
        ASN1Tag type_tag, class_tag;
        size_t tag_size = decodeTag(source, type_tag, class_tag);
        if (type_tag == ASN1Tag.NO_OBJECT)
            break;
        
        size_t length_size = 0;
        const bool constructed = (class_tag & ASN1Tag.CONSTRUCTED) != 0;
        size_t item_size = decodeLength(source, length_size, false, constructed, allow_indef);
        if (type_tag == ASN1Tag.EOC && class_tag == ASN1Tag.UNIVERSAL
            && (length_size != 1 || item_size != 0))
            throw new BERDecodingError("EOC marker with non-zero length");
        source.discardNext(item_size);
        
        length += item_size + length_size + tag_size;
        
        if (type_tag == ASN1Tag.EOC && class_tag == ASN1Tag.UNIVERSAL)
            break;
    }
    return length;
}

static if (BOTAN_HAS_TESTS && !SKIP_ASN1_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.utils.exceptn;

    auto state = globalState();
    logDebug("Testing ber_dec.d S2 nest bound ...");
    size_t fails;

    ubyte[] nest(size_t depth)
    {
        auto v = new ubyte[depth * 4];
        size_t o;
        foreach (i; 0 .. depth)
        {
            v[o++] = 0x30;
            v[o++] = 0x80;
        }
        foreach (i; 0 .. depth)
        {
            v[o++] = 0x00;
            v[o++] = 0x00;
        }
        return v;
    }

    {
        auto v = nest(2);
        auto dec = BERDecoder(v.ptr, v.length);
        auto obj = dec.getNextObject();
        if (obj.type_tag != ASN1Tag.SEQUENCE)
            ++fails;
    }
    {
        auto v = nest(17);
        bool threw;
        try
        {
            auto dec = BERDecoder(v.ptr, v.length);
            auto obj = dec.getNextObject();
        }
        catch (BERDecodingError)
            threw = true;
        if (!threw)
        {
            logError("S2 17-deep indefinite BER accepted");
            ++fails;
        }
    }

    testReport("ber_dec_s2", 2, fails);
    assert(fails == 0);
}


