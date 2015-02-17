/**
* TLS Data Reader
* 
* Copyright:
* (C) 2010-2011,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.reader;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.exceptn;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.get_byte;
import std.exception;
import std.conv : to;
/**
* Helper class for decoding TLS protocol messages
*/
struct TLSDataReader
{
public:
    this(string type, const ref Vector!ubyte buf_input) 
    {
        m_typename = type;
        m_buf = &buf_input; 
        m_offset = 0;
    }

    void assertDone() const
    {
        if (hasRemaining())
            throw decodeError("Extra bytes at end of message");
    }

    size_t remainingBytes() const
    {
        return m_buf.length - m_offset;
    }

    bool hasRemaining() const
    {
        return (remainingBytes() > 0);
    }

    void discardNext(size_t bytes)
    {
        assertAtLeast(bytes);
        m_offset += bytes;
    }

    ushort get_uint()
    {
        assertAtLeast(4);
        ushort result = cast(ushort) make_uint((*m_buf)[m_offset  ], (*m_buf)[m_offset+1],
                                               (*m_buf)[m_offset+2], (*m_buf)[m_offset+3]);
        m_offset += 4;
        return result;
    }

    ushort get_ushort()
    {
        assertAtLeast(2);
        ushort result = make_ushort((*m_buf)[m_offset], (*m_buf)[m_offset+1]);
        m_offset += 2;
        return result;
    }

    ubyte get_byte()
    {
        assertAtLeast(1);
        ubyte result = (*m_buf)[m_offset];
        m_offset += 1;
        return result;
    }

    
    Container getElem(T, Container)(size_t num_elems)
    {
        assertAtLeast(num_elems * T.sizeof);

        Container result = Container(num_elems);

        foreach (size_t i; 0 .. num_elems)
            result[i] = loadBigEndian!T(&(*m_buf)[m_offset], i);

        m_offset += num_elems * T.sizeof;

        return result;
    }

    Vector!T getRange(T)(size_t len_bytes,
                         size_t min_elems,
                         size_t max_elems)
    {
        const size_t num_elems = getNumElems(len_bytes, T.sizeof, min_elems, max_elems);

        return getElem!(T, Vector!T)(num_elems);
    }

    Vector!T getRangeVector(T)(size_t len_bytes,
                                 size_t min_elems,
                                 size_t max_elems)
    {
        const size_t num_elems = getNumElems(len_bytes, T.sizeof, min_elems, max_elems);

        return getElem!(T, Vector!T)(num_elems);
    }

    string getString(size_t len_bytes,
                      size_t min_bytes,
                      size_t max_bytes)
    {
        Vector!ubyte v = getRangeVector!ubyte(len_bytes, min_bytes, max_bytes);

        return (cast(immutable(char)*) v.ptr)[0 .. v.length];
    }

    Vector!T getFixed(T)(size_t size)
    {
        return getElem!(T, Vector!T)(size);
    }

private:
    size_t getLengthField(size_t len_bytes)
    {
        assertAtLeast(len_bytes);

        if (len_bytes == 1)
            return get_byte();
        else if (len_bytes == 2)
            return get_ushort();

        throw decodeError("Bad length size");
    }

    size_t getNumElems(size_t len_bytes,
                            size_t T_size,
                            size_t min_elems,
                            size_t max_elems)
    {
        const size_t byte_length = getLengthField(len_bytes);

        if (byte_length % T_size != 0)
            throw decodeError("Size isn't multiple of T");

        const size_t num_elems = byte_length / T_size;

        if (num_elems < min_elems || num_elems > max_elems)
            throw decodeError("Length field outside parameters");

        return num_elems;
    }

    void assertAtLeast(size_t n) const
    {
        if (m_buf.length - m_offset < n)
            throw decodeError("Expected " ~ to!string(n) ~ " bytes remaining, only " ~
                              to!string(m_buf.length-m_offset) ~ " left");
    }

    DecodingError decodeError(in string why) const
    {
        return new DecodingError("Invalid " ~ m_typename ~ ": " ~ why);
    }

    string m_typename;
    const Vector!ubyte* m_buf;
    size_t m_offset;
}

/**
* Helper function for encoding length-tagged vectors
*/
void appendTlsLengthValue(T, Alloc)(ref Vector!( ubyte, Alloc ) buf, in T* vals, 
                                        size_t vals_size, size_t tag_size)
{
    const size_t T_size = T.sizeof;
    const size_t val_bytes = T_size * vals_size;

    if (tag_size != 1 && tag_size != 2)
        throw new InvalidArgument("appendTlsLengthValue: invalid tag size");

    if ((tag_size == 1 && val_bytes > 255) ||
        (tag_size == 2 && val_bytes > 65535))
        throw new InvalidArgument("appendTlsLengthValue: value too large");

    foreach (size_t i; 0 .. tag_size)
        buf.pushBack(get_byte((val_bytes).sizeof-tag_size+i, val_bytes));

    foreach (size_t i; 0 .. vals_size)
        foreach (size_t j; 0 .. T_size)
            buf.pushBack(get_byte(j, vals[i]));
}

void appendTlsLengthValue(T, Alloc, Alloc2)(ref Vector!( ubyte, Alloc ) buf, 
                                                    auto const ref Vector!( T, Alloc2 ) vals, 
                                                    size_t tag_size)
{
    appendTlsLengthValue(buf, vals.ptr, vals.length, tag_size);
}

void appendTlsLengthValue(Alloc)(ref Vector!( ubyte, Alloc ) buf, 
                                     in string str, size_t tag_size)
{
    appendTlsLengthValue(buf, cast(const(ubyte)*)(str.ptr), str.length, tag_size);
}
