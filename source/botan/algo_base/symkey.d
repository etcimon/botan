/**
* OctetString
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_base.symkey;

import botan.utils.xor_buf;
import botan.rng.rng;
import botan.filters.pipe;
import botan.codec.hex;
import std.algorithm;
import memutils.vector;
import botan.utils.types;
import memutils.refcounted;
alias OctetString = RefCounted!OctetStringImpl;

/**
* Octet String
*/
struct OctetStringImpl
{
public:
    /**
    * Returns: size of this octet string in bytes
    */
    @property size_t length() const { return m_bits.length; }
    
    /**
    * Returns: this object as a $(D SecureVector!ubyte)
    */
    SecureVector!ubyte bitsOf() const { return m_bits.dup; }
    
    /**
    * Returns: Pointer to the first ubyte of this string
    */
    @property ubyte* ptr() const { return m_bits.ptr; }
    
    /**
    * Returns: Pointer to one past the end of this string
    */
    ubyte* end() const{ return ptr + m_bits.length; }
    
    /**
    * Returns: this encoded as hex
    */
    string toString() const
    {
        return hexEncode(m_bits.ptr, m_bits.length);
    }
        
    /**
    * XOR the contents of another octet string into this one
    * 
    * Params:
    *  other = octet string
    * 
    * Returns: reference to this
    */
    OctetString opOpAssign(string op)(in OctetString other)
        if (op == "^")
    {
        if (other.ptr is this.ptr) { zeroise(m_bits); return; }
        xorBuf(m_bits.ptr, other.ptr, min(length(), other.length));
        return this;
    }
    
    /**
    * Force to have odd parity
    */
    void setOddParity()
    {
        __gshared immutable ubyte[256] ODD_PARITY = [
                0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07, 0x08, 0x08, 0x0B, 0x0B,
                0x0D, 0x0D, 0x0E, 0x0E, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
                0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F, 0x20, 0x20, 0x23, 0x23,
                0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
                0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3B, 0x3B,
                0x3D, 0x3D, 0x3E, 0x3E, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
                0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x51, 0x51, 0x52, 0x52,
                0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
                0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6B, 0x6B,
                0x6D, 0x6D, 0x6E, 0x6E, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
                0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F, 0x80, 0x80, 0x83, 0x83,
                0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
                0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9B, 0x9B,
                0x9D, 0x9D, 0x9E, 0x9E, 0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
                0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE, 0xB0, 0xB0, 0xB3, 0xB3,
                0xB5, 0xB5, 0xB6, 0xB6, 0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
                0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7, 0xC8, 0xC8, 0xCB, 0xCB,
                0xCD, 0xCD, 0xCE, 0xCE, 0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
                0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF, 0xE0, 0xE0, 0xE3, 0xE3,
                0xE5, 0xE5, 0xE6, 0xE6, 0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
                0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7, 0xF8, 0xF8, 0xFB, 0xFB,
                0xFD, 0xFD, 0xFE, 0xFE ];
        
        foreach (j; 0 .. m_bits.length)
            m_bits[j] = ODD_PARITY[m_bits[j]];
    }
    
    /**
    * Create a new OctetString
    * 
    * Params:
    *  hex_string = A hex encoded string
    */
    this(in string hex_string = "")
    {
        m_bits.resize(1 + hex_string.length / 2);
        m_bits.resize(hexDecode(m_bits.ptr, hex_string));
    }

    /**
    * Create a new random OctetString
    * 
    * Params:
    *  rng = is a random number generator
    *  len = is the desired length in bytes
    */
    this(RandomNumberGenerator rng, size_t len)
    {
        m_bits = rng.randomVec(len);
    }
    
    /**
    * Create a new OctetString
    * 
    * Params:
    *  input = is an array
    *  len = is the length of in in bytes
    */
    this(const(ubyte)* input, size_t len)
    {
        m_bits = SecureVector!ubyte(input[0 .. len]);
    }
    
    /**
    * Create a new OctetString
    * 
    * Params:
    *  input = a bytestring
    */
    this(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input) {  m_bits = SecureVector!ubyte(input.ptr[0 .. input.length]); }

    /// ditto
    this(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input) {  m_bits = SecureVector!ubyte(input.ptr[0 .. input.length]); }


    /**
    * Compare two strings
    * 
    * Params:
    *  other = an octet string
    * 
    * Returns: true if x is equal to y
    */
    bool opEquals(const ref OctetString other) const
    {
        return (bitsOf() == other.bitsOf());
    }

    /**
    * Compare two strings
    * Params:
    *  other = an octet string
    * 
    * Returns: 1 if this is bigger, -1 if smaller, 0 if equal to other
    */
    int opCmp(const ref OctetString other) const
    {
        if (this == other) return 0;
        else if (bitsOf()[] < other.bitsOf()[])
            return -1;
        else return 1;
    }

	/// Append another $(D OctetString) to this
    void opOpAssign(string op)(auto const ref OctetString other)
        if (op == "~")
    {
        m_bits ~= other.m_bits[];
    }

    /**
    * Concatenate two strings
    * 
    * Params:
    *  other = an octet string
    *
    * Returns: this concatenated with other
    */
    OctetString opBinary(string op)(auto const ref OctetString other)
        if (op == "~") 
    {
        SecureVector!ubyte output;
        output = bitsOf();
        output ~= other.bitsOf();
        return OctetString(output);
    }
    
    /**
    * XOR two strings
    * 
    * Params:
    *  other = an octet string
    * 
    * Returns: this XORed with other
    */
    OctetString opBinary(string op)(auto const ref OctetString other)
        if (op == "^") 
    {
        SecureVector!ubyte ret = SecureVector!ubyte(max(length(), other.length));
        
        copyMem(ret.ptr, k1.ptr, k1.length);
        xorBuf(ret.ptr, k2.ptr, k2.length);
        return OctetString(ret);
    }

	/// Returns: A copy of the underlying bits in a new octet string
    @property OctetString dup() const
    {
        return OctetString(m_bits.dup);
    }

private:
    SecureVector!ubyte m_bits;
}

/**
* Alternate name for octet string showing intent to use as a key
*/
alias SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
alias InitializationVector = OctetString;