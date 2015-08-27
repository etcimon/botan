/**
* EMSA1
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.emsa1;

import botan.constants;
static if (BOTAN_HAS_EMSA1):

public import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.utils.types;

/**
* EMSA1 from IEEE 1363
* Essentially, sign the hash directly
*/
class EMSA1 : EMSA
{
public:
    /**
    * Params:
    *  hash = the hash function to use
    */
    this(HashFunction hash) 
    {
        m_hash = hash;
    }

    size_t hashOutputLength() const { return m_hash.outputLength; }

    override void update(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    override SecureVector!ubyte rawData()
    {
        return m_hash.finished();
    }

    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng)
    {
        //logDebug("EMSA1 Encode");
        if (msg.length != hashOutputLength())
            throw new EncodingError("encodingOf: Invalid size for input");
        return emsa1Encoding(msg, output_bits);
    }

    override bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw, size_t key_bits)
    {
        try {
            if (raw.length != m_hash.outputLength)
                throw new EncodingError("encodingOf: Invalid size for input");
            
            SecureVector!ubyte our_coding = emsa1Encoding(raw, key_bits);
            if (our_coding == coded) return true;
            if (our_coding.empty || our_coding[0] != 0) return false;
            if (our_coding.length <= coded.length) return false;
            
            size_t offset = 0;
            while (offset < our_coding.length && our_coding[offset] == 0)
                ++offset;
            if (our_coding.length - offset != coded.length)
                return false;
            
            for (size_t j = 0; j != coded.length; ++j)
                if (coded[j] != our_coding[j+offset])
                    return false;
            
            return true;
        }
        catch(InvalidArgument)
        {
            return false;
        }
    }

    Unique!HashFunction m_hash;
}

private:

SecureVector!ubyte emsa1Encoding(const ref SecureVector!ubyte msg_, size_t output_bits)
{
    SecureVector!ubyte msg = msg_.dup;

    if (8*msg.length <= output_bits)
        return msg.move;
    // logDebug("Generate digest");
    size_t shift = 8*msg.length - output_bits;
    
    size_t byte_shift = shift / 8, bit_shift = shift % 8;
    SecureVector!ubyte digest = SecureVector!ubyte(msg.length - byte_shift);
    
    for (size_t j = 0; j != msg.length - byte_shift; ++j)
        digest[j] = msg[j];
    
    if (bit_shift)
    {
        ubyte carry = 0;
        for (size_t j = 0; j != digest.length; ++j)
        {
            ubyte temp = digest[j];
            digest[j] = (temp >> bit_shift) | carry;
            carry = cast(ubyte)(temp << (8 - bit_shift));
        }
    }
    return digest.move();
}
