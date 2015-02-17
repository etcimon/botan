/**
* X9.31 EMSA
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.emsa_x931;

import botan.constants;
static if (BOTAN_HAS_EMSA_X931):
import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.pk_pad.hash_id;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* EMSA from X9.31 (EMSA2 in IEEE 1363)
* Useful for Rabin-Williams, also sometimes used with RSA in
* odd protocols.
*/
final class EMSAX931 : EMSA
{
public:
    /**
    * Params:
    *  hash = the hash object to use
    */
    this(HashFunction hash)
    {
        m_hash = hash;
        m_empty_hash = m_hash.finished();
        
        m_hash_id = ieee1363HashId(m_hash.name);
        
        if (!m_hash_id)
            throw new EncodingError("EMSA_X931 no hash identifier for " ~ hash.name);
    }
public:
    override void update(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    override SecureVector!ubyte rawData()
    {
        return m_hash.finished();
    }

    /*
    * EMSA_X931 Encode Operation
    */
    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator)
    {
        return emsa2Encoding(msg, output_bits, m_empty_hash, m_hash_id);
    }

    /*
    * EMSA_X931 Verify Operation
    */
    bool verify(const ref SecureVector!ubyte coded,
                const ref SecureVector!ubyte raw,
                size_t key_bits)
    {
        try
        {
            return (coded == emsa2Encoding(raw, key_bits,
                                            m_empty_hash, m_hash_id));
        }
        catch (Throwable)
        {
            return false;
        }
    }

private:
    SecureVector!ubyte m_empty_hash;
    Unique!HashFunction m_hash;
    ubyte m_hash_id;
}

private:

SecureVector!ubyte emsa2Encoding(const ref SecureVector!ubyte msg,
                                size_t output_bits,
                                const ref SecureVector!ubyte empty_hash,
                                ubyte hash_id)
{
    const size_t HASH_SIZE = empty_hash.length;
    
    size_t output_length = (output_bits + 1) / 8;
    
    if (msg.length != HASH_SIZE)
        throw new EncodingError("encodingOf: Bad input length");
    if (output_length < HASH_SIZE + 4)
        throw new EncodingError("encodingOf: Output length is too small");
    
    const bool empty_input = (msg == empty_hash);
    
    SecureVector!ubyte output = SecureVector!ubyte(output_length);
    
    output[0] = (empty_input ? 0x4B : 0x6B);
    output[output_length - 3 - HASH_SIZE] = 0xBA;
    setMem(&output[1], output_length - 4 - HASH_SIZE, 0xBB);
    bufferInsert(output, output_length - (HASH_SIZE + 2), msg.ptr, msg.length);
    output[output_length-2] = hash_id;
    output[output_length-1] = 0xCC;
    
    return output;
}
