/**
* PSSR
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.pssr;

import botan.constants;
static if (BOTAN_HAS_EMSA_PSSR):

import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.utils.types;
import botan.pk_pad.mgf1;
import botan.utils.bit_ops;
import botan.utils.xor_buf;
import botan.utils.mem_ops;

/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR : EMSA
{
public:

    /**
    * Params:
    *  hash = the hash object to use
    */
    this(HashFunction hash)
    {
        m_SALT_SIZE = hash.outputLength;
        m_hash = hash;
    }

    /**
    * Params:
    *  hash = the hash object to use
    *  salt_size = the size of the salt to use in bytes
    */
    this(HashFunction hash, size_t salt_size)
    {
        m_SALT_SIZE = salt_size;
        m_hash = hash;
    }

    /*
    * PSSR Update Operation
    */
    override void update(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    /*
    * Return the raw (unencoded) data
    */
    override SecureVector!ubyte rawData()
    {
        return m_hash.finished();
    }

    /*
    * PSSR Encode Operation
    */
    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng)
    {
        const size_t HASH_SIZE = m_hash.outputLength;
        
        if (msg.length != HASH_SIZE)
            throw new EncodingError("encodingOf: Bad input length");
        if (output_bits < 8*HASH_SIZE + 8*m_SALT_SIZE + 9)
            throw new EncodingError("encodingOf: Output length is too small");
        
        const size_t output_length = (output_bits + 7) / 8;
        
        SecureVector!ubyte salt = rng.randomVec(m_SALT_SIZE);
        
        foreach (size_t j; 0 .. 8)
            m_hash.update(0);
        m_hash.update(msg);
        m_hash.update(salt);
        SecureVector!ubyte H = m_hash.finished();
        
        SecureVector!ubyte EM = SecureVector!ubyte(output_length);
        
        EM[output_length - HASH_SIZE - m_SALT_SIZE - 2] = 0x01;
        bufferInsert(EM, output_length - 1 - HASH_SIZE - m_SALT_SIZE, salt);
        mgf1Mask(*m_hash, H.ptr, HASH_SIZE, EM.ptr, output_length - HASH_SIZE - 1);
        EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
        bufferInsert(EM, output_length - 1 - HASH_SIZE, H);
        EM[output_length-1] = 0xBC;
        
        return EM;
    }

    /*
    * PSSR Decode/Verify Operation
    */
    override bool verify(const ref SecureVector!ubyte const_coded,
                         const ref SecureVector!ubyte raw, size_t key_bits)
    {
        const size_t HASH_SIZE = m_hash.outputLength;
        const size_t KEY_BYTES = (key_bits + 7) / 8;
        
        if (key_bits < 8*HASH_SIZE + 9)
            return false;
        
        if (raw.length != HASH_SIZE)
            return false;
        
        if (const_coded.length > KEY_BYTES || const_coded.length <= 1)
            return false;
        
        if (const_coded[const_coded.length-1] != 0xBC)
            return false;
        
        SecureVector!ubyte coded = const_coded.dup;
        if (coded.length < KEY_BYTES)
        {
            SecureVector!ubyte temp = SecureVector!ubyte(KEY_BYTES);
            bufferInsert(temp, KEY_BYTES - coded.length, coded);
            coded = temp;
        }
        
        const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
        if (TOP_BITS > 8 - highBit(coded[0]))
            return false;
        
        ubyte* DB = coded.ptr;
        const size_t DB_size = coded.length - HASH_SIZE - 1;
        
        const(ubyte)* H = &coded[DB_size];
        const size_t H_size = HASH_SIZE;
        
        mgf1Mask(*m_hash, H, H_size, DB, DB_size);
        DB[0] &= 0xFF >> TOP_BITS;
        
        size_t salt_offset = 0;
        foreach (size_t j; 0 .. DB_size)
        {
            if (DB[j] == 0x01)
            { salt_offset = j + 1; break; }
            if (DB[j])
                return false;
        }
        if (salt_offset == 0)
            return false;
        
        foreach (size_t j; 0 .. 8)
            m_hash.update(0);
        m_hash.update(raw);
        m_hash.update(&DB[salt_offset], DB_size - salt_offset);
        SecureVector!ubyte H2 = m_hash.finished();
        
        return sameMem(H, H2.ptr, HASH_SIZE);
    }

private:
    size_t m_SALT_SIZE;
    Unique!HashFunction m_hash;
}
