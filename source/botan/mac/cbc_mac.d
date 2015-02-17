/**
* CBC-MAC
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.cbc_mac;

import botan.constants;
static if (BOTAN_HAS_CBC_MAC):

import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import std.algorithm;

/**
* CBC-MAC
*/
final class CBCMAC : MessageAuthenticationCode, SymmetricAlgorithm
{
public:
    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "CBC-MAC(" ~ m_cipher.name ~ ")";
    }

    /*
    * Return a clone of this object
    */
    override MessageAuthenticationCode clone() const
    {
        return new CBCMAC(m_cipher.clone());
    }

    override @property size_t outputLength() const { return m_cipher.blockSize(); }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_cipher.clear();
        zeroise(m_state);
        m_position = 0;
    }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    /**
    * Params:
    *  cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher)
    {
        m_cipher = cipher;
        m_state = m_cipher.blockSize();
    }


protected:
    /*
    * Update an CBC-MAC Calculation
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        size_t xored = std.algorithm.min(outputLength() - m_position, length);
        xorBuf(&m_state[m_position], input, xored);
        m_position += xored;
        
        if (m_position < outputLength())
            return;
        
        m_cipher.encrypt(m_state);
        input += xored;
        length -= xored;
        while (length >= outputLength())
        {
            xorBuf(m_state, input, outputLength());
            m_cipher.encrypt(m_state);
            input += outputLength();
            length -= outputLength();
        }
        
        xorBuf(m_state, input, length);
        m_position = length;
    }    

    /*
    * Finalize an CBC-MAC Calculation
    */
    override void finalResult(ubyte* mac)
    {
        if (m_position)
            m_cipher.encrypt(m_state);
        
        copyMem(mac, m_state.ptr, m_state.length);
        zeroise(m_state);
        m_position = 0;
    }

    /*
    * CBC-MAC Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_state;
    size_t m_position;
}