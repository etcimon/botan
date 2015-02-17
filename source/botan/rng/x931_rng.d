/**
* ANSI X9.31 RNG
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.x931_rng;

import botan.constants;
static if (BOTAN_HAS_X931_RNG):

import botan.rng.rng;
import botan.block.block_cipher;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm;

/**
* ANSI X9.31 RNG
*/
final class ANSIX931RNG : RandomNumberGenerator
{
public:
    override void randomize(ubyte* output, size_t length)
    {
        if (!isSeeded())
        {
            reseed(BOTAN_RNG_RESEED_POLL_BITS);
            
            if (!isSeeded())
                throw new PRNGUnseeded(name);
        }
        
        while (length)
        {
            if (m_R_pos == m_R.length)
                updateBuffer();
            
            const size_t copied = std.algorithm.min(length, m_R.length - m_R_pos);
            
            copyMem(output, &m_R[m_R_pos], copied);
            output += copied;
            length -= copied;
            m_R_pos += copied;
        }
    }

    override bool isSeeded() const
    {
        return (m_V.length > 0);
    }

    override void clear()
    {
        m_cipher.clear();
        m_prng.clear();
        zeroise(m_R);
        m_V.clear();
        
        m_R_pos = 0;
    }

    override @property string name() const
    {
        return "X9.31(" ~ m_cipher.name ~ ")";
    }

    override void reseed(size_t poll_bits)
    {
        m_prng.reseed(poll_bits);
        rekey();
    }

    override void addEntropy(const(ubyte)* input, size_t length)
    {
        m_prng.addEntropy(input, length);
        rekey();
    }

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }

    /**
    * Params:
    *  cipher = the block cipher to use in this PRNG
    *  rng = the underlying PRNG for generating inputs
    * (eg, an HMAC_RNG)
    */
    this(BlockCipher cipher,
         RandomNumberGenerator prng)
    {
        m_cipher = cipher;
        m_prng = prng;
        m_R = m_cipher.blockSize();
        m_R_pos = 0;
    }

private:
    /*
    * Reset V and the cipher key with new values
    */
    void rekey()
    {
        const size_t BLOCK_SIZE = m_cipher.blockSize();
        
        if (m_prng.isSeeded())
        {
            m_cipher.setKey(m_prng.randomVec(m_cipher.maximumKeylength()));
            
            if (m_V.length != BLOCK_SIZE)
                m_V.resize(BLOCK_SIZE);
            m_prng.randomize(m_V.ptr, m_V.length);
            
            updateBuffer();
        }
    }

    /*
    * Refill the internal state
    */
    void updateBuffer()
    {
        const size_t BLOCK_SIZE = m_cipher.blockSize();
        
        SecureVector!ubyte DT = m_prng.randomVec(BLOCK_SIZE);
        m_cipher.encrypt(DT);
        
        xorBuf(m_R.ptr, m_V.ptr, DT.ptr, BLOCK_SIZE);
        m_cipher.encrypt(m_R);
        
        xorBuf(m_V.ptr, m_R.ptr, DT.ptr, BLOCK_SIZE);
        m_cipher.encrypt(m_V);
        
        m_R_pos = 0;
    }


    Unique!BlockCipher m_cipher;
    Unique!RandomNumberGenerator m_prng;
    SecureVector!ubyte m_V, m_R;
    size_t m_R_pos;
}