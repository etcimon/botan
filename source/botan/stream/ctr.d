/**
* CTR-BE Mode
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.ctr;

import botan.constants;
static if (BOTAN_HAS_CTR_BE):

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* CTR-BE (Counter mode, big-endian)
*/
final class CTRBE : StreamCipher, SymmetricAlgorithm
{
public:
    override void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        while (length >= m_pad.length - m_pad_pos)
        {
            xorBuf(output, input, &m_pad[m_pad_pos], m_pad.length - m_pad_pos);
            length -= (m_pad.length - m_pad_pos);
            input += (m_pad.length - m_pad_pos);
            output += (m_pad.length - m_pad_pos);
            increment_counter();
        }
        xorBuf(output, input, &m_pad[m_pad_pos], length);
        m_pad_pos += length;
    }


    override void setIv(const(ubyte)* iv, size_t iv_len)
    {
        if (!validIvLength(iv_len))
            throw new InvalidIVLength(name, iv_len);
        
        const size_t bs = m_cipher.blockSize();
        
        zeroise(m_counter);
        
        bufferInsert(m_counter, 0, iv, iv_len);
        
        // Set m_counter blocks to IV, IV + 1, ... IV + 255
        foreach (size_t i; 1 .. 256)
        {
            bufferInsert(m_counter, i*bs, &m_counter[(i-1)*bs], bs);
            
            foreach (size_t j; 0 .. bs)
                if (++(m_counter[i*bs + (bs - 1 - j)]))
                    break;
        }
        
        m_cipher.encryptN(m_counter.ptr, m_pad.ptr, 256);
        m_pad_pos = 0;
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len <= m_cipher.blockSize()); }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    @property string name() const
    {
        return ("CTR-BE(" ~ m_cipher.name ~ ")");
    }

    override CTRBE clone() const
    { return new CTRBE(m_cipher.clone()); }

    override void clear()
    {
        m_cipher.clear();
        zeroise(m_pad);
        zeroise(m_counter);
        m_pad_pos = 0;
    }

    /**
    * Params:
    *  cipher = the underlying block cipher to use
    */
    this(BlockCipher ciph)
    {
        m_cipher = ciph;
        m_counter = 256 * m_cipher.blockSize();
        m_pad = m_counter.length;
        m_pad_pos = 0;
    }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
        
        // Set a default all-zeros IV
        setIv(null, 0);
    }

    /*
    * Increment the counter and update the buffer
    */
    void increment_counter()
    {
        const size_t bs = m_cipher.blockSize();
        
        /*
        * Each counter value always needs to be incremented by 256,
        * so we don't touch the lowest ubyte and instead treat it as
        * an increment of one starting with the next ubyte.
        */
        foreach (size_t i; 0 .. 256)
        {
            foreach (size_t j; 1 .. bs)
                if (++(m_counter[i*bs + (bs - 1 - j)]))
                    break;
        }
        
        m_cipher.encryptN(m_counter.ptr, m_pad.ptr, 256);
        m_pad_pos = 0;
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_counter, m_pad;
    size_t m_pad_pos;
}
