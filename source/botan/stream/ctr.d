/**
* CTR-BE Mode
* 
* Copyright:
* (C) 1999-2011,2014 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
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
import botan.utils.exceptn;

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

        zeroise(m_iv);
        if (iv_len)
            copyMem(m_iv.ptr, iv, iv_len);

        const size_t bs = m_block_size;
        zeroise(m_counter);
        copyMem(m_counter.ptr, m_iv.ptr, bs);

        // Set m_counter blocks to IV, IV + 1, ... IV + 255
        foreach (size_t i; 1 .. 256)
        {
            copyMem(&m_counter[i*bs], &m_counter[(i-1)*bs], bs);
            foreach (size_t j; 0 .. m_ctr_size)
                if (++(m_counter[i*bs + (bs - 1 - j)]))
                    break;
        }

        m_cipher.encryptN(m_counter.ptr, m_pad.ptr, 256);
        m_pad_pos = 0;
    }

    override void seek(ulong offset)
    {
        if (m_ctr_size < 8)
        {
            const ulong max_blocks = 1uL << (8 * m_ctr_size);
            if (offset / m_block_size >= max_blocks)
                throw new InvalidArgument("CTR-BE seek past counter range");
        }
        // setIv zeros m_iv before reading `iv`; copy first.
        auto ivcopy = Vector!ubyte(m_iv[].dup);
        setIv(ivcopy.ptr, m_block_size);
        const ulong batches = offset / m_counter.length;
        foreach (i; 0 .. batches)
            increment_counter();
        m_pad_pos = cast(size_t)(offset % m_counter.length);
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len <= m_cipher.blockSize()); }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    @property string name() const
    {
        if (m_ctr_size == m_block_size)
            return ("CTR-BE(" ~ m_cipher.name ~ ")");
        import std.conv : to;
        return ("CTR-BE(" ~ m_cipher.name ~ "," ~ m_ctr_size.to!string ~ ")");
    }

    override CTRBE clone() const
    { return new CTRBE(m_cipher.clone(), m_ctr_size); }

    override void clear()
    {
        m_cipher.clear();
        zeroise(m_pad);
        zeroise(m_counter);
        zeroise(m_iv);
        m_pad_pos = 0;
    }

    /**
    * Params:
    *  ciph = the underlying block cipher to use
    *  ctr_size = counter width in bytes (default = block size)
    */
    this(BlockCipher ciph, size_t ctr_size = 0)
    {
        // Unique.opAssign nulls `ciph`; read sizes before taking ownership.
        const size_t bs = ciph.blockSize();
        m_block_size = bs;
        m_ctr_size = ctr_size ? ctr_size : bs;
        if (m_ctr_size < 4 || m_ctr_size > bs)
            throw new InvalidArgument("Invalid CTR-BE counter size");
        m_counter = 256 * bs;
        m_pad = m_counter.length;
        m_iv = SecureVector!ubyte(bs);
        m_pad_pos = 0;
        m_cipher = ciph;
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
            foreach (size_t j; 1 .. m_ctr_size)
                if (++(m_counter[i*bs + (bs - 1 - j)]))
                    break;
        }
        
        m_cipher.encryptN(m_counter.ptr, m_pad.ptr, 256);
        m_pad_pos = 0;
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_counter, m_pad, m_iv;
    size_t m_pad_pos;
    size_t m_block_size;
    size_t m_ctr_size;
}
