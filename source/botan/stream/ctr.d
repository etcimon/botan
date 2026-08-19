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
        // Raw pad pointer: Vector.opIndex was 9.75% exclusive Ir on /64k
        // (bounds check on every increment_counter / xorBuf offset).
        auto pad = m_pad.ptr;
        const size_t pad_len = m_pad.length;
        while (length >= pad_len - m_pad_pos)
        {
            const size_t n = pad_len - m_pad_pos;
            xorBuf(output, input, pad + m_pad_pos, n);
            length -= n;
            input += n;
            output += n;
            increment_counter();
            pad = m_pad.ptr;
        }
        xorBuf(output, input, pad + m_pad_pos, length);
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

        // Set m_counter blocks to IV, IV + 1, ... IV + (pad_blocks-1)
        auto ctr = m_counter.ptr;
        foreach (size_t i; 1 .. m_pad_blocks)
        {
            copyMem(ctr + i * bs, ctr + (i - 1) * bs, bs);
            addToCounter(ctr + i * bs, 1);
        }

        m_cipher.encryptN(m_counter.ptr, m_pad.ptr, m_pad_blocks);
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
    { return new CTRBE(m_cipher.clone(), m_ctr_size, m_pad_blocks); }

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
    *  pad_blocks = precomputed keystream blocks (default 256; GCM uses 32)
    */
    this(BlockCipher ciph, size_t ctr_size = 0, size_t pad_blocks = 256)
    {
        // Unique.opAssign nulls `ciph`; read sizes before taking ownership.
        const size_t bs = ciph.blockSize();
        m_block_size = bs;
        m_ctr_size = ctr_size ? ctr_size : bs;
        if (m_ctr_size < 4 || m_ctr_size > bs)
            throw new InvalidArgument("Invalid CTR-BE counter size");
        if (pad_blocks < 1 || pad_blocks > 256)
            throw new InvalidArgument("Invalid CTR-BE pad blocks");
        m_pad_blocks = pad_blocks;
        m_counter = pad_blocks * bs;
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

    /// Add `n` to the big-endian `m_ctr_size`-byte counter at the end of `blk`.
    void addToCounter(ubyte* blk, size_t n)
    {
        size_t off = m_block_size - 1;
        size_t x = n;
        foreach (size_t j; 0 .. m_ctr_size)
        {
            x += blk[off - j];
            blk[off - j] = cast(ubyte) x;
            x >>= 8;
            if (x == 0)
                return;
        }
    }

    /*
    * Increment each precomputed counter by pad_blocks and refill the pad.
    * (pad_blocks == 256 used to skip the lowest byte; that is add-256 only.)
    */
    void increment_counter()
    {
        const size_t bs = m_block_size;
        const size_t n = m_pad_blocks;
        auto ctr = m_counter.ptr;
        foreach (size_t i; 0 .. n)
            addToCounter(ctr + i * bs, n);

        m_cipher.encryptN(ctr, m_pad.ptr, n);
        m_pad_pos = 0;
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_counter, m_pad, m_iv;
    size_t m_pad_pos;
    size_t m_block_size;
    size_t m_ctr_size;
    size_t m_pad_blocks;
}
