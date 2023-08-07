/*
* BLAKE2b
* (C) 2016 cynecx
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
module botan.hash.blake2b;

import botan.constants;
static if (BOTAN_HAS_BLAKE2B):

import botan.hash.hash;
import botan.algo_base.sym_algo;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.get_byte;
import botan.utils.rotate;
import std.conv : to;
import std.algorithm : min;
import std.format : format;

enum blake2b_constant { BLAKE2B_BLOCKBYTES = 128, BLAKE2B_IVU64COUNT = 8 };


const ulong[blake2b_constant.BLAKE2B_IVU64COUNT] blake2b_IV = [0x6a09e667f3bcc908,
                                                                0xbb67ae8584caa73b,
                                                                0x3c6ef372fe94f82b,
                                                                0xa54ff53a5f1d36f1,
                                                                0x510e527fade682d1,
                                                                0x9b05688c2b3e6c1f,
                                                                0x1f83d9abfb41bd6b,
                                                                0x5be0cd19137e2179];

enum string G(string a, string b, string c, string d, string M0, string M1) = q{
   %1$s = %1$s + %2$s + %5$s;
   %4$s = rotateRight(%4$s ^ %1$s, 32);
   %3$s = %3$s + %4$s;
   %2$s = rotateRight(%2$s ^ %3$s, 24);
   %1$s = %1$s + %2$s + %6$s;
   %4$s = rotateRight(%4$s ^ %1$s, 16);
   %3$s = %3$s + %4$s;
   %2$s = rotateRight(%2$s ^ %3$s, 63);
}.format(a, b, c, d, M0, M1);

enum string ARRAY_I(alias array, size_t index) = __traits(identifier, array) ~ "[" ~ index.to!string ~ "]";

enum string ROUND(
                size_t i0,
                size_t i1,
                size_t i2,
                size_t i3,
                size_t i4,
                size_t i5,
                size_t i6,
                size_t i7,
                size_t i8,
                size_t i9,
                size_t iA,
                size_t iB,
                size_t iC,
                size_t iD,
                size_t iE,
                size_t iF,
                alias v,
                alias M) =
    G!(ARRAY_I!(v, 0), ARRAY_I!(v, 4), ARRAY_I!(v, 8), ARRAY_I!(v, 12), ARRAY_I!(M, i0), ARRAY_I!(M, i1)) ~
    G!(ARRAY_I!(v, 1), ARRAY_I!(v, 5), ARRAY_I!(v, 9), ARRAY_I!(v, 13), ARRAY_I!(M, i2), ARRAY_I!(M, i3)) ~
    G!(ARRAY_I!(v, 2), ARRAY_I!(v, 6), ARRAY_I!(v, 10), ARRAY_I!(v, 14), ARRAY_I!(M, i4), ARRAY_I!(M, i5)) ~
    G!(ARRAY_I!(v, 3), ARRAY_I!(v, 7), ARRAY_I!(v, 11), ARRAY_I!(v, 15), ARRAY_I!(M, i6), ARRAY_I!(M, i7)) ~
    G!(ARRAY_I!(v, 0), ARRAY_I!(v, 5), ARRAY_I!(v, 10), ARRAY_I!(v, 15), ARRAY_I!(M, i8), ARRAY_I!(M, i9)) ~
    G!(ARRAY_I!(v, 1), ARRAY_I!(v, 6), ARRAY_I!(v, 11), ARRAY_I!(v, 12), ARRAY_I!(M, iA), ARRAY_I!(M, iB)) ~
    G!(ARRAY_I!(v, 2), ARRAY_I!(v, 7), ARRAY_I!(v, 8), ARRAY_I!(v, 13), ARRAY_I!(M, iC), ARRAY_I!(M, iD)) ~
    G!(ARRAY_I!(v, 3), ARRAY_I!(v, 4), ARRAY_I!(v, 9), ARRAY_I!(v, 14), ARRAY_I!(M, iE), ARRAY_I!(M, iF));

/**
* BLAKE2B
*/
final class Blake2b : HashFunction, SymmetricAlgorithm
{
public:

   /**
    * Params:
    *  output_bits = the output size of BLAKE2b in bits
    */
    this(size_t output_bits = 512)
    {
        m_output_bits = output_bits;
        m_buffer = blake2b_constant.BLAKE2B_BLOCKBYTES;
        m_bufpos = 0;
        m_H = blake2b_constant.BLAKE2B_IVU64COUNT;
        m_key_size = 0;

        if(output_bits == 0 || output_bits > 512 || output_bits % 8 != 0)
            throw new InvalidArgument("Bad output bits size for BLAKE2b");

        stateInit();
    }

    override @property size_t hashBlockSize() const { return 128; }
    override @property size_t outputLength() const { return m_output_bits / 8; }
    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(1, 64); }

    override HashFunction clone() const
    {
        return new Blake2b(m_output_bits);
    }

    override @property string name() const
    {
        return "BLAKE2b(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_H);
        zeroise(m_buffer);
        zeroise(m_padded_key_buffer);
        m_bufpos = 0;
        m_key_size = 0;
        stateInit();
    }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        assert(length <= m_buffer.length);

        m_key_size = length;
        m_padded_key_buffer.resize(m_buffer.length);

        if(m_padded_key_buffer.length > length)
        {
            size_t padding = m_padded_key_buffer.length - length;
            clearMem(m_padded_key_buffer.ptr + length, padding);
        }

        copyMem(m_padded_key_buffer.ptr, key, length);
        stateInit();
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if(length == 0)
            return;

        if(m_bufpos > 0)
        {
            if(m_bufpos < blake2b_constant.BLAKE2B_BLOCKBYTES)
            {
                const size_t take = min(blake2b_constant.BLAKE2B_BLOCKBYTES - m_bufpos, length);
                copyMem(&m_buffer[m_bufpos], input, take);
                m_bufpos += take;
                length -= take;
                input += take;
            }

            if(m_bufpos == m_buffer.length && length > 0)
            {
                compress(m_buffer.ptr, 1, blake2b_constant.BLAKE2B_BLOCKBYTES);
                m_bufpos = 0;
            }
        }

        if(length > blake2b_constant.BLAKE2B_BLOCKBYTES)
        {
            const size_t full_blocks = ((length - 1) / blake2b_constant.BLAKE2B_BLOCKBYTES);
            compress(input, full_blocks, blake2b_constant.BLAKE2B_BLOCKBYTES);

            input += full_blocks * blake2b_constant.BLAKE2B_BLOCKBYTES;
            length -= full_blocks * blake2b_constant.BLAKE2B_BLOCKBYTES;
        }

        if(length > 0)
        {
            copyMem(&m_buffer[m_bufpos], input, length);
            m_bufpos += length;
        }
    }

    override void finalResult(ubyte* output)
    {
        if(m_bufpos != blake2b_constant.BLAKE2B_BLOCKBYTES)
            clearMem(&m_buffer[m_bufpos], blake2b_constant.BLAKE2B_BLOCKBYTES - m_bufpos);

        m_F = 0xFFFFFFFFFFFFFFFF;
        compress(m_buffer.ptr, 1, m_bufpos);

        foreach (size_t i; 0 .. outputLength())
            output[i] = get_byte(7 - (i % 8), m_H[i/8]);

        stateInit();
    }

private:
    void stateInit()
    {
        copyMem(m_H.ptr, blake2b_IV.ptr, blake2b_constant.BLAKE2B_IVU64COUNT);
        m_H[0] ^= (0x01010000 | (cast(ubyte)(m_key_size) << 8) | cast(ubyte)(outputLength()));
        m_T[0] = m_T[1] = 0;
        m_F = 0;

        if(m_key_size == 0)
        {
            m_bufpos = 0;
        } else
        {
            assert(m_padded_key_buffer.length == m_buffer.length);
            copyMem(m_buffer.ptr, m_padded_key_buffer.ptr, m_padded_key_buffer.length);
            m_bufpos = m_padded_key_buffer.length;
        }
    }

    void compress(const(ubyte)* input, size_t blocks, ulong increment)
    {
        for(size_t b = 0; b != blocks; ++b)
        {
            m_T[0] += increment;
            if(m_T[0] < increment)
                m_T[1]++;

            ulong[16] M;
            ulong[16] v;
            loadLittleEndian(M.ptr, input, 16);

            input += blake2b_constant.BLAKE2B_BLOCKBYTES;

            for(size_t i = 0; i < 8; i++)
            {
                v[i] = m_H[i];
            }

            for(size_t i = 0; i != 8; ++i)
            {
                v[i + 8] = blake2b_IV[i];
            }

            v[12] ^= m_T[0];
            v[13] ^= m_T[1];
            v[14] ^= m_F;

            mixin(ROUND!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, v, M));
            mixin(ROUND!(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, v, M));
            mixin(ROUND!(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, v, M));
            mixin(ROUND!(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, v, M));
            mixin(ROUND!(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, v, M));
            mixin(ROUND!(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, v, M));
            mixin(ROUND!(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, v, M));
            mixin(ROUND!(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, v, M));
            mixin(ROUND!(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, v, M));
            mixin(ROUND!(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0, v, M));
            mixin(ROUND!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, v, M));
            mixin(ROUND!(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, v, M));

            for(size_t i = 0; i < 8; i++)
            {
                m_H[i] ^= v[i] ^ v[i + 8];
            }
        }
    }

    const size_t m_output_bits;

    SecureVector!ubyte m_buffer;
    size_t m_bufpos;

    SecureVector!ulong m_H;
    ulong[2] m_T;
    ulong m_F;

    size_t m_key_size;
    SecureVector!ubyte m_padded_key_buffer;
}
