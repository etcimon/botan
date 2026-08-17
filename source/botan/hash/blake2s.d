/**
* BLAKE2s
*
* Copyright:
* (C) 2023, 2025       Richard Huveneers
* (C) 2025             Kagan Can Sit
* (C) 2025             René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.blake2s;

import botan.constants;
static if (BOTAN_HAS_BLAKE2S):

import botan.hash.hash;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.rotate;
import botan.utils.types;
import std.algorithm : min;
import std.conv : to;

enum size_t BLAKE2S_BLOCKBYTES = 64;

immutable uint[8] blake2s_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
];

/**
* BLAKE2s (RFC 7693). SCAN: "BLAKE2s" or "BLAKE2s(256)".
*/
final class Blake2s : HashFunction
{
public:
    this(size_t output_bits = 256)
    {
        if (output_bits == 0 || output_bits > 256 || output_bits % 8 != 0)
            throw new InvalidArgument("Bad output bits size for BLAKE2s");
        m_output_bits = output_bits;
        m_buffer = SecureVector!ubyte(BLAKE2S_BLOCKBYTES);
        m_H = SecureVector!uint(8);
        stateInit();
    }

    override @property size_t hashBlockSize() const { return BLAKE2S_BLOCKBYTES; }
    override @property size_t outputLength() const { return m_output_bits / 8; }
    override HashFunction clone() const { return new Blake2s(m_output_bits); }
    override @property string name() const { return "BLAKE2s(" ~ to!string(m_output_bits) ~ ")"; }

    override void clear()
    {
        zeroise(m_H);
        zeroise(m_buffer);
        m_bufpos = 0;
        stateInit();
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        if (length == 0)
            return;

        if (m_bufpos > 0)
        {
            if (m_bufpos < BLAKE2S_BLOCKBYTES)
            {
                const size_t take = min(BLAKE2S_BLOCKBYTES - m_bufpos, length);
                copyMem(&m_buffer[m_bufpos], input, take);
                m_bufpos += take;
                length -= take;
                input += take;
            }
            if (m_bufpos == BLAKE2S_BLOCKBYTES && length > 0)
            {
                compress(m_buffer.ptr, false, BLAKE2S_BLOCKBYTES);
                m_bufpos = 0;
            }
        }

        if (length > BLAKE2S_BLOCKBYTES)
        {
            const size_t full_blocks = (length - 1) / BLAKE2S_BLOCKBYTES;
            foreach (b; 0 .. full_blocks)
            {
                compress(input, false, BLAKE2S_BLOCKBYTES);
                input += BLAKE2S_BLOCKBYTES;
                length -= BLAKE2S_BLOCKBYTES;
            }
        }

        if (length > 0)
        {
            copyMem(&m_buffer[m_bufpos], input, length);
            m_bufpos += length;
        }
    }

    override void finalResult(ubyte* output)
    {
        if (m_bufpos != BLAKE2S_BLOCKBYTES)
            clearMem(&m_buffer[m_bufpos], BLAKE2S_BLOCKBYTES - m_bufpos);
        compress(m_buffer.ptr, true, m_bufpos);
        foreach (i; 0 .. outputLength())
            output[i] = cast(ubyte)(m_H[i / 4] >> (8 * (i % 4)));
        stateInit();
    }

private:
    void stateInit()
    {
        m_H[] = blake2s_IV[];
        m_H[0] ^= 0x01010000 ^ cast(uint) outputLength();
        m_T = 0;
        m_bufpos = 0;
    }

    void G(ref uint[16] v, size_t a, size_t b, size_t c, size_t d, uint x, uint y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = rotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = rotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = rotateRight(v[b] ^ v[c], 7);
    }

    void compress(const(ubyte)* input, bool last, ulong increment)
    {
        m_T += increment;

        uint[16] M;
        loadLittleEndian(M.ptr, input, 16);

        uint[16] v;
        foreach (i; 0 .. 8)
        {
            v[i] = m_H[i];
            v[i + 8] = blake2s_IV[i];
        }
        v[12] ^= cast(uint) m_T;
        v[13] ^= cast(uint)(m_T >> 32);
        if (last)
            v[14] = ~v[14];

        static immutable ubyte[16][10] sigma = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
            [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
            [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
            [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
            [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
            [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
            [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
            [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
            [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
        ];

        foreach (r; 0 .. 10)
        {
            auto p = sigma[r];
            G(v, 0, 4, 8, 12, M[p[0]], M[p[1]]);
            G(v, 1, 5, 9, 13, M[p[2]], M[p[3]]);
            G(v, 2, 6, 10, 14, M[p[4]], M[p[5]]);
            G(v, 3, 7, 11, 15, M[p[6]], M[p[7]]);
            G(v, 0, 5, 10, 15, M[p[8]], M[p[9]]);
            G(v, 1, 6, 11, 12, M[p[10]], M[p[11]]);
            G(v, 2, 7, 8, 13, M[p[12]], M[p[13]]);
            G(v, 3, 4, 9, 14, M[p[14]], M[p[15]]);
        }

        foreach (i; 0 .. 8)
            m_H[i] ^= v[i] ^ v[i + 8];
    }

    const size_t m_output_bits;
    SecureVector!ubyte m_buffer;
    size_t m_bufpos;
    SecureVector!uint m_H;
    ulong m_T;
}
