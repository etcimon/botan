/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
module botan.hash.sha3;

import botan.constants;
static if (BOTAN_HAS_SHA3):

import botan.hash.hash;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.get_byte;
import botan.utils.rotate;
import std.conv : to;
import std.algorithm : min;

/**
* SHA-3
*/
class SHA3 : HashFunction
{
public:

    /**
    * Params:
    *  output_bits = the size of the hash output; must be one of
    *                          224, 256, 384, or 512
    */
    this(size_t output_bits = 512)
    {
        m_output_bits = output_bits;
        m_bitrate = 1600 - 2 * output_bits;
        m_S = 25;
        m_S_pos = 0;

        // We only support the parameters for SHA-3 in this constructor

        if (output_bits != 224 && output_bits != 256 &&
            output_bits != 384 && output_bits != 512)
            throw new InvalidArgument("SHA_3: Invalid output length " ~ to!string(output_bits));
    }

    override @property size_t hashBlockSize() const { return m_bitrate / 8; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new SHA3(m_output_bits);
    }

    override @property string name() const
    {
        return "SHA-3(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_S);
        m_S_pos = 0;
    }

    pragma(inline, true)
    static void round(ref ulong[25] T, const ulong[25] A, ulong RC) pure
    {
        const ulong C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        const ulong C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        const ulong C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        const ulong C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        const ulong C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

        const ulong D0 = rotateLeft(C0, 1) ^ C3;
        const ulong D1 = rotateLeft(C1, 1) ^ C4;
        const ulong D2 = rotateLeft(C2, 1) ^ C0;
        const ulong D3 = rotateLeft(C3, 1) ^ C1;
        const ulong D4 = rotateLeft(C4, 1) ^ C2;

        const ulong B00 = A[ 0] ^ D1;
        const ulong B01 = rotateLeft(A[6] ^ D2, 44);
        const ulong B02 = rotateLeft(A[12] ^ D3, 43);
        const ulong B03 = rotateLeft(A[18] ^ D4, 21);
        const ulong B04 = rotateLeft(A[24] ^ D0, 14);
        T[0] = B00 ^ (~B01 & B02) ^ RC;
        T[1] = B01 ^ (~B02 & B03);
        T[2] = B02 ^ (~B03 & B04);
        T[3] = B03 ^ (~B04 & B00);
        T[4] = B04 ^ (~B00 & B01);

        const ulong B05 = rotateLeft(A[3] ^ D4, 28);
        const ulong B06 = rotateLeft(A[9] ^ D0, 20);
        const ulong B07 = rotateLeft(A[10] ^ D1, 3);
        const ulong B08 = rotateLeft(A[16] ^ D2, 45);
        const ulong B09 = rotateLeft(A[22] ^ D3, 61);
        T[5] = B05 ^ (~B06 & B07);
        T[6] = B06 ^ (~B07 & B08);
        T[7] = B07 ^ (~B08 & B09);
        T[8] = B08 ^ (~B09 & B05);
        T[9] = B09 ^ (~B05 & B06);

        const ulong B10 = rotateLeft(A[1] ^ D2, 1);
        const ulong B11 = rotateLeft(A[7] ^ D3, 6);
        const ulong B12 = rotateLeft(A[13] ^ D4, 25);
        const ulong B13 = rotateLeft(A[19] ^ D0, 8);
        const ulong B14 = rotateLeft(A[20] ^ D1, 18);
        T[10] = B10 ^ (~B11 & B12);
        T[11] = B11 ^ (~B12 & B13);
        T[12] = B12 ^ (~B13 & B14);
        T[13] = B13 ^ (~B14 & B10);
        T[14] = B14 ^ (~B10 & B11);

        const ulong B15 = rotateLeft(A[4] ^ D0, 27);
        const ulong B16 = rotateLeft(A[5] ^ D1, 36);
        const ulong B17 = rotateLeft(A[11] ^ D2, 10);
        const ulong B18 = rotateLeft(A[17] ^ D3, 15);
        const ulong B19 = rotateLeft(A[23] ^ D4, 56);
        T[15] = B15 ^ (~B16 & B17);
        T[16] = B16 ^ (~B17 & B18);
        T[17] = B17 ^ (~B18 & B19);
        T[18] = B18 ^ (~B19 & B15);
        T[19] = B19 ^ (~B15 & B16);

        const ulong B20 = rotateLeft(A[2] ^ D3, 62);
        const ulong B21 = rotateLeft(A[8] ^ D4, 55);
        const ulong B22 = rotateLeft(A[14] ^ D0, 39);
        const ulong B23 = rotateLeft(A[15] ^ D1, 41);
        const ulong B24 = rotateLeft(A[21] ^ D2, 2);
        T[20] = B20 ^ (~B21 & B22);
        T[21] = B21 ^ (~B22 & B23);
        T[22] = B22 ^ (~B23 & B24);
        T[23] = B23 ^ (~B24 & B20);
        T[24] = B24 ^ (~B20 & B21);
    }

    static void permute(ref ulong[25] A) pure
    {
        __gshared immutable ulong[24] RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ];

        ulong[25] T;

        for(size_t i = 0; i != 24; i += 2)
        {
            SHA3.round(T, A, RC[i + 0]);
            SHA3.round(A, T, RC[i + 1]);
        }
    }

    static size_t absorb(size_t bitrate, ref SecureVector!ulong S, size_t S_pos, const(ubyte)* input, size_t length)
    {
        while(length > 0)
        {
            size_t to_take = min(length, bitrate / 8 - S_pos);

            length -= to_take;

            while(to_take && S_pos % 8)
            {
                S[S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (S_pos % 8));

                ++S_pos;
                ++input;
                --to_take;
            }

            while(to_take && to_take % 8 == 0)
            {
                S[S_pos / 8] ^= loadLittleEndian!ulong(input, 0);
                S_pos += 8;
                input += 8;
                to_take -= 8;
            }

            while(to_take)
            {
                S[S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (S_pos % 8));

                ++S_pos;
                ++input;
                --to_take;
            }

            if(S_pos == bitrate / 8)
            {
                SHA3.permute(*cast(ulong[25]*) S.ptr);
                S_pos = 0;
            }
        }

        return S_pos;
    }

    static void finish(size_t bitrate, ref SecureVector!ulong S, size_t S_pos, ubyte init_pad, ubyte fini_pad)
    {
        if (bitrate % 64 != 0)
            throw new InvalidArgument("SHA-3 bitrate must be multiple of 64");

        S[S_pos / 8] ^= cast(ulong)(init_pad) << (8 * (S_pos % 8));
        S[(bitrate / 64) - 1] ^= cast(ulong)(fini_pad) << 56;
        SHA3.permute(*cast(ulong[25]*) S.ptr);
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        m_S_pos = SHA3.absorb(m_bitrate, m_S, m_S_pos, input, length);
    }

    override void finalResult(ubyte* output)
    {
        SHA3.finish(m_bitrate, m_S, m_S_pos, 0x06, 0x80);

        /*
        * We never have to run the permutation again because we only support
        * limited output lengths
        */
        foreach (size_t i; 0 .. m_output_bits/8)
            output[i] = get_byte(7 - (i % 8), m_S[i/8]);

        clear();
    }

    size_t m_output_bits, m_bitrate;
    SecureVector!ulong m_S;
    size_t m_S_pos;
}

final class SHA3_224 : SHA3
{
    this() { super(224); }
}

final class SHA3_256 : SHA3
{
    this() { super(256); }
}

final class SHA3_384 : SHA3
{
    this() { super(384); }
}

final class SHA3_512 : SHA3
{
    this() { super(512); }
}
