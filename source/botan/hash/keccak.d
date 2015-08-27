/**
* Keccak
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.keccak;

import botan.constants;
static if (BOTAN_HAS_KECCAK):

import botan.hash.hash;
import memutils.vector;
import botan.utils.loadstor;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.get_byte;
import botan.utils.types;
import std.conv : to;

/**
* Keccak[1600], a SHA-3 candidate
*/
final class Keccak1600 : HashFunction
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
        m_bitrate = 1600 - 2*output_bits;
        m_S = 25;
        m_S_pos = 0;
        
        // We only support the parameters for the SHA-3 proposal
        
        if (output_bits != 224 && output_bits != 256 &&
            output_bits != 384 && output_bits != 512)
            throw new InvalidArgument("Keccak_1600: Invalid output length " ~ to!string(output_bits));
    }

    override @property size_t hashBlockSize() const { return m_bitrate / 8; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new Keccak1600(m_output_bits);
    }

    override @property string name() const
    {
        return "Keccak-1600(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_S);
        m_S_pos = 0;
    }

protected:
    override void addData(const(ubyte)* input, size_t length)
    {
        if (length == 0)
            return;
        
        while (length)
        {
            size_t to_take = std.algorithm.min(length, m_bitrate / 8 - m_S_pos);
            
            length -= to_take;
            
            while (to_take && m_S_pos % 8)
            {
                m_S[m_S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (m_S_pos % 8));
                
                ++m_S_pos;
                ++input;
                --to_take;
            }
            
            while (to_take && to_take % 8 == 0)
            {
                m_S[m_S_pos / 8] ^= loadLittleEndian!ulong(input, 0);
                m_S_pos += 8;
                input += 8;
                to_take -= 8;
            }
            
            while (to_take)
            {
                m_S[m_S_pos / 8] ^= cast(ulong)(input[0]) << (8 * (m_S_pos % 8));
                
                ++m_S_pos;
                ++input;
                --to_take;
            }
            
            if (m_S_pos == m_bitrate / 8)
            {
                keccak_f_1600(*cast(ulong[25]*) m_S.ptr);
                m_S_pos = 0;
            }
        }
    }

    override void finalResult(ubyte* output)
    {
        Vector!ubyte padding = Vector!ubyte(m_bitrate / 8 - m_S_pos);
        
        padding[0] = 0x01;
        padding[padding.length-1] |= 0x80;
        
        addData(padding.ptr, padding.length);
        
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




void keccak_f_1600(ref ulong[25] A) pure
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
    
    foreach (size_t i; 0 .. 24)
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
        const ulong B01 = rotateLeft(A[ 6] ^ D2, 44);
        const ulong B02 = rotateLeft(A[12] ^ D3, 43);
        const ulong B03 = rotateLeft(A[18] ^ D4, 21);
        const ulong B04 = rotateLeft(A[24] ^ D0, 14);
        const ulong B05 = rotateLeft(A[ 3] ^ D4, 28);
        const ulong B06 = rotateLeft(A[ 9] ^ D0, 20);
        const ulong B07 = rotateLeft(A[10] ^ D1, 3);
        const ulong B08 = rotateLeft(A[16] ^ D2, 45);
        const ulong B09 = rotateLeft(A[22] ^ D3, 61);
        const ulong B10 = rotateLeft(A[ 1] ^ D2, 1);
        const ulong B11 = rotateLeft(A[ 7] ^ D3, 6);
        const ulong B12 = rotateLeft(A[13] ^ D4, 25);
        const ulong B13 = rotateLeft(A[19] ^ D0, 8);
        const ulong B14 = rotateLeft(A[20] ^ D1, 18);
        const ulong B15 = rotateLeft(A[ 4] ^ D0, 27);
        const ulong B16 = rotateLeft(A[ 5] ^ D1, 36);
        const ulong B17 = rotateLeft(A[11] ^ D2, 10);
        const ulong B18 = rotateLeft(A[17] ^ D3, 15);
        const ulong B19 = rotateLeft(A[23] ^ D4, 56);
        const ulong B20 = rotateLeft(A[ 2] ^ D3, 62);
        const ulong B21 = rotateLeft(A[ 8] ^ D4, 55);
        const ulong B22 = rotateLeft(A[14] ^ D0, 39);
        const ulong B23 = rotateLeft(A[15] ^ D1, 41);
        const ulong B24 = rotateLeft(A[21] ^ D2, 2);
        
        A[ 0] = B00 ^ (~B01 & B02);
        A[ 1] = B01 ^ (~B02 & B03);
        A[ 2] = B02 ^ (~B03 & B04);
        A[ 3] = B03 ^ (~B04 & B00);
        A[ 4] = B04 ^ (~B00 & B01);
        A[ 5] = B05 ^ (~B06 & B07);
        A[ 6] = B06 ^ (~B07 & B08);
        A[ 7] = B07 ^ (~B08 & B09);
        A[ 8] = B08 ^ (~B09 & B05);
        A[ 9] = B09 ^ (~B05 & B06);
        A[10] = B10 ^ (~B11 & B12);
        A[11] = B11 ^ (~B12 & B13);
        A[12] = B12 ^ (~B13 & B14);
        A[13] = B13 ^ (~B14 & B10);
        A[14] = B14 ^ (~B10 & B11);
        A[15] = B15 ^ (~B16 & B17);
        A[16] = B16 ^ (~B17 & B18);
        A[17] = B17 ^ (~B18 & B19);
        A[18] = B18 ^ (~B19 & B15);
        A[19] = B19 ^ (~B15 & B16);
        A[20] = B20 ^ (~B21 & B22);
        A[21] = B21 ^ (~B22 & B23);
        A[22] = B22 ^ (~B23 & B24);
        A[23] = B23 ^ (~B24 & B20);
        A[24] = B24 ^ (~B20 & B21);
        
        A[0] ^= RC[i];
    }
}