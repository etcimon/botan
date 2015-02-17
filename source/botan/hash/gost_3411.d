/**
* GOST 34.11
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.gost_3411;

import botan.constants;
static if (BOTAN_HAS_GOST_34_11):

import botan.hash.hash;
import botan.block.gost_28147;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.get_byte;

/**
* GOST 34.11
*/
class GOST3411 : HashFunction
{
public:
    override @property string name() const { return "GOST-R-34.11-94" ; }
    override @property size_t outputLength() const { return 32; }
    override @property size_t hashBlockSize() const { return 32; }
    override HashFunction clone() const { return new GOST3411; }

    override void clear()
    {
        m_cipher.clear();
        zeroise(m_sum);
        zeroise(m_hash);
        m_count = 0;
        m_position = 0;
    }

    /**
    * GOST 34.11 Constructor
    */
    this() 
    {
        m_cipher = new GOST_28147_89(scoped!GOST_28147_89_Params("R3411_CryptoPro").Scoped_payload);
        m_buffer = SecureVector!ubyte(32);
        m_sum = SecureVector!ubyte(32);
        m_hash = SecureVector!ubyte(32);
        m_count = 0;
        m_position = 0;
    }

protected:
    /**
    * The GOST 34.11 compression function
    */
    void compress_n(const(ubyte)* input, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            for (ushort j = 0, carry = 0; j != 32; ++j)
            {
                ushort s = cast(ushort)(m_sum[j] + input[32*i+j] + carry);
                carry = get_byte(0, s);
                m_sum[j] = get_byte(1, s);
            }
            
            ubyte[32] S;
            
            ulong[4] U, V;
            loadBigEndian(U.ptr, m_hash.ptr, 4);
            loadBigEndian(V.ptr, input + 32*i, 4);
            
            foreach (size_t j; 0 .. 4)
            {
                ubyte[32] key;
                
                // P transformation
                foreach (size_t k; 0 .. 4)
                    foreach (size_t l; 0 .. 8)
                        key[4*l+k] = get_byte(l, U[k]) ^ get_byte(l, V[k]);
                
                m_cipher.setKey(key.ptr, 32);
                m_cipher.encrypt(&m_hash[8*j], S.ptr + 8*j);
                
                if (j == 3)
                    break;
                
                // A(x)
                ulong A_U = U[0];
                U[0] = U[1];
                U[1] = U[2];
                U[2] = U[3];
                U[3] = U[0] ^ A_U;
                
                if (j == 1) // C_3
                {
                    U[0] ^= 0x00FF00FF00FF00FF;
                    U[1] ^= 0xFF00FF00FF00FF00;
                    U[2] ^= 0x00FFFF00FF0000FF;
                    U[3] ^= 0xFF000000FFFF00FF;
                }
                
                // A(A(x))
                ulong AA_V_1 = V[0] ^ V[1];
                ulong AA_V_2 = V[1] ^ V[2];
                V[0] = V[2];
                V[1] = V[3];
                V[2] = AA_V_1;
                V[3] = AA_V_2;
            }
            
            ubyte[32] S2;
            
            // 12 rounds of psi
            S2[ 0] = S[24];
            S2[ 1] = S[25];
            S2[ 2] = S[26];
            S2[ 3] = S[27];
            S2[ 4] = S[28];
            S2[ 5] = S[29];
            S2[ 6] = S[30];
            S2[ 7] = S[31];
            S2[ 8] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[ 6] ^ S[24] ^ S[30];
            S2[ 9] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[ 7] ^ S[25] ^ S[31];
            S2[10] = S[ 0] ^ S[ 8] ^ S[24] ^ S[26] ^ S[30];
            S2[11] = S[ 1] ^ S[ 9] ^ S[25] ^ S[27] ^ S[31];
            S2[12] = S[ 0] ^ S[ 4] ^ S[ 6] ^ S[10] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
            S2[13] = S[ 1] ^ S[ 5] ^ S[ 7] ^ S[11] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
            S2[14] = S[ 0] ^ S[ 4] ^ S[ 8] ^ S[12] ^ S[24] ^ S[26] ^ S[28];
            S2[15] = S[ 1] ^ S[ 5] ^ S[ 9] ^ S[13] ^ S[25] ^ S[27] ^ S[29];
            S2[16] = S[ 2] ^ S[ 6] ^ S[10] ^ S[14] ^ S[26] ^ S[28] ^ S[30];
            S2[17] = S[ 3] ^ S[ 7] ^ S[11] ^ S[15] ^ S[27] ^ S[29] ^ S[31];
            S2[18] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[12] ^ S[16] ^ S[24] ^ S[28];
            S2[19] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[13] ^ S[17] ^ S[25] ^ S[29];
            S2[20] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[14] ^ S[18] ^ S[26] ^ S[30];
            S2[21] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[15] ^ S[19] ^ S[27] ^ S[31];
            S2[22] = S[ 0] ^ S[ 2] ^ S[10] ^ S[12] ^ S[16] ^ S[20] ^ S[24] ^ S[28] ^ S[30];
            S2[23] = S[ 1] ^ S[ 3] ^ S[11] ^ S[13] ^ S[17] ^ S[21] ^ S[25] ^ S[29] ^ S[31];
            S2[24] = S[ 0] ^ S[ 6] ^ S[12] ^ S[14] ^ S[18] ^ S[22] ^ S[24] ^ S[26];
            S2[25] = S[ 1] ^ S[ 7] ^ S[13] ^ S[15] ^ S[19] ^ S[23] ^ S[25] ^ S[27];
            S2[26] = S[ 2] ^ S[ 8] ^ S[14] ^ S[16] ^ S[20] ^ S[24] ^ S[26] ^ S[28];
            S2[27] = S[ 3] ^ S[ 9] ^ S[15] ^ S[17] ^ S[21] ^ S[25] ^ S[27] ^ S[29];
            S2[28] = S[ 4] ^ S[10] ^ S[16] ^ S[18] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
            S2[29] = S[ 5] ^ S[11] ^ S[17] ^ S[19] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
            S2[30] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[12] ^ S[18] ^ S[20] ^ S[28];
            S2[31] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[13] ^ S[19] ^ S[21] ^ S[29];
            
            xorBuf(S.ptr, S2.ptr, input + 32*i, 32);
            
            S2[0] = S[0] ^ S[2] ^ S[4] ^ S[6] ^ S[24] ^ S[30];
            S2[1] = S[1] ^ S[3] ^ S[5] ^ S[7] ^ S[25] ^ S[31];
            
            copyMem(S.ptr, S.ptr+2, 30);
            S[30] = S2[0];
            S[31] = S2[1];
            
            xorBuf(S.ptr, m_hash.ptr, 32);
            
            // 61 rounds of psi
            S2[ 0] = S[ 2] ^ S[ 6] ^ S[14] ^ S[20] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
            S2[ 1] = S[ 3] ^ S[ 7] ^ S[15] ^ S[21] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
            S2[ 2] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[16] ^ S[22] ^ S[28];
            S2[ 3] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[17] ^ S[23] ^ S[29];
            S2[ 4] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[18] ^ S[24] ^ S[30];
            S2[ 5] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[19] ^ S[25] ^ S[31];
            S2[ 6] = S[ 0] ^ S[ 2] ^ S[10] ^ S[12] ^ S[20] ^ S[24] ^ S[26] ^ S[30];
            S2[ 7] = S[ 1] ^ S[ 3] ^ S[11] ^ S[13] ^ S[21] ^ S[25] ^ S[27] ^ S[31];
            S2[ 8] = S[ 0] ^ S[ 6] ^ S[12] ^ S[14] ^ S[22] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
            S2[ 9] = S[ 1] ^ S[ 7] ^ S[13] ^ S[15] ^ S[23] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
            S2[10] = S[ 0] ^ S[ 4] ^ S[ 6] ^ S[ 8] ^ S[14] ^ S[16] ^ S[26] ^ S[28];
            S2[11] = S[ 1] ^ S[ 5] ^ S[ 7] ^ S[ 9] ^ S[15] ^ S[17] ^ S[27] ^ S[29];
            S2[12] = S[ 2] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[16] ^ S[18] ^ S[28] ^ S[30];
            S2[13] = S[ 3] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[17] ^ S[19] ^ S[29] ^ S[31];
            S2[14] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[12] ^ S[18] ^ S[20] ^ S[24];
            S2[15] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[13] ^ S[19] ^ S[21] ^ S[25];
            S2[16] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[12] ^ S[14] ^ S[20] ^ S[22] ^ S[26];
            S2[17] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[13] ^ S[15] ^ S[21] ^ S[23] ^ S[27];
            S2[18] = S[ 4] ^ S[ 6] ^ S[10] ^ S[12] ^ S[14] ^ S[16] ^ S[22] ^ S[24] ^ S[28];
            S2[19] = S[ 5] ^ S[ 7] ^ S[11] ^ S[13] ^ S[15] ^ S[17] ^ S[23] ^ S[25] ^ S[29];
            S2[20] = S[ 6] ^ S[ 8] ^ S[12] ^ S[14] ^ S[16] ^ S[18] ^ S[24] ^ S[26] ^ S[30];
            S2[21] = S[ 7] ^ S[ 9] ^ S[13] ^ S[15] ^ S[17] ^ S[19] ^ S[25] ^ S[27] ^ S[31];
            S2[22] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[14] ^ S[16] ^
                     S[18] ^ S[20] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
            S2[23] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[15] ^ S[17] ^
                     S[19] ^ S[21] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
            S2[24] = S[ 0] ^ S[ 8] ^ S[10] ^ S[12] ^ S[16] ^ S[18] ^ S[20] ^ S[22] ^
                     S[24] ^ S[26] ^ S[28];
            S2[25] = S[ 1] ^ S[ 9] ^ S[11] ^ S[13] ^ S[17] ^ S[19] ^ S[21] ^ S[23] ^
                     S[25] ^ S[27] ^ S[29];
            S2[26] = S[ 2] ^ S[10] ^ S[12] ^ S[14] ^ S[18] ^ S[20] ^ S[22] ^ S[24] ^
                     S[26] ^ S[28] ^ S[30];
            S2[27] = S[ 3] ^ S[11] ^ S[13] ^ S[15] ^ S[19] ^ S[21] ^ S[23] ^ S[25] ^
                     S[27] ^ S[29] ^ S[31];
            S2[28] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[12] ^ S[14] ^ S[16] ^ S[20] ^ S[22] ^ S[26] ^ S[28];
            S2[29] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[13] ^ S[15] ^ S[17] ^ S[21] ^ S[23] ^ S[27] ^ S[29];
            S2[30] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[14] ^ S[16] ^ S[18] ^ S[22] ^ S[24] ^ S[28] ^ S[30];
            S2[31] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[15] ^ S[17] ^ S[19] ^ S[23] ^ S[25] ^ S[29] ^ S[31];
            
            copyMem(m_hash.ptr, S2.ptr, 32);
        }
    }

    /**
    * Hash additional inputs
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        m_count += length;
        
        if (m_position)
        {
            bufferInsert(m_buffer, m_position, input, length);
            
            if (m_position + length >= hashBlockSize)
            {
                compress_n(m_buffer.ptr, 1);
                input += (hashBlockSize - m_position);
                length -= (hashBlockSize - m_position);
                m_position = 0;
            }
        }
        
        const size_t full_blocks = length / hashBlockSize;
        const size_t remaining   = length % hashBlockSize;
        
        if (full_blocks)
            compress_n(input, full_blocks);
        
        bufferInsert(m_buffer, m_position, input + full_blocks * hashBlockSize, remaining);
        m_position += remaining;
    }

    /**
    * Produce the final GOST 34.11 output
    */
    override void finalResult(ubyte* output)
    {
        if (m_position)
        {
            clearMem(m_buffer.ptr + m_position, m_buffer.length - m_position);
            compress_n(m_buffer.ptr, 1);
        }
        
        SecureVector!ubyte length_buf = SecureVector!ubyte(32);
        const ulong bit_count = m_count * 8;
        storeLittleEndian(bit_count, length_buf.ptr);
        
        SecureVector!ubyte sum_buf = m_sum.dup;
        
        compress_n(length_buf.ptr, 1);
        compress_n(sum_buf.ptr, 1);
        
        copyMem(output, m_hash.ptr, 32);
        clear();
    }

    Unique!GOST_28147_89 m_cipher;
    SecureVector!ubyte m_buffer, m_sum, m_hash;
    size_t m_position;
    ulong m_count;
}