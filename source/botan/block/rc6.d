/**
* RC6
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.rc6;

import botan.constants;
static if (BOTAN_HAS_RC6):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import std.algorithm;
import botan.utils.mem_ops;

/**
* RC6, Ron Rivest's AES candidate
*/
final class RC6 : BlockCipherFixedParams!(16, 1, 32), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * RC6 Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadLittleEndian!uint(input, 0);
            uint B = loadLittleEndian!uint(input, 1);
            uint C = loadLittleEndian!uint(input, 2);
            uint D = loadLittleEndian!uint(input, 3);
            
            B += m_S[0]; D += m_S[1];
            
            for (size_t j = 0; j != 20; j += 4)
            {
                uint T1, T2;
                
                T1 = rotateLeft(B*(2*B+1), 5);
                T2 = rotateLeft(D*(2*D+1), 5);
                A = rotateLeft(A ^ T1, T2 % 32) + m_S[2*j+2];
                C = rotateLeft(C ^ T2, T1 % 32) + m_S[2*j+3];
                
                T1 = rotateLeft(C*(2*C+1), 5);
                T2 = rotateLeft(A*(2*A+1), 5);
                B = rotateLeft(B ^ T1, T2 % 32) + m_S[2*j+4];
                D = rotateLeft(D ^ T2, T1 % 32) + m_S[2*j+5];
                
                T1 = rotateLeft(D*(2*D+1), 5);
                T2 = rotateLeft(B*(2*B+1), 5);
                C = rotateLeft(C ^ T1, T2 % 32) + m_S[2*j+6];
                A = rotateLeft(A ^ T2, T1 % 32) + m_S[2*j+7];
                
                T1 = rotateLeft(A*(2*A+1), 5);
                T2 = rotateLeft(C*(2*C+1), 5);
                D = rotateLeft(D ^ T1, T2 % 32) + m_S[2*j+8];
                B = rotateLeft(B ^ T2, T1 % 32) + m_S[2*j+9];
            }
            
            A += m_S[42]; C += m_S[43];
            
            storeLittleEndian(output, A, B, C, D);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    /*
    * RC6 Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadLittleEndian!uint(input, 0);
            uint B = loadLittleEndian!uint(input, 1);
            uint C = loadLittleEndian!uint(input, 2);
            uint D = loadLittleEndian!uint(input, 3);
            
            C -= m_S[43]; A -= m_S[42];
            
            for (size_t j = 0; j != 20; j += 4)
            {
                uint T1, T2;
                
                T1 = rotateLeft(A*(2*A+1), 5);
                T2 = rotateLeft(C*(2*C+1), 5);
                B = rotateRight(B - m_S[41 - 2*j], T1 % 32) ^ T2;
                D = rotateRight(D - m_S[40 - 2*j], T2 % 32) ^ T1;
                
                T1 = rotateLeft(D*(2*D+1), 5);
                T2 = rotateLeft(B*(2*B+1), 5);
                A = rotateRight(A - m_S[39 - 2*j], T1 % 32) ^ T2;
                C = rotateRight(C - m_S[38 - 2*j], T2 % 32) ^ T1;
                
                T1 = rotateLeft(C*(2*C+1), 5);
                T2 = rotateLeft(A*(2*A+1), 5);
                D = rotateRight(D - m_S[37 - 2*j], T1 % 32) ^ T2;
                B = rotateRight(B - m_S[36 - 2*j], T2 % 32) ^ T1;
                
                T1 = rotateLeft(B*(2*B+1), 5);
                T2 = rotateLeft(D*(2*D+1), 5);
                C = rotateRight(C - m_S[35 - 2*j], T1 % 32) ^ T2;
                A = rotateRight(A - m_S[34 - 2*j], T2 % 32) ^ T1;
            }
            
            D -= m_S[1]; B -= m_S[0];
            
            storeLittleEndian(output, A, B, C, D);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_S);
    }

    override @property string name() const { return "RC6"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new RC6; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /*
    * RC6 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_S.resize(44);
        
        const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
        const size_t MIX_ROUNDS      = 3 * std.algorithm.max(WORD_KEYLENGTH, m_S.length);
        
        m_S[0] = 0xB7E15163;
        foreach (size_t i; 1 .. m_S.length)
            m_S[i] = m_S[i-1] + 0x9E3779B9;
        
        SecureVector!uint K = SecureVector!uint(8);
        
        for (int i = cast(int) length-1; i >= 0; --i)
            K[i/4] = (K[i/4] << 8) + key[i];
        
        uint A = 0, B = 0;
        foreach (size_t i; 0 .. MIX_ROUNDS)
        {
            A = rotateLeft(m_S[i % m_S.length] + A + B, 3);
            B = rotateLeft(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
            m_S[i % m_S.length] = A;
            K[i % WORD_KEYLENGTH] = B;
        }
    }

    SecureVector!uint m_S;
}