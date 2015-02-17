/**
* RC5
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.rc5;

import botan.constants;
static if (BOTAN_HAS_RC5):

import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.parsing;
import std.algorithm;
import botan.block.block_cipher;
import std.conv : to;
import botan.utils.mem_ops;

/**
* RC5
*/
final class RC5 : BlockCipherFixedParams!(8, 1, 32), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * RC5 Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadLittleEndian!uint(input, 0);
            uint B = loadLittleEndian!uint(input, 1);
            
            A += m_S[0]; B += m_S[1];
            for (size_t j = 0; j != m_rounds; j += 4)
            {
                A = rotateLeft(A ^ B, B % 32) + m_S[2*j+2];
                B = rotateLeft(B ^ A, A % 32) + m_S[2*j+3];
                
                A = rotateLeft(A ^ B, B % 32) + m_S[2*j+4];
                B = rotateLeft(B ^ A, A % 32) + m_S[2*j+5];
                
                A = rotateLeft(A ^ B, B % 32) + m_S[2*j+6];
                B = rotateLeft(B ^ A, A % 32) + m_S[2*j+7];
                
                A = rotateLeft(A ^ B, B % 32) + m_S[2*j+8];
                B = rotateLeft(B ^ A, A % 32) + m_S[2*j+9];
            }
            
            storeLittleEndian(output, A, B);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * RC5 Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadLittleEndian!uint(input, 0);
            uint B = loadLittleEndian!uint(input, 1);
            
            for (size_t j = m_rounds; j != 0; j -= 4)
            {
                B = rotateRight(B - m_S[2*j+1], A % 32) ^ A;
                A = rotateRight(A - m_S[2*j  ], B % 32) ^ B;
                
                B = rotateRight(B - m_S[2*j-1], A % 32) ^ A;
                A = rotateRight(A - m_S[2*j-2], B % 32) ^ B;
                
                B = rotateRight(B - m_S[2*j-3], A % 32) ^ A;
                A = rotateRight(A - m_S[2*j-4], B % 32) ^ B;
                
                B = rotateRight(B - m_S[2*j-5], A % 32) ^ A;
                A = rotateRight(A - m_S[2*j-6], B % 32) ^ B;
            }
            B -= m_S[1]; A -= m_S[0];
            
            storeLittleEndian(output, A, B);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_S);
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "RC5(" ~ to!string(m_rounds) ~ ")";
    }

    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new RC5(m_rounds); }

    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

    /**
    * RC5 Constructor
    * Params:
    *  rounds = the number of RC5 rounds to run. Must be between
    * 8 and 32 and a multiple of 4.
    */
    this(size_t r)
    {
        m_rounds = r;
        if (m_rounds < 8 || m_rounds > 32 || (m_rounds % 4 != 0))
            throw new InvalidArgument("RC5: Invalid number of rounds " ~
                                       to!string(m_rounds));
    }
protected:

    /*
    * RC5 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_S.resize(2*m_rounds + 2);
        
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


    size_t m_rounds;
    SecureVector!uint m_S;
}