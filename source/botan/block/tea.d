/**
* TEA
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.tea;

import botan.constants;
static if (BOTAN_HAS_TEA):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.mem_ops;

/**
* TEA
*/
final class TEA : BlockCipherFixedParams!(8, 16), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * TEA Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            uint S = 0;
            foreach (size_t j; 0 .. 32)
            {
                S += 0x9E3779B9;
                L += ((R << 4) + m_K[0]) ^ (R + S) ^ ((R >> 5) + m_K[1]);
                R += ((L << 4) + m_K[2]) ^ (L + S) ^ ((L >> 5) + m_K[3]);
            }
            
            storeBigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    /*
    * TEA Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            uint S = 0xC6EF3720;
            foreach (size_t j; 0 .. 32)
            {
                R -= ((L << 4) + m_K[2]) ^ (L + S) ^ ((L >> 5) + m_K[3]);
                L -= ((R << 4) + m_K[0]) ^ (R + S) ^ ((R >> 5) + m_K[1]);
                S -= 0x9E3779B9;
            }
            
            storeBigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_K);
    }

    override @property string name() const { return "TEA"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new TEA; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

protected:
    /*
    * TEA Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_K.resize(4);
        foreach (size_t i; 0 .. 4)
            m_K[i] = loadBigEndian!uint(key, i);
    }
    SecureVector!uint m_K;
}