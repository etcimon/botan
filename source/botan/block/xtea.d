/**
* XTEA
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.xtea;

import botan.constants;
static if (BOTAN_HAS_XTEA):

import std.range : iota;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.mem_ops;

/**
* XTEA
*/
class XTEA : BlockCipherFixedParams!(8, 16), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * XTEA Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        while (blocks >= 4)
        {
            xtea_encrypt_4(*cast(ubyte[32]*) input, *cast(ubyte[32]*) output, *cast(uint[64]*) m_EK.ptr);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            foreach (size_t j; 0 .. 32)
            {
                L += (((R << 4) ^ (R >> 5)) + R) ^ m_EK[2*j];
                R += (((L << 4) ^ (L >> 5)) + L) ^ m_EK[2*j+1];
            }
            
            storeBigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    
    /*
    * XTEA Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        while (blocks >= 4)
        {
            xtea_decrypt_4(*cast(ubyte[32]*) input, *cast(ubyte[32]*) output, *cast(uint[64]*) m_EK.ptr);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            foreach (size_t j; 0 .. 32)
            {
                R -= (((L << 4) ^ (L >> 5)) + L) ^ m_EK[63 - 2*j];
                L -= (((R << 4) ^ (R >> 5)) + R) ^ m_EK[62 - 2*j];
            }
            
            storeBigEndian(output, L, R);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_EK);
    }

    override @property string name() const { return "XTEA"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new XTEA; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /**
    * Returns: const reference to the key schedule
    */
    ref const(SecureVector!uint) getEK() const { return m_EK; }

protected:
    /*
    * XTEA Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(64);
        
        SecureVector!uint UK = SecureVector!uint(4);
        foreach (size_t i; 0 .. 4)
            UK[i] = loadBigEndian!uint(key, i);
        
        uint D = 0;
        foreach (size_t i; iota(0, 64, 2))
        {
            m_EK[i  ] = D + UK[D % 4];
            D += 0x9E3779B9;
            m_EK[i+1] = D + UK[(D >> 11) % 4];
        }
    }

    SecureVector!uint m_EK;
}

package:

void xtea_encrypt_4(in ubyte[32] input, ref ubyte[32] output, in uint[64] EK)
{
    uint L0, R0, L1, R1, L2, R2, L3, R3;
    loadBigEndian(input.ptr, L0, R0, L1, R1, L2, R2, L3, R3);
    
    foreach (size_t i; 0 .. 32)
    {
        L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[2*i];
        L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[2*i];
        L2 += (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[2*i];
        L3 += (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[2*i];
        
        R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[2*i+1];
        R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[2*i+1];
        R2 += (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[2*i+1];
        R3 += (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[2*i+1];
    }
    
    storeBigEndian(output.ptr, L0, R0, L1, R1, L2, R2, L3, R3);
}

void xtea_decrypt_4(in ubyte[32] input, ref ubyte[32] output, in uint[64] EK)
{
    uint L0, R0, L1, R1, L2, R2, L3, R3;
    loadBigEndian(input.ptr, L0, R0, L1, R1, L2, R2, L3, R3);
    
    foreach (size_t i; 0 .. 32)
    {
        R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[63 - 2*i];
        R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[63 - 2*i];
        R2 -= (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[63 - 2*i];
        R3 -= (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[63 - 2*i];
        
        L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[62 - 2*i];
        L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[62 - 2*i];
        L2 -= (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[62 - 2*i];
        L3 -= (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[62 - 2*i];
    }
    
    storeBigEndian(output.ptr, L0, R0, L1, R1, L2, R2, L3, R3);
}
