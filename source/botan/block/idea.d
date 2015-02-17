/**
* IDEA
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.idea;

import botan.constants;
static if (BOTAN_HAS_IDEA):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* IDEA
*/
class IDEA : BlockCipherFixedParams!(8, 16), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * IDEA Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        idea_op(input, output, blocks, m_EK.ptr);
    }

    /*
    * IDEA Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        idea_op(input, output, blocks, m_DK.ptr);
    }

    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    @property string name() const { return "IDEA"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new IDEA; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /**
    * Returns: const reference to encryption subkeys
    */
    ref const(SecureVector!ushort) getEK() const { return m_EK; }

    /**
    * Returns: const reference to decryption subkeys
    */
    ref const(SecureVector!ushort) getDK() const { return m_DK; }

    /*
    * IDEA Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(52);
        m_DK.resize(52);
        
        foreach (size_t i; 0 .. 8)
            m_EK[i] = loadBigEndian!ushort(key, i);
        
        for (size_t i = 1, j = 8, offset = 0; j != 52; i %= 8, ++i, ++j)
        {
            m_EK[i+7+offset] = cast(ushort)((m_EK[(i      % 8) + offset] << 9) |
                                              (m_EK[((i+1) % 8) + offset] >> 7));
            offset += (i == 8) ? 8 : 0;
        }
        
        m_DK[51] = mul_inv(m_EK[3]);
        m_DK[50] = -m_EK[2];
        m_DK[49] = -m_EK[1];
        m_DK[48] = mul_inv(m_EK[0]);
        
        for (size_t i = 1, j = 4, counter = 47; i != 8; ++i, j += 6)
        {
            m_DK[counter--] = m_EK[j+1];
            m_DK[counter--] = m_EK[j];
            m_DK[counter--] = mul_inv(m_EK[j+5]);
            m_DK[counter--] = -m_EK[j+3];
            m_DK[counter--] = -m_EK[j+4];
            m_DK[counter--] = mul_inv(m_EK[j+2]);
        }
        
        m_DK[5] = m_EK[47];
        m_DK[4] = m_EK[46];
        m_DK[3] = mul_inv(m_EK[51]);
        m_DK[2] = -m_EK[50];
        m_DK[1] = -m_EK[49];
        m_DK[0] = mul_inv(m_EK[48]);
    }

    SecureVector!ushort m_EK, m_DK;
}

package:
    
/*
* Multiplication modulo 65537
*/
ushort mul(ushort x, ushort y) pure
{
    const uint P = cast(uint)(x) * y;
    
    // P ? 0xFFFF : 0
    const ushort P_mask = cast(const ushort)(!P - 1);
    
    const uint P_hi = P >> 16;
    const uint P_lo = P & 0xFFFF;
    
    const ushort r_1 = cast(const ushort) ((P_lo - P_hi) + (P_lo < P_hi));
    const ushort r_2 = cast(const ushort) (1 - x - y);
    
    return cast(const ushort) ((r_1 & P_mask) | (r_2 & ~P_mask));
}

/*
* Find multiplicative inverses modulo 65537
*
* 65537 is prime; thus Fermat's little theorem tells us that
* x^65537 == x modulo 65537, which means
* x^(65537-2) == x^-1 modulo 65537 since
* x^(65537-2) * x == 1 mod 65537
*
* Do the exponentiation with a basic square and multiply: all bits are
* of exponent are 1 so we always multiply
*/
ushort mul_inv(ushort x) pure
{
    ushort y = x;
    
    foreach (size_t i; 0 .. 15)
    {
        y = mul(y, y); // square
        y = mul(y, x);
    }
    
    return y;
}

/**
* IDEA is involutional, depending only on the key schedule
*/
void idea_op(const(ubyte)* input, ubyte* output, size_t blocks, in const(ushort)* K)
{
    __gshared immutable size_t BLOCK_SIZE = 8;
    
    foreach (size_t i; 0 .. blocks)
    {
        ushort X1 = loadBigEndian!ushort(input, 0);
        ushort X2 = loadBigEndian!ushort(input, 1);
        ushort X3 = loadBigEndian!ushort(input, 2);
        ushort X4 = loadBigEndian!ushort(input, 3);
        
        foreach (size_t j; 0 .. 8)
        {
            X1 = mul(X1, K[6*j+0]);
            X2 += K[6*j+1];
            X3 += K[6*j+2];
            X4 = mul(X4, K[6*j+3]);
            
            ushort T0 = X3;
            X3 = mul(X3 ^ X1, K[6*j+4]);
            
            ushort T1 = X2;
            X2 = mul(cast(ushort) ((X2 ^ X4) + X3), K[6*j+5]);
            X3 += X2;
            
            X1 ^= X2;
            X4 ^= X3;
            X2 ^= T0;
            X3 ^= T1;
        }
        
        X1  = mul(X1, K[48]);
        X2 += K[50];
        X3 += K[49];
        X4  = mul(X4, K[51]);
        
        storeBigEndian(output, X1, X3, X2, X4);
        
        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
    }
}
