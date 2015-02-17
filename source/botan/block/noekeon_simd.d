/**
* Noekeon in SIMD
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.noekeon_simd;

import botan.constants;
static if (BOTAN_HAS_NOEKEON_SIMD):

import botan.block.noekeon;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.simd.simd_32;
import botan.utils.mem_ops;

/**
* Noekeon implementation using SIMD operations
*/
final class NoekeonSIMD : Noekeon
{
public:
    override @property size_t parallelism() const { return 4; }

    /*
    * Noekeon Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const SecureVector!uint* EK = &this.getEK();
        
        SIMD32 K0 = SIMD32((*EK)[0]);
        SIMD32 K1 = SIMD32((*EK)[1]);
        SIMD32 K2 = SIMD32((*EK)[2]);
        SIMD32 K3 = SIMD32((*EK)[3]);
        
        while (blocks >= 4)
        {
            SIMD32 A0 = SIMD32.loadBigEndian(input      );
            SIMD32 A1 = SIMD32.loadBigEndian(input + 16);
            SIMD32 A2 = SIMD32.loadBigEndian(input + 32);
            SIMD32 A3 = SIMD32.loadBigEndian(input + 48);
            
            SIMD32.transpose(A0, A1, A2, A3);
            
            foreach (size_t i; 0 .. 16)
            {
                A0 ^= SIMD32(cast(uint) m_RC[i]);
                
                mixin(NOK_SIMD_THETA());
                
                A1.rotateLeft!1();
                A2.rotateLeft!5();
                A3.rotateLeft!2();

                mixin(NOK_SIMD_GAMMA());
                
                A1.rotateRight!1();
                A2.rotateRight!5();
                A3.rotateRight!2();
            }
            
            A0 ^= SIMD32(cast(uint) m_RC[16]);
            mixin(NOK_SIMD_THETA());
            
            SIMD32.transpose(A0, A1, A2, A3);
            
            A0.storeBigEndian(output);
            A1.storeBigEndian(output + 16);
            A2.storeBigEndian(output + 32);
            A3.storeBigEndian(output + 48);
            
            input += 64;
            output += 64;
            blocks -= 4;
        }
        
        if (blocks)
            super.encryptN(input, output, blocks);
    }

    /*
    * Noekeon Encryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const SecureVector!uint* DK = &this.getDK();
        
        SIMD32 K0 = SIMD32((*DK)[0]);
        SIMD32 K1 = SIMD32((*DK)[1]);
        SIMD32 K2 = SIMD32((*DK)[2]);
        SIMD32 K3 = SIMD32((*DK)[3]);
        
        while (blocks >= 4)
        {
            SIMD32 A0 = SIMD32.loadBigEndian(input      );
            SIMD32 A1 = SIMD32.loadBigEndian(input + 16);
            SIMD32 A2 = SIMD32.loadBigEndian(input + 32);
            SIMD32 A3 = SIMD32.loadBigEndian(input + 48);
            
            SIMD32.transpose(A0, A1, A2, A3);
            
            foreach (size_t i; 0 .. 16)
            {
                mixin(NOK_SIMD_THETA());
                
                A0 ^= SIMD32(cast(uint) m_RC[16-i]);
                
                A1.rotateLeft!1();
                A2.rotateLeft!5();
                A3.rotateLeft!2();
                
                mixin(NOK_SIMD_GAMMA());
                
                A1.rotateRight!1();
                A2.rotateRight!5();
                A3.rotateRight!2();
            }
            
            mixin(NOK_SIMD_THETA());
            A0 ^= SIMD32(cast(uint) m_RC[0]);
            
            SIMD32.transpose(A0, A1, A2, A3);
            
            A0.storeBigEndian(output);
            A1.storeBigEndian(output + 16);
            A2.storeBigEndian(output + 32);
            A3.storeBigEndian(output + 48);
            
            input += 64;
            output += 64;
            blocks -= 4;
        }
        
        if (blocks)
            super.decryptN(input, output, blocks);
    }

    override BlockCipher clone() const { return new NoekeonSIMD; }
}

/*
* Noekeon's Theta Operation
*/
string NOK_SIMD_THETA() {
    return `{SIMD32 T = A0 ^ A2;
    SIMD32 T_l8 = T;
    SIMD32 T_r8 = T;
    T_l8.rotateLeft!8();
    T_r8.rotateRight!8();
    T ^= T_l8;
    T ^= T_r8;
    A1 ^= T;            
    A3 ^= T;
    A0 ^= K0;                
    A1 ^= K1;                
    A2 ^= K2;                
    A3 ^= K3;
    T = A1 ^ A3;            
    T_l8 = T;                
    T_r8 = T;                
    T_l8.rotateLeft!8();
    T_r8.rotateRight!8();
    T ^= T_l8;
    T ^= T_r8;
    A0 ^= T;            
    A2 ^= T;}`;            
} 

/*
* Noekeon's Gamma S-Box Layer
*/
string NOK_SIMD_GAMMA() {
    return `{A1 ^= A3.andc(~A2);
    A0 ^= A2 & A1;
    SIMD32 T = A3;
    A3 = A0;
    A0 = T;
    A2 ^= A0 ^ A1 ^ A3;
    A1 ^= A3.andc(~A2);
    A0 ^= A2 & A1;}`;
}