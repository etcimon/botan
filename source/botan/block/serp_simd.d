/**
* Serpent (SIMD)
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.serp_simd;

import botan.constants;
static if (BOTAN_HAS_SERPENT_SIMD):

import botan.simd.simd_32;
import botan.utils.loadstor;
import botan.block.serpent;
import botan.block.block_cipher;
import botan.utils.mem_ops;

/**
* Serpent implementation using SIMD
*/
final class SerpentSIMD : Serpent
{
public:
    override @property size_t parallelism() const { return 4; }

    /*
    * Serpent Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const uint* KS = this.getRoundKeys().ptr;
        
        while (blocks >= 4)
        {
            serpent_encrypt_4(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(uint[132]*) KS);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        if (blocks)
            super.encryptN(input, output, blocks);
    }

    /*
    * Serpent Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const uint* KS = this.getRoundKeys().ptr;
        
        while (blocks >= 4)
        {
            serpent_decrypt_4(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(uint[132]*) KS);
            input += 4 * BLOCK_SIZE;
            output += 4 * BLOCK_SIZE;
            blocks -= 4;
        }
        
        if (blocks)
            super.decryptN(input, output, blocks);
    }

    override BlockCipher clone() const { return new SerpentSIMD; }
}

package:

/*
* SIMD Serpent Encryption of 4 blocks in parallel
*/
void serpent_encrypt_4(in ubyte[64] input, ref ubyte[64] output, in uint[132] keys)
{
    SIMD32 B0 = SIMD32.loadLittleEndian(input.ptr);
    SIMD32 B1 = SIMD32.loadLittleEndian(input.ptr + 16);
    SIMD32 B2 = SIMD32.loadLittleEndian(input.ptr + 32);
    SIMD32 B3 = SIMD32.loadLittleEndian(input.ptr + 48);
    
    SIMD32.transpose(B0, B1, B2, B3);
    
    mixin(key_xor!( 0) ~  SBoxE1!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 1) ~  SBoxE2!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 2) ~  SBoxE3!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 3) ~  SBoxE4!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 4) ~  SBoxE5!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 5) ~  SBoxE6!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 6) ~  SBoxE7!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 7) ~  SBoxE8!("B0", "B1", "B2", "B3") ~ transform);
    
    mixin(key_xor!( 8) ~  SBoxE1!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!( 9) ~  SBoxE2!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(10) ~  SBoxE3!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(11) ~  SBoxE4!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(12) ~  SBoxE5!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(13) ~  SBoxE6!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(14) ~  SBoxE7!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(15) ~  SBoxE8!("B0", "B1", "B2", "B3") ~ transform);
    
    mixin(key_xor!(16) ~  SBoxE1!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(17) ~  SBoxE2!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(18) ~  SBoxE3!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(19) ~  SBoxE4!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(20) ~  SBoxE5!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(21) ~  SBoxE6!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(22) ~  SBoxE7!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(23) ~  SBoxE8!("B0", "B1", "B2", "B3") ~ transform);
    
    mixin(key_xor!(24) ~  SBoxE1!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(25) ~  SBoxE2!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(26) ~  SBoxE3!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(27) ~  SBoxE4!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(28) ~  SBoxE5!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(29) ~  SBoxE6!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(30) ~  SBoxE7!("B0", "B1", "B2", "B3") ~ transform);
    mixin(key_xor!(31) ~  SBoxE8!("B0", "B1", "B2", "B3") ~ key_xor!(32));
    
    SIMD32.transpose(B0, B1, B2, B3);
    
    B0.storeLittleEndian(output.ptr);
    B1.storeLittleEndian(output.ptr + 16);
    B2.storeLittleEndian(output.ptr + 32);
    B3.storeLittleEndian(output.ptr + 48);
}

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
void serpent_decrypt_4(in ubyte[64] input, ref ubyte[64] output, in uint[132] keys) 
{
    SIMD32 B0 = SIMD32.loadLittleEndian(input.ptr);
    SIMD32 B1 = SIMD32.loadLittleEndian(input.ptr + 16);
    SIMD32 B2 = SIMD32.loadLittleEndian(input.ptr + 32);
    SIMD32 B3 = SIMD32.loadLittleEndian(input.ptr + 48);
    
    SIMD32.transpose(B0, B1, B2, B3);
    
    mixin(key_xor!(32));  mixin(SBoxD8); mixin(key_xor!(31));
    mixin(i_transform); mixin(SBoxD7); mixin(key_xor!(30));
    mixin(i_transform); mixin(SBoxD6); mixin(key_xor!(29));
    mixin(i_transform); mixin(SBoxD5); mixin(key_xor!(28));
    mixin(i_transform); mixin(SBoxD4); mixin(key_xor!(27));
    mixin(i_transform); mixin(SBoxD3); mixin(key_xor!(26));
    mixin(i_transform); mixin(SBoxD2); mixin(key_xor!(25));
    mixin(i_transform); mixin(SBoxD1); mixin(key_xor!(24));
    
    mixin(i_transform); mixin(SBoxD8); mixin(key_xor!(23));
    mixin(i_transform); mixin(SBoxD7); mixin(key_xor!(22));
    mixin(i_transform); mixin(SBoxD6); mixin(key_xor!(21));
    mixin(i_transform); mixin(SBoxD5); mixin(key_xor!(20));
    mixin(i_transform); mixin(SBoxD4); mixin(key_xor!(19));
    mixin(i_transform); mixin(SBoxD3); mixin(key_xor!(18));
    mixin(i_transform); mixin(SBoxD2); mixin(key_xor!(17));
    mixin(i_transform); mixin(SBoxD1); mixin(key_xor!(16));
    
    mixin(i_transform); mixin(SBoxD8); mixin(key_xor!(15));
    mixin(i_transform); mixin(SBoxD7); mixin(key_xor!(14));
    mixin(i_transform); mixin(SBoxD6); mixin(key_xor!(13));
    mixin(i_transform); mixin(SBoxD5); mixin(key_xor!(12));
    mixin(i_transform); mixin(SBoxD4); mixin(key_xor!(11));
    mixin(i_transform); mixin(SBoxD3); mixin(key_xor!(10));
    mixin(i_transform); mixin(SBoxD2); mixin(key_xor!( 9));
    mixin(i_transform); mixin(SBoxD1); mixin(key_xor!( 8));
    
    mixin(i_transform); mixin(SBoxD8); mixin(key_xor!( 7));
    mixin(i_transform); mixin(SBoxD7); mixin(key_xor!( 6));
    mixin(i_transform); mixin(SBoxD6); mixin(key_xor!( 5));
    mixin(i_transform); mixin(SBoxD5); mixin(key_xor!( 4));
    mixin(i_transform); mixin(SBoxD4); mixin(key_xor!( 3));
    mixin(i_transform); mixin(SBoxD3); mixin(key_xor!( 2));
    mixin(i_transform); mixin(SBoxD2); mixin(key_xor!( 1));
    mixin(i_transform); mixin(SBoxD1); mixin(key_xor!( 0));
    
    SIMD32.transpose(B0, B1, B2, B3);
    
    B0.storeLittleEndian(output.ptr);
    B1.storeLittleEndian(output.ptr + 16);
    B2.storeLittleEndian(output.ptr + 32);
    B3.storeLittleEndian(output.ptr + 48);
}

private:

/*
* Serpent's linear transformations
*/
enum string transform =
    `B0.rotateLeft!13();                
    B2.rotateLeft!3();
    B1 ^= B0 ^ B2;
    B3 ^= B2 ^ (B0.lshift!3());
    B1.rotateLeft!1();
    B3.rotateLeft!7();
    B0 ^= B1 ^ B3;
    B2 ^= B3 ^ (B1.lshift!7());
    B0.rotateLeft!5();
        B2.rotateLeft!22();`;

enum string i_transform =
    `B2.rotateRight!22();
    B0.rotateRight!5();
    B2 ^= B3 ^ (B1.lshift!7());
    B0 ^= B1 ^ B3;
    B3.rotateRight!7();
    B1.rotateRight!1();
    B3 ^= B2 ^ (B0.lshift!3());
    B1 ^= B0 ^ B2;
    B2.rotateRight!3();
    B0.rotateRight!13();`;

enum string key_xor(uint round) =
    `B0 ^= SIMD32(keys[4*` ~ round.stringof ~ `  ]);
    B1 ^= SIMD32(keys[4*` ~ round.stringof ~ `+1]);
    B2 ^= SIMD32(keys[4*` ~ round.stringof ~ `+2]);
    B3 ^= SIMD32(keys[4*` ~ round.stringof ~ `+3]);`;
