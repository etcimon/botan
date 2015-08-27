/**
* Serpent
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.serpent;

import botan.constants;
static if (BOTAN_HAS_SERPENT):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* Serpent, an AES finalist
*/
class Serpent : BlockCipherFixedParams!(16, 16, 32, 8), BlockCipher, SymmetricAlgorithm
{
public:
    /*
    * Serpent Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint B0 = loadLittleEndian!uint(input, 0);
            uint B1 = loadLittleEndian!uint(input, 1);
            uint B2 = loadLittleEndian!uint(input, 2);
            uint B3 = loadLittleEndian!uint(input, 3);
            
            mixin(key_xor!( 0)()); mixin(SBoxE1!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 1)()); mixin(SBoxE2!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 2)()); mixin(SBoxE3!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 3)()); mixin(SBoxE4!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 4)()); mixin(SBoxE5!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 5)()); mixin(SBoxE6!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 6)()); mixin(SBoxE7!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 7)()); mixin(SBoxE8!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 8)()); mixin(SBoxE1!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!( 9)()); mixin(SBoxE2!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(10)()); mixin(SBoxE3!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(11)()); mixin(SBoxE4!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(12)()); mixin(SBoxE5!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(13)()); mixin(SBoxE6!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(14)()); mixin(SBoxE7!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(15)()); mixin(SBoxE8!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(16)()); mixin(SBoxE1!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(17)()); mixin(SBoxE2!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(18)()); mixin(SBoxE3!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(19)()); mixin(SBoxE4!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(20)()); mixin(SBoxE5!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(21)()); mixin(SBoxE6!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(22)()); mixin(SBoxE7!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(23)()); mixin(SBoxE8!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(24)()); mixin(SBoxE1!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(25)()); mixin(SBoxE2!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(26)()); mixin(SBoxE3!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(27)()); mixin(SBoxE4!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(28)()); mixin(SBoxE5!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(29)()); mixin(SBoxE6!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(30)()); mixin(SBoxE7!("B0", "B1", "B2", "B3")()); transform(B0,B1,B2,B3);
            mixin(key_xor!(31)()); mixin(SBoxE8!("B0", "B1", "B2", "B3")()); mixin(key_xor!(32)());
            
            storeLittleEndian(output, B0, B1, B2, B3);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * Serpent Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint B0 = loadLittleEndian!uint(input, 0);
            uint B1 = loadLittleEndian!uint(input, 1);
            uint B2 = loadLittleEndian!uint(input, 2);
            uint B3 = loadLittleEndian!uint(input, 3);
            
            mixin(key_xor!(32)());  mixin(SBoxD8()); mixin(key_xor!(31)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD7()); mixin(key_xor!(30)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD6()); mixin(key_xor!(29)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD5()); mixin(key_xor!(28)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD4()); mixin(key_xor!(27)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD3()); mixin(key_xor!(26)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD2()); mixin(key_xor!(25)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD1()); mixin(key_xor!(24)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD8()); mixin(key_xor!(23)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD7()); mixin(key_xor!(22)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD6()); mixin(key_xor!(21)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD5()); mixin(key_xor!(20)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD4()); mixin(key_xor!(19)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD3()); mixin(key_xor!(18)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD2()); mixin(key_xor!(17)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD1()); mixin(key_xor!(16)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD8()); mixin(key_xor!(15)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD7()); mixin(key_xor!(14)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD6()); mixin(key_xor!(13)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD5()); mixin(key_xor!(12)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD4()); mixin(key_xor!(11)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD3()); mixin(key_xor!(10)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD2()); mixin(key_xor!( 9)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD1()); mixin(key_xor!( 8)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD8()); mixin(key_xor!( 7)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD7()); mixin(key_xor!( 6)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD6()); mixin(key_xor!( 5)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD5()); mixin(key_xor!( 4)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD4()); mixin(key_xor!( 3)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD3()); mixin(key_xor!( 2)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD2()); mixin(key_xor!( 1)());
            i_transform(B0,B1,B2,B3); mixin(SBoxD1()); mixin(key_xor!( 0)());
            
            storeLittleEndian(output, B0, B1, B2, B3);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear()
    {
        zap(m_round_key);
    }

    override @property string name() const { return "Serpent"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new Serpent; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /**
    * For use by subclasses using SIMD, asm, etc
    * Returns: const reference to the key schedule
    */
    ref const(SecureVector!uint) getRoundKeys() const
    { return m_round_key; }

    /**
    * For use by subclasses that implement the key schedule
    * Params:
    *  ks = is the new key schedule value to set
    */
    void setRoundKeys(in uint[132] ks)
    {
        m_round_key[] = ks.ptr[0 .. 132];
    }

    /*
    * Serpent Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        const uint PHI = 0x9E3779B9;
        
        SecureVector!uint W = SecureVector!uint(140);
        foreach (size_t i; 0 .. (length / 4))
            W[i] = loadLittleEndian!uint(key, i);
        
        W[length / 4] |= uint(1) << ((length%4)*8);
        
        foreach (size_t i; 8 .. 140)
        {
            uint wi = cast(uint) (W[i-8] ^ W[i-5] ^ W[i-3] ^ W[i-1] ^ PHI ^ (cast(uint) i - 8));
            W[i] = rotateLeft(wi, 11);
        }

        mixin(SBoxE4!("W[  8]", "W[  9]", "W[ 10]", "W[ 11]")()); mixin(SBoxE3!("W[ 12]", "W[ 13]", "W[ 14]", "W[ 15]")());
        mixin(SBoxE2!("W[ 16]", "W[ 17]", "W[ 18]", "W[ 19]")()); mixin(SBoxE1!("W[ 20]", "W[ 21]", "W[ 22]", "W[ 23]")());
        mixin(SBoxE8!("W[ 24]", "W[ 25]", "W[ 26]", "W[ 27]")()); mixin(SBoxE7!("W[ 28]", "W[ 29]", "W[ 30]", "W[ 31]")());
        mixin(SBoxE6!("W[ 32]", "W[ 33]", "W[ 34]", "W[ 35]")()); mixin(SBoxE5!("W[ 36]", "W[ 37]", "W[ 38]", "W[ 39]")());
        mixin(SBoxE4!("W[ 40]", "W[ 41]", "W[ 42]", "W[ 43]")()); mixin(SBoxE3!("W[ 44]", "W[ 45]", "W[ 46]", "W[ 47]")());
        mixin(SBoxE2!("W[ 48]", "W[ 49]", "W[ 50]", "W[ 51]")()); mixin(SBoxE1!("W[ 52]", "W[ 53]", "W[ 54]", "W[ 55]")());
        mixin(SBoxE8!("W[ 56]", "W[ 57]", "W[ 58]", "W[ 59]")()); mixin(SBoxE7!("W[ 60]", "W[ 61]", "W[ 62]", "W[ 63]")());
        mixin(SBoxE6!("W[ 64]", "W[ 65]", "W[ 66]", "W[ 67]")()); mixin(SBoxE5!("W[ 68]", "W[ 69]", "W[ 70]", "W[ 71]")());
        mixin(SBoxE4!("W[ 72]", "W[ 73]", "W[ 74]", "W[ 75]")()); mixin(SBoxE3!("W[ 76]", "W[ 77]", "W[ 78]", "W[ 79]")());
        mixin(SBoxE2!("W[ 80]", "W[ 81]", "W[ 82]", "W[ 83]")()); mixin(SBoxE1!("W[ 84]", "W[ 85]", "W[ 86]", "W[ 87]")());
        mixin(SBoxE8!("W[ 88]", "W[ 89]", "W[ 90]", "W[ 91]")()); mixin(SBoxE7!("W[ 92]", "W[ 93]", "W[ 94]", "W[ 95]")());
        mixin(SBoxE6!("W[ 96]", "W[ 97]", "W[ 98]", "W[ 99]")()); mixin(SBoxE5!("W[100]", "W[101]", "W[102]", "W[103]")());
        mixin(SBoxE4!("W[104]", "W[105]", "W[106]", "W[107]")()); mixin(SBoxE3!("W[108]", "W[109]", "W[110]", "W[111]")());
        mixin(SBoxE2!("W[112]", "W[113]", "W[114]", "W[115]")()); mixin(SBoxE1!("W[116]", "W[117]", "W[118]", "W[119]")());
        mixin(SBoxE8!("W[120]", "W[121]", "W[122]", "W[123]")()); mixin(SBoxE7!("W[124]", "W[125]", "W[126]", "W[127]")());
        mixin(SBoxE6!("W[128]", "W[129]", "W[130]", "W[131]")()); mixin(SBoxE5!("W[132]", "W[133]", "W[134]", "W[135]")());
        mixin(SBoxE4!("W[136]", "W[137]", "W[138]", "W[139]")());
        
        m_round_key[] = W.ptr[8 .. 140];
    }

    SecureVector!uint m_round_key;
}


package:

string SBoxE1(string B0, string B1, string B2, string B3)() {

    return `{` ~ B3 ~ ` ^= ` ~ B0 ~ `;
            auto B4 = ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= ` ~ B3 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B3 ~ `;
            ` ~ B0 ~ ` ^= B4;
            B4 ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` |= ` ~ B1 ~ `;
            ` ~ B2 ~ ` ^= B4;
            B4 = ~B4;
            B4 |= ` ~ B1 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B1 ~ ` ^= B4;
            ` ~ B3 ~ ` |= ` ~ B0 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            B4 ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ` ~ B0 ~ `;
            ` ~ B0 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = B4; }`;
}

string SBoxE2(string B0, string B1, string B2, string B3)() {

    return `{` ~ B0 ~ ` = ~` ~ B0 ~ `;
            ` ~ B2 ~ ` = ~` ~ B2 ~ `;
            auto B4 = ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B1 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B3 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` ^= B4;
            B4 |= ` ~ B1 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B2 ~ ` |= ` ~ B0 ~ `;
            ` ~ B2 ~ ` &= B4;
            ` ~ B0 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= ` ~ B2 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B2 ~ `;
            B4 ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` = ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = B4;}`;
}

string SBoxE3(string B0, string B1, string B2, string B3)() {

    return `{auto B4 = ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B2 ~ `;
            ` ~ B0 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B3 ~ ` |= B4;
            ` ~ B3 ~ ` ^= ` ~ B1 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B1 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` |= B4;
            ` ~ B3 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B1 ~ `;
            B4 ^= ` ~ B0 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B1 ~ ` ^= B4;
            ` ~ B0 ~ ` = ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ~B4;}`;
}

string SBoxE4(string B0, string B1, string B2, string B3)() {

    return `{auto B4 = ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B3 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= B4;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` &= ` ~ B0 ~ `;
            B4 |= ` ~ B1 ~ `;
            ` ~ B3 ~ ` ^= B4;
            ` ~ B0 ~ ` ^= ` ~ B1 ~ `;
            B4 &= ` ~ B0 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B1 ~ ` |= ` ~ B0 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B0 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B2 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` |= ` ~ B3 ~ `;
            ` ~ B0 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` = ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` = B4;}`;
}

string SBoxE5(string B0, string B1, string B2, string B3)() {

    return `{` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ~` ~ B3 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B0 ~ `;
            auto B4 = ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= ` ~ B3 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B2 ~ `;
            B4 ^= ` ~ B3 ~ `;
            ` ~ B0 ~ ` ^= B4;
            ` ~ B2 ~ ` &= B4;
            ` ~ B2 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B1 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B0 ~ `;
            B4 |= ` ~ B1 ~ `;
            B4 ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B3 ~ `;
            ` ~ B0 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` &= ` ~ B3 ~ `;
            ` ~ B0 ~ ` = ~` ~ B0 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B0 ~ `;
            ` ~ B0 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = B4;}`;
}

string SBoxE6(string B0, string B1, string B2, string B3)() {

    return `{` ~ B0 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ~` ~ B3 ~ `;
            auto B4 = ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= ` ~ B0 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` |= B4;
            B4 ^= ` ~ B3 ~ `;
            ` ~ B3 ~ ` &= ` ~ B1 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B0 ~ `;
            B4 ^= ` ~ B1 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` &= ` ~ B3 ~ `;
            ` ~ B2 ~ ` = ~` ~ B2 ~ `;
            ` ~ B0 ~ ` ^= B4;
            B4 |= ` ~ B3 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B0 ~ `;
            ` ~ B0 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` = B4;}`;
}

string SBoxE7(string B0, string B1, string B2, string B3)() {

    return `{` ~ B2 ~ ` = ~` ~ B2 ~ `;
            auto B4 = ` ~ B3 ~ `;
            ` ~ B3 ~ ` &= ` ~ B0 ~ `;
            ` ~ B0 ~ ` ^= B4;
            ` ~ B3 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` |= B4;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B1 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B1 ~ `;
            B4 ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= ` ~ B3 ~ `;
            ` ~ B0 ~ ` ^= ` ~ B2 ~ `;
            B4 ^= ` ~ B3 ~ `;
            B4 ^= ` ~ B0 ~ `;
            ` ~ B3 ~ ` = ~` ~ B3 ~ `;
            ` ~ B2 ~ ` &= B4;
            ` ~ B3 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` = B4;}`;
}

string SBoxE8(string B0, string B1, string B2, string B3)() {

    return `{auto B4 = ` ~ B1 ~ `;
            ` ~ B1 ~ ` |= ` ~ B2 ~ `;
            ` ~ B1 ~ ` ^= ` ~ B3 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B3 ~ ` |= B4;
            ` ~ B3 ~ ` &= ` ~ B0 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B3 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` |= B4;
            ` ~ B1 ~ ` ^= ` ~ B0 ~ `;
            ` ~ B0 ~ ` |= B4;
            ` ~ B0 ~ ` ^= ` ~ B2 ~ `;
            ` ~ B1 ~ ` ^= B4;
            ` ~ B2 ~ ` ^= ` ~ B1 ~ `;
            ` ~ B1 ~ ` &= ` ~ B0 ~ `;
            ` ~ B1 ~ ` ^= B4;
            ` ~ B2 ~ ` = ~` ~ B2 ~ `;
            ` ~ B2 ~ ` |= ` ~ B0 ~ `;
            B4 ^= ` ~ B2 ~ `;
            ` ~ B2 ~ ` = ` ~ B1 ~ `;
            ` ~ B1 ~ ` = ` ~ B3 ~ `;
            ` ~ B3 ~ ` = ` ~ B0 ~ `;
            ` ~ B0 ~ ` = B4;}`;
}

string SBoxD1() {
    return `{B2 = ~B2;
            auto B4 = B1;
            B1 |= B0;
            B4 = ~B4;
            B1 ^= B2;
            B2 |= B4;
            B1 ^= B3;
            B0 ^= B4;
            B2 ^= B0;
            B0 &= B3;
            B4 ^= B0;
            B0 |= B1;
            B0 ^= B2;
            B3 ^= B4;
            B2 ^= B1;
            B3 ^= B0;
            B3 ^= B1;
            B2 &= B3;
            B4 ^= B2;
            B2 = B1;
            B1 = B4;}`;
}

string SBoxD2() {

    return `{auto B4 = B1;
            B1 ^= B3;
            B3 &= B1;
            B4 ^= B2;
            B3 ^= B0;
            B0 |= B1;
            B2 ^= B3;
            B0 ^= B4;
            B0 |= B2;
            B1 ^= B3;
            B0 ^= B1;
            B1 |= B3;
            B1 ^= B0;
            B4 = ~B4;
            B4 ^= B1;
            B1 |= B0;
            B1 ^= B0;
            B1 |= B4;
            B3 ^= B1;
            B1 = B0;
            B0 = B4;
            B4 = B2;
            B2 = B3;
            B3 = B4;}`;
}

string SBoxD3() {
    return `{B2 ^= B3;
            B3 ^= B0;
            auto B4 = B3;
            B3 &= B2;
            B3 ^= B1;
            B1 |= B2;
            B1 ^= B4;
            B4 &= B3;
            B2 ^= B3;
            B4 &= B0;
            B4 ^= B2;
            B2 &= B1;
            B2 |= B0;
            B3 = ~B3;
            B2 ^= B3;
            B0 ^= B3;
            B0 &= B1;
            B3 ^= B4;
            B3 ^= B0;
            B0 = B1;
            B1 = B4;}`;
}

string SBoxD4() {
    return `{auto B4 = B2;
            B2 ^= B1;
            B0 ^= B2;
            B4 &= B2;
            B4 ^= B0;
            B0 &= B1;
            B1 ^= B3;
            B3 |= B4;
            B2 ^= B3;
            B0 ^= B3;
            B1 ^= B4;
            B3 &= B2;
            B3 ^= B1;
            B1 ^= B0;
            B1 |= B2;
            B0 ^= B3;
            B1 ^= B4;
            B0 ^= B1;
            B4 = B0;
            B0 = B2;
            B2 = B3;
            B3 = B4;}`;
}

string SBoxD5() {
    return `{auto B4 = B2;
            B2 &= B3;
            B2 ^= B1;
            B1 |= B3;
            B1 &= B0;
            B4 ^= B2;
            B4 ^= B1;
            B1 &= B2;
            B0 = ~B0;
            B3 ^= B4;
            B1 ^= B3;
            B3 &= B0;
            B3 ^= B2;
            B0 ^= B1;
            B2 &= B0;
            B3 ^= B0;
            B2 ^= B4;
            B2 |= B3;
            B3 ^= B0;
            B2 ^= B1;
            B1 = B3;
            B3 = B4;}`;
}

string SBoxD6() {
    return `{B1 = ~B1;
            auto B4 = B3;
            B2 ^= B1;
            B3 |= B0;
            B3 ^= B2;
            B2 |= B1;
            B2 &= B0;
            B4 ^= B3;
            B2 ^= B4;
            B4 |= B0;
            B4 ^= B1;
            B1 &= B2;
            B1 ^= B3;
            B4 ^= B2;
            B3 &= B4;
            B4 ^= B1;
            B3 ^= B4;
            B4 = ~B4;
            B3 ^= B0;
            B0 = B1;
            B1 = B4;
            B4 = B3;
            B3 = B2;
            B2 = B4;}`;
}

string SBoxD7() {
    return `{B0 ^= B2;
            auto B4 = B2;
            B2 &= B0;
            B4 ^= B3;
            B2 = ~B2;
            B3 ^= B1;
            B2 ^= B3;
            B4 |= B0;
            B0 ^= B2;
            B3 ^= B4;
            B4 ^= B1;
            B1 &= B3;
            B1 ^= B0;
            B0 ^= B3;
            B0 |= B2;
            B3 ^= B1;
            B4 ^= B0;
            B0 = B1;
            B1 = B2;
            B2 = B4;}`;
}

string SBoxD8() {
    return `{auto B4 = B2;
            B2 ^= B0;
            B0 &= B3;
            B4 |= B3;
            B2 = ~B2;
            B3 ^= B1;
            B1 |= B0;
            B0 ^= B2;
            B2 &= B4;
            B3 &= B4;
            B1 ^= B2;
            B2 ^= B0;
            B0 |= B2;
            B4 ^= B1;
            B0 ^= B3;
            B3 ^= B4;
            B4 |= B0;
            B3 ^= B2;
            B4 ^= B2;
            B2 = B1;
            B1 = B0;
            B0 = B3;
            B3 = B4;}`;
}

private:

/*
* Serpent's Linear Transformation
*/
void transform(ref uint B0, ref uint B1, ref uint B2, ref uint B3)
{
    B0  = rotateLeft(B0, 13);    B2  = rotateLeft(B2, 3);
    B1 ^= B0 ^ B2;B3 ^= B2 ^ (B0 << 3);
    B1  = rotateLeft(B1, 1);     B3  = rotateLeft(B3, 7);
    B0 ^= B1 ^ B3;B2 ^= B3 ^ (B1 << 7);
    B0  = rotateLeft(B0, 5);     B2  = rotateLeft(B2, 22);
}

/*
* Serpent's Inverse Linear Transformation
*/
void i_transform(ref uint B0, ref uint B1, ref uint B2, ref uint B3)
{
    B2  = rotateRight(B2, 22);  B0  = rotateRight(B0, 5);
    B2 ^= B3 ^ (B1 << 7);          B0 ^= B1 ^ B3;
    B3  = rotateRight(B3, 7);    B1  = rotateRight(B1, 1);
    B3 ^= B2 ^ (B0 << 3);          B1 ^= B0 ^ B2;
    B2  = rotateRight(B2, 3);    B0  = rotateRight(B0, 13);
}
/*
* XOR a key block with a data block
*/
string key_xor(ubyte round)()
{
    return `B0 ^= m_round_key[4*` ~ round.stringof ~ `  ];
            B1 ^= m_round_key[4*` ~ round.stringof ~ `+1];
            B2 ^= m_round_key[4*` ~ round.stringof ~ `+2];
            B3 ^= m_round_key[4*` ~ round.stringof ~ `+3];`;
}