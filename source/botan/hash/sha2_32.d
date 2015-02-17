/**
* SHA-{224,256}
* 
* Copyright:
* (C) 1999-2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*      2007 FlexSecure GmbH
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha2_32;

import botan.constants;
static if (BOTAN_HAS_SHA2_32):

import botan.hash.mdx_hash;
import botan.hash.sha2_32;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.hash.hash;
import botan.utils.types;

/**
* SHA-224
*/
final class SHA224 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "SHA-224"; }
    override @property size_t outputLength() const { return 28; }
    override HashFunction clone() const { return new SHA224; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        m_digest[0] = 0xC1059ED8;
        m_digest[1] = 0x367CD507;
        m_digest[2] = 0x3070DD17;
        m_digest[3] = 0xF70E5939;
        m_digest[4] = 0xFFC00B31;
        m_digest[5] = 0x68581511;
        m_digest[6] = 0x64F98FA7;
        m_digest[7] = 0xBEFA4FA4;
    }


    this()
    { 
        super(64, true, true);
        m_digest.length = 8;
        clear(); 
    }

protected:
    /*
    * SHA-224 compression function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        compress(m_digest, input, blocks);
    }

    /*
    * Copy out the digest
    */
    override void copyOut(ubyte* output)
    {
        for (size_t i = 0; i != outputLength(); i += 4)
            storeBigEndian(m_digest[i/4], output + i);
    }

    SecureVector!uint m_digest;
}


/**
* SHA-256
*/
class SHA256 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "SHA-256"; }
    override @property size_t outputLength() const { return 32; }
    override HashFunction clone() const { return new SHA256; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        m_digest[0] = 0x6A09E667;
        m_digest[1] = 0xBB67AE85;
        m_digest[2] = 0x3C6EF372;
        m_digest[3] = 0xA54FF53A;
        m_digest[4] = 0x510E527F;
        m_digest[5] = 0x9B05688C;
        m_digest[6] = 0x1F83D9AB;
        m_digest[7] = 0x5BE0CD19;
    }

    this()
    { 
        super(64, true, true);
        m_digest.length = 8;
        clear();
    }
protected:
    /*
    * SHA-256 compression function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        compress(m_digest, input, blocks);
    }

    /*
    * Copy out the digest
    */
    override void copyOut(ubyte* output)
    {
        for (size_t i = 0; i != outputLength(); i += 4)
            storeBigEndian(m_digest[i/4], output + i);
    }


    SecureVector!uint m_digest;
}

private:
pure:

/*
* SHA-256 Rho Function
*/
uint rho(uint X, uint rot1, uint rot2, uint rot3)
{
    return (rotateRight(X, rot1) ^ rotateRight(X, rot2) ^ rotateRight(X, rot3));
}

/*
* SHA-256 Sigma Function
*/
uint sigma(uint X, uint rot1, uint rot2, uint shift)
{
    return (rotateRight(X, rot1) ^ rotateRight(X, rot2) ^ (X >> shift));
}

/*
* SHA-256 F1 Function
*
* Use a macro as many compilers won't  a function this big,
* even though it is much faster if d.
*/
string SHA2_32_F(alias _A, alias _B, alias _C, alias _D, alias _E, alias _F, alias _G, alias _H, alias _M1, alias _M2, alias _M3, alias _M4, uint magic)()
{
    enum A = __traits(identifier, _A);
    enum B = __traits(identifier, _B);
    enum C = __traits(identifier, _C);
    enum D = __traits(identifier, _D);
    enum E = __traits(identifier, _E);
    enum F = __traits(identifier, _F);
    enum G = __traits(identifier, _G);
    enum H = __traits(identifier, _H);
    enum M1 = __traits(identifier, _M1);
    enum M2 = __traits(identifier, _M2);
    enum M3 = __traits(identifier, _M3);
    enum M4 = __traits(identifier, _M4);
    
    return H ~ ` += ` ~ magic.stringof ~ ` + rho(` ~ E ~ `, 6, 11, 25) + ((` ~ E ~ ` & ` ~ F ~ `) ^ (~` ~ E ~ ` & ` ~ G ~ `)) + ` ~ M1 ~ `;
        ` ~ D ~ ` += ` ~ H ~ `;
        ` ~ H ~ ` += rho(` ~ A ~ `, 2, 13, 22) + ((` ~ A ~ ` & ` ~ B ~ `) | ((` ~ A ~ ` | ` ~ B ~ `) & ` ~ C ~ `));
        ` ~ M1 ~ ` += sigma(` ~ M2 ~ `, 17, 19, 10) + ` ~ M3 ~ ` + sigma(` ~ M4 ~ `, 7, 18, 3);`;
}

/*
* SHA-224 / SHA-256 compression function
*/
void compress(ref SecureVector!uint digest,
              const(ubyte)* input, size_t blocks) pure
{
    uint A = digest[0], B = digest[1], C = digest[2],
        D = digest[3], E = digest[4], F = digest[5],
        G = digest[6], H = digest[7];
    
    foreach (size_t i; 0 .. blocks)
    {
        uint W00 = loadBigEndian!uint(input,  0);
        uint W01 = loadBigEndian!uint(input,  1);
        uint W02 = loadBigEndian!uint(input,  2);
        uint W03 = loadBigEndian!uint(input,  3);
        uint W04 = loadBigEndian!uint(input,  4);
        uint W05 = loadBigEndian!uint(input,  5);
        uint W06 = loadBigEndian!uint(input,  6);
        uint W07 = loadBigEndian!uint(input,  7);
        uint W08 = loadBigEndian!uint(input,  8);
        uint W09 = loadBigEndian!uint(input,  9);
        uint W10 = loadBigEndian!uint(input, 10);
        uint W11 = loadBigEndian!uint(input, 11);
        uint W12 = loadBigEndian!uint(input, 12);
        uint W13 = loadBigEndian!uint(input, 13);
        uint W14 = loadBigEndian!uint(input, 14);
        uint W15 = loadBigEndian!uint(input, 15);
        
        mixin(
            SHA2_32_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x428A2F98)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x71374491)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xB5C0FBCF)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xE9B5DBA5)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x3956C25B)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x59F111F1)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x923F82A4)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0xAB1C5ED5)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xD807AA98)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x12835B01)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x243185BE)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x550C7DC3)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x72BE5D74)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x80DEB1FE)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x9BDC06A7)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC19BF174)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xE49B69C1)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xEFBE4786)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x0FC19DC6)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x240CA1CC)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x2DE92C6F)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4A7484AA)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5CB0A9DC)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x76F988DA)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x983E5152)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA831C66D)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xB00327C8)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xBF597FC7)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xC6E00BF3)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD5A79147)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x06CA6351)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x14292967)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x27B70A85)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x2E1B2138)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x4D2C6DFC)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x53380D13)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x650A7354)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x766A0ABB)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x81C2C92E)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x92722C85)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xA2BFE8A1)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA81A664B)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xC24B8B70)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xC76C51A3)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xD192E819)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD6990624)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xF40E3585)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x106AA070)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x19A4C116)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x1E376C08)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x2748774C)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x34B0BCB5)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x391C0CB3)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4ED8AA4A)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5B9CCA4F)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x682E6FF3)() ~ 
            SHA2_32_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x748F82EE)() ~ 
            SHA2_32_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x78A5636F)() ~ 
            SHA2_32_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x84C87814)() ~ 
            SHA2_32_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x8CC70208)() ~ 
            SHA2_32_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x90BEFFFA)() ~ 
            SHA2_32_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xA4506CEB)() ~ 
            SHA2_32_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xBEF9A3F7)() ~ 
            SHA2_32_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC67178F2)()
            );
        
        A = (digest[0] += A);
        B = (digest[1] += B);
        C = (digest[2] += C);
        D = (digest[3] += D);
        E = (digest[4] += E);
        F = (digest[5] += F);
        G = (digest[6] += G);
        H = (digest[7] += H);
        
        input += 64;
    }
}