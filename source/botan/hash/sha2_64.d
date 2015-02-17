/**
* SHA-{384,512}
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha2_64;

import botan.constants;
static if (BOTAN_HAS_SHA2_64):

import botan.hash.mdx_hash;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;

/**
* SHA-384
*/
final class SHA384 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "SHA-384"; }
    override @property size_t outputLength() const { return 48; }
    override HashFunction clone() const { return new SHA384; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        m_digest[0] = 0xCBBB9D5DC1059ED8;
        m_digest[1] = 0x629A292A367CD507;
        m_digest[2] = 0x9159015A3070DD17;
        m_digest[3] = 0x152FECD8F70E5939;
        m_digest[4] = 0x67332667FFC00B31;
        m_digest[5] = 0x8EB44A8768581511;
        m_digest[6] = 0xDB0C2E0D64F98FA7;
        m_digest[7] = 0x47B5481DBEFA4FA4;
    }

    this()
    {  
        super(128, true, true, 16);
        m_digest.length = 8;
        clear();
    }

protected:
    /*
    * SHA-384 compression function
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
        for (size_t i = 0; i != outputLength(); i += 8)
            storeBigEndian(m_digest[i/8], output + i);
    }

    SecureVector!ulong m_digest;
}

/**
* SHA-512
*/
final class SHA512 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "SHA-512"; }
    override @property size_t outputLength() const { return 64; }
    override HashFunction clone() const { return new SHA512; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        m_digest[0] = 0x6A09E667F3BCC908;
        m_digest[1] = 0xBB67AE8584CAA73B;
        m_digest[2] = 0x3C6EF372FE94F82B;
        m_digest[3] = 0xA54FF53A5F1D36F1;
        m_digest[4] = 0x510E527FADE682D1;
        m_digest[5] = 0x9B05688C2B3E6C1F;
        m_digest[6] = 0x1F83D9ABFB41BD6B;
        m_digest[7] = 0x5BE0CD19137E2179;
    }

    this() 
    { 
        super(128, true, true, 16);
        m_digest.length = 8;
        clear(); 
    }

protected:
    /*
    * SHA-512 compression function
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
        for (size_t i = 0; i != outputLength(); i += 8)
            storeBigEndian(m_digest[i/8], output + i);
    }

    SecureVector!ulong m_digest;
}

private:
pure:

/*
* SHA-{384,512} Rho Function
*/
ulong rho(ulong X, uint rot1, uint rot2, uint rot3)
{
    return (rotateRight(X, rot1) ^ rotateRight(X, rot2) ^
            rotateRight(X, rot3));
}

/*
* SHA-{384,512} Sigma Function
*/
ulong sigma(ulong X, uint rot1, uint rot2, uint shift)
{
    return (rotateRight(X, rot1) ^ rotateRight(X, rot2) ^ (X >> shift));
}

/*
* SHA-512 F1 Function
*
* Use a macro as many compilers won't  a function this big,
* even though it is much faster if d.
*/
string SHA2_64_F(alias _A, alias _B, alias _C, alias _D, alias _E, alias _F, alias _G, alias _H, alias _M1, alias _M2, alias _M3, alias _M4, ulong magic)()
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
    
    return H ~ ` += ` ~ magic.stringof ~ `+ rho(` ~ E ~ `, 14, 18, 41) + ((` ~ E ~ ` & ` ~ F ~ `) ^ (~` ~ E ~ ` & ` ~ G ~ `)) + ` ~ M1 ~ `;
    ` ~ D ~ ` += ` ~ H ~ `;
    ` ~ H ~ ` += rho(` ~ A ~ `, 28, 34, 39) + ((` ~ A ~ ` & ` ~ B ~ `) | ((` ~ A ~ ` | ` ~ B ~ `) & ` ~ C ~ `));
    ` ~ M1 ~ ` += sigma(` ~ M2 ~ `, 19, 61, 6) + ` ~ M3 ~ ` + sigma(` ~ M4 ~ `, 1, 8, 7);`;
}

/*
* SHA-{384,512} Compression Function
*/
void compress(ref SecureVector!ulong digest,
              const(ubyte)* input, size_t blocks) pure
{
    ulong A = digest[0], B = digest[1], C = digest[2],
        D = digest[3], E = digest[4], F = digest[5],
        G = digest[6], H = digest[7];
    
    foreach (size_t i; 0 .. blocks)
    {
        ulong W00 = loadBigEndian!ulong(input,  0);
        ulong W01 = loadBigEndian!ulong(input,  1);
        ulong W02 = loadBigEndian!ulong(input,  2);
        ulong W03 = loadBigEndian!ulong(input,  3);
        ulong W04 = loadBigEndian!ulong(input,  4);
        ulong W05 = loadBigEndian!ulong(input,  5);
        ulong W06 = loadBigEndian!ulong(input,  6);
        ulong W07 = loadBigEndian!ulong(input,  7);
        ulong W08 = loadBigEndian!ulong(input,  8);
        ulong W09 = loadBigEndian!ulong(input,  9);
        ulong W10 = loadBigEndian!ulong(input, 10);
        ulong W11 = loadBigEndian!ulong(input, 11);
        ulong W12 = loadBigEndian!ulong(input, 12);
        ulong W13 = loadBigEndian!ulong(input, 13);
        ulong W14 = loadBigEndian!ulong(input, 14);
        ulong W15 = loadBigEndian!ulong(input, 15);
        
        mixin(
            SHA2_64_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x428A2F98D728AE22)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x7137449123EF65CD)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xB5C0FBCFEC4D3B2F)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xE9B5DBA58189DBBC)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x3956C25BF348B538)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x59F111F1B605D019)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x923F82A4AF194F9B)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0xAB1C5ED5DA6D8118)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xD807AA98A3030242)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x12835B0145706FBE)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x243185BE4EE4B28C)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x550C7DC3D5FFB4E2)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x72BE5D74F27B896F)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x80DEB1FE3B1696B1)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x9BDC06A725C71235)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC19BF174CF692694)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xE49B69C19EF14AD2)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xEFBE4786384F25E3)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x0FC19DC68B8CD5B5)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x240CA1CC77AC9C65)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x2DE92C6F592B0275)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4A7484AA6EA6E483)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5CB0A9DCBD41FBD4)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x76F988DA831153B5)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x983E5152EE66DFAB)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA831C66D2DB43210)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xB00327C898FB213F)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xBF597FC7BEEF0EE4)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xC6E00BF33DA88FC2)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD5A79147930AA725)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x06CA6351E003826F)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x142929670A0E6E70)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x27B70A8546D22FFC)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x2E1B21385C26C926)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x4D2C6DFC5AC42AED)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x53380D139D95B3DF)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x650A73548BAF63DE)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x766A0ABB3C77B2A8)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x81C2C92E47EDAEE6)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x92722C851482353B)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xA2BFE8A14CF10364)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA81A664BBC423001)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xC24B8B70D0F89791)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xC76C51A30654BE30)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xD192E819D6EF5218)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD69906245565A910)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xF40E35855771202A)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x106AA07032BBD1B8)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x19A4C116B8D2D0C8)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x1E376C085141AB53)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x2748774CDF8EEB99)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x34B0BCB5E19B48A8)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x391C0CB3C5C95A63)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4ED8AA4AE3418ACB)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5B9CCA4F7763E373)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x682E6FF3D6B2B8A3)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x748F82EE5DEFB2FC)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x78A5636F43172F60)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x84C87814A1F0AB72)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x8CC702081A6439EC)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x90BEFFFA23631E28)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xA4506CEBDE82BDE9)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xBEF9A3F7B2C67915)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC67178F2E372532B)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xCA273ECEEA26619C)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xD186B8C721C0C207)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xEADA7DD6CDE0EB1E)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xF57D4F7FEE6ED178)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x06F067AA72176FBA)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x0A637DC5A2C898A6)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x113F9804BEF90DAE)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x1B710B35131C471B)() ~
            SHA2_64_F!(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x28DB77F523047D84)() ~
            SHA2_64_F!(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x32CAAB7B40C72493)() ~
            SHA2_64_F!(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x3C9EBE0A15C9BEBC)() ~
            SHA2_64_F!(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x431D67C49C100D4C)() ~
            SHA2_64_F!(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x4CC5D4BECB3E42B6)() ~
            SHA2_64_F!(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x597F299CFC657E2A)() ~
            SHA2_64_F!(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x5FCB6FAB3AD6FAEC)() ~
            SHA2_64_F!(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x6C44198C4A475817)()
            );
        
        A = (digest[0] += A);
        B = (digest[1] += B);
        C = (digest[2] += C);
        D = (digest[3] += D);
        E = (digest[4] += E);
        F = (digest[5] += F);
        G = (digest[6] += G);
        H = (digest[7] += H);
        
        input += 128;
    }
}