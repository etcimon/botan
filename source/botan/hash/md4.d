/**
* MD4
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.md4;

import botan.constants;
static if (BOTAN_HAS_MD4):


import botan.hash.mdx_hash;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* MD4
*/
class MD4 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "MD4"; }
    override @property size_t outputLength() const { return 16; }
    override HashFunction clone() const { return new MD4; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        zeroise(m_M);
        m_digest[0] = 0x67452301;
        m_digest[1] = 0xEFCDAB89;
        m_digest[2] = 0x98BADCFE;
        m_digest[3] = 0x10325476;
    }

    this()
    {  
        super(64, false, true);
        m_M = 16;
        m_digest.length = 4;
        clear(); 
    }
protected:
    /*
    * MD4 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        uint A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3];
        
        foreach (size_t i; 0 .. blocks)
        {
            loadLittleEndian(m_M.ptr, input, m_M.length);
            
            FF(A,B,C,D,m_M[ 0], 3);    FF(D,A,B,C,m_M[ 1], 7);
            FF(C,D,A,B,m_M[ 2],11);    FF(B,C,D,A,m_M[ 3],19);
            FF(A,B,C,D,m_M[ 4], 3);    FF(D,A,B,C,m_M[ 5], 7);
            FF(C,D,A,B,m_M[ 6],11);    FF(B,C,D,A,m_M[ 7],19);
            FF(A,B,C,D,m_M[ 8], 3);    FF(D,A,B,C,m_M[ 9], 7);
            FF(C,D,A,B,m_M[10],11);    FF(B,C,D,A,m_M[11],19);
            FF(A,B,C,D,m_M[12], 3);    FF(D,A,B,C,m_M[13], 7);
            FF(C,D,A,B,m_M[14],11);    FF(B,C,D,A,m_M[15],19);
            
            GG(A,B,C,D,m_M[ 0], 3);    GG(D,A,B,C,m_M[ 4], 5);
            GG(C,D,A,B,m_M[ 8], 9);    GG(B,C,D,A,m_M[12],13);
            GG(A,B,C,D,m_M[ 1], 3);    GG(D,A,B,C,m_M[ 5], 5);
            GG(C,D,A,B,m_M[ 9], 9);    GG(B,C,D,A,m_M[13],13);
            GG(A,B,C,D,m_M[ 2], 3);    GG(D,A,B,C,m_M[ 6], 5);
            GG(C,D,A,B,m_M[10], 9);    GG(B,C,D,A,m_M[14],13);
            GG(A,B,C,D,m_M[ 3], 3);    GG(D,A,B,C,m_M[ 7], 5);
            GG(C,D,A,B,m_M[11], 9);    GG(B,C,D,A,m_M[15],13);
            
            HH(A,B,C,D,m_M[ 0], 3);    HH(D,A,B,C,m_M[ 8], 9);
            HH(C,D,A,B,m_M[ 4],11);    HH(B,C,D,A,m_M[12],15);
            HH(A,B,C,D,m_M[ 2], 3);    HH(D,A,B,C,m_M[10], 9);
            HH(C,D,A,B,m_M[ 6],11);    HH(B,C,D,A,m_M[14],15);
            HH(A,B,C,D,m_M[ 1], 3);    HH(D,A,B,C,m_M[ 9], 9);
            HH(C,D,A,B,m_M[ 5],11);    HH(B,C,D,A,m_M[13],15);
            HH(A,B,C,D,m_M[ 3], 3);    HH(D,A,B,C,m_M[11], 9);
            HH(C,D,A,B,m_M[ 7],11);    HH(B,C,D,A,m_M[15],15);
            
            A = (m_digest[0] += A);
            B = (m_digest[1] += B);
            C = (m_digest[2] += C);
            D = (m_digest[3] += D);
            
            input += hashBlockSize;
        }
    }

    /*
    * Copy out the digest
    */
    override void copyOut(ubyte* output)
    {
        for (size_t i = 0; i != outputLength; i += 4)
            storeLittleEndian(m_digest[i/4], output + i);
    }

    /**
    * The message buffer, exposed for use by subclasses (x86 asm)
    */
    SecureVector!uint m_M;

    /**
    * The digest value, exposed for use by subclasses (x86 asm)
    */
    SecureVector!uint m_digest;
}

private:

/*
* MD4 FF Function
*/
void FF(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
    A += (D ^ (B & (C ^ D))) + M;
    A  = rotateLeft(A, S);
}

/*
* MD4 GG Function
*/
void GG(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
    A += ((B & C) | (D & (B | C))) + M + 0x5A827999;
    A  = rotateLeft(A, S);
}

/*
* MD4 HH Function
*/
void HH(ref uint A, uint B, uint C, uint D, uint M, ubyte S)
{
    A += (B ^ C ^ D) + M + 0x6ED9EBA1;
    A  = rotateLeft(A, S);
}