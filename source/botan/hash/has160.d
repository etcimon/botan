/**
* HAS-160
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.has160;

import botan.constants;
static if (BOTAN_HAS_HAS_160):

import botan.hash.mdx_hash;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* HAS-160, a Korean hash function standardized in
* TTAS.KO-12.0011/R1. Used in conjuction with KCDSA
*/
class HAS160 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "HAS-160"; }
    override @property size_t outputLength() const { return 20; }
    override HashFunction clone() const { return new HAS160; }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        super.clear();
        zeroise(m_X);
        m_digest[0] = 0x67452301;
        m_digest[1] = 0xEFCDAB89;
        m_digest[2] = 0x98BADCFE;
        m_digest[3] = 0x10325476;
        m_digest[4] = 0xC3D2E1F0;
    }

    this()
    {
        super(64, false, true);
        m_X = 20;
        m_digest.length = 5;
        clear(); 
    }

protected:
    /*
    * HAS-160 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        
        uint A = m_digest[0], B = m_digest[1], C = m_digest[2],
            D = m_digest[3], E = m_digest[4];
        
        foreach (size_t i; 0 .. blocks)
        {
            loadLittleEndian(m_X.ptr, input, 16);
            
            m_X[16] = m_X[ 0] ^ m_X[ 1] ^ m_X[ 2] ^ m_X[ 3];
            m_X[17] = m_X[ 4] ^ m_X[ 5] ^ m_X[ 6] ^ m_X[ 7];
            m_X[18] = m_X[ 8] ^ m_X[ 9] ^ m_X[10] ^ m_X[11];
            m_X[19] = m_X[12] ^ m_X[13] ^ m_X[14] ^ m_X[15];
            F1(A,B,C,D,E,m_X[18], 5);    F1(E,A,B,C,D,m_X[ 0],11);
            F1(D,E,A,B,C,m_X[ 1], 7);    F1(C,D,E,A,B,m_X[ 2],15);
            F1(B,C,D,E,A,m_X[ 3], 6);    F1(A,B,C,D,E,m_X[19],13);
            F1(E,A,B,C,D,m_X[ 4], 8);    F1(D,E,A,B,C,m_X[ 5],14);
            F1(C,D,E,A,B,m_X[ 6], 7);    F1(B,C,D,E,A,m_X[ 7],12);
            F1(A,B,C,D,E,m_X[16], 9);    F1(E,A,B,C,D,m_X[ 8],11);
            F1(D,E,A,B,C,m_X[ 9], 8);    F1(C,D,E,A,B,m_X[10],15);
            F1(B,C,D,E,A,m_X[11], 6);    F1(A,B,C,D,E,m_X[17],12);
            F1(E,A,B,C,D,m_X[12], 9);    F1(D,E,A,B,C,m_X[13],14);
            F1(C,D,E,A,B,m_X[14], 5);    F1(B,C,D,E,A,m_X[15],13);
            
            m_X[16] = m_X[ 3] ^ m_X[ 6] ^ m_X[ 9] ^ m_X[12];
            m_X[17] = m_X[ 2] ^ m_X[ 5] ^ m_X[ 8] ^ m_X[15];
            m_X[18] = m_X[ 1] ^ m_X[ 4] ^ m_X[11] ^ m_X[14];
            m_X[19] = m_X[ 0] ^ m_X[ 7] ^ m_X[10] ^ m_X[13];
            F2(A,B,C,D,E,m_X[18], 5);    F2(E,A,B,C,D,m_X[ 3],11);
            F2(D,E,A,B,C,m_X[ 6], 7);    F2(C,D,E,A,B,m_X[ 9],15);
            F2(B,C,D,E,A,m_X[12], 6);    F2(A,B,C,D,E,m_X[19],13);
            F2(E,A,B,C,D,m_X[15], 8);    F2(D,E,A,B,C,m_X[ 2],14);
            F2(C,D,E,A,B,m_X[ 5], 7);    F2(B,C,D,E,A,m_X[ 8],12);
            F2(A,B,C,D,E,m_X[16], 9);    F2(E,A,B,C,D,m_X[11],11);
            F2(D,E,A,B,C,m_X[14], 8);    F2(C,D,E,A,B,m_X[ 1],15);
            F2(B,C,D,E,A,m_X[ 4], 6);    F2(A,B,C,D,E,m_X[17],12);
            F2(E,A,B,C,D,m_X[ 7], 9);    F2(D,E,A,B,C,m_X[10],14);
            F2(C,D,E,A,B,m_X[13], 5);    F2(B,C,D,E,A,m_X[ 0],13);
            
            m_X[16] = m_X[ 5] ^ m_X[ 7] ^ m_X[12] ^ m_X[14];
            m_X[17] = m_X[ 0] ^ m_X[ 2] ^ m_X[ 9] ^ m_X[11];
            m_X[18] = m_X[ 4] ^ m_X[ 6] ^ m_X[13] ^ m_X[15];
            m_X[19] = m_X[ 1] ^ m_X[ 3] ^ m_X[ 8] ^ m_X[10];
            F3(A,B,C,D,E,m_X[18], 5);    F3(E,A,B,C,D,m_X[12],11);
            F3(D,E,A,B,C,m_X[ 5], 7);    F3(C,D,E,A,B,m_X[14],15);
            F3(B,C,D,E,A,m_X[ 7], 6);    F3(A,B,C,D,E,m_X[19],13);
            F3(E,A,B,C,D,m_X[ 0], 8);    F3(D,E,A,B,C,m_X[ 9],14);
            F3(C,D,E,A,B,m_X[ 2], 7);    F3(B,C,D,E,A,m_X[11],12);
            F3(A,B,C,D,E,m_X[16], 9);    F3(E,A,B,C,D,m_X[ 4],11);
            F3(D,E,A,B,C,m_X[13], 8);    F3(C,D,E,A,B,m_X[ 6],15);
            F3(B,C,D,E,A,m_X[15], 6);    F3(A,B,C,D,E,m_X[17],12);
            F3(E,A,B,C,D,m_X[ 8], 9);    F3(D,E,A,B,C,m_X[ 1],14);
            F3(C,D,E,A,B,m_X[10], 5);    F3(B,C,D,E,A,m_X[ 3],13);
            
            m_X[16] = m_X[ 2] ^ m_X[ 7] ^ m_X[ 8] ^ m_X[13];
            m_X[17] = m_X[ 3] ^ m_X[ 4] ^ m_X[ 9] ^ m_X[14];
            m_X[18] = m_X[ 0] ^ m_X[ 5] ^ m_X[10] ^ m_X[15];
            m_X[19] = m_X[ 1] ^ m_X[ 6] ^ m_X[11] ^ m_X[12];
            F4(A,B,C,D,E,m_X[18], 5);    F4(E,A,B,C,D,m_X[ 7],11);
            F4(D,E,A,B,C,m_X[ 2], 7);    F4(C,D,E,A,B,m_X[13],15);
            F4(B,C,D,E,A,m_X[ 8], 6);    F4(A,B,C,D,E,m_X[19],13);
            F4(E,A,B,C,D,m_X[ 3], 8);    F4(D,E,A,B,C,m_X[14],14);
            F4(C,D,E,A,B,m_X[ 9], 7);    F4(B,C,D,E,A,m_X[ 4],12);
            F4(A,B,C,D,E,m_X[16], 9);    F4(E,A,B,C,D,m_X[15],11);
            F4(D,E,A,B,C,m_X[10], 8);    F4(C,D,E,A,B,m_X[ 5],15);
            F4(B,C,D,E,A,m_X[ 0], 6);    F4(A,B,C,D,E,m_X[17],12);
            F4(E,A,B,C,D,m_X[11], 9);    F4(D,E,A,B,C,m_X[ 6],14);
            F4(C,D,E,A,B,m_X[ 1], 5);    F4(B,C,D,E,A,m_X[12],13);
            
            A = (m_digest[0] += A);
            B = (m_digest[1] += B);
            C = (m_digest[2] += C);
            D = (m_digest[3] += D);
            E = (m_digest[4] += E);
            
            input += hashBlockSize;
        }
    }

    /*
    * Copy out the digest
    */
    override void copyOut(ubyte* output)
    {
        for (size_t i = 0; i != outputLength(); i += 4)
            storeLittleEndian(m_digest[i/4], output + i);
    }


    SecureVector!uint m_X, m_digest;
}

private:

/*
* HAS-160 F1 Function
*/
void F1(uint A, ref uint B, uint C, uint D, ref uint E,
        uint msg, uint rot)
{
    E += rotateLeft(A, rot) + (D ^ (B & (C ^ D))) + msg;
    B  = rotateLeft(B, 10);
}

/*
* HAS-160 F2 Function
*/
void F2(uint A, ref uint B, uint C, uint D, ref uint E,
        uint msg, uint rot)
{
    E += rotateLeft(A, rot) + (B ^ C ^ D) + msg + 0x5A827999;
    B  = rotateLeft(B, 17);
}

/*
* HAS-160 F3 Function
*/
void F3(uint A, ref uint B, uint C, uint D, ref uint E,
        uint msg, uint rot)
{
    E += rotateLeft(A, rot) + (C ^ (B | ~D)) + msg + 0x6ED9EBA1;
    B  = rotateLeft(B, 25);
}

/*
* HAS-160 F4 Function
*/
void F4(uint A, ref uint B, uint C, uint D, ref uint E,
        uint msg, uint rot)
{
    E += rotateLeft(A, rot) + (B ^ C ^ D) + msg + 0x8F1BBCDC;
    B  = rotateLeft(B, 30);
}
