/**
* SHA-160
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha160;

import botan.constants;
static if (BOTAN_HAS_SHA1):

import botan.hash.mdx_hash;

import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* NIST's SHA-160
*/
class SHA160 : MDxHashFunction, HashFunction
{
public:
    
    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override final @property string name() const { return "SHA-160"; }
    override final @property size_t outputLength() const { return 20; }
    override HashFunction clone() const { return new SHA160; }

    /*
    * Clear memory of sensitive data
    */
    override final void clear()
    {
        super.clear();
        zeroise(m_W);
        m_digest[0] = 0x67452301;
        m_digest[1] = 0xEFCDAB89;
        m_digest[2] = 0x98BADCFE;
        m_digest[3] = 0x10325476;
        m_digest[4] = 0xC3D2E1F0;
    }

    this()
    {
        super(64, true, true);
        m_digest.length = 5;
        m_W = 80;
        clear();
    }
protected:
    /**
    * Set a custom size for the W array. Normally 80, but some
    * subclasses need slightly more for best performance/internal
    * constraints
    * Params:
    *  W_size = how big to make W
    */
    this(size_t W_size) 
    {
        super(64, true, true);
        m_digest.length = 5;
        m_W = W_size;
        clear();
    }

    /*
    * SHA-160 Compression Function
    */
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        uint A = m_digest[0], B = m_digest[1], C = m_digest[2],
            D = m_digest[3], E = m_digest[4];
        
        foreach (size_t i; 0 .. blocks)
        {
            loadBigEndian(m_W.ptr, input, 16);
            
            for (size_t j = 16; j != 80; j += 8)
            {
                m_W[j  ] = rotateLeft((m_W[j-3] ^ m_W[j-8] ^ m_W[j-14] ^ m_W[j-16]), 1);
                m_W[j+1] = rotateLeft((m_W[j-2] ^ m_W[j-7] ^ m_W[j-13] ^ m_W[j-15]), 1);
                m_W[j+2] = rotateLeft((m_W[j-1] ^ m_W[j-6] ^ m_W[j-12] ^ m_W[j-14]), 1);
                m_W[j+3] = rotateLeft((m_W[j  ] ^ m_W[j-5] ^ m_W[j-11] ^ m_W[j-13]), 1);
                m_W[j+4] = rotateLeft((m_W[j+1] ^ m_W[j-4] ^ m_W[j-10] ^ m_W[j-12]), 1);
                m_W[j+5] = rotateLeft((m_W[j+2] ^ m_W[j-3] ^ m_W[j- 9] ^ m_W[j-11]), 1);
                m_W[j+6] = rotateLeft((m_W[j+3] ^ m_W[j-2] ^ m_W[j- 8] ^ m_W[j-10]), 1);
                m_W[j+7] = rotateLeft((m_W[j+4] ^ m_W[j-1] ^ m_W[j- 7] ^ m_W[j- 9]), 1);
            }
            
            F1(A, B, C, D, E, m_W[ 0]);    F1(E, A, B, C, D, m_W[ 1]);
            F1(D, E, A, B, C, m_W[ 2]);    F1(C, D, E, A, B, m_W[ 3]);
            F1(B, C, D, E, A, m_W[ 4]);    F1(A, B, C, D, E, m_W[ 5]);
            F1(E, A, B, C, D, m_W[ 6]);    F1(D, E, A, B, C, m_W[ 7]);
            F1(C, D, E, A, B, m_W[ 8]);    F1(B, C, D, E, A, m_W[ 9]);
            F1(A, B, C, D, E, m_W[10]);    F1(E, A, B, C, D, m_W[11]);
            F1(D, E, A, B, C, m_W[12]);    F1(C, D, E, A, B, m_W[13]);
            F1(B, C, D, E, A, m_W[14]);    F1(A, B, C, D, E, m_W[15]);
            F1(E, A, B, C, D, m_W[16]);    F1(D, E, A, B, C, m_W[17]);
            F1(C, D, E, A, B, m_W[18]);    F1(B, C, D, E, A, m_W[19]);
            
            F2(A, B, C, D, E, m_W[20]);    F2(E, A, B, C, D, m_W[21]);
            F2(D, E, A, B, C, m_W[22]);    F2(C, D, E, A, B, m_W[23]);
            F2(B, C, D, E, A, m_W[24]);    F2(A, B, C, D, E, m_W[25]);
            F2(E, A, B, C, D, m_W[26]);    F2(D, E, A, B, C, m_W[27]);
            F2(C, D, E, A, B, m_W[28]);    F2(B, C, D, E, A, m_W[29]);
            F2(A, B, C, D, E, m_W[30]);    F2(E, A, B, C, D, m_W[31]);
            F2(D, E, A, B, C, m_W[32]);    F2(C, D, E, A, B, m_W[33]);
            F2(B, C, D, E, A, m_W[34]);    F2(A, B, C, D, E, m_W[35]);
            F2(E, A, B, C, D, m_W[36]);    F2(D, E, A, B, C, m_W[37]);
            F2(C, D, E, A, B, m_W[38]);    F2(B, C, D, E, A, m_W[39]);
            
            F3(A, B, C, D, E, m_W[40]);    F3(E, A, B, C, D, m_W[41]);
            F3(D, E, A, B, C, m_W[42]);    F3(C, D, E, A, B, m_W[43]);
            F3(B, C, D, E, A, m_W[44]);    F3(A, B, C, D, E, m_W[45]);
            F3(E, A, B, C, D, m_W[46]);    F3(D, E, A, B, C, m_W[47]);
            F3(C, D, E, A, B, m_W[48]);    F3(B, C, D, E, A, m_W[49]);
            F3(A, B, C, D, E, m_W[50]);    F3(E, A, B, C, D, m_W[51]);
            F3(D, E, A, B, C, m_W[52]);    F3(C, D, E, A, B, m_W[53]);
            F3(B, C, D, E, A, m_W[54]);    F3(A, B, C, D, E, m_W[55]);
            F3(E, A, B, C, D, m_W[56]);    F3(D, E, A, B, C, m_W[57]);
            F3(C, D, E, A, B, m_W[58]);    F3(B, C, D, E, A, m_W[59]);
            
            F4(A, B, C, D, E, m_W[60]);    F4(E, A, B, C, D, m_W[61]);
            F4(D, E, A, B, C, m_W[62]);    F4(C, D, E, A, B, m_W[63]);
            F4(B, C, D, E, A, m_W[64]);    F4(A, B, C, D, E, m_W[65]);
            F4(E, A, B, C, D, m_W[66]);    F4(D, E, A, B, C, m_W[67]);
            F4(C, D, E, A, B, m_W[68]);    F4(B, C, D, E, A, m_W[69]);
            F4(A, B, C, D, E, m_W[70]);    F4(E, A, B, C, D, m_W[71]);
            F4(D, E, A, B, C, m_W[72]);    F4(C, D, E, A, B, m_W[73]);
            F4(B, C, D, E, A, m_W[74]);    F4(A, B, C, D, E, m_W[75]);
            F4(E, A, B, C, D, m_W[76]);    F4(D, E, A, B, C, m_W[77]);
            F4(C, D, E, A, B, m_W[78]);    F4(B, C, D, E, A, m_W[79]);
            
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
    override final void copyOut(ubyte* output)
    {
        for (size_t i = 0; i != outputLength(); i += 4)
            storeBigEndian(m_digest[i/4], output + i);
    }

    /**
    * The digest value, exposed for use by subclasses (asm, SSE2)
    */
    SecureVector!uint m_digest;

    /**
    * The message buffer, exposed for use by subclasses (asm, SSE2)
    */
    SecureVector!uint m_W;
}

private:
pure:
/*
* SHA-160 F1 Function
*/
void F1(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
    E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + rotateLeft(A, 5);
    B  = rotateLeft(B, 30);
}

/*
* SHA-160 F2 Function
*/
void F2(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
    E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotateLeft(A, 5);
    B  = rotateLeft(B, 30);
}

/*
* SHA-160 F3 Function
*/
void F3(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
    E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + rotateLeft(A, 5);
    B  = rotateLeft(B, 30);
}

/*
* SHA-160 F4 Function
*/
void F4(uint A, ref uint B, uint C, uint D, ref uint E, uint msg)
{
    E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotateLeft(A, 5);
    B  = rotateLeft(B, 30);
}