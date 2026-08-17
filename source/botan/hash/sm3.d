/**
* SM3
*
* Copyright:
* (C) 2017 Ribose Inc.
* (C) 2021 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sm3;

import botan.constants;
static if (BOTAN_HAS_SM3):

import botan.hash.mdx_hash;
import botan.hash.hash;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;

/**
* SM3 (GM/T 0004-2012). SCAN: "SM3".
*/
final class SM3 : MDxHashFunction, HashFunction
{
public:
    this()
    {
        super(64, true, true);
        m_digest.length = 8;
        clear();
    }

    override @property size_t hashBlockSize() const { return super.hashBlockSize(); }
    override @property string name() const { return "SM3"; }
    override @property size_t outputLength() const { return 32; }
    override HashFunction clone() const { return new SM3; }

    override void clear()
    {
        super.clear();
        m_digest[0] = 0x7380166F;
        m_digest[1] = 0x4914B2B9;
        m_digest[2] = 0x172442D7;
        m_digest[3] = 0xDA8A0600;
        m_digest[4] = 0xA96F30BC;
        m_digest[5] = 0x163138AA;
        m_digest[6] = 0xE38DEE4D;
        m_digest[7] = 0xB0FB0E4E;
    }

protected:
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        uint A = m_digest[0];
        uint B = m_digest[1];
        uint C = m_digest[2];
        uint D = m_digest[3];
        uint E = m_digest[4];
        uint F = m_digest[5];
        uint G = m_digest[6];
        uint H = m_digest[7];
        uint[16] W;

        foreach (size_t i; 0 .. blocks)
        {
            foreach (size_t j; 0 .. 16)
                W[j] = loadBigEndian!uint(input, j);
            input += 64;

            r1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 4]); W[ 0] = sm3E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
            r1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 5]); W[ 1] = sm3E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
            r1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 6]); W[ 2] = sm3E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
            r1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 7]); W[ 3] = sm3E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
            r1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 8]); W[ 4] = sm3E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
            r1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 9]); W[ 5] = sm3E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
            r1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[10]); W[ 6] = sm3E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
            r1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[11]); W[ 7] = sm3E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
            r1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[12]); W[ 8] = sm3E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
            r1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[13]); W[ 9] = sm3E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
            r1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[14]); W[10] = sm3E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
            r1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[15]); W[11] = sm3E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
            r1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[ 0]); W[12] = sm3E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
            r1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[ 1]); W[13] = sm3E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
            r1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[ 2]); W[14] = sm3E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
            r1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[ 3]); W[15] = sm3E(W[15], W[ 6], W[12], W[ 2], W[ 9]);

            r2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]); W[ 0] = sm3E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
            r2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]); W[ 1] = sm3E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
            r2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]); W[ 2] = sm3E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
            r2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]); W[ 3] = sm3E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
            r2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]); W[ 4] = sm3E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
            r2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]); W[ 5] = sm3E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
            r2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]); W[ 6] = sm3E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
            r2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]); W[ 7] = sm3E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
            r2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]); W[ 8] = sm3E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
            r2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]); W[ 9] = sm3E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
            r2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]); W[10] = sm3E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
            r2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]); W[11] = sm3E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
            r2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]); W[12] = sm3E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
            r2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]); W[13] = sm3E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
            r2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]); W[14] = sm3E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
            r2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]); W[15] = sm3E(W[15], W[ 6], W[12], W[ 2], W[ 9]);
            r2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[ 0], W[ 4]); W[ 0] = sm3E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
            r2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[ 1], W[ 5]); W[ 1] = sm3E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
            r2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[ 2], W[ 6]); W[ 2] = sm3E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
            r2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[ 3], W[ 7]); W[ 3] = sm3E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
            r2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[ 4], W[ 8]); W[ 4] = sm3E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
            r2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[ 5], W[ 9]); W[ 5] = sm3E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
            r2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[ 6], W[10]); W[ 6] = sm3E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
            r2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[ 7], W[11]); W[ 7] = sm3E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
            r2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[ 8], W[12]); W[ 8] = sm3E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
            r2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[ 9], W[13]); W[ 9] = sm3E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
            r2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[10], W[14]); W[10] = sm3E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
            r2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[11], W[15]); W[11] = sm3E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
            r2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[12], W[ 0]); W[12] = sm3E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
            r2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[13], W[ 1]); W[13] = sm3E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
            r2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[14], W[ 2]); W[14] = sm3E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
            r2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[15], W[ 3]); W[15] = sm3E(W[15], W[ 6], W[12], W[ 2], W[ 9]);
            r2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]); W[ 0] = sm3E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
            r2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]); W[ 1] = sm3E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
            r2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]); W[ 2] = sm3E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
            r2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]); W[ 3] = sm3E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
            r2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
            r2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
            r2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
            r2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);
            r2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
            r2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
            r2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
            r2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);
            r2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
            r2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
            r2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
            r2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);

            A = (m_digest[0] ^= A);
            B = (m_digest[1] ^= B);
            C = (m_digest[2] ^= C);
            D = (m_digest[3] ^= D);
            E = (m_digest[4] ^= E);
            F = (m_digest[5] ^= F);
            G = (m_digest[6] ^= G);
            H = (m_digest[7] ^= H);
        }
    }

    override void copyOut(ubyte* output)
    {
        foreach (size_t i; 0 .. 8)
            storeBigEndian(m_digest[i], output + 4 * i);
    }

    SecureVector!uint m_digest;
}

private:

uint p0(uint x) { return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17); }
uint p1(uint x) { return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23); }

uint sm3E(uint w0, uint w7, uint w13, uint w3, uint w10)
{
    return p1(w0 ^ w7 ^ rotateLeft(w13, 15)) ^ rotateLeft(w3, 7) ^ w10;
}

uint majority(uint x, uint y, uint z) { return (x & y) | ((x | y) & z); }
uint choose(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }

void r1(uint A, ref uint B, uint C, ref uint D, uint E, ref uint F, uint G, ref uint H,
        uint tj, uint wi, uint wj)
{
    const uint a12 = rotateLeft(A, 12);
    const uint ss1 = rotateLeft(a12 + E + tj, 7);
    const uint tt1 = (A ^ B ^ C) + D + (ss1 ^ a12) + (wi ^ wj);
    const uint tt2 = (E ^ F ^ G) + H + ss1 + wi;
    B = rotateLeft(B, 9);
    D = tt1;
    F = rotateLeft(F, 19);
    H = p0(tt2);
}

void r2(uint A, ref uint B, uint C, ref uint D, uint E, ref uint F, uint G, ref uint H,
        uint tj, uint wi, uint wj)
{
    const uint a12 = rotateLeft(A, 12);
    const uint ss1 = rotateLeft(a12 + E + tj, 7);
    const uint tt1 = majority(A, B, C) + D + (ss1 ^ a12) + (wi ^ wj);
    const uint tt2 = choose(E, F, G) + H + ss1 + wi;
    B = rotateLeft(B, 9);
    D = tt1;
    F = rotateLeft(F, 19);
    H = p0(tt2);
}
