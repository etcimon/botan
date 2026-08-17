/**
* SHACAL-2
*
* Copyright:
* (C) 2017,2020 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.shacal2;

import botan.constants;
static if (BOTAN_HAS_SHACAL2):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.mem_ops;
import botan.utils.types;

/**
* SHACAL-2 (32-byte block, 16–64 byte key, multiple of 4).
* SCAN: "SHACAL2".
*/
final class SHACAL2 : BlockCipherFixedParams!(32, 16, 64, 4), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadBigEndian!uint(input, 0);
            uint B = loadBigEndian!uint(input, 1);
            uint C = loadBigEndian!uint(input, 2);
            uint D = loadBigEndian!uint(input, 3);
            uint E = loadBigEndian!uint(input, 4);
            uint F = loadBigEndian!uint(input, 5);
            uint G = loadBigEndian!uint(input, 6);
            uint H = loadBigEndian!uint(input, 7);

            for (size_t r = 0; r != 64; r += 8)
            {
                shacal2Fwd(A, B, C, D, E, F, G, H, m_RK[r + 0]);
                shacal2Fwd(H, A, B, C, D, E, F, G, m_RK[r + 1]);
                shacal2Fwd(G, H, A, B, C, D, E, F, m_RK[r + 2]);
                shacal2Fwd(F, G, H, A, B, C, D, E, m_RK[r + 3]);
                shacal2Fwd(E, F, G, H, A, B, C, D, m_RK[r + 4]);
                shacal2Fwd(D, E, F, G, H, A, B, C, m_RK[r + 5]);
                shacal2Fwd(C, D, E, F, G, H, A, B, m_RK[r + 6]);
                shacal2Fwd(B, C, D, E, F, G, H, A, m_RK[r + 7]);
            }

            storeBigEndian(output, A, B, C, D, E, F, G, H);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint A = loadBigEndian!uint(input, 0);
            uint B = loadBigEndian!uint(input, 1);
            uint C = loadBigEndian!uint(input, 2);
            uint D = loadBigEndian!uint(input, 3);
            uint E = loadBigEndian!uint(input, 4);
            uint F = loadBigEndian!uint(input, 5);
            uint G = loadBigEndian!uint(input, 6);
            uint H = loadBigEndian!uint(input, 7);

            for (size_t r = 0; r != 64; r += 8)
            {
                shacal2Rev(B, C, D, E, F, G, H, A, m_RK[63 - r]);
                shacal2Rev(C, D, E, F, G, H, A, B, m_RK[62 - r]);
                shacal2Rev(D, E, F, G, H, A, B, C, m_RK[61 - r]);
                shacal2Rev(E, F, G, H, A, B, C, D, m_RK[60 - r]);
                shacal2Rev(F, G, H, A, B, C, D, E, m_RK[59 - r]);
                shacal2Rev(G, H, A, B, C, D, E, F, m_RK[58 - r]);
                shacal2Rev(H, A, B, C, D, E, F, G, m_RK[57 - r]);
                shacal2Rev(A, B, C, D, E, F, G, H, m_RK[56 - r]);
            }

            storeBigEndian(output, A, B, C, D, E, F, G, H);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear() { zap(m_RK); }
    @property string name() const { return "SHACAL2"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new SHACAL2; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        __gshared immutable uint[64] RC = [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        ];

        m_RK = SecureVector!uint(64);
        foreach (size_t i; 0 .. length / 4)
            m_RK[i] = loadBigEndian!uint(key, i);

        foreach (size_t i; 16 .. 64)
        {
            const uint s0 = sigma(m_RK[i - 15], 7, 18, 3);
            const uint s1 = sigma(m_RK[i - 2], 17, 19, 10);
            m_RK[i] = m_RK[i - 16] + s0 + m_RK[i - 7] + s1;
        }

        foreach (size_t i; 0 .. 64)
            m_RK[i] += RC[i];
    }

private:
    SecureVector!uint m_RK;
}

private:

uint rho(uint x, uint r1, uint r2, uint r3)
{
    return rotateRight(x, r1) ^ rotateRight(x, r2) ^ rotateRight(x, r3);
}

uint sigma(uint x, uint r1, uint r2, uint sh)
{
    return rotateRight(x, r1) ^ rotateRight(x, r2) ^ (x >> sh);
}

uint choose(uint x, uint y, uint z)
{
    return (x & y) ^ (~x & z);
}

uint majority(uint x, uint y, uint z)
{
    return (x & y) | ((x | y) & z);
}

void shacal2Fwd(uint A, uint B, uint C, ref uint D, uint E, uint F, uint G, ref uint H, uint RK)
{
    H += rho(E, 6, 11, 25) + choose(E, F, G) + RK;
    D += H;
    H += rho(A, 2, 13, 22) + majority(A, B, C);
}

void shacal2Rev(uint A, uint B, uint C, ref uint D, uint E, uint F, uint G, ref uint H, uint RK)
{
    H -= rho(A, 2, 13, 22) + majority(A, B, C);
    D -= H;
    H -= rho(E, 6, 11, 25) + choose(E, F, G) + RK;
}
