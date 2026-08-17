/**
* Kuznyechik (GOST R 34.12-2015 / RFC 7801)
*
* Copyright:
* (C) 2023 Richard Huveneers
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.kuznyechik;

import botan.constants;
static if (BOTAN_HAS_KUZNYECHIK):

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.get_byte;
import botan.utils.mem_ops;
import botan.utils.types;
import std.algorithm : swap;

/**
* Kuznyechik. SCAN: "Kuznyechik". 128-bit block, 256-bit key.
*/
final class Kuznyechik : BlockCipherFixedParams!(16, 32), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        ensureTables();
        foreach (size_t n; 0 .. blocks)
        {
            ulong x1 = loadLittleEndian!ulong(input, 0);
            ulong x2 = loadLittleEndian!ulong(input, 1);

            x1 ^= m_rke[0]; x2 ^= m_rke[1]; ls(x1, x2);
            x1 ^= m_rke[2]; x2 ^= m_rke[3]; ls(x1, x2);
            x1 ^= m_rke[4]; x2 ^= m_rke[5]; ls(x1, x2);
            x1 ^= m_rke[6]; x2 ^= m_rke[7]; ls(x1, x2);
            x1 ^= m_rke[8]; x2 ^= m_rke[9]; ls(x1, x2);
            x1 ^= m_rke[10]; x2 ^= m_rke[11]; ls(x1, x2);
            x1 ^= m_rke[12]; x2 ^= m_rke[13]; ls(x1, x2);
            x1 ^= m_rke[14]; x2 ^= m_rke[15]; ls(x1, x2);
            x1 ^= m_rke[16]; x2 ^= m_rke[17]; ls(x1, x2);
            x1 ^= m_rke[18]; x2 ^= m_rke[19];

            storeLittleEndian(output, x1, x2);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        ensureTables();
        foreach (size_t n; 0 .. blocks)
        {
            ulong x1 = loadLittleEndian!ulong(input, 0);
            ulong x2 = loadLittleEndian!ulong(input, 1);

            ilss(x1, x2);
            x1 ^= m_rkd[0]; x2 ^= m_rkd[1]; ils(x1, x2);
            x1 ^= m_rkd[2]; x2 ^= m_rkd[3]; ils(x1, x2);
            x1 ^= m_rkd[4]; x2 ^= m_rkd[5]; ils(x1, x2);
            x1 ^= m_rkd[6]; x2 ^= m_rkd[7]; ils(x1, x2);
            x1 ^= m_rkd[8]; x2 ^= m_rkd[9]; ils(x1, x2);
            x1 ^= m_rkd[10]; x2 ^= m_rkd[11]; ils(x1, x2);
            x1 ^= m_rkd[12]; x2 ^= m_rkd[13]; ils(x1, x2);
            x1 ^= m_rkd[14]; x2 ^= m_rkd[15]; ils(x1, x2);
            x1 ^= m_rkd[16]; x2 ^= m_rkd[17];
            x1 = isi(x1);
            x2 = isi(x2);
            x1 ^= m_rkd[18]; x2 ^= m_rkd[19];

            storeLittleEndian(output, x1, x2);
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    override void clear() { zap(m_rke); zap(m_rkd); }
    @property string name() const { return "Kuznyechik"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new Kuznyechik; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }

protected:
    override void keySchedule(const(ubyte)* key, size_t)
    {
        ensureTables();
        ulong k0 = loadLittleEndian!ulong(key, 0);
        ulong k1 = loadLittleEndian!ulong(key, 1);
        ulong k2 = loadLittleEndian!ulong(key, 2);
        ulong k3 = loadLittleEndian!ulong(key, 3);

        m_rke = SecureVector!ulong(20);
        m_rke[0] = k0; m_rke[1] = k1; m_rke[2] = k2; m_rke[3] = k3;

        foreach (size_t i; 0 .. 4)
        {
            for (size_t r = 0; r != 8; r += 2)
            {
                ulong t0 = k0 ^ C[8 * i + r][0];
                ulong t1 = k1 ^ C[8 * i + r][1];
                const ulong t2 = k0;
                const ulong t3 = k1;
                ls(t0, t1);
                t0 ^= k2;
                t1 ^= k3;

                k0 = t0 ^ C[8 * i + r + 1][0];
                k1 = t1 ^ C[8 * i + r + 1][1];
                k2 = t0;
                k3 = t1;
                ls(k0, k1);
                k0 ^= t2;
                k1 ^= t3;
            }
            m_rke[4 * (i + 1) + 0] = k0;
            m_rke[4 * (i + 1) + 1] = k1;
            m_rke[4 * (i + 1) + 2] = k2;
            m_rke[4 * (i + 1) + 3] = k3;
        }

        m_rkd = SecureVector!ulong(20);
        foreach (size_t i; 0 .. 10)
        {
            ulong t0 = m_rke[2 * i + 0];
            ulong t1 = m_rke[2 * i + 1];
            if (i > 0)
                ilss(t0, t1);
            const size_t dest = 9 - i;
            m_rkd[2 * dest + 0] = t0;
            m_rkd[2 * dest + 1] = t1;
        }
    }

private:
    SecureVector!ulong m_rke;
    SecureVector!ulong m_rkd;
}

private:

__gshared immutable ubyte[256] S = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
];

__gshared immutable ubyte[256] IS = [
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145,
    100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63,
    224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183,
    200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213,
    195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47,
    155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30,
    162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107,
    81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60,
    123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54,
    219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173,
    55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250,
    150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88,
    247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4,
    235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128,
    144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38,
    18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116
];

__gshared immutable ubyte[16] LINEAR = [
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
];

__gshared immutable ulong[2][32] C = [
    [0xb87a486c7276a26e, 0x019484dd10bd275d], [0xb3f490d8e4ec87dc, 0x02ebcb7920b94eba],
    [0x0b8ed8b4969a25b2, 0x037f4fa4300469e7], [0xa52be3730b1bcd7b, 0x041555f240b19cb7],
    [0x1d51ab1f796d6f15, 0x0581d12f500cbbea], [0x16df73abeff74aa7, 0x06fe9e8b6008d20d],
    [0xaea53bc79d81e8c9, 0x076a1a5670b5f550], [0x895605e6163659f6, 0x082aaa2780a1fbad],
    [0x312c4d8a6440fb98, 0x09be2efa901cdcf0], [0x3aa2953ef2dade2a, 0x0ac1615ea018b517],
    [0x82d8dd5280ac7c44, 0x0b55e583b0a5924a], [0x2c7de6951d2d948d, 0x0c3fffd5c010671a],
    [0x9407aef96f5b36e3, 0x0dab7b08d0ad4047], [0x9f89764df9c11351, 0x0ed434ace0a929a0],
    [0x27f33e218bb7b13f, 0x0f40b071f0140efd], [0xd1ac0a0f2c6cb22f, 0x1054974ec3813599],
    [0x69d642635e1a1041, 0x11c01393d33c12c4], [0x62589ad7c88035f3, 0x12bf5c37e3387b23],
    [0xda22d2bbbaf6979d, 0x132bd8eaf3855c7e], [0x7487e97c27777f54, 0x1441c2bc8330a92e],
    [0xccfda1105501dd3a, 0x15d54661938d8e73], [0xc77379a4c39bf888, 0x16aa09c5a389e794],
    [0x7f0931c8b1ed5ae6, 0x173e8d18b334c0c9], [0x58fa0fe93a5aebd9, 0x187e3d694320ce34],
    [0xe0804785482c49b7, 0x19eab9b4539de969], [0xeb0e9f31deb66c05, 0x1a95f6106399808e],
    [0x5374d75dacc0ce6b, 0x1b0172cd7324a7d3], [0xfdd1ec9a314126a2, 0x1c6b689b03915283],
    [0x45aba4f6433784cc, 0x1dffec46132c75de], [0x4e257c42d5ada17e, 0x1e80a3e223281c39],
    [0xf65f342ea7db0310, 0x1f14273f33953b64], [0x619b141e58d8a75e, 0x20a8ed9c45c16af1]
];

__gshared ulong[8192] T;
__gshared ulong[8192] IT;
__gshared bool tables_ready;

ulong polyMulC3(ulong x, ubyte y)
{
    enum ulong lo_bit = ulong.max / 255;
    enum ulong mask = ~(lo_bit << 7);
    enum ulong poly = 0xC3;
    ulong r = 0;
    while (x && y)
    {
        if (y & 1)
            r ^= x;
        const ulong carry = ((x >> 7) & lo_bit) * poly;
        x = ((x & mask) << 1) ^ carry;
        y >>= 1;
    }
    return r;
}

ubyte polyMulC3b(ubyte x, ubyte y)
{
    ubyte r = 0;
    while (x && y)
    {
        if (y & 1)
            r ^= x;
        const ubyte carry = (x & 0x80) ? 0xC3 : 0;
        x = cast(ubyte)((x << 1) ^ carry);
        y >>= 1;
    }
    return r;
}

ubyte[256] lTable(bool forward)
{
    ubyte[256] L;
    foreach (i; 0 .. 16)
    {
        L[i] = LINEAR[i];
        if (i > 0)
            L[17 * i - 1] = 1;
    }
    if (!forward)
    {
        foreach (i; 0 .. 128)
            swap(L[i], L[255 - i]);
    }
    foreach (n; 0 .. 4)
    {
        ubyte[256] res;
        foreach (i; 0 .. 16)
            foreach (j; 0 .. 16)
                foreach (k; 0 .. 16)
                    res[16 * i + j] ^= polyMulC3b(L[16 * i + k], L[16 * k + j]);
        L = res;
    }
    return L;
}

void fillT(ref ulong[8192] dest, const ubyte[256] L, const ubyte[256] SB)
{
    foreach (i; 0 .. 16)
    {
        ulong L0 = 0, L1 = 0;
        foreach (j; 0 .. 8)
        {
            L0 |= cast(ulong) L[i + 16 * j] << (8 * j);
            L1 |= cast(ulong) L[i + 16 * (j + 8)] << (8 * j);
        }
        foreach (j; 0 .. 256)
        {
            const ubyte sj = SB[j];
            dest[512 * i + 2 * j] = polyMulC3(L0, sj);
            dest[512 * i + 2 * j + 1] = polyMulC3(L1, sj);
        }
    }
}

void ensureTables()
{
    if (tables_ready)
        return;
    auto L = lTable(true);
    auto IL = lTable(false);
    fillT(T, L, S);
    fillT(IT, IL, IS);
    tables_ready = true;
}

void ls(ref ulong x1, ref ulong x2)
{
    ulong t1 = 0, t2 = 0;
    foreach (i; 0 .. 16)
    {
        const ubyte x = get_byte(7 - (i % 8), (i < 8) ? x1 : x2);
        t1 ^= T[512 * i + 2 * x + 0];
        t2 ^= T[512 * i + 2 * x + 1];
    }
    x1 = t1;
    x2 = t2;
}

void ils(ref ulong x1, ref ulong x2)
{
    ulong t1 = 0, t2 = 0;
    foreach (i; 0 .. 16)
    {
        const ubyte x = get_byte(7 - (i % 8), (i < 8) ? x1 : x2);
        t1 ^= IT[512 * i + 2 * x + 0];
        t2 ^= IT[512 * i + 2 * x + 1];
    }
    x1 = t1;
    x2 = t2;
}

void ilss(ref ulong x1, ref ulong x2)
{
    ulong t1 = 0, t2 = 0;
    foreach (i; 0 .. 16)
    {
        const ubyte x = S[get_byte(7 - (i % 8), (i < 8) ? x1 : x2)];
        t1 ^= IT[512 * i + 2 * x + 0];
        t2 ^= IT[512 * i + 2 * x + 1];
    }
    x1 = t1;
    x2 = t2;
}

ulong isi(ulong val)
{
    ulong outv = 0;
    foreach (i; 0 .. 8)
    {
        outv <<= 8;
        outv |= IS[get_byte(i, val)];
    }
    return outv;
}
