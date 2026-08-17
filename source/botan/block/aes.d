/**
* AES — portable constant-time bitslice (C++ Botan 3.14)
*
* Native word size: 32-bit processes 2 blocks, 64-bit processes 4.
* Hardware AES-NI / SSSE3 stay in the ISA engines.
*
* Copyright:
* (C) 1999-2010,2015,2017,2018,2020,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.aes;

import botan.constants;
static if (BOTAN_HAS_AES):

import botan.block.block_cipher;
import botan.algo_base.sym_algo;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import botan.utils.mem_ops;

version (D_LP64)
    alias AesBsWord = ulong;
else
    alias AesBsWord = uint;

enum size_t AES_BITSLICED_BLOCKS = 8 * AesBsWord.sizeof / 16;

/**
* AES-128
*/
class AES128 : BlockCipherFixedParams!(16, 16), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesEncryptN(input, output, blocks, m_EK);
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesDecryptN(input, output, blocks, m_DK);
    }

    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    override @property string name() const { return "AES-128"; }
    override @property size_t parallelism() const { return AES_BITSLICED_BLOCKS; }
    override BlockCipher clone() const { return new AES128; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        aesKeySchedule(key, length, m_EK, m_DK);
    }

    SecureVector!uint m_EK, m_DK;
}

/**
* AES-192
*/
final class AES192 : BlockCipherFixedParams!(16, 24), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesEncryptN(input, output, blocks, m_EK);
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesDecryptN(input, output, blocks, m_DK);
    }

    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    override @property string name() const { return "AES-192"; }
    override @property size_t parallelism() const { return AES_BITSLICED_BLOCKS; }
    override BlockCipher clone() const { return new AES192; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        aesKeySchedule(key, length, m_EK, m_DK);
    }

    SecureVector!uint m_EK, m_DK;
}

/**
* AES-256
*/
final class AES256 : BlockCipherFixedParams!(16, 32), BlockCipher, SymmetricAlgorithm
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesEncryptN(input, output, blocks, m_EK);
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        aesDecryptN(input, output, blocks, m_DK);
    }

    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    override @property string name() const { return "AES-256"; }
    override @property size_t parallelism() const { return AES_BITSLICED_BLOCKS; }
    override BlockCipher clone() const { return new AES256; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        aesKeySchedule(key, length, m_EK, m_DK);
    }

    SecureVector!uint m_EK, m_DK;
}

private:

AesBsWord rep32(uint x)
{
    static if (is(AesBsWord == uint))
        return x;
    else
        return (cast(AesBsWord) x << 32) | x;
}

AesBsWord columnRotr(size_t N)(AesBsWord x)
{
    static if (is(AesBsWord == uint))
        return rotateRight(x, N);
    else
    {
        enum AesBsWord mask = (cast(AesBsWord)(0xFFFFFFFFu >> N) << 32) | (0xFFFFFFFFu >> N);
        return ((x >> N) & mask) | ((x << (32 - N)) & ~mask);
    }
}

AesBsWord bitPermuteStep(AesBsWord x, AesBsWord mask, size_t shift)
{
    const AesBsWord swap = ((x >> shift) ^ x) & mask;
    return (x ^ swap) ^ (swap << shift);
}

void swapBits(ref AesBsWord x, ref AesBsWord y, AesBsWord mask, size_t shift)
{
    const AesBsWord swap = ((x >> shift) ^ y) & mask;
    x ^= swap << shift;
    y ^= swap;
}

void aesSbox(ref AesBsWord[8] V)
{
    const U0 = V[0];
    const U1 = V[1];
    const U2 = V[2];
    const U3 = V[3];
    const U4 = V[4];
    const U5 = V[5];
    const U6 = V[6];
    const U7 = V[7];

    const y14 = U3 ^ U5;
    const y13 = U0 ^ U6;
    const y9 = U0 ^ U3;
    const y8 = U0 ^ U5;
    const t0 = U1 ^ U2;
    const y1 = t0 ^ U7;
    const y4 = y1 ^ U3;
    const y12 = y13 ^ y14;
    const y2 = y1 ^ U0;
    const y5 = y1 ^ U6;
    const y3 = y5 ^ y8;
    const t1 = U4 ^ y12;
    const y15 = t1 ^ U5;
    const y20 = t1 ^ U1;
    const y6 = y15 ^ U7;
    const y10 = y15 ^ t0;
    const y11 = y20 ^ y9;
    const y7 = U7 ^ y11;
    const y17 = y10 ^ y11;
    const y19 = y10 ^ y8;
    const y16 = t0 ^ y11;
    const y21 = y13 ^ y16;
    const y18 = U0 ^ y16;
    const t2 = y12 & y15;
    const t3 = y3 & y6;
    const t4 = t3 ^ t2;
    const t5 = y4 & U7;
    const t6 = t5 ^ t2;
    const t7 = y13 & y16;
    const t8 = y5 & y1;
    const t9 = t8 ^ t7;
    const t10 = y2 & y7;
    const t11 = t10 ^ t7;
    const t12 = y9 & y11;
    const t13 = y14 & y17;
    const t14 = t13 ^ t12;
    const t15 = y8 & y10;
    const t16 = t15 ^ t12;
    const t17 = t4 ^ y20;
    const t18 = t6 ^ t16;
    const t19 = t9 ^ t14;
    const t20 = t11 ^ t16;
    const t21 = t17 ^ t14;
    const t22 = t18 ^ y19;
    const t23 = t19 ^ y21;
    const t24 = t20 ^ y18;
    const t25 = t21 ^ t22;
    const t26 = t21 & t23;
    const t27 = t24 ^ t26;
    const t28 = t25 & t27;
    const t29 = t28 ^ t22;
    const t30 = t23 ^ t24;
    const t31 = t22 ^ t26;
    const t32 = t31 & t30;
    const t33 = t32 ^ t24;
    const t34 = t23 ^ t33;
    const t35 = t27 ^ t33;
    const t36 = t24 & t35;
    const t37 = t36 ^ t34;
    const t38 = t27 ^ t36;
    const t39 = t29 & t38;
    const t40 = t25 ^ t39;
    const t41 = t40 ^ t37;
    const t42 = t29 ^ t33;
    const t43 = t29 ^ t40;
    const t44 = t33 ^ t37;
    const t45 = t42 ^ t41;
    const z0 = t44 & y15;
    const z1 = t37 & y6;
    const z2 = t33 & U7;
    const z3 = t43 & y16;
    const z4 = t40 & y1;
    const z5 = t29 & y7;
    const z6 = t42 & y11;
    const z7 = t45 & y17;
    const z8 = t41 & y10;
    const z9 = t44 & y12;
    const z10 = t37 & y3;
    const z11 = t33 & y4;
    const z12 = t43 & y13;
    const z13 = t40 & y5;
    const z14 = t29 & y2;
    const z15 = t42 & y9;
    const z16 = t45 & y14;
    const z17 = t41 & y8;
    const tc1 = z15 ^ z16;
    const tc2 = z10 ^ tc1;
    const tc3 = z9 ^ tc2;
    const tc4 = z0 ^ z2;
    const tc5 = z1 ^ z0;
    const tc6 = z3 ^ z4;
    const tc7 = z12 ^ tc4;
    const tc8 = z7 ^ tc6;
    const tc9 = z8 ^ tc7;
    const tc10 = tc8 ^ tc9;
    const tc11 = tc6 ^ tc5;
    const tc12 = z3 ^ z5;
    const tc13 = z13 ^ tc1;
    const tc14 = tc4 ^ tc12;
    const S3 = tc3 ^ tc11;
    const tc16 = z6 ^ tc8;
    const tc17 = z14 ^ tc10;
    const tc18 = ~tc13 ^ tc14;
    const S7 = z12 ^ tc18;
    const tc20 = z15 ^ tc16;
    const tc21 = tc2 ^ z11;
    const S0 = tc3 ^ tc16;
    const S6 = tc10 ^ tc18;
    const S4 = tc14 ^ S3;
    const S1 = ~(S3 ^ tc16);
    const tc26 = tc17 ^ tc20;
    const S2 = ~(tc26 ^ z17);
    const S5 = tc21 ^ tc17;

    V[0] = S0;
    V[1] = S1;
    V[2] = S2;
    V[3] = S3;
    V[4] = S4;
    V[5] = S5;
    V[6] = S6;
    V[7] = S7;
}

void aesInvSbox(ref AesBsWord[8] V)
{
    const U0 = V[0];
    const U1 = V[1];
    const U2 = V[2];
    const U3 = V[3];
    const U4 = V[4];
    const U5 = V[5];
    const U6 = V[6];
    const U7 = V[7];

    const Y0 = U0 ^ U3;
    const Y2 = ~(U1 ^ U3);
    const Y4 = U0 ^ Y2;
    const RTL0 = U6 ^ U7;
    const Y1 = Y2 ^ RTL0;
    const Y7 = ~(U2 ^ Y1);
    const RTL1 = U3 ^ U4;
    const Y6 = ~(U7 ^ RTL1);
    const Y3 = Y1 ^ RTL1;
    const RTL2 = ~(U0 ^ U2);
    const Y5 = U5 ^ RTL2;
    const sa1 = Y0 ^ Y2;
    const sa0 = Y1 ^ Y3;
    const sb1 = Y4 ^ Y6;
    const sb0 = Y5 ^ Y7;
    const ah = Y0 ^ Y1;
    const al = Y2 ^ Y3;
    const aa = sa0 ^ sa1;
    const bh = Y4 ^ Y5;
    const bl = Y6 ^ Y7;
    const bb = sb0 ^ sb1;
    const ab20 = sa0 ^ sb0;
    const ab22 = al ^ bl;
    const ab23 = Y3 ^ Y7;
    const ab21 = sa1 ^ sb1;
    const abcd1 = ah & bh;
    const rr1 = Y0 & Y4;
    const ph11 = ab20 ^ abcd1;
    const t01 = Y1 & Y5;
    const ph01 = t01 ^ abcd1;
    const abcd2 = al & bl;
    const r1 = Y2 & Y6;
    const pl11 = ab22 ^ abcd2;
    const r2 = Y3 & Y7;
    const pl01 = r2 ^ abcd2;
    const r3 = sa0 & sb0;
    const vr1 = aa & bb;
    const pr1 = vr1 ^ r3;
    const wr1 = sa1 & sb1;
    const qr1 = wr1 ^ r3;
    const ab0 = ph11 ^ rr1;
    const ab1 = ph01 ^ ab21;
    const ab2 = pl11 ^ r1;
    const ab3 = pl01 ^ qr1;
    const cp1 = ab0 ^ pr1;
    const cp2 = ab1 ^ qr1;
    const cp3 = ab2 ^ pr1;
    const cp4 = ab3 ^ ab23;
    const tinv1 = cp3 ^ cp4;
    const tinv2 = cp3 & cp1;
    const tinv3 = cp2 ^ tinv2;
    const tinv4 = cp1 ^ cp2;
    const tinv5 = cp4 ^ tinv2;
    const tinv6 = tinv5 & tinv4;
    const tinv7 = tinv3 & tinv1;
    const d2 = cp4 ^ tinv7;
    const d0 = cp2 ^ tinv6;
    const tinv8 = cp1 & cp4;
    const tinv9 = tinv4 & tinv8;
    const tinv10 = tinv4 ^ tinv2;
    const d1 = tinv9 ^ tinv10;
    const tinv11 = cp2 & cp3;
    const tinv12 = tinv1 & tinv11;
    const tinv13 = tinv1 ^ tinv2;
    const d3 = tinv12 ^ tinv13;
    const sd1 = d1 ^ d3;
    const sd0 = d0 ^ d2;
    const dl = d0 ^ d1;
    const dh = d2 ^ d3;
    const dd = sd0 ^ sd1;
    const abcd3 = dh & bh;
    const rr2 = d3 & Y4;
    const t02 = d2 & Y5;
    const abcd4 = dl & bl;
    const r4 = d1 & Y6;
    const r5 = d0 & Y7;
    const r6 = sd0 & sb0;
    const vr2 = dd & bb;
    const wr2 = sd1 & sb1;
    const abcd5 = dh & ah;
    const r7 = d3 & Y0;
    const r8 = d2 & Y1;
    const abcd6 = dl & al;
    const r9 = d1 & Y2;
    const r10 = d0 & Y3;
    const r11 = sd0 & sa0;
    const vr3 = dd & aa;
    const wr3 = sd1 & sa1;
    const ph12 = rr2 ^ abcd3;
    const ph02 = t02 ^ abcd3;
    const pl12 = r4 ^ abcd4;
    const pl02 = r5 ^ abcd4;
    const pr2 = vr2 ^ r6;
    const qr2 = wr2 ^ r6;
    const p0 = ph12 ^ pr2;
    const p1 = ph02 ^ qr2;
    const p2 = pl12 ^ pr2;
    const p3 = pl02 ^ qr2;
    const ph13 = r7 ^ abcd5;
    const ph03 = r8 ^ abcd5;
    const pl13 = r9 ^ abcd6;
    const pl03 = r10 ^ abcd6;
    const pr3 = vr3 ^ r11;
    const qr3 = wr3 ^ r11;
    const p4 = ph13 ^ pr3;
    const S7 = ph03 ^ qr3;
    const p6 = pl13 ^ pr3;
    const p7 = pl03 ^ qr3;
    const S3 = p1 ^ p6;
    const S6 = p2 ^ p6;
    const S0 = p3 ^ p6;
    const X11 = p0 ^ p2;
    const S5 = S0 ^ X11;
    const X13 = p4 ^ p7;
    const X14 = X11 ^ X13;
    const S1 = S3 ^ X14;
    const X16 = p1 ^ S7;
    const S2 = X14 ^ X16;
    const X18 = p0 ^ p4;
    const X19 = S5 ^ X16;
    const S4 = X18 ^ X19;

    V[0] = S0;
    V[1] = S1;
    V[2] = S2;
    V[3] = S3;
    V[4] = S4;
    V[5] = S5;
    V[6] = S6;
    V[7] = S7;
}

void bitTranspose(ref AesBsWord[8] B)
{
    swapBits(B[1], B[0], rep32(0x55555555), 1);
    swapBits(B[3], B[2], rep32(0x55555555), 1);
    swapBits(B[5], B[4], rep32(0x55555555), 1);
    swapBits(B[7], B[6], rep32(0x55555555), 1);

    swapBits(B[2], B[0], rep32(0x33333333), 2);
    swapBits(B[3], B[1], rep32(0x33333333), 2);
    swapBits(B[6], B[4], rep32(0x33333333), 2);
    swapBits(B[7], B[5], rep32(0x33333333), 2);

    swapBits(B[4], B[0], rep32(0x0F0F0F0F), 4);
    swapBits(B[5], B[1], rep32(0x0F0F0F0F), 4);
    swapBits(B[6], B[2], rep32(0x0F0F0F0F), 4);
    swapBits(B[7], B[3], rep32(0x0F0F0F0F), 4);
}

void ksExpand(AesBsWord* B, const(uint)* K, size_t r)
{
    foreach (i; 0 .. 4)
        B[i] = rep32(K[r + i]);

    swapBits(B[1], B[0], rep32(0x55555555), 1);
    swapBits(B[3], B[2], rep32(0x55555555), 1);

    swapBits(B[2], B[0], rep32(0x33333333), 2);
    swapBits(B[3], B[1], rep32(0x33333333), 2);

    B[4] = B[0];
    B[5] = B[1];
    B[6] = B[2];
    B[7] = B[3];

    swapBits(B[4], B[0], rep32(0x0F0F0F0F), 4);
    swapBits(B[5], B[1], rep32(0x0F0F0F0F), 4);
    swapBits(B[6], B[2], rep32(0x0F0F0F0F), 4);
    swapBits(B[7], B[3], rep32(0x0F0F0F0F), 4);
}

void shiftRows(ref AesBsWord[8] B)
{
    foreach (i; 0 .. 8)
    {
        B[i] = bitPermuteStep(B[i], rep32(0x00223311), 2);
        B[i] = bitPermuteStep(B[i], rep32(0x00550055), 1);
    }
}

void invShiftRows(ref AesBsWord[8] B)
{
    foreach (i; 0 .. 8)
    {
        B[i] = bitPermuteStep(B[i], rep32(0x00550055), 1);
        B[i] = bitPermuteStep(B[i], rep32(0x00223311), 2);
    }
}

void mixColumns(ref AesBsWord[8] B)
{
    AesBsWord[8] X2 = [
        B[1],
        B[2],
        B[3],
        B[4] ^ B[0],
        B[5] ^ B[0],
        B[6],
        B[7] ^ B[0],
        B[0],
    ];
    foreach (i; 0 .. 8)
    {
        const X3 = B[i] ^ X2[i];
        B[i] = X2[i] ^ columnRotr!8(B[i]) ^ columnRotr!16(B[i]) ^ columnRotr!24(X3);
    }
}

void invMixColumns(ref AesBsWord[8] B)
{
    AesBsWord[8] X4 = [
        B[2],
        B[3],
        B[4] ^ B[0],
        B[5] ^ B[0] ^ B[1],
        B[6] ^ B[1],
        B[7] ^ B[0],
        B[0] ^ B[1],
        B[1],
    ];
    foreach (i; 0 .. 8)
    {
        const X5 = X4[i] ^ B[i];
        B[i] = X5 ^ columnRotr!16(X4[i]);
    }
    mixColumns(B);
}

void bsLoad(ref AesBsWord[8] B, const(ubyte)* inp, size_t nBlocks)
{
    static if (is(AesBsWord == uint))
        loadBigEndian(B.ptr, inp, nBlocks * 4);
    else
    {
        uint[16] T;
        loadBigEndian(T.ptr, inp, nBlocks * 4);
        foreach (i; 0 .. 8)
            B[i] = (cast(AesBsWord) T[i] << 32) | T[i + 8];
    }
}

void bsStore(ubyte* outp, const ref AesBsWord[8] B, size_t nBlocks)
{
    static if (is(AesBsWord == uint))
    {
        foreach (i; 0 .. nBlocks * 4)
            storeBigEndian(B[i], outp + 4 * i);
    }
    else
    {
        uint[16] T;
        foreach (i; 0 .. 8)
        {
            T[i] = cast(uint)(B[i] >> 32);
            T[i + 8] = cast(uint) B[i];
        }
        foreach (i; 0 .. nBlocks * 4)
            storeBigEndian(T[i], outp + 4 * i);
    }
}

void aesEncryptN(const(ubyte)* inp, ubyte* outp, size_t blocks, const ref SecureVector!uint EK)
{
    assert(EK.length == 44 || EK.length == 52 || EK.length == 60, "Key was set");
    const rounds = (EK.length - 4) / 4;

    AesBsWord[13 * 8] KS;
    foreach (i; 0 .. rounds - 1)
        ksExpand(&KS[8 * i], EK.ptr, 4 * i + 4);

    while (blocks > 0)
    {
        const thisLoop = blocks < AES_BITSLICED_BLOCKS ? blocks : AES_BITSLICED_BLOCKS;
        AesBsWord[8] B;
        bsLoad(B, inp, thisLoop);

        foreach (i; 0 .. 8)
            B[i] ^= rep32(EK[i % 4]);

        bitTranspose(B);

        foreach (r; 0 .. rounds - 1)
        {
            aesSbox(B);
            shiftRows(B);
            mixColumns(B);
            foreach (i; 0 .. 8)
                B[i] ^= KS[8 * r + i];
        }

        aesSbox(B);
        shiftRows(B);
        bitTranspose(B);

        foreach (i; 0 .. 8)
            B[i] ^= rep32(EK[4 * rounds + i % 4]);

        bsStore(outp, B, thisLoop);
        inp += thisLoop * 16;
        outp += thisLoop * 16;
        blocks -= thisLoop;
    }
}

void aesDecryptN(const(ubyte)* inp, ubyte* outp, size_t blocks, const ref SecureVector!uint DK)
{
    assert(DK.length == 44 || DK.length == 52 || DK.length == 60, "Key was set");
    const rounds = (DK.length - 4) / 4;

    AesBsWord[13 * 8] KS;
    foreach (i; 0 .. rounds - 1)
        ksExpand(&KS[8 * i], DK.ptr, 4 * i + 4);

    while (blocks > 0)
    {
        const thisLoop = blocks < AES_BITSLICED_BLOCKS ? blocks : AES_BITSLICED_BLOCKS;
        AesBsWord[8] B;
        bsLoad(B, inp, thisLoop);

        foreach (i; 0 .. 8)
            B[i] ^= rep32(DK[i % 4]);

        bitTranspose(B);

        foreach (r; 0 .. rounds - 1)
        {
            aesInvSbox(B);
            invShiftRows(B);
            invMixColumns(B);
            foreach (i; 0 .. 8)
                B[i] ^= KS[8 * r + i];
        }

        aesInvSbox(B);
        invShiftRows(B);
        bitTranspose(B);

        foreach (i; 0 .. 8)
            B[i] ^= rep32(DK[4 * rounds + i % 4]);

        bsStore(outp, B, thisLoop);
        inp += thisLoop * 16;
        outp += thisLoop * 16;
        blocks -= thisLoop;
    }
}

uint xtime32(uint s)
{
    enum uint loBit = 0x01010101;
    enum uint mask = 0x7F7F7F7F;
    enum uint poly = 0x1B;
    return ((s & mask) << 1) ^ (((s >> 7) & loBit) * poly);
}

uint invMixColumn(uint s1)
{
    const s2 = xtime32(s1);
    const s4 = xtime32(s2);
    const s8 = xtime32(s4);
    const s9 = s8 ^ s1;
    const s11 = s9 ^ s2;
    const s13 = s9 ^ s4;
    const s14 = s8 ^ s4 ^ s2;
    return s14 ^ rotateRight(s9, 8) ^ rotateRight(s13, 16) ^ rotateRight(s11, 24);
}

void invMixColumnX4(uint* x)
{
    x[0] = invMixColumn(x[0]);
    x[1] = invMixColumn(x[1]);
    x[2] = invMixColumn(x[2]);
    x[3] = invMixColumn(x[3]);
}

uint seWord(uint x)
{
    AesBsWord[8] I;
    foreach (i; 0 .. 8)
        I[i] = (x >> (7 - i)) & 0x01010101;
    aesSbox(I);
    x = 0;
    foreach (i; 0 .. 8)
        x |= cast(uint)((I[i] & 0x01010101) << (7 - i));
    return x;
}

void aesKeySchedule(const(ubyte)* key, size_t length,
                    ref SecureVector!uint EK, ref SecureVector!uint DK)
{
    immutable uint[10] RC = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    ];
    const X = length / 4;
    assert(X == 4 || X == 6 || X == 8);
    const rounds = (length / 4) + 6;
    const ksLen = length + 28;
    EK.resize(ksLen);
    DK.resize(ksLen);

    foreach (i; 0 .. X)
        EK[i] = loadBigEndian!uint(key, i);

    for (size_t i = X; i < 4 * (rounds + 1); i += X)
    {
        EK[i] = EK[i - X] ^ RC[(i - X) / X] ^ rotateLeft(seWord(EK[i - 1]), 8);
        foreach (j; 1 .. X)
        {
            if (i + j >= EK.length)
                break;
            EK[i + j] = EK[i + j - X];
            if (X == 8 && j == 4)
                EK[i + j] ^= seWord(EK[i + j - 1]);
            else
                EK[i + j] ^= EK[i + j - 1];
        }
    }

    for (size_t i = 0; i != 4 * (rounds + 1); i += 4)
    {
        DK[i] = EK[4 * rounds - i];
        DK[i + 1] = EK[4 * rounds - i + 1];
        DK[i + 2] = EK[4 * rounds - i + 2];
        DK[i + 3] = EK[4 * rounds - i + 3];
    }

    for (size_t i = 4; i != 4 * rounds; i += 4)
        invMixColumnX4(&DK[i]);
}
