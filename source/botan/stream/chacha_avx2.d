/**
* ChaCha AVX2 x8 (eight blocks in parallel)
*
* Copyright:
* (C) 2018 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.chacha_avx2;

import botan.constants;
static if (BOTAN_HAS_CHACHA && BOTAN_HAS_CHACHA_AVX2):

version (LDC):

import core.simd;
import ldc.simd;

private alias Y = int8;

private Y splat(uint x)
{
    Y v = cast(int) x;
    return v;
}

private Y rotl(int n)(Y x)
{
    return (x << n) | (x >>> (32 - n));
}

private Y unsignedLt(Y a, Y b)
{
    const bias = splat(0x80000000);
    return cast(Y)((b ^ bias) > (a ^ bias));
}

private Y unpacklo32(Y a, Y b)
{
    return shufflevector!(Y, 0, 8, 1, 9, 4, 12, 5, 13)(a, b);
}

private Y unpackhi32(Y a, Y b)
{
    return shufflevector!(Y, 2, 10, 3, 11, 6, 14, 7, 15)(a, b);
}

private Y unpacklo64(Y a, Y b)
{
    return shufflevector!(Y, 0, 1, 8, 9, 4, 5, 12, 13)(a, b);
}

private Y unpackhi64(Y a, Y b)
{
    return shufflevector!(Y, 2, 3, 10, 11, 6, 7, 14, 15)(a, b);
}

private void transpose4(ref Y B0, ref Y B1, ref Y B2, ref Y B3)
{
    auto T0 = unpacklo32(B0, B1);
    auto T1 = unpacklo32(B2, B3);
    auto T2 = unpackhi32(B0, B1);
    auto T3 = unpackhi32(B2, B3);
    B0 = unpacklo64(T0, T1);
    B1 = unpackhi64(T0, T1);
    B2 = unpacklo64(T2, T3);
    B3 = unpackhi64(T2, T3);
}

private void swapTops(ref Y A, ref Y B)
{
    auto T0 = shufflevector!(Y, 0, 1, 2, 3, 8, 9, 10, 11)(A, B);
    auto T1 = shufflevector!(Y, 4, 5, 6, 7, 12, 13, 14, 15)(A, B);
    A = T0;
    B = T1;
}

private void transpose8(ref Y B0, ref Y B1, ref Y B2, ref Y B3,
                        ref Y B4, ref Y B5, ref Y B6, ref Y B7)
{
    transpose4(B0, B1, B2, B3);
    transpose4(B4, B5, B6, B7);
    swapTops(B0, B4);
    swapTops(B1, B5);
    swapTops(B2, B6);
    swapTops(B3, B7);
}

private void storeLe(ubyte* p, Y v)
{
    storeUnaligned(cast(Y*) p, v);
}

private void zeroupper()
{
    version (D_InlineAsm_X86_64)
        asm pure nothrow @nogc { db 0xC5, 0xF8, 0x77; }
}

/// Eight ChaCha blocks; advances input[12]/[13] by 8.
package void chachaAvx2x8(ref ubyte[64 * 8] output, ref uint[16] input, size_t rounds)
{
    assert(rounds % 2 == 0, "Valid rounds");
    zeroupper();

    align(32) int[8] inc = [0, 1, 2, 3, 4, 5, 6, 7];
    auto CTR_LO = splat(input[12]) + *cast(Y*) inc.ptr;
    auto CTR_HI = splat(input[13]) - unsignedLt(CTR_LO, splat(input[12]));

    auto R00 = splat(input[0]);
    auto R01 = splat(input[1]);
    auto R02 = splat(input[2]);
    auto R03 = splat(input[3]);
    auto R04 = splat(input[4]);
    auto R05 = splat(input[5]);
    auto R06 = splat(input[6]);
    auto R07 = splat(input[7]);
    auto R08 = splat(input[8]);
    auto R09 = splat(input[9]);
    auto R10 = splat(input[10]);
    auto R11 = splat(input[11]);
    auto R12 = CTR_LO;
    auto R13 = CTR_HI;
    auto R14 = splat(input[14]);
    auto R15 = splat(input[15]);

    foreach (size_t _; 0 .. rounds / 2)
    {
        R00 = R00 + R04; R01 = R01 + R05; R02 = R02 + R06; R03 = R03 + R07;
        R12 = R12 ^ R00; R13 = R13 ^ R01; R14 = R14 ^ R02; R15 = R15 ^ R03;
        R12 = rotl!16(R12); R13 = rotl!16(R13); R14 = rotl!16(R14); R15 = rotl!16(R15);
        R08 = R08 + R12; R09 = R09 + R13; R10 = R10 + R14; R11 = R11 + R15;
        R04 = R04 ^ R08; R05 = R05 ^ R09; R06 = R06 ^ R10; R07 = R07 ^ R11;
        R04 = rotl!12(R04); R05 = rotl!12(R05); R06 = rotl!12(R06); R07 = rotl!12(R07);
        R00 = R00 + R04; R01 = R01 + R05; R02 = R02 + R06; R03 = R03 + R07;
        R12 = R12 ^ R00; R13 = R13 ^ R01; R14 = R14 ^ R02; R15 = R15 ^ R03;
        R12 = rotl!8(R12); R13 = rotl!8(R13); R14 = rotl!8(R14); R15 = rotl!8(R15);
        R08 = R08 + R12; R09 = R09 + R13; R10 = R10 + R14; R11 = R11 + R15;
        R04 = R04 ^ R08; R05 = R05 ^ R09; R06 = R06 ^ R10; R07 = R07 ^ R11;
        R04 = rotl!7(R04); R05 = rotl!7(R05); R06 = rotl!7(R06); R07 = rotl!7(R07);

        R00 = R00 + R05; R01 = R01 + R06; R02 = R02 + R07; R03 = R03 + R04;
        R15 = R15 ^ R00; R12 = R12 ^ R01; R13 = R13 ^ R02; R14 = R14 ^ R03;
        R15 = rotl!16(R15); R12 = rotl!16(R12); R13 = rotl!16(R13); R14 = rotl!16(R14);
        R10 = R10 + R15; R11 = R11 + R12; R08 = R08 + R13; R09 = R09 + R14;
        R05 = R05 ^ R10; R06 = R06 ^ R11; R07 = R07 ^ R08; R04 = R04 ^ R09;
        R05 = rotl!12(R05); R06 = rotl!12(R06); R07 = rotl!12(R07); R04 = rotl!12(R04);
        R00 = R00 + R05; R01 = R01 + R06; R02 = R02 + R07; R03 = R03 + R04;
        R15 = R15 ^ R00; R12 = R12 ^ R01; R13 = R13 ^ R02; R14 = R14 ^ R03;
        R15 = rotl!8(R15); R12 = rotl!8(R12); R13 = rotl!8(R13); R14 = rotl!8(R14);
        R10 = R10 + R15; R11 = R11 + R12; R08 = R08 + R13; R09 = R09 + R14;
        R05 = R05 ^ R10; R06 = R06 ^ R11; R07 = R07 ^ R08; R04 = R04 ^ R09;
        R05 = rotl!7(R05); R06 = rotl!7(R06); R07 = rotl!7(R07); R04 = rotl!7(R04);
    }

    R00 = R00 + splat(input[0]);
    R01 = R01 + splat(input[1]);
    R02 = R02 + splat(input[2]);
    R03 = R03 + splat(input[3]);
    R04 = R04 + splat(input[4]);
    R05 = R05 + splat(input[5]);
    R06 = R06 + splat(input[6]);
    R07 = R07 + splat(input[7]);
    R08 = R08 + splat(input[8]);
    R09 = R09 + splat(input[9]);
    R10 = R10 + splat(input[10]);
    R11 = R11 + splat(input[11]);
    R12 = R12 + CTR_LO;
    R13 = R13 + CTR_HI;
    R14 = R14 + splat(input[14]);
    R15 = R15 + splat(input[15]);

    transpose8(R00, R01, R02, R03, R04, R05, R06, R07);
    transpose8(R08, R09, R10, R11, R12, R13, R14, R15);

    storeLe(output.ptr + 32 * 0, R00);
    storeLe(output.ptr + 32 * 1, R08);
    storeLe(output.ptr + 32 * 2, R01);
    storeLe(output.ptr + 32 * 3, R09);
    storeLe(output.ptr + 32 * 4, R02);
    storeLe(output.ptr + 32 * 5, R10);
    storeLe(output.ptr + 32 * 6, R03);
    storeLe(output.ptr + 32 * 7, R11);
    storeLe(output.ptr + 32 * 8, R04);
    storeLe(output.ptr + 32 * 9, R12);
    storeLe(output.ptr + 32 * 10, R05);
    storeLe(output.ptr + 32 * 11, R13);
    storeLe(output.ptr + 32 * 12, R06);
    storeLe(output.ptr + 32 * 13, R14);
    storeLe(output.ptr + 32 * 14, R07);
    storeLe(output.ptr + 32 * 15, R15);

    zeroupper();

    input[12] += 8;
    if (input[12] < 8)
        input[13]++;
}

static if (BOTAN_HAS_TESTS && !SKIP_STREAM_CIPHER_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.stream.chacha;
    import botan.utils.cpuid;
    import botan.utils.types;

    auto gs = globalState();
    size_t fails;

    if (CPUID.hasAvx2())
    {
        void checkRounds(size_t rounds)
        {
            uint[16] st_p = [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0, 0, 0x03020100, 0x07060504
            ];
            uint[16] st_a = st_p;
            ubyte[64 * 8] out_p;
            ubyte[64 * 8] out_a;
            chachaPortableX4(*cast(ubyte[64 * 4]*) out_p.ptr, st_p, rounds);
            chachaPortableX4(*cast(ubyte[64 * 4]*)(out_p.ptr + 256), st_p, rounds);
            chachaAvx2x8(out_a, st_a, rounds);
            if (out_p[] != out_a[])
            {
                logError("ChaCha AVX2 mismatch rounds ", rounds);
                ++fails;
            }
            if (st_p[12] != st_a[12] || st_p[13] != st_a[13])
            {
                logError("ChaCha AVX2 counter mismatch rounds ", rounds);
                ++fails;
            }
        }

        checkRounds(8);
        checkRounds(12);
        checkRounds(20);

        fails += checkMemutilsRepeat("chacha_avx2", {
            uint[16] st;
            st[0] = 0x61707865;
            st[1] = 0x3320646e;
            st[2] = 0x79622d32;
            st[3] = 0x6b206574;
            ubyte[64 * 8] outp;
            chachaAvx2x8(outp, st, 20);
        });
        testReport("chacha_avx2", 3, fails);
    }
    else
        testReport("chacha_avx2", 0, fails);

    assert(fails == 0);
}
