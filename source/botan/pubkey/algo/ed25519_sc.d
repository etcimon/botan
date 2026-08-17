/**
* Ed25519 scalar arithmetic (mod L)
*
* Copyright:
* (C) 2017 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ed25519_sc;

import botan.constants;
static if (BOTAN_HAS_ED25519):

import botan.pubkey.algo.ed25519_fe;

void scReduce(ubyte* s)
{
    enum uint MASK = 0x1fffff;
    long s0 = MASK & load3(s);
    long s1 = MASK & (load4(s + 2) >> 5);
    long s2 = MASK & (load3(s + 5) >> 2);
    long s3 = MASK & (load4(s + 7) >> 7);
    long s4 = MASK & (load4(s + 10) >> 4);
    long s5 = MASK & (load3(s + 13) >> 1);
    long s6 = MASK & (load4(s + 15) >> 6);
    long s7 = MASK & (load3(s + 18) >> 3);
    long s8 = MASK & load3(s + 21);
    long s9 = MASK & (load4(s + 23) >> 5);
    long s10 = MASK & (load3(s + 26) >> 2);
    long s11 = MASK & (load4(s + 28) >> 7);
    long s12 = MASK & (load4(s + 31) >> 4);
    long s13 = MASK & (load3(s + 34) >> 1);
    long s14 = MASK & (load4(s + 36) >> 6);
    long s15 = MASK & (load3(s + 39) >> 3);
    long s16 = MASK & load3(s + 42);
    long s17 = MASK & (load4(s + 44) >> 5);
    long s18 = MASK & (load3(s + 47) >> 2);
    long s19 = MASK & (load4(s + 49) >> 7);
    long s20 = MASK & (load4(s + 52) >> 4);
    long s21 = MASK & (load3(s + 55) >> 1);
    long s22 = MASK & (load4(s + 57) >> 6);
    long s23 = (load4(s + 60) >> 3);

    redcMul(s11, s12, s13, s14, s15, s16, s23);
    redcMul(s10, s11, s12, s13, s14, s15, s22);
    redcMul(s9, s10, s11, s12, s13, s14, s21);
    redcMul(s8, s9, s10, s11, s12, s13, s20);
    redcMul(s7, s8, s9, s10, s11, s12, s19);
    redcMul(s6, s7, s8, s9, s10, s11, s18);

    feCarry!21(s6, s7);
    feCarry!21(s8, s9);
    feCarry!21(s10, s11);
    feCarry!21(s12, s13);
    feCarry!21(s14, s15);
    feCarry!21(s16, s17);

    feCarry!21(s7, s8);
    feCarry!21(s9, s10);
    feCarry!21(s11, s12);
    feCarry!21(s13, s14);
    feCarry!21(s15, s16);

    redcMul(s5, s6, s7, s8, s9, s10, s17);
    redcMul(s4, s5, s6, s7, s8, s9, s16);
    redcMul(s3, s4, s5, s6, s7, s8, s15);
    redcMul(s2, s3, s4, s5, s6, s7, s14);
    redcMul(s1, s2, s3, s4, s5, s6, s13);
    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry!21(s0, s1);
    feCarry!21(s2, s3);
    feCarry!21(s4, s5);
    feCarry!21(s6, s7);
    feCarry!21(s8, s9);
    feCarry!21(s10, s11);

    feCarry!21(s1, s2);
    feCarry!21(s3, s4);
    feCarry!21(s5, s6);
    feCarry!21(s7, s8);
    feCarry!21(s9, s10);
    feCarry!21(s11, s12);

    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry0!21(s0, s1);
    feCarry0!21(s1, s2);
    feCarry0!21(s2, s3);
    feCarry0!21(s3, s4);
    feCarry0!21(s4, s5);
    feCarry0!21(s5, s6);
    feCarry0!21(s6, s7);
    feCarry0!21(s7, s8);
    feCarry0!21(s8, s9);
    feCarry0!21(s9, s10);
    feCarry0!21(s10, s11);
    feCarry0!21(s11, s12);

    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry0!21(s0, s1);
    feCarry0!21(s1, s2);
    feCarry0!21(s2, s3);
    feCarry0!21(s3, s4);
    feCarry0!21(s4, s5);
    feCarry0!21(s5, s6);
    feCarry0!21(s6, s7);
    feCarry0!21(s7, s8);
    feCarry0!21(s8, s9);
    feCarry0!21(s9, s10);
    feCarry0!21(s10, s11);
    feCarry0!21(s11, s12);

    packScalar(s, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11);
}

void scMuladd(ubyte* s, const(ubyte)* a, const(ubyte)* b, const(ubyte)* c)
{
    enum int MASK = 0x1fffff;
    const long a0 = MASK & load3(a);
    const long a1 = MASK & (load4(a + 2) >> 5);
    const long a2 = MASK & (load3(a + 5) >> 2);
    const long a3 = MASK & (load4(a + 7) >> 7);
    const long a4 = MASK & (load4(a + 10) >> 4);
    const long a5 = MASK & (load3(a + 13) >> 1);
    const long a6 = MASK & (load4(a + 15) >> 6);
    const long a7 = MASK & (load3(a + 18) >> 3);
    const long a8 = MASK & load3(a + 21);
    const long a9 = MASK & (load4(a + 23) >> 5);
    const long a10 = MASK & (load3(a + 26) >> 2);
    const long a11 = (load4(a + 28) >> 7);
    const long b0 = MASK & load3(b);
    const long b1 = MASK & (load4(b + 2) >> 5);
    const long b2 = MASK & (load3(b + 5) >> 2);
    const long b3 = MASK & (load4(b + 7) >> 7);
    const long b4 = MASK & (load4(b + 10) >> 4);
    const long b5 = MASK & (load3(b + 13) >> 1);
    const long b6 = MASK & (load4(b + 15) >> 6);
    const long b7 = MASK & (load3(b + 18) >> 3);
    const long b8 = MASK & load3(b + 21);
    const long b9 = MASK & (load4(b + 23) >> 5);
    const long b10 = MASK & (load3(b + 26) >> 2);
    const long b11 = (load4(b + 28) >> 7);
    const long c0 = MASK & load3(c);
    const long c1 = MASK & (load4(c + 2) >> 5);
    const long c2 = MASK & (load3(c + 5) >> 2);
    const long c3 = MASK & (load4(c + 7) >> 7);
    const long c4 = MASK & (load4(c + 10) >> 4);
    const long c5 = MASK & (load3(c + 13) >> 1);
    const long c6 = MASK & (load4(c + 15) >> 6);
    const long c7 = MASK & (load3(c + 18) >> 3);
    const long c8 = MASK & load3(c + 21);
    const long c9 = MASK & (load4(c + 23) >> 5);
    const long c10 = MASK & (load3(c + 26) >> 2);
    const long c11 = (load4(c + 28) >> 7);

    long s0 = c0 + a0 * b0;
    long s1 = c1 + a0 * b1 + a1 * b0;
    long s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    long s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    long s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    long s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    long s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    long s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    long s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    long s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
    long s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    long s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    long s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
    long s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
    long s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    long s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    long s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    long s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    long s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    long s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    long s20 = a9 * b11 + a10 * b10 + a11 * b9;
    long s21 = a10 * b11 + a11 * b10;
    long s22 = a11 * b11;
    long s23 = 0;

    feCarry!21(s0, s1);
    feCarry!21(s2, s3);
    feCarry!21(s4, s5);
    feCarry!21(s6, s7);
    feCarry!21(s8, s9);
    feCarry!21(s10, s11);
    feCarry!21(s12, s13);
    feCarry!21(s14, s15);
    feCarry!21(s16, s17);
    feCarry!21(s18, s19);
    feCarry!21(s20, s21);
    feCarry!21(s22, s23);

    feCarry!21(s1, s2);
    feCarry!21(s3, s4);
    feCarry!21(s5, s6);
    feCarry!21(s7, s8);
    feCarry!21(s9, s10);
    feCarry!21(s11, s12);
    feCarry!21(s13, s14);
    feCarry!21(s15, s16);
    feCarry!21(s17, s18);
    feCarry!21(s19, s20);
    feCarry!21(s21, s22);

    redcMul(s11, s12, s13, s14, s15, s16, s23);
    redcMul(s10, s11, s12, s13, s14, s15, s22);
    redcMul(s9, s10, s11, s12, s13, s14, s21);
    redcMul(s8, s9, s10, s11, s12, s13, s20);
    redcMul(s7, s8, s9, s10, s11, s12, s19);
    redcMul(s6, s7, s8, s9, s10, s11, s18);

    feCarry!21(s6, s7);
    feCarry!21(s8, s9);
    feCarry!21(s10, s11);
    feCarry!21(s12, s13);
    feCarry!21(s14, s15);
    feCarry!21(s16, s17);

    feCarry!21(s7, s8);
    feCarry!21(s9, s10);
    feCarry!21(s11, s12);
    feCarry!21(s13, s14);
    feCarry!21(s15, s16);

    redcMul(s5, s6, s7, s8, s9, s10, s17);
    redcMul(s4, s5, s6, s7, s8, s9, s16);
    redcMul(s3, s4, s5, s6, s7, s8, s15);
    redcMul(s2, s3, s4, s5, s6, s7, s14);
    redcMul(s1, s2, s3, s4, s5, s6, s13);
    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry!21(s0, s1);
    feCarry!21(s2, s3);
    feCarry!21(s4, s5);
    feCarry!21(s6, s7);
    feCarry!21(s8, s9);
    feCarry!21(s10, s11);

    feCarry!21(s1, s2);
    feCarry!21(s3, s4);
    feCarry!21(s5, s6);
    feCarry!21(s7, s8);
    feCarry!21(s9, s10);
    feCarry!21(s11, s12);

    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry0!21(s0, s1);
    feCarry0!21(s1, s2);
    feCarry0!21(s2, s3);
    feCarry0!21(s3, s4);
    feCarry0!21(s4, s5);
    feCarry0!21(s5, s6);
    feCarry0!21(s6, s7);
    feCarry0!21(s7, s8);
    feCarry0!21(s8, s9);
    feCarry0!21(s9, s10);
    feCarry0!21(s10, s11);
    feCarry0!21(s11, s12);

    redcMul(s0, s1, s2, s3, s4, s5, s12);

    feCarry0!21(s0, s1);
    feCarry0!21(s1, s2);
    feCarry0!21(s2, s3);
    feCarry0!21(s3, s4);
    feCarry0!21(s4, s5);
    feCarry0!21(s5, s6);
    feCarry0!21(s6, s7);
    feCarry0!21(s7, s8);
    feCarry0!21(s8, s9);
    feCarry0!21(s9, s10);
    feCarry0!21(s10, s11);

    packScalar(s, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11);
}

private:

void packScalar(ubyte* s, long s0, long s1, long s2, long s3, long s4, long s5,
                long s6, long s7, long s8, long s9, long s10, long s11)
{
    s[0] = cast(ubyte)(s0 >> 0);
    s[1] = cast(ubyte)(s0 >> 8);
    s[2] = cast(ubyte)((s0 >> 16) | (s1 << 5));
    s[3] = cast(ubyte)(s1 >> 3);
    s[4] = cast(ubyte)(s1 >> 11);
    s[5] = cast(ubyte)((s1 >> 19) | (s2 << 2));
    s[6] = cast(ubyte)(s2 >> 6);
    s[7] = cast(ubyte)((s2 >> 14) | (s3 << 7));
    s[8] = cast(ubyte)(s3 >> 1);
    s[9] = cast(ubyte)(s3 >> 9);
    s[10] = cast(ubyte)((s3 >> 17) | (s4 << 4));
    s[11] = cast(ubyte)(s4 >> 4);
    s[12] = cast(ubyte)(s4 >> 12);
    s[13] = cast(ubyte)((s4 >> 20) | (s5 << 1));
    s[14] = cast(ubyte)(s5 >> 7);
    s[15] = cast(ubyte)((s5 >> 15) | (s6 << 6));
    s[16] = cast(ubyte)(s6 >> 2);
    s[17] = cast(ubyte)(s6 >> 10);
    s[18] = cast(ubyte)((s6 >> 18) | (s7 << 3));
    s[19] = cast(ubyte)(s7 >> 5);
    s[20] = cast(ubyte)(s7 >> 13);
    s[21] = cast(ubyte)(s8 >> 0);
    s[22] = cast(ubyte)(s8 >> 8);
    s[23] = cast(ubyte)((s8 >> 16) | (s9 << 5));
    s[24] = cast(ubyte)(s9 >> 3);
    s[25] = cast(ubyte)(s9 >> 11);
    s[26] = cast(ubyte)((s9 >> 19) | (s10 << 2));
    s[27] = cast(ubyte)(s10 >> 6);
    s[28] = cast(ubyte)((s10 >> 14) | (s11 << 7));
    s[29] = cast(ubyte)(s11 >> 1);
    s[30] = cast(ubyte)(s11 >> 9);
    s[31] = cast(ubyte)(s11 >> 17);
}
