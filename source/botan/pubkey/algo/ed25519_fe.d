/**
* Ed25519 field element (Z/(2^255-19))
*
* Copyright:
* (C) 2017 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ed25519_fe;

import botan.constants;
static if (BOTAN_HAS_ED25519):

struct Fe
{
    int[10] v;

    static Fe zero() { Fe f; return f; }
    static Fe one() { Fe f; f.v[0] = 1; return f; }

    this(long h0, long h1, long h2, long h3, long h4,
         long h5, long h6, long h7, long h8, long h9)
    {
        v[0] = cast(int) h0; v[1] = cast(int) h1; v[2] = cast(int) h2;
        v[3] = cast(int) h3; v[4] = cast(int) h4; v[5] = cast(int) h5;
        v[6] = cast(int) h6; v[7] = cast(int) h7; v[8] = cast(int) h8;
        v[9] = cast(int) h9;
    }

    Fe opBinary(string op)(in Fe b) const
        if (op == "+" || op == "-" || op == "*")
    {
        static if (op == "+")
        {
            Fe z;
            foreach (i; 0 .. 10) z.v[i] = v[i] + b.v[i];
            return z;
        }
        else static if (op == "-")
        {
            Fe z;
            foreach (i; 0 .. 10) z.v[i] = v[i] - b.v[i];
            return z;
        }
        else
            return feMul(this, b);
    }

    Fe opUnary(string op)() const if (op == "-")
    {
        Fe z;
        foreach (i; 0 .. 10) z.v[i] = -v[i];
        return z;
    }

    Fe sqr() const { return sqrIter(1); }
    Fe sqr2() const { return feSqr2(this); }
    Fe sqrIter(size_t iter) const { return feSqrIter(this, iter); }
    Fe invert() const { return feInvert(this); }
    Fe pow22523() const { return fePow22523(this); }

    bool isZero() const
    {
        ubyte[32] s;
        serializeTo(s);
        ubyte acc = 0;
        foreach (b; s) acc |= b;
        return acc == 0;
    }

    bool isNegative() const
    {
        ubyte[32] s;
        serializeTo(s);
        return (s[0] & 1) == 1;
    }

    void serializeTo(ref ubyte[32] s) const { feSerialize(this, s); }

    static Fe deserialize(const(ubyte)* b) { return feDeserialize(b); }
}

package:

uint load3(const(ubyte)* inn)
{
    return inn[0] | (cast(uint) inn[1] << 8) | (cast(uint) inn[2] << 16);
}

uint load4(const(ubyte)* inn)
{
    return inn[0] | (cast(uint) inn[1] << 8) | (cast(uint) inn[2] << 16) | (cast(uint) inn[3] << 24);
}

void feCarry(int S, int MUL = 1)(ref long h0, ref long h1)
{
    const long X1 = 1L << S;
    const long X2 = 1L << (S - 1);
    const long c = (h0 + X2) >> S;
    h1 += c * MUL;
    h0 -= c * X1;
}

void feCarry0(int S)(ref long h0, ref long h1)
{
    const long X1 = 1L << S;
    const long c = h0 >> S;
    h1 += c;
    h0 -= c * X1;
}

void feCarry0i(int S)(ref int h0, ref int h1)
{
    const int X1 = 1 << S;
    const int c = h0 >> S;
    h1 += c;
    h0 -= c * X1;
}

void redcMul(ref long s1, ref long s2, ref long s3, ref long s4, ref long s5, ref long s6, ref long X)
{
    s1 += X * 666643;
    s2 += X * 470296;
    s3 += X * 654183;
    s4 -= X * 997805;
    s5 += X * 136657;
    s6 -= X * 683901;
    X = 0;
}

private:

void feFinish(ref long h0, ref long h1, ref long h2, ref long h3, ref long h4,
              ref long h5, ref long h6, ref long h7, ref long h8, ref long h9)
{
    feCarry!26(h0, h1);
    feCarry!26(h4, h5);
    feCarry!25(h1, h2);
    feCarry!25(h5, h6);
    feCarry!26(h2, h3);
    feCarry!26(h6, h7);
    feCarry!25(h3, h4);
    feCarry!25(h7, h8);
    feCarry!26(h4, h5);
    feCarry!26(h8, h9);
    feCarry!(25, 19)(h9, h0);
    feCarry!26(h0, h1);
}

Fe feMul(in Fe f, in Fe g)
{
    const int f0 = f.v[0], f1 = f.v[1], f2 = f.v[2], f3 = f.v[3], f4 = f.v[4];
    const int f5 = f.v[5], f6 = f.v[6], f7 = f.v[7], f8 = f.v[8], f9 = f.v[9];
    const int g0 = g.v[0], g1 = g.v[1], g2 = g.v[2], g3 = g.v[3], g4 = g.v[4];
    const int g5 = g.v[5], g6 = g.v[6], g7 = g.v[7], g8 = g.v[8], g9 = g.v[9];

    const int g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    const int g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
    const int f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

    long h0 = f0 * cast(long) g0 + f1_2 * cast(long) g9_19 + f2 * cast(long) g8_19 + f3_2 * cast(long) g7_19
        + f4 * cast(long) g6_19 + f5_2 * cast(long) g5_19 + f6 * cast(long) g4_19 + f7_2 * cast(long) g3_19
        + f8 * cast(long) g2_19 + f9_2 * cast(long) g1_19;
    long h1 = f0 * cast(long) g1 + f1 * cast(long) g0 + f2 * cast(long) g9_19 + f3 * cast(long) g8_19
        + f4 * cast(long) g7_19 + f5 * cast(long) g6_19 + f6 * cast(long) g5_19 + f7 * cast(long) g4_19
        + f8 * cast(long) g3_19 + f9 * cast(long) g2_19;
    long h2 = f0 * cast(long) g2 + f1_2 * cast(long) g1 + f2 * cast(long) g0 + f3_2 * cast(long) g9_19
        + f4 * cast(long) g8_19 + f5_2 * cast(long) g7_19 + f6 * cast(long) g6_19 + f7_2 * cast(long) g5_19
        + f8 * cast(long) g4_19 + f9_2 * cast(long) g3_19;
    long h3 = f0 * cast(long) g3 + f1 * cast(long) g2 + f2 * cast(long) g1 + f3 * cast(long) g0
        + f4 * cast(long) g9_19 + f5 * cast(long) g8_19 + f6 * cast(long) g7_19 + f7 * cast(long) g6_19
        + f8 * cast(long) g5_19 + f9 * cast(long) g4_19;
    long h4 = f0 * cast(long) g4 + f1_2 * cast(long) g3 + f2 * cast(long) g2 + f3_2 * cast(long) g1
        + f4 * cast(long) g0 + f5_2 * cast(long) g9_19 + f6 * cast(long) g8_19 + f7_2 * cast(long) g7_19
        + f8 * cast(long) g6_19 + f9_2 * cast(long) g5_19;
    long h5 = f0 * cast(long) g5 + f1 * cast(long) g4 + f2 * cast(long) g3 + f3 * cast(long) g2
        + f4 * cast(long) g1 + f5 * cast(long) g0 + f6 * cast(long) g9_19 + f7 * cast(long) g8_19
        + f8 * cast(long) g7_19 + f9 * cast(long) g6_19;
    long h6 = f0 * cast(long) g6 + f1_2 * cast(long) g5 + f2 * cast(long) g4 + f3_2 * cast(long) g3
        + f4 * cast(long) g2 + f5_2 * cast(long) g1 + f6 * cast(long) g0 + f7_2 * cast(long) g9_19
        + f8 * cast(long) g8_19 + f9_2 * cast(long) g7_19;
    long h7 = f0 * cast(long) g7 + f1 * cast(long) g6 + f2 * cast(long) g5 + f3 * cast(long) g4
        + f4 * cast(long) g3 + f5 * cast(long) g2 + f6 * cast(long) g1 + f7 * cast(long) g0
        + f8 * cast(long) g9_19 + f9 * cast(long) g8_19;
    long h8 = f0 * cast(long) g8 + f1_2 * cast(long) g7 + f2 * cast(long) g6 + f3_2 * cast(long) g5
        + f4 * cast(long) g4 + f5_2 * cast(long) g3 + f6 * cast(long) g2 + f7_2 * cast(long) g1
        + f8 * cast(long) g0 + f9_2 * cast(long) g9_19;
    long h9 = f0 * cast(long) g9 + f1 * cast(long) g8 + f2 * cast(long) g7 + f3 * cast(long) g6
        + f4 * cast(long) g5 + f5 * cast(long) g4 + f6 * cast(long) g3 + f7 * cast(long) g2
        + f8 * cast(long) g1 + f9 * cast(long) g0;

    feFinish(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    return Fe(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

Fe feSqrIter(in Fe src, size_t iter)
{
    int f0 = src.v[0], f1 = src.v[1], f2 = src.v[2], f3 = src.v[3], f4 = src.v[4];
    int f5 = src.v[5], f6 = src.v[6], f7 = src.v[7], f8 = src.v[8], f9 = src.v[9];

    foreach (n; 0 .. iter)
    {
        const int f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3, f4_2 = 2 * f4;
        const int f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7;
        const int f5_38 = 38 * f5, f6_19 = 19 * f6, f7_38 = 38 * f7, f8_19 = 19 * f8, f9_38 = 38 * f9;

        const long f0f0 = f0 * cast(long) f0;
        const long f0f1_2 = f0_2 * cast(long) f1;
        const long f0f2_2 = f0_2 * cast(long) f2;
        const long f0f3_2 = f0_2 * cast(long) f3;
        const long f0f4_2 = f0_2 * cast(long) f4;
        const long f0f5_2 = f0_2 * cast(long) f5;
        const long f0f6_2 = f0_2 * cast(long) f6;
        const long f0f7_2 = f0_2 * cast(long) f7;
        const long f0f8_2 = f0_2 * cast(long) f8;
        const long f0f9_2 = f0_2 * cast(long) f9;
        const long f1f1_2 = f1_2 * cast(long) f1;
        const long f1f2_2 = f1_2 * cast(long) f2;
        const long f1f3_4 = f1_2 * cast(long) f3_2;
        const long f1f4_2 = f1_2 * cast(long) f4;
        const long f1f5_4 = f1_2 * cast(long) f5_2;
        const long f1f6_2 = f1_2 * cast(long) f6;
        const long f1f7_4 = f1_2 * cast(long) f7_2;
        const long f1f8_2 = f1_2 * cast(long) f8;
        const long f1f9_76 = f1_2 * cast(long) f9_38;
        const long f2f2 = f2 * cast(long) f2;
        const long f2f3_2 = f2_2 * cast(long) f3;
        const long f2f4_2 = f2_2 * cast(long) f4;
        const long f2f5_2 = f2_2 * cast(long) f5;
        const long f2f6_2 = f2_2 * cast(long) f6;
        const long f2f7_2 = f2_2 * cast(long) f7;
        const long f2f8_38 = f2_2 * cast(long) f8_19;
        const long f2f9_38 = f2 * cast(long) f9_38;
        const long f3f3_2 = f3_2 * cast(long) f3;
        const long f3f4_2 = f3_2 * cast(long) f4;
        const long f3f5_4 = f3_2 * cast(long) f5_2;
        const long f3f6_2 = f3_2 * cast(long) f6;
        const long f3f7_76 = f3_2 * cast(long) f7_38;
        const long f3f8_38 = f3_2 * cast(long) f8_19;
        const long f3f9_76 = f3_2 * cast(long) f9_38;
        const long f4f4 = f4 * cast(long) f4;
        const long f4f5_2 = f4_2 * cast(long) f5;
        const long f4f6_38 = f4_2 * cast(long) f6_19;
        const long f4f7_38 = f4 * cast(long) f7_38;
        const long f4f8_38 = f4_2 * cast(long) f8_19;
        const long f4f9_38 = f4 * cast(long) f9_38;
        const long f5f5_38 = f5 * cast(long) f5_38;
        const long f5f6_38 = f5_2 * cast(long) f6_19;
        const long f5f7_76 = f5_2 * cast(long) f7_38;
        const long f5f8_38 = f5_2 * cast(long) f8_19;
        const long f5f9_76 = f5_2 * cast(long) f9_38;
        const long f6f6_19 = f6 * cast(long) f6_19;
        const long f6f7_38 = f6 * cast(long) f7_38;
        const long f6f8_38 = f6_2 * cast(long) f8_19;
        const long f6f9_38 = f6 * cast(long) f9_38;
        const long f7f7_38 = f7 * cast(long) f7_38;
        const long f7f8_38 = f7_2 * cast(long) f8_19;
        const long f7f9_76 = f7_2 * cast(long) f9_38;
        const long f8f8_19 = f8 * cast(long) f8_19;
        const long f8f9_38 = f8 * cast(long) f9_38;
        const long f9f9_38 = f9 * cast(long) f9_38;

        long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

        feFinish(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
        f0 = cast(int) h0; f1 = cast(int) h1; f2 = cast(int) h2; f3 = cast(int) h3; f4 = cast(int) h4;
        f5 = cast(int) h5; f6 = cast(int) h6; f7 = cast(int) h7; f8 = cast(int) h8; f9 = cast(int) h9;
    }
    return Fe(f0, f1, f2, f3, f4, f5, f6, f7, f8, f9);
}

Fe feSqr2(in Fe src)
{
    const int f0 = src.v[0], f1 = src.v[1], f2 = src.v[2], f3 = src.v[3], f4 = src.v[4];
    const int f5 = src.v[5], f6 = src.v[6], f7 = src.v[7], f8 = src.v[8], f9 = src.v[9];
    const int f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3, f4_2 = 2 * f4;
    const int f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7;
    const int f5_38 = 38 * f5, f6_19 = 19 * f6, f7_38 = 38 * f7, f8_19 = 19 * f8, f9_38 = 38 * f9;

    const long f0f0 = f0 * cast(long) f0;
    const long f0f1_2 = f0_2 * cast(long) f1;
    const long f0f2_2 = f0_2 * cast(long) f2;
    const long f0f3_2 = f0_2 * cast(long) f3;
    const long f0f4_2 = f0_2 * cast(long) f4;
    const long f0f5_2 = f0_2 * cast(long) f5;
    const long f0f6_2 = f0_2 * cast(long) f6;
    const long f0f7_2 = f0_2 * cast(long) f7;
    const long f0f8_2 = f0_2 * cast(long) f8;
    const long f0f9_2 = f0_2 * cast(long) f9;
    const long f1f1_2 = f1_2 * cast(long) f1;
    const long f1f2_2 = f1_2 * cast(long) f2;
    const long f1f3_4 = f1_2 * cast(long) f3_2;
    const long f1f4_2 = f1_2 * cast(long) f4;
    const long f1f5_4 = f1_2 * cast(long) f5_2;
    const long f1f6_2 = f1_2 * cast(long) f6;
    const long f1f7_4 = f1_2 * cast(long) f7_2;
    const long f1f8_2 = f1_2 * cast(long) f8;
    const long f1f9_76 = f1_2 * cast(long) f9_38;
    const long f2f2 = f2 * cast(long) f2;
    const long f2f3_2 = f2_2 * cast(long) f3;
    const long f2f4_2 = f2_2 * cast(long) f4;
    const long f2f5_2 = f2_2 * cast(long) f5;
    const long f2f6_2 = f2_2 * cast(long) f6;
    const long f2f7_2 = f2_2 * cast(long) f7;
    const long f2f8_38 = f2_2 * cast(long) f8_19;
    const long f2f9_38 = f2 * cast(long) f9_38;
    const long f3f3_2 = f3_2 * cast(long) f3;
    const long f3f4_2 = f3_2 * cast(long) f4;
    const long f3f5_4 = f3_2 * cast(long) f5_2;
    const long f3f6_2 = f3_2 * cast(long) f6;
    const long f3f7_76 = f3_2 * cast(long) f7_38;
    const long f3f8_38 = f3_2 * cast(long) f8_19;
    const long f3f9_76 = f3_2 * cast(long) f9_38;
    const long f4f4 = f4 * cast(long) f4;
    const long f4f5_2 = f4_2 * cast(long) f5;
    const long f4f6_38 = f4_2 * cast(long) f6_19;
    const long f4f7_38 = f4 * cast(long) f7_38;
    const long f4f8_38 = f4_2 * cast(long) f8_19;
    const long f4f9_38 = f4 * cast(long) f9_38;
    const long f5f5_38 = f5 * cast(long) f5_38;
    const long f5f6_38 = f5_2 * cast(long) f6_19;
    const long f5f7_76 = f5_2 * cast(long) f7_38;
    const long f5f8_38 = f5_2 * cast(long) f8_19;
    const long f5f9_76 = f5_2 * cast(long) f9_38;
    const long f6f6_19 = f6 * cast(long) f6_19;
    const long f6f7_38 = f6 * cast(long) f7_38;
    const long f6f8_38 = f6_2 * cast(long) f8_19;
    const long f6f9_38 = f6 * cast(long) f9_38;
    const long f7f7_38 = f7 * cast(long) f7_38;
    const long f7f8_38 = f7_2 * cast(long) f8_19;
    const long f7f9_76 = f7_2 * cast(long) f9_38;
    const long f8f8_19 = f8 * cast(long) f8_19;
    const long f8f9_38 = f8 * cast(long) f9_38;
    const long f9f9_38 = f9 * cast(long) f9_38;

    long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    h0 += h0; h1 += h1; h2 += h2; h3 += h3; h4 += h4;
    h5 += h5; h6 += h6; h7 += h7; h8 += h8; h9 += h9;
    feFinish(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    return Fe(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

Fe feInvert(in Fe z)
{
    auto t0 = z.sqr();
    auto t1 = t0.sqrIter(2);
    t1 = z * t1;
    t0 = t0 * t1;
    auto t2 = t0.sqr();
    t1 = t1 * t2;
    t2 = t1.sqrIter(5);
    t1 = t2 * t1;
    t2 = t1.sqrIter(10);
    t2 = t2 * t1;
    auto t3 = t2.sqrIter(20);
    t2 = t3 * t2;
    t2 = t2.sqrIter(10);
    t1 = t2 * t1;
    t2 = t1.sqrIter(50);
    t2 = t2 * t1;
    t3 = t2.sqrIter(100);
    t2 = t3 * t2;
    t2 = t2.sqrIter(50);
    t1 = t2 * t1;
    t1 = t1.sqrIter(5);
    t0 = t1 * t0;
    return t0;
}

Fe fePow22523(in Fe z)
{
    auto t0 = z.sqr();
    auto t1 = t0.sqrIter(2);
    t1 = z * t1;
    t0 = t0 * t1;
    t0 = t0.sqr();
    t0 = t1 * t0;
    t1 = t0.sqrIter(5);
    t0 = t1 * t0;
    t1 = t0.sqrIter(10);
    t1 = t1 * t0;
    auto t2 = t1.sqrIter(20);
    t1 = t2 * t1;
    t1 = t1.sqrIter(10);
    t0 = t1 * t0;
    t1 = t0.sqrIter(50);
    t1 = t1 * t0;
    t2 = t1.sqrIter(100);
    t1 = t2 * t1;
    t1 = t1.sqrIter(50);
    t0 = t1 * t0;
    t0 = t0.sqrIter(2);
    t0 = t0 * z;
    return t0;
}

Fe feDeserialize(const(ubyte)* s)
{
    long h0 = load4(s);
    long h1 = cast(long) load3(s + 4) << 6;
    long h2 = cast(long) load3(s + 7) << 5;
    long h3 = cast(long) load3(s + 10) << 3;
    long h4 = cast(long) load3(s + 13) << 2;
    long h5 = load4(s + 16);
    long h6 = cast(long) load3(s + 20) << 7;
    long h7 = cast(long) load3(s + 23) << 5;
    long h8 = cast(long) load3(s + 26) << 4;
    long h9 = cast(long)(load3(s + 29) & 0x7fffff) << 2;

    feCarry!(25, 19)(h9, h0);
    feCarry!25(h1, h2);
    feCarry!25(h3, h4);
    feCarry!25(h5, h6);
    feCarry!25(h7, h8);
    feCarry!26(h0, h1);
    feCarry!26(h2, h3);
    feCarry!26(h4, h5);
    feCarry!26(h6, h7);
    feCarry!26(h8, h9);
    return Fe(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

void feSerialize(in Fe f, ref ubyte[32] s)
{
    int h0 = f.v[0], h1 = f.v[1], h2 = f.v[2], h3 = f.v[3], h4 = f.v[4];
    int h5 = f.v[5], h6 = f.v[6], h7 = f.v[7], h8 = f.v[8], h9 = f.v[9];

    int q = (19 * h9 + (1 << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;
    h0 += 19 * q;

    feCarry0i!26(h0, h1);
    feCarry0i!25(h1, h2);
    feCarry0i!26(h2, h3);
    feCarry0i!25(h3, h4);
    feCarry0i!26(h4, h5);
    feCarry0i!25(h5, h6);
    feCarry0i!26(h6, h7);
    feCarry0i!25(h7, h8);
    feCarry0i!26(h8, h9);
    const int carry9 = h9 >> 25;
    h9 -= carry9 * (1 << 25);

    s[0] = cast(ubyte)(h0 >> 0);
    s[1] = cast(ubyte)(h0 >> 8);
    s[2] = cast(ubyte)(h0 >> 16);
    s[3] = cast(ubyte)((h0 >> 24) | (h1 << 2));
    s[4] = cast(ubyte)(h1 >> 6);
    s[5] = cast(ubyte)(h1 >> 14);
    s[6] = cast(ubyte)((h1 >> 22) | (h2 << 3));
    s[7] = cast(ubyte)(h2 >> 5);
    s[8] = cast(ubyte)(h2 >> 13);
    s[9] = cast(ubyte)((h2 >> 21) | (h3 << 5));
    s[10] = cast(ubyte)(h3 >> 3);
    s[11] = cast(ubyte)(h3 >> 11);
    s[12] = cast(ubyte)((h3 >> 19) | (h4 << 6));
    s[13] = cast(ubyte)(h4 >> 2);
    s[14] = cast(ubyte)(h4 >> 10);
    s[15] = cast(ubyte)(h4 >> 18);
    s[16] = cast(ubyte)(h5 >> 0);
    s[17] = cast(ubyte)(h5 >> 8);
    s[18] = cast(ubyte)(h5 >> 16);
    s[19] = cast(ubyte)((h5 >> 24) | (h6 << 1));
    s[20] = cast(ubyte)(h6 >> 7);
    s[21] = cast(ubyte)(h6 >> 15);
    s[22] = cast(ubyte)((h6 >> 23) | (h7 << 3));
    s[23] = cast(ubyte)(h7 >> 5);
    s[24] = cast(ubyte)(h7 >> 13);
    s[25] = cast(ubyte)((h7 >> 21) | (h8 << 4));
    s[26] = cast(ubyte)(h8 >> 4);
    s[27] = cast(ubyte)(h8 >> 12);
    s[28] = cast(ubyte)((h8 >> 20) | (h9 << 6));
    s[29] = cast(ubyte)(h9 >> 2);
    s[30] = cast(ubyte)(h9 >> 10);
    s[31] = cast(ubyte)(h9 >> 18);
}
