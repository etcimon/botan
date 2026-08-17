/**
* Curve448 field GF(2^448 - 2^224 - 1)
*
* Copyright:
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.curve448_gf;

import botan.constants;
static if (BOTAN_HAS_ED448 || BOTAN_HAS_X448):

import botan.math.mp.mp_core;
import botan.utils.loadstor;
import botan.utils.mem_ops;

static assert(BOTAN_MP_WORD_BITS == 64, "Curve448 GF uses 7 x 64-bit words");

enum size_t BYTES_448 = 56;
enum size_t WORDS_448 = 7;

/**
* GF(2^448 - 2^224 - 1) in 7 little-endian 64-bit words.
* Reduction is Nath–Sarkar (eprint 2019/1304). Internals may be unreduced;
* toBytes() returns the canonical representative.
*/
struct Gf448Elem
{
public:
    this(ulong least)
    {
        m_x[] = 0;
        m_x[0] = least;
    }

    this(ulong[WORDS_448] words)
    {
        m_x[] = words[];
    }

    static Gf448Elem zero() { return Gf448Elem(0); }
    static Gf448Elem one() { return Gf448Elem(1); }

    static Gf448Elem fromBytes(const(ubyte)[] x)
    {
        assert(x.length == BYTES_448);
        Gf448Elem r = Gf448Elem(0);
        loadLittleEndian(r.m_x.ptr, x.ptr, WORDS_448);
        return r;
    }

    void toBytes(ubyte[] dest) const
    {
        assert(dest.length == BYTES_448);
        ulong[WORDS_448] c = toCanonical(m_x);
        foreach (i; 0 .. WORDS_448)
            storeLittleEndian(c[i], dest.ptr + 8 * i);
    }

    ubyte[BYTES_448] toBytes() const
    {
        ubyte[BYTES_448] outbuf;
        toBytes(outbuf[]);
        return outbuf;
    }

    void ctCondSwap(ulong mask, ref Gf448Elem other)
    {
        foreach (i; 0 .. WORDS_448)
        {
            const ulong t = mask & (m_x[i] ^ other.m_x[i]);
            m_x[i] ^= t;
            other.m_x[i] ^= t;
        }
    }

    void ctCondAssign(ulong mask, Gf448Elem other)
    {
        foreach (i; 0 .. WORDS_448)
            m_x[i] = (other.m_x[i] & mask) | (m_x[i] & ~mask);
    }

    Gf448Elem opBinary(string op)(Gf448Elem other) const
        if (op == "+" || op == "-" || op == "*" || op == "/")
    {
        Gf448Elem res = Gf448Elem(0);
        static if (op == "+")
            gfAdd(res.m_x, m_x, other.m_x);
        else static if (op == "-")
            gfSub(res.m_x, m_x, other.m_x);
        else static if (op == "*")
            gfMul(res.m_x, m_x, other.m_x);
        else static if (op == "/")
        {
            gfInv(res.m_x, other.m_x);
            gfMul(res.m_x, m_x, res.m_x);
        }
        return res;
    }

    Gf448Elem opUnary(string op)() const
        if (op == "-")
    {
        Gf448Elem z = Gf448Elem(0);
        Gf448Elem res = Gf448Elem(0);
        gfSub(res.m_x, z.m_x, m_x);
        return res;
    }

    bool opEquals(Gf448Elem other) const
    {
        ulong[WORDS_448] a = toCanonical(m_x);
        ulong[WORDS_448] b = toCanonical(other.m_x);
        ulong acc = 0;
        foreach (i; 0 .. WORDS_448)
            acc |= a[i] ^ b[i];
        return acc == 0;
    }

    bool isZero() const
    {
        ulong[WORDS_448] c = toCanonical(m_x);
        ulong acc = 0;
        foreach (i; 0 .. WORDS_448)
            acc |= c[i];
        return acc == 0;
    }

    bool isOdd() const
    {
        ulong[WORDS_448] c = toCanonical(m_x);
        return (c[0] & 1) != 0;
    }

    ref ulong[WORDS_448] words() return { return m_x; }
    ref const(ulong[WORDS_448]) words() const return { return m_x; }

    static bool bytesAreCanonical(const(ubyte)[] x)
    {
        if (x.length != BYTES_448)
            return false;
        ulong[WORDS_448] w;
        loadLittleEndian(w.ptr, x.ptr, WORDS_448);
        ulong[WORDS_448] c = toCanonical(w);
        ulong acc = 0;
        foreach (i; 0 .. WORDS_448)
            acc |= w[i] ^ c[i];
        return acc == 0;
    }

    ulong[WORDS_448] m_x;
}

Gf448Elem mulA24(Gf448Elem a)
{
    Gf448Elem res = Gf448Elem(0);
    gfMulA24(res.m_x, a.m_x);
    return res;
}

Gf448Elem square(Gf448Elem elem)
{
    Gf448Elem res = Gf448Elem(0);
    gfSquare(res.m_x, elem.m_x);
    return res;
}

Gf448Elem root(Gf448Elem elem)
{
    // (P-3)/4 = 2^446 - 2^222 - 1 = x223 << 223 + x222
    ulong[WORDS_448] x222;
    ulong[WORDS_448] x223;
    gfPow222m1(x222, x223, elem.m_x);
    Gf448Elem res = Gf448Elem(0);
    gfSqrN(res.m_x, x223, 223);
    gfMul(res.m_x, res.m_x, x222);
    return res;
}

private:

void reduceAfterAdd(ref ulong[WORDS_448] h3, const ref ulong[8] h1)
{
    ulong[8] h2;
    word carry = 0;
    enum word zero = 0;

    h2[0] = word_add(h1[0], h1[7], &carry);
    h2[1] = word_add(h1[1], zero, &carry);
    h2[2] = word_add(h1[2], zero, &carry);
    h2[3] = word_add(h1[3], h1[7] << 32, &carry);
    h2[4] = word_add(h1[4], zero, &carry);
    h2[5] = word_add(h1[5], zero, &carry);
    h2[6] = word_add(h1[6], zero, &carry);
    h2[7] = carry;

    carry = 0;
    h3[0] = word_add(h2[0], h2[7], &carry);
    h3[1] = word_add(h2[1], zero, &carry);
    h3[2] = word_add(h2[2], zero, &carry);
    h3[3] = h2[3] + (h2[7] << 32) + carry;
    h3[4] = h2[4];
    h3[5] = h2[5];
    h3[6] = h2[6];
}

void reduceAfterMul(ref ulong[WORDS_448] outw, const ref ulong[14] inn)
{
    ulong[8] r;
    ulong[8] s;
    ulong[8] t0;
    ulong[8] h1;
    word carry = 0;

    r[0] = word_add(inn[0], inn[7], &carry);
    r[1] = word_add(inn[1], inn[8], &carry);
    r[2] = word_add(inn[2], inn[9], &carry);
    r[3] = word_add(inn[3], inn[10], &carry);
    r[4] = word_add(inn[4], inn[11], &carry);
    r[5] = word_add(inn[5], inn[12], &carry);
    r[6] = word_add(inn[6], inn[13], &carry);
    r[7] = carry;
    s[0] = r[0];
    s[1] = r[1];
    s[2] = r[2];
    carry = 0;
    s[3] = word_add(r[3], inn[10] & 0xFFFFFFFF00000000UL, &carry);
    s[4] = word_add(r[4], inn[11], &carry);
    s[5] = word_add(r[5], inn[12], &carry);
    s[6] = word_add(r[6], inn[13], &carry);
    s[7] = r[7] + carry;

    t0[0] = (inn[11] << 32) | (inn[10] >> 32);
    t0[1] = (inn[12] << 32) | (inn[11] >> 32);
    t0[2] = (inn[13] << 32) | (inn[12] >> 32);
    t0[3] = (inn[7] << 32) | (inn[13] >> 32);
    t0[4] = (inn[8] << 32) | (inn[7] >> 32);
    t0[5] = (inn[9] << 32) | (inn[8] >> 32);
    t0[6] = (inn[10] << 32) | (inn[9] >> 32);

    carry = 0;
    h1[0] = word_add(s[0], t0[0], &carry);
    h1[1] = word_add(s[1], t0[1], &carry);
    h1[2] = word_add(s[2], t0[2], &carry);
    h1[3] = word_add(s[3], t0[3], &carry);
    h1[4] = word_add(s[4], t0[4], &carry);
    h1[5] = word_add(s[5], t0[5], &carry);
    h1[6] = word_add(s[6], t0[6], &carry);
    h1[7] = s[7] + carry;

    reduceAfterAdd(outw, h1);
}

void schoolbookMul7(ref ulong[14] z, const ref ulong[WORDS_448] a, const ref ulong[WORDS_448] b)
{
    z[] = 0;
    foreach (i; 0 .. WORDS_448)
    {
        word carry = 0;
        foreach (j; 0 .. WORDS_448)
            z[i + j] = word_madd3(a[i], b[j], z[i + j], &carry);
        z[i + WORDS_448] = carry;
    }
}

void gfMulA24(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a)
{
    enum ulong A24 = 39081;
    ulong[8] ws;
    word carry = 0;
    ws[0] = word_madd2(a[0], A24, &carry);
    ws[1] = word_madd2(a[1], A24, &carry);
    ws[2] = word_madd2(a[2], A24, &carry);
    ws[3] = word_madd2(a[3], A24, &carry);
    ws[4] = word_madd2(a[4], A24, &carry);
    ws[5] = word_madd2(a[5], A24, &carry);
    ws[6] = word_madd2(a[6], A24, &carry);
    ws[7] = carry;
    reduceAfterAdd(outw, ws);
}

void gfMul(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a, const ref ulong[WORDS_448] b)
{
    ulong[14] ws;
    schoolbookMul7(ws, a, b);
    reduceAfterMul(outw, ws);
}

void gfSquare(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a)
{
    gfMul(outw, a, a);
}

void gfAdd(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a, const ref ulong[WORDS_448] b)
{
    ulong[8] ws;
    word carry = 0;
    ws[0] = word_add(a[0], b[0], &carry);
    ws[1] = word_add(a[1], b[1], &carry);
    ws[2] = word_add(a[2], b[2], &carry);
    ws[3] = word_add(a[3], b[3], &carry);
    ws[4] = word_add(a[4], b[4], &carry);
    ws[5] = word_add(a[5], b[5], &carry);
    ws[6] = word_add(a[6], b[6], &carry);
    ws[7] = carry;
    reduceAfterAdd(outw, ws);
}

void gfSub(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a, const ref ulong[WORDS_448] b)
{
    ulong[WORDS_448] h0;
    ulong[WORDS_448] h1;
    word borrow = 0;
    h0[0] = word_sub(a[0], b[0], &borrow);
    h0[1] = word_sub(a[1], b[1], &borrow);
    h0[2] = word_sub(a[2], b[2], &borrow);
    h0[3] = word_sub(a[3], b[3], &borrow);
    h0[4] = word_sub(a[4], b[4], &borrow);
    h0[5] = word_sub(a[5], b[5], &borrow);
    h0[6] = word_sub(a[6], b[6], &borrow);
    word delta = borrow;
    word delta_p = delta << 32;
    borrow = 0;
    enum word zero = 0;

    h1[0] = word_sub(h0[0], delta, &borrow);
    h1[1] = word_sub(h0[1], zero, &borrow);
    h1[2] = word_sub(h0[2], zero, &borrow);
    h1[3] = word_sub(h0[3], delta_p, &borrow);
    h1[4] = word_sub(h0[4], zero, &borrow);
    h1[5] = word_sub(h0[5], zero, &borrow);
    h1[6] = word_sub(h0[6], zero, &borrow);

    delta = borrow;
    delta_p = delta << 32;
    borrow = 0;

    outw[0] = word_sub(h1[0], delta, &borrow);
    outw[1] = word_sub(h1[1], zero, &borrow);
    outw[2] = word_sub(h1[2], zero, &borrow);
    outw[3] = word_sub(h1[3], delta_p, &borrow);
    outw[4] = h1[4];
    outw[5] = h1[5];
    outw[6] = h1[6];
}

void gfSqrN(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a, size_t n)
{
    gfSquare(outw, a);
    foreach (i; 1 .. n)
        gfSquare(outw, outw);
}

void gfPow222m1(ref ulong[WORDS_448] x222, ref ulong[WORDS_448] x223, const ref ulong[WORDS_448] a)
{
    ulong[WORDS_448] t;
    ulong[WORDS_448] a2;
    ulong[WORDS_448] a3;
    ulong[WORDS_448] a7;
    ulong[WORDS_448] a63;
    ulong[WORDS_448] x12;
    ulong[WORDS_448] x24;
    ulong[WORDS_448] i34;
    ulong[WORDS_448] x30;
    ulong[WORDS_448] x48;
    ulong[WORDS_448] x96;
    ulong[WORDS_448] x192;

    gfSquare(a2, a);
    gfMul(a3, a, a2);
    gfSquare(t, a3);
    gfMul(a7, a, t);
    gfSqrN(t, a7, 3);
    gfMul(a63, a7, t);
    gfSqrN(t, a63, 6);
    gfMul(x12, a63, t);
    gfSqrN(t, x12, 12);
    gfMul(x24, x12, t);
    gfSqrN(i34, x24, 6);
    gfMul(x30, a63, i34);
    gfSqrN(t, i34, 18);
    gfMul(x48, x24, t);
    gfSqrN(t, x48, 48);
    gfMul(x96, x48, t);
    gfSqrN(t, x96, 96);
    gfMul(x192, x96, t);
    gfSqrN(t, x192, 30);
    gfMul(x222, x30, t);
    gfSquare(t, x222);
    gfMul(x223, a, t);
}

void gfInv(ref ulong[WORDS_448] outw, const ref ulong[WORDS_448] a)
{
    ulong[WORDS_448] x222;
    ulong[WORDS_448] x223;
    gfPow222m1(x222, x223, a);
    ulong[WORDS_448] t;
    gfSqrN(t, x223, 223);
    gfMul(t, t, x222);
    gfSqrN(t, t, 2);
    gfMul(outw, t, a);
}

ulong[WORDS_448] toCanonical(const ref ulong[WORDS_448] inn)
{
    static immutable ulong[WORDS_448] p = [
        0xffffffffffffffffUL,
        0xffffffffffffffffUL,
        0xffffffffffffffffUL,
        0xfffffffeffffffffUL,
        0xffffffffffffffffUL,
        0xffffffffffffffffUL,
        0xffffffffffffffffUL
    ];
    ulong[WORDS_448] minus_p;
    word borrow = 0;
    foreach (i; 0 .. WORDS_448)
        minus_p[i] = word_sub(inn[i], p[i], &borrow);
    const word keep = 0UL - borrow;
    ulong[WORDS_448] outw;
    foreach (i; 0 .. WORDS_448)
        outw[i] = (inn[i] & keep) | (minus_p[i] & ~keep);
    return outw;
}
