/**
* Ed448 scalar modulo L (RFC 7748 4.2 / RFC 8032 5.2)
*
* Copyright:
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.curve448_scalar;

import botan.constants;
static if (BOTAN_HAS_ED448):

import botan.math.mp.mp_core;
import botan.utils.exceptn;
import botan.utils.loadstor;
import botan.utils.mem_ops;
import std.algorithm : min;

static assert(BOTAN_MP_WORD_BITS == 64, "Ed448 scalar uses 64-bit words");

/**
* Scalar in 0 <= s < L, L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
* Constructor and ops reduce mod L (HAC 14.47).
*/
struct Scalar448
{
public:
    enum size_t WORDS = 7;
    enum size_t BYTES = 56;

    this(const(ubyte)[] x)
    {
        if (x.length > 114)
            throw new InvalidArgument("Ed448 scalar input must be at most 114 bytes");
        ubyte[114] max_bytes = 0;
        if (x.length)
            max_bytes[0 .. x.length] = x[];
        word[WORDS_REDUCE_SZ] xw = bytesToWords114(max_bytes);
        m_scalar_words = ctReduceModL(xw);
    }

    this(word[WORDS] words)
    {
        m_scalar_words[] = words[];
    }

    void toBytes(ubyte[] dest) const
    {
        assert(dest.length >= BYTES);
        dest[] = 0;
        foreach (i; 0 .. WORDS)
            storeLittleEndian(m_scalar_words[i], dest.ptr + 8 * i);
    }

    ubyte[N] toBytes(size_t N = BYTES)() const
        if (N >= BYTES)
    {
        ubyte[N] result = 0;
        toBytes(result[0 .. BYTES]);
        return result;
    }

    bool getBit(size_t bit_pos) const
    {
        if (bit_pos >= 446)
            throw new InvalidArgument("Ed448 scalar bit position out of range");
        enum word_sz = 64;
        return ((m_scalar_words[bit_pos / word_sz] >> (bit_pos % word_sz)) & 1) == 1;
    }

    uint getWindow(size_t starting_pos, size_t width) const
    {
        if (width > 32)
            throw new InvalidArgument("Ed448 scalar window too wide");
        if (starting_pos >= 446)
            return 0;
        const size_t effective = min(width, cast(size_t)(446 - starting_pos));
        enum word_sz = 64;
        const size_t word_idx = starting_pos / word_sz;
        const size_t bit_idx = starting_pos % word_sz;
        const ulong mask = (effective >= 64) ? ~0UL : ((1UL << effective) - 1);
        ulong val = m_scalar_words[word_idx] >> bit_idx;
        if (bit_idx + effective > word_sz && word_idx + 1 < WORDS)
            val |= m_scalar_words[word_idx + 1] << (word_sz - bit_idx);
        return cast(uint)(val & mask);
    }

    Scalar448 opBinary(string op)(Scalar448 other) const
        if (op == "+")
    {
        word[WORDS] sum = addWords(m_scalar_words, other.m_scalar_words);
        ctSubtractLIfBigger(sum);
        return Scalar448(sum);
    }

    Scalar448 opBinary(string op)(Scalar448 other) const
        if (op == "*")
    {
        word[WORDS_REDUCE_SZ] product = 0;
        word[WORDS_REDUCE_SZ] ws = 0;
        bigint_mul(product.ptr, product.length, ws.ptr,
                   m_scalar_words.ptr, WORDS, WORDS,
                   other.m_scalar_words.ptr, WORDS, WORDS);
        return Scalar448(ctReduceModL(product));
    }

    static bool bytesAreReduced(const(ubyte)[] x)
    {
        if (x.length < BYTES)
            throw new InvalidArgument("Ed448 scalar input is not long enough");
        ubyte acc = 0;
        foreach (b; x[BYTES .. $])
            acc |= b;
        if (acc != 0)
            return false;
        ubyte[56] first56 = 0;
        first56[] = x[0 .. 56];
        word[WORDS] words = bytesToWords56(first56);
        return !ctSubtractLIfBigger(words);
    }

private:
    word[WORDS] m_scalar_words;
}

private:

enum size_t WORDS_REDUCE_SZ = 15;
enum size_t WORDS_C = 4;

immutable word[WORDS_C] C_WORDS = [
    0xdc873d6d54a7bb0dUL,
    0xde933d8d723a70aaUL,
    0x3bb124b65129c96fUL,
    0x000000008335dc16UL
];

immutable word[Scalar448.WORDS] BIG_L = [
    0x2378c292ab5844f3UL,
    0x216cc2728dc58f55UL,
    0xc44edb49aed63690UL,
    0xffffffff7cca23e9UL,
    0xffffffffffffffffUL,
    0xffffffffffffffffUL,
    0x3fffffffffffffffUL
];

word[Scalar448.WORDS] bytesToWords56(const ref ubyte[56] x)
{
    word[Scalar448.WORDS] w;
    loadLittleEndian(w.ptr, x.ptr, Scalar448.WORDS);
    return w;
}

word[WORDS_REDUCE_SZ] bytesToWords114(const ref ubyte[114] x)
{
    ubyte[120] padded = 0;
    padded[0 .. 114] = x[];
    word[WORDS_REDUCE_SZ] w;
    loadLittleEndian(w.ptr, padded.ptr, WORDS_REDUCE_SZ);
    return w;
}

void divMod2446(const(word)* x, size_t s, word* q, size_t q_len, ref word[Scalar448.WORDS] r)
{
    r[] = 0;
    if (q_len)
        q[0 .. q_len] = 0;
    if (s < Scalar448.WORDS)
    {
        r[0 .. s] = x[0 .. s];
        return;
    }
    r[] = x[0 .. Scalar448.WORDS];
    r[Scalar448.WORDS - 1] &= ~(3UL << 62);
    bigint_shr2(q, x, s, 6, 62);
}

void mulC(const(word)* x, size_t s, word[] res)
{
    word[16] ws = 0;
    bigint_mul(res.ptr, res.length, ws.ptr,
               x, s, s,
               C_WORDS.ptr, WORDS_C, WORDS_C);
}

word[Scalar448.WORDS] addWords(const ref word[Scalar448.WORDS] x, const ref word[Scalar448.WORDS] y)
{
    word[Scalar448.WORDS] res = x;
    const word carry = bigint_add2_nc(res.ptr, res.length, y.ptr, y.length);
    if (carry != 0)
        throw new InvalidState("Ed448 scalar add overflowed 448 bits");
    return res;
}

/// Returns true iff a reduction (x >= L) was performed.
bool ctSubtractLIfBigger(ref word[Scalar448.WORDS] x)
{
    word[Scalar448.WORDS] tmp = x;
    const word borrow = bigint_sub2(tmp.ptr, tmp.length, BIG_L.ptr, BIG_L.length);
    const word keep = 0UL - borrow;
    foreach (i; 0 .. Scalar448.WORDS)
        x[i] = (x[i] & keep) | (tmp[i] & ~keep);
    return borrow == 0;
}

word[Scalar448.WORDS] ctReduceModL(const ref word[WORDS_REDUCE_SZ] x)
{
    word[9] q0;
    word[Scalar448.WORDS] r0;
    divMod2446(x.ptr, WORDS_REDUCE_SZ, q0.ptr, q0.length, r0);

    word[Scalar448.WORDS] r = r0;

    word[13] q0c;
    mulC(q0.ptr, q0.length, q0c);
    word[7] q1;
    word[Scalar448.WORDS] r1;
    divMod2446(q0c.ptr, q0c.length, q1.ptr, q1.length, r1);
    r = addWords(r, r1);

    word[11] q1c;
    mulC(q1.ptr, q1.length, q1c);
    word[5] q2;
    word[Scalar448.WORDS] r2;
    divMod2446(q1c.ptr, q1c.length, q2.ptr, q2.length, r2);
    r = addWords(r, r2);

    word[9] q2c;
    mulC(q2.ptr, q2.length, q2c);
    word[3] q3;
    word[Scalar448.WORDS] r3;
    divMod2446(q2c.ptr, q2c.length, q3.ptr, q3.length, r3);
    r = addWords(r, r3);

    word acc = 0;
    foreach (w; q3)
        acc |= w;
    if (acc != 0)
        throw new InvalidState("Ed448 scalar reduction left a leftover quotient");

    foreach (i; 0 .. 4)
        ctSubtractLIfBigger(r);
    return r;
}
