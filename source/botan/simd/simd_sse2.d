/**
* Lightweight wrappers for SSE2 intrinsics for 32-bit operations
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.simd.simd_sse2;

import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2):

import botan.utils.cpuid;
import botan.utils.simd.emmintrin;

struct SIMDSSE2
{
public:
    static bool enabled() { return CPUID.hasSse2(); }

    this(in uint[4] B)
    {
        m_reg = _mm_loadu_si128(cast(const(__m128i*))(B.ptr));
    }

    this(uint B0, uint B1, uint B2, uint B3)
    {
        m_reg = _mm_set_epi32(B0, B1, B2, B3);
    }

    this(uint B)
    {
        m_reg = _mm_set1_epi32(B);
    }

    static SIMDSSE2 loadLittleEndian(in void* input)
    {
        SIMDSSE2 simd;
        simd.m_reg = _mm_loadu_si128(cast(const(__m128i*))(input));
        return simd;
    }

    static SIMDSSE2 loadBigEndian(in void* input)
    {
        return loadLittleEndian(input).bswap();
    }

    void storeLittleEndian(ubyte* output)
    {
        _mm_storeu_si128(cast(__m128i*)(output), m_reg);
    }

    void storeBigEndian(ubyte* output)
    {
        bswap().storeLittleEndian(output);
    }

    void rotateLeft(int ROT)()
    {
        m_reg = _mm_or_si128(_mm_slli_epi32!ROT(m_reg),
                             _mm_srli_epi32!(32-ROT)(m_reg));
    }

    void rotateRight(int rot)()
    {
        rotateLeft!(32 - rot)();
    }

    void opOpAssign(string op)(in SIMDSSE2 other)
        if (op == "+")
    {
        m_reg = _mm_add_epi32(m_reg, other.m_reg);
    }

    SIMDSSE2 opBinary(string op)(in SIMDSSE2 other)
        if (op == "+")
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_add_epi32(m_reg, other.m_reg);
        return ret;
    }

    void opOpAssign(string op)(in SIMDSSE2 other)
        if (op == "-")
    {
        m_reg = _mm_sub_epi32(m_reg, other.m_reg);
    }

    SIMDSSE2 opBinary(string op)(in SIMDSSE2 other)
        if (op == "-")
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_sub_epi32(m_reg, other.m_reg);
        return ret;
    }

    void opOpAssign(string op)(in SIMDSSE2 other)
        if (op == "^")
    {
        m_reg = _mm_xor_si128(m_reg, other.m_reg);
    }

    SIMDSSE2 opBinary(string op)(in SIMDSSE2 other)
        if (op == "^")
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_xor_si128(m_reg, other.m_reg);
        return ret;
    }

    void opOpAssign(string op)(in SIMDSSE2 other)
        if (op == "|")
    {
        m_reg = _mm_or_si128(m_reg, other.m_reg);
    }

    SIMDSSE2 opBinary(string op)(in SIMDSSE2 other)
        if (op == "&")
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_and_si128(m_reg, other.m_reg);
        return ret;
    }

    void opOpAssign(string op)(in SIMDSSE2 other)
        if (op == "&")
    {
        m_reg = _mm_and_si128(m_reg, other.m_reg);
    }

    SIMDSSE2 lshift(size_t shift)()
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_slli_epi32!shift(m_reg);
        return ret;
    }

    SIMDSSE2 rshift(size_t shift)()
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_srli_epi32!shift(m_reg);
        return ret;
    }

    SIMDSSE2 opUnary(string op)()
        if (op == "~")
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_xor_si128(m_reg, _mm_set1_epi32!(0xFFFFFFFF)());
        return ret;
    }

    // (~reg) & other
    SIMDSSE2 andc(in SIMDSSE2 other)
    {
        SIMDSSE2 ret;
        ret.m_reg = _mm_andnot_si128(m_reg, other.m_reg);
        return ret;
    }

    SIMDSSE2 bswap()
    {
        __m128i T = m_reg;

        const SHUF = _MM_SHUFFLE(2, 3, 0, 1);
        T = _mm_shufflehi_epi16!SHUF(T);
        T = _mm_shufflelo_epi16!SHUF(T);

        SIMDSSE2 ret;
        ret.m_reg = _mm_or_si128(_mm_srli_epi16!8(T),
                                 _mm_slli_epi16!8(T));
        return ret;
    }

    static void transpose(ref SIMDSSE2 B0, ref SIMDSSE2 B1,
                          ref SIMDSSE2 B2, ref SIMDSSE2 B3)
    {
        __m128i T0 = _mm_unpacklo_epi32(B0.m_reg, B1.m_reg);
        __m128i T1 = _mm_unpacklo_epi32(B2.m_reg, B3.m_reg);
        __m128i T2 = _mm_unpackhi_epi32(B0.m_reg, B1.m_reg);
        __m128i T3 = _mm_unpackhi_epi32(B2.m_reg, B3.m_reg);
        B0.m_reg = _mm_unpacklo_epi64(T0, T1);
        B1.m_reg = _mm_unpackhi_epi64(T0, T1);
        B2.m_reg = _mm_unpacklo_epi64(T2, T3);
        B3.m_reg = _mm_unpackhi_epi64(T2, T3);
    }

private:
    this(__m128i input) { m_reg = input; }

    __m128i m_reg;
}