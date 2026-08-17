/**
* SM4 using AES-NI for the S-box (C++ sm4_hwaes)
*
* Copyright:
* (C) 2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.sm4_hwaes;

import botan.constants;
static if (BOTAN_HAS_SM4 && BOTAN_HAS_SM4_HWAES && BOTAN_HAS_AES_NI && BOTAN_HAS_SIMD_SSE2):

import botan.utils.simd.emmintrin;
import botan.utils.simd.wmmintrin;
import botan.utils.mem_ops;
import botan.utils.types;

private ulong gfniMatrix(string s)
{
    ulong matrix = 0;
    size_t bit_cnt;
    ubyte row;
    foreach (c; s)
    {
        if (c == ' ' || c == '\n')
            continue;
        if (c == '1')
            row |= 0x80 >> (7 - bit_cnt % 8);
        ++bit_cnt;
        if (bit_cnt % 8 == 0)
        {
            matrix <<= 8;
            matrix |= row;
            row = 0;
        }
    }
    assert(bit_cnt == 64, "gfni_matrix bit count");
    return matrix;
}

private ubyte gf2MatVec(ulong M, ubyte x)
{
    ubyte result;
    foreach (i; 0 .. 8)
    {
        ubyte bit;
        foreach (j; 0 .. 8)
        {
            if (((M >> (56 - 8 * i + j)) & 1) == 1)
                bit ^= (x >> j) & 1;
        }
        result |= bit << i;
    }
    return result;
}

private ulong gf2MatMul(ulong A, ulong B)
{
    ulong result;
    foreach (i; 0 .. 8)
    {
        foreach (j; 0 .. 8)
        {
            ubyte bit;
            foreach (k; 0 .. 8)
            {
                const a_ik = cast(ubyte)((A >> (56 - 8 * i + k)) & 1);
                const b_kj = cast(ubyte)((B >> (56 - 8 * k + j)) & 1);
                bit ^= a_ik & b_kj;
            }
            if (bit)
                result |= 1UL << (56 - 8 * i + j);
        }
    }
    return result;
}

private struct Gf2Aff
{
    uint[4] lo;
    uint[4] hi;
}

private Gf2Aff makeAff(ulong M, ubyte c)
{
    Gf2Aff t;
    foreach (i; 0 .. 16)
    {
        const lo_val = gf2MatVec(M, cast(ubyte) i) ^ c;
        const hi_val = gf2MatVec(M, cast(ubyte)(i << 4));
        t.lo[i / 4] |= cast(uint) lo_val << (8 * (i % 4));
        t.hi[i / 4] |= cast(uint) hi_val << (8 * (i % 4));
    }
    return t;
}

private __gshared Gf2Aff g_pre;
private __gshared Gf2Aff g_post;
private __gshared bool g_ready;

private void ensureTables()
{
    if (g_ready)
        return;
    enum AES_AFF = gfniMatrix(
        "1 0 0 0 1 1 1 1\n" ~
        "1 1 0 0 0 1 1 1\n" ~
        "1 1 1 0 0 0 1 1\n" ~
        "1 1 1 1 0 0 0 1\n" ~
        "1 1 1 1 1 0 0 0\n" ~
        "0 1 1 1 1 1 0 0\n" ~
        "0 0 1 1 1 1 1 0\n" ~
        "0 0 0 1 1 1 1 1");
    enum AES_AFF_INV = gfniMatrix(
        "0 0 1 0 0 1 0 1\n" ~
        "1 0 0 1 0 0 1 0\n" ~
        "0 1 0 0 1 0 0 1\n" ~
        "1 0 1 0 0 1 0 0\n" ~
        "0 1 0 1 0 0 1 0\n" ~
        "0 0 1 0 1 0 0 1\n" ~
        "1 0 0 1 0 1 0 0\n" ~
        "0 1 0 0 1 0 1 0");
    enum ubyte AES_C = 0x63;
    enum pre_a = gfniMatrix(
        "0 0 1 1 0 0 1 0\n" ~
        "0 0 0 1 0 1 0 0\n" ~
        "1 0 1 1 1 1 1 0\n" ~
        "1 0 0 1 1 1 0 1\n" ~
        "0 1 0 1 1 0 0 0\n" ~
        "0 1 0 0 0 1 0 0\n" ~
        "0 0 0 0 1 0 1 0\n" ~
        "1 0 1 1 1 0 1 0");
    enum ubyte pre_c = 0b00111110;
    enum post_a = gfniMatrix(
        "1 1 0 0 1 1 1 1\n" ~
        "1 1 0 1 0 1 0 1\n" ~
        "0 0 1 0 1 1 0 0\n" ~
        "1 0 0 1 0 1 0 1\n" ~
        "0 0 1 0 1 1 1 0\n" ~
        "0 1 1 0 0 1 0 1\n" ~
        "1 0 1 0 1 1 0 1\n" ~
        "1 0 0 1 0 0 0 1");
    enum ubyte post_c = 0b11010011;
    g_pre = makeAff(pre_a, pre_c);
    const comb_M = gf2MatMul(post_a, AES_AFF_INV);
    const comb_c = gf2MatVec(comb_M, AES_C) ^ post_c;
    g_post = makeAff(comb_M, comb_c);
    g_ready = true;
}

private __m128i bswap32(__m128i v)
{
    const SHUF = _MM_SHUFFLE(2, 3, 0, 1);
    v = _mm_shufflehi_epi16!SHUF(v);
    v = _mm_shufflelo_epi16!SHUF(v);
    return _mm_or_si128(_mm_srli_epi16!8(v), _mm_slli_epi16!8(v));
}

private __m128i loadBe(const(ubyte)* p)
{
    return bswap32(_mm_loadu_si128(cast(const(__m128i)*) p));
}

private void storeBe(ubyte* p, __m128i v)
{
    _mm_storeu_si128(cast(__m128i*) p, bswap32(v));
}

private __m128i rotl(int n)(__m128i x)
{
    return _mm_or_si128(_mm_slli_epi32!n(x), _mm_srli_epi32!(32 - n)(x));
}

private void transpose(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    auto T0 = _mm_unpacklo_epi32(B0, B1);
    auto T1 = _mm_unpacklo_epi32(B2, B3);
    auto T2 = _mm_unpackhi_epi32(B0, B1);
    auto T3 = _mm_unpackhi_epi32(B2, B3);
    B0 = _mm_unpacklo_epi64(T0, T1);
    B1 = _mm_unpackhi_epi64(T0, T1);
    B2 = _mm_unpacklo_epi64(T2, T3);
    B3 = _mm_unpackhi_epi64(T2, T3);
}

private __m128i tblLoad(const ref uint[4] w)
{
    return _mm_set_epi32(w[3], w[2], w[1], w[0]);
}

private __m128i affine(const ref Gf2Aff t, __m128i x)
{
    const mask = _mm_set1_epi8!(cast(byte) 0x0F)();
    const lo = tblLoad(t.lo);
    const hi = tblLoad(t.hi);
    const idx_lo = _mm_and_si128(x, mask);
    const idx_hi = _mm_and_si128(_mm_srli_epi32!4(x), mask);
    return _mm_xor_si128(_mm_shuffle_epi8(lo, idx_lo), _mm_shuffle_epi8(hi, idx_hi));
}

/// AES S-box on each byte: AESENCLAST then undo ShiftRows.
private __m128i hwAesSbox(__m128i x)
{
    const inv_sr = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);
    auto enc = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return _mm_shuffle_epi8(enc, inv_sr);
}

private __m128i sm4Sbox(__m128i x)
{
    ensureTables();
    return affine(g_post, hwAesSbox(affine(g_pre, x)));
}

private __m128i sm4F(__m128i x)
{
    auto s = sm4Sbox(x);
    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(s, rotl!2(s)), rotl!10(s)), rotl!18(s)), rotl!24(s));
}

private __m128i splatU32(uint w)
{
    return _mm_set1_epi32(cast(int) w);
}

private void encrypt4(const(ubyte)* ptext, ubyte* ctext, const(uint)* RK)
{
    auto B0 = loadBe(ptext + 0);
    auto B1 = loadBe(ptext + 16);
    auto B2 = loadBe(ptext + 32);
    auto B3 = loadBe(ptext + 48);
    transpose(B0, B1, B2, B3);
    foreach (j; 0 .. 8)
    {
        const K0 = splatU32(RK[4 * j]);
        const K1 = splatU32(RK[4 * j + 1]);
        const K2 = splatU32(RK[4 * j + 2]);
        const K3 = splatU32(RK[4 * j + 3]);
        B0 = _mm_xor_si128(B0, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B1, B2), B3), K0)));
        B1 = _mm_xor_si128(B1, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B2, B3), B0), K1)));
        B2 = _mm_xor_si128(B2, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B3, B0), B1), K2)));
        B3 = _mm_xor_si128(B3, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B0, B1), B2), K3)));
    }
    transpose(B3, B2, B1, B0);
    storeBe(ctext + 0, B3);
    storeBe(ctext + 16, B2);
    storeBe(ctext + 32, B1);
    storeBe(ctext + 48, B0);
}

private void decrypt4(const(ubyte)* ctext, ubyte* ptext, const(uint)* RK)
{
    auto B0 = loadBe(ctext + 0);
    auto B1 = loadBe(ctext + 16);
    auto B2 = loadBe(ctext + 32);
    auto B3 = loadBe(ctext + 48);
    transpose(B0, B1, B2, B3);
    foreach (j; 0 .. 8)
    {
        const K0 = splatU32(RK[32 - (4 * j + 1)]);
        const K1 = splatU32(RK[32 - (4 * j + 2)]);
        const K2 = splatU32(RK[32 - (4 * j + 3)]);
        const K3 = splatU32(RK[32 - (4 * j + 4)]);
        B0 = _mm_xor_si128(B0, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B1, B2), B3), K0)));
        B1 = _mm_xor_si128(B1, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B2, B3), B0), K1)));
        B2 = _mm_xor_si128(B2, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B3, B0), B1), K2)));
        B3 = _mm_xor_si128(B3, sm4F(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B0, B1), B2), K3)));
    }
    transpose(B3, B2, B1, B0);
    storeBe(ptext + 0, B3);
    storeBe(ptext + 16, B2);
    storeBe(ptext + 32, B1);
    storeBe(ptext + 48, B0);
}

package void sm4HwaesEncrypt(const(ubyte)* ptext, ubyte* ctext, size_t blocks, const(uint)* RK)
{
    while (blocks >= 4)
    {
        encrypt4(ptext, ctext, RK);
        ptext += 64;
        ctext += 64;
        blocks -= 4;
    }
    if (blocks)
    {
        ubyte[64] ibuf;
        ubyte[64] obuf;
        copyMem(ibuf.ptr, ptext, blocks * 16);
        encrypt4(ibuf.ptr, obuf.ptr, RK);
        copyMem(ctext, obuf.ptr, blocks * 16);
    }
}

package void sm4HwaesDecrypt(const(ubyte)* ctext, ubyte* ptext, size_t blocks, const(uint)* RK)
{
    while (blocks >= 4)
    {
        decrypt4(ctext, ptext, RK);
        ptext += 64;
        ctext += 64;
        blocks -= 4;
    }
    if (blocks)
    {
        ubyte[64] ibuf;
        ubyte[64] obuf;
        copyMem(ibuf.ptr, ctext, blocks * 16);
        decrypt4(ibuf.ptr, obuf.ptr, RK);
        copyMem(ptext, obuf.ptr, blocks * 16);
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_BLOCK_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.block.sm4;
    import botan.block.block_cipher;

    auto gs = globalState();
    size_t fails;
    ensureTables();

    {
        Unique!SM4 sm = new SM4;
        ubyte[16] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        sm.setKey(key.ptr, key.length);
        ubyte[80] pt;
        foreach (i; 0 .. pt.length)
            pt[i] = cast(ubyte)(i * 3 + 1);
        ubyte[80] c_hw, c_pt, p_hw;
        foreach (n; [1, 4, 5])
        {
            sm4PortableEncrypt(pt.ptr, c_pt.ptr, n, sm.roundKeys());
            sm4HwaesEncrypt(pt.ptr, c_hw.ptr, n, sm.roundKeys().ptr);
            if (c_pt[0 .. n * 16] != c_hw[0 .. n * 16])
            {
                logError("SM4 HWAES encrypt mismatch blocks ", n);
                ++fails;
            }
            sm4HwaesDecrypt(c_hw.ptr, p_hw.ptr, n, sm.roundKeys().ptr);
            if (p_hw[0 .. n * 16] != pt[0 .. n * 16])
            {
                logError("SM4 HWAES decrypt mismatch blocks ", n);
                ++fails;
            }
        }
    }

    fails += checkMemutilsRepeat("sm4_hwaes", {
        Unique!SM4 sm = new SM4;
        ubyte[16] key = 0x11;
        sm.setKey(key.ptr, key.length);
        ubyte[64] pt = 0x22;
        ubyte[64] ct;
        sm4HwaesEncrypt(pt.ptr, ct.ptr, 4, sm.roundKeys().ptr);
    });

    testReport("sm4_hwaes", 3, fails);
    assert(fails == 0);
}
