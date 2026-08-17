/**
* ARIA using AES-NI for the S-boxes (C++ aria_hwaes)
*
* Copyright:
* (C) 2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.aria_hwaes;

import botan.constants;
static if (BOTAN_HAS_ARIA && BOTAN_HAS_ARIA_HWAES && BOTAN_HAS_AES_NI && BOTAN_HAS_SIMD_SSE2):

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

private __gshared Gf2Aff g_post_s2;
private __gshared Gf2Aff g_pre_x2;
private __gshared bool g_ready;

private void ensureTables()
{
    if (g_ready)
        return;
    enum AES_AFF = gfniMatrix(
        "1 0 0 0 1 1 1 1\n1 1 0 0 0 1 1 1\n1 1 1 0 0 0 1 1\n1 1 1 1 0 0 0 1\n" ~
        "1 1 1 1 1 0 0 0\n0 1 1 1 1 1 0 0\n0 0 1 1 1 1 1 0\n0 0 0 1 1 1 1 1");
    enum AES_AFF_INV = gfniMatrix(
        "0 0 1 0 0 1 0 1\n1 0 0 1 0 0 1 0\n0 1 0 0 1 0 0 1\n1 0 1 0 0 1 0 0\n" ~
        "0 1 0 1 0 0 1 0\n0 0 1 0 1 0 0 1\n1 0 0 1 0 1 0 0\n0 1 0 0 1 0 1 0");
    enum ubyte AES_C = 0x63;
    enum ubyte AES_C_INV = 0x05;
    enum AFF_S2 = gfniMatrix(
        "0 1 0 1 0 1 1 1\n0 0 1 1 1 1 1 1\n1 1 1 0 1 1 0 1\n1 1 0 0 0 0 1 1\n" ~
        "0 1 0 0 0 0 1 1\n1 1 0 0 1 1 1 0\n0 1 1 0 0 0 1 1\n1 1 1 1 0 1 1 0");
    enum AFF_X2 = gfniMatrix(
        "0 0 0 1 1 0 0 0\n0 0 1 0 0 1 1 0\n0 0 0 0 1 0 1 0\n1 1 1 0 0 0 1 1\n" ~
        "1 1 1 0 1 1 0 0\n0 1 1 0 1 0 1 1\n1 0 1 1 1 1 0 1\n1 0 0 1 0 0 1 1");
    const comb_s2 = gf2MatMul(AFF_S2, AES_AFF_INV);
    const c_s2 = gf2MatVec(comb_s2, AES_C) ^ 0xE2;
    g_post_s2 = makeAff(comb_s2, c_s2);
    const comb_x2 = gf2MatMul(AES_AFF, AFF_X2);
    const c_x2 = gf2MatVec(AES_AFF, cast(ubyte)(0x2C ^ AES_C_INV));
    g_pre_x2 = makeAff(comb_x2, c_x2);
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

private __m128i hwAesSbox(__m128i x)
{
    const inv_sr = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);
    return _mm_shuffle_epi8(_mm_aesenclast_si128(x, _mm_setzero_si128()), inv_sr);
}

private __m128i hwAesInvSbox(__m128i x)
{
    const sr = _mm_set_epi32(0x0B06010C, 0x07020D08, 0x030E0904, 0x0F0A0500);
    return _mm_shuffle_epi8(_mm_aesdeclast_si128(x, _mm_setzero_si128()), sr);
}

private __m128i byteShuffle(__m128i x, __m128i tbl)
{
    return _mm_shuffle_epi8(x, tbl);
}

private __m128i byteTranspose(__m128i v)
{
    const tbl = _mm_set_epi32(0x0F0B0703, 0x0E0A0602, 0x0D090501, 0x0C080400);
    return byteShuffle(v, tbl);
}

private __m128i swapAbcdBadc(__m128i x)
{
    const shuf = _mm_set_epi32(0x0E0F0C0D, 0x0A0B0809, 0x06070405, 0x02030001);
    return byteShuffle(x, shuf);
}

private __m128i ariaS1(__m128i v) { return hwAesSbox(v); }
private __m128i ariaX1(__m128i v) { return hwAesInvSbox(v); }

private __m128i ariaS2(__m128i v)
{
    ensureTables();
    return affine(g_post_s2, hwAesSbox(v));
}

private __m128i ariaX2(__m128i v)
{
    ensureTables();
    return hwAesInvSbox(affine(g_pre_x2, v));
}

private __m128i ariaFoM(__m128i x)
{
    return _mm_xor_si128(_mm_xor_si128(rotl!8(x), rotl!16(x)), rotl!24(x));
}

private __m128i ariaFeM(__m128i x)
{
    return _mm_xor_si128(_mm_xor_si128(x, rotl!8(x)), rotl!24(x));
}

private void ariaMix(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    B1 = _mm_xor_si128(B1, B2);
    B2 = _mm_xor_si128(B2, B3);
    B0 = _mm_xor_si128(B0, B1);
    B3 = _mm_xor_si128(B3, B1);
    B2 = _mm_xor_si128(B2, B0);
    B1 = _mm_xor_si128(B1, B2);
}

private void applyBt4(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    B0 = byteTranspose(B0);
    B1 = byteTranspose(B1);
    B2 = byteTranspose(B2);
    B3 = byteTranspose(B3);
}

private void ariaFoSbox(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    applyBt4(B0, B1, B2, B3);
    transpose(B0, B1, B2, B3);
    B3 = ariaS1(B3);
    B2 = ariaS2(B2);
    B1 = ariaX1(B1);
    B0 = ariaX2(B0);
    transpose(B0, B1, B2, B3);
    applyBt4(B0, B1, B2, B3);
}

private void ariaFeSbox(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    applyBt4(B0, B1, B2, B3);
    transpose(B0, B1, B2, B3);
    B3 = ariaX1(B3);
    B2 = ariaX2(B2);
    B1 = ariaS1(B1);
    B0 = ariaS2(B0);
    transpose(B0, B1, B2, B3);
    applyBt4(B0, B1, B2, B3);
}

private void ariaFo(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    ariaFoSbox(B0, B1, B2, B3);
    B0 = ariaFoM(B0);
    B1 = ariaFoM(B1);
    B2 = ariaFoM(B2);
    B3 = ariaFoM(B3);
    ariaMix(B0, B1, B2, B3);
    B1 = swapAbcdBadc(B1);
    B2 = rotl!16(B2);
    B3 = bswap32(B3);
    ariaMix(B0, B1, B2, B3);
}

private void ariaFe(ref __m128i B0, ref __m128i B1, ref __m128i B2, ref __m128i B3)
{
    ariaFeSbox(B0, B1, B2, B3);
    B0 = ariaFeM(B0);
    B1 = ariaFeM(B1);
    B2 = ariaFeM(B2);
    B3 = ariaFeM(B3);
    ariaMix(B0, B1, B2, B3);
    B3 = swapAbcdBadc(B3);
    B0 = rotl!16(B0);
    B1 = bswap32(B1);
    ariaMix(B0, B1, B2, B3);
}

private __m128i splatU32(uint w)
{
    return _mm_set1_epi32(cast(int) w);
}

private void transform4(const(ubyte)* inn, ubyte* outp, const(uint)* KS, size_t ks_len)
{
    const size_t rounds = (ks_len / 4) - 1;
    auto B0 = loadBe(inn);
    auto B1 = loadBe(inn + 16);
    auto B2 = loadBe(inn + 32);
    auto B3 = loadBe(inn + 48);
    transpose(B0, B1, B2, B3);
    for (size_t r = 0; r != rounds; r += 2)
    {
        B0 = _mm_xor_si128(B0, splatU32(KS[4 * r]));
        B1 = _mm_xor_si128(B1, splatU32(KS[4 * r + 1]));
        B2 = _mm_xor_si128(B2, splatU32(KS[4 * r + 2]));
        B3 = _mm_xor_si128(B3, splatU32(KS[4 * r + 3]));
        ariaFo(B0, B1, B2, B3);
        B0 = _mm_xor_si128(B0, splatU32(KS[4 * r + 4]));
        B1 = _mm_xor_si128(B1, splatU32(KS[4 * r + 5]));
        B2 = _mm_xor_si128(B2, splatU32(KS[4 * r + 6]));
        B3 = _mm_xor_si128(B3, splatU32(KS[4 * r + 7]));
        if (r != rounds - 2)
            ariaFe(B0, B1, B2, B3);
    }
    ariaFeSbox(B0, B1, B2, B3);
    B0 = _mm_xor_si128(B0, splatU32(KS[4 * rounds]));
    B1 = _mm_xor_si128(B1, splatU32(KS[4 * rounds + 1]));
    B2 = _mm_xor_si128(B2, splatU32(KS[4 * rounds + 2]));
    B3 = _mm_xor_si128(B3, splatU32(KS[4 * rounds + 3]));
    transpose(B0, B1, B2, B3);
    storeBe(outp, B0);
    storeBe(outp + 16, B1);
    storeBe(outp + 32, B2);
    storeBe(outp + 48, B3);
}

package void ariaHwaesTransform(const(ubyte)* inn, ubyte* outp, size_t blocks, const(uint)* KS, size_t ks_len)
{
    while (blocks >= 4)
    {
        transform4(inn, outp, KS, ks_len);
        inn += 64;
        outp += 64;
        blocks -= 4;
    }
    if (blocks)
    {
        ubyte[64] ibuf;
        ubyte[64] obuf;
        copyMem(ibuf.ptr, inn, blocks * 16);
        transform4(ibuf.ptr, obuf.ptr, KS, ks_len);
        copyMem(outp, obuf.ptr, blocks * 16);
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_BLOCK_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.block.aria;

    auto gs = globalState();
    size_t fails;
    ensureTables();

    // Direct compare using stored keys on ARIA128/192/256.
    void checkOne(T)(size_t klen)
    {
        Unique!T c = new T;
        auto key = new ubyte[klen];
        foreach (i; 0 .. klen)
            key[i] = cast(ubyte)(0x11 + i * 3);
        c.setKey(key.ptr, klen);
        ubyte[80] pt;
        foreach (i; 0 .. pt.length)
            pt[i] = cast(ubyte)(i * 5 + 2);
        ubyte[80] c_hw, c_pt, p_hw;
        foreach (n; [1, 4, 5])
        {
            ariaTransform(pt.ptr, c_pt.ptr, n, c.erk());
            ariaHwaesTransform(pt.ptr, c_hw.ptr, n, c.erk().ptr, c.erk().length);
            if (c_pt[0 .. n * 16] != c_hw[0 .. n * 16])
            {
                logError(T.stringof, " HWAES enc mismatch blocks ", n);
                ++fails;
            }
            ariaHwaesTransform(c_hw.ptr, p_hw.ptr, n, c.drk().ptr, c.drk().length);
            if (p_hw[0 .. n * 16] != pt[0 .. n * 16])
            {
                logError(T.stringof, " HWAES dec mismatch blocks ", n);
                ++fails;
            }
        }
    }

    checkOne!ARIA128(16);
    checkOne!ARIA192(24);
    checkOne!ARIA256(32);

    fails += checkMemutilsRepeat("aria_hwaes", {
        Unique!ARIA128 c = new ARIA128;
        ubyte[16] key = 0x33;
        c.setKey(key.ptr, key.length);
        ubyte[64] pt = 0x44;
        ubyte[64] ct;
        ariaHwaesTransform(pt.ptr, ct.ptr, 4, c.erk().ptr, c.erk().length);
    });

    testReport("aria_hwaes", 9, fails);
    assert(fails == 0);
}
