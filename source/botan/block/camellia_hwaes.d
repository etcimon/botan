/**
* Camellia using AES-NI for the S-boxes (C++ camellia_hwaes)
*
* Copyright:
* (C) 2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.camellia_hwaes;

import botan.constants;
static if (BOTAN_HAS_CAMELLIA && BOTAN_HAS_CAMELLIA_HWAES && BOTAN_HAS_AES_NI && BOTAN_HAS_SIMD_SSE2):

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

private Gf2Aff postSbox(ulong M, ubyte c)
{
    enum AES_AFF_INV = gfniMatrix(
        "0 0 1 0 0 1 0 1\n1 0 0 1 0 0 1 0\n0 1 0 0 1 0 0 1\n1 0 1 0 0 1 0 0\n" ~
        "0 1 0 1 0 0 1 0\n0 0 1 0 1 0 0 1\n1 0 0 1 0 1 0 0\n0 1 0 0 1 0 1 0");
    enum ubyte AES_C = 0x63;
    const comb_M = gf2MatMul(M, AES_AFF_INV);
    const comb_c = gf2MatVec(comb_M, AES_C) ^ c;
    return makeAff(comb_M, comb_c);
}

private __gshared Gf2Aff g_pre123;
private __gshared Gf2Aff g_pre4;
private __gshared Gf2Aff g_post14;
private __gshared Gf2Aff g_post2;
private __gshared Gf2Aff g_post3;
private __gshared bool g_ready;

private void ensureTables()
{
    if (g_ready)
        return;
    enum PRE123_A = gfniMatrix(
        "1 1 1 0 1 1 0 1\n0 0 1 1 0 0 1 0\n1 1 0 1 0 0 0 0\n1 0 1 1 0 0 1 1\n" ~
        "0 0 0 0 1 1 0 0\n1 0 1 0 0 1 0 0\n0 0 1 0 1 1 0 0\n1 0 0 0 0 1 1 0");
    enum PRE4_A = gfniMatrix(
        "1 1 0 1 1 0 1 1\n0 1 1 0 0 1 0 0\n1 0 1 0 0 0 0 1\n0 1 1 0 0 1 1 1\n" ~
        "0 0 0 1 1 0 0 0\n0 1 0 0 1 0 0 1\n0 1 0 1 1 0 0 0\n0 0 0 0 1 1 0 1");
    enum POST14_A = gfniMatrix(
        "0 0 0 0 0 0 0 1\n0 1 1 0 0 1 1 0\n1 0 1 1 1 1 1 0\n0 0 0 1 1 0 1 1\n" ~
        "1 0 0 0 1 1 1 0\n0 1 0 1 1 1 1 0\n0 1 1 1 1 1 1 1\n0 0 0 1 1 1 0 0");
    enum POST2_A = gfniMatrix(
        "0 0 0 1 1 1 0 0\n0 0 0 0 0 0 0 1\n0 1 1 0 0 1 1 0\n1 0 1 1 1 1 1 0\n" ~
        "0 0 0 1 1 0 1 1\n1 0 0 0 1 1 1 0\n0 1 0 1 1 1 1 0\n0 1 1 1 1 1 1 1");
    enum POST3_A = gfniMatrix(
        "0 1 1 0 0 1 1 0\n1 0 1 1 1 1 1 0\n0 0 0 1 1 0 1 1\n1 0 0 0 1 1 1 0\n" ~
        "0 1 0 1 1 1 1 0\n0 1 1 1 1 1 1 1\n0 0 0 1 1 1 0 0\n0 0 0 0 0 0 0 1");
    g_pre123 = makeAff(PRE123_A, 0x45);
    g_pre4 = makeAff(PRE4_A, 0x45);
    g_post14 = postSbox(POST14_A, 0x6E);
    g_post2 = postSbox(POST2_A, 0xDC);
    g_post3 = postSbox(POST3_A, 0x37);
    g_ready = true;
}

private __m128i set4(uint b0, uint b1, uint b2, uint b3)
{
    return _mm_set_epi32(cast(int) b3, cast(int) b2, cast(int) b1, cast(int) b0);
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
    auto idx_lo = _mm_and_si128(x, mask);
    auto idx_hi = _mm_and_si128(_mm_srli_epi32!4(x), mask);
    return _mm_xor_si128(_mm_shuffle_epi8(lo, idx_lo), _mm_shuffle_epi8(hi, idx_hi));
}

private __m128i hwAesSbox(__m128i x)
{
    const inv_sr = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);
    auto enc = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return _mm_shuffle_epi8(enc, inv_sr);
}

private __m128i byteBlend(__m128i mask, __m128i a, __m128i b)
{
    return _mm_xor_si128(_mm_and_si128(mask, a), _mm_andnot_si128(mask, b));
}

private __m128i swapHalves(__m128i v)
{
    return _mm_shuffle_epi32!0b01001110(v);
}

private __m128i rotl1(__m128i x)
{
    return _mm_or_si128(_mm_slli_epi32!1(x), _mm_srli_epi32!31(x));
}

private __m128i splat32(uint w)
{
    return _mm_set1_epi32(cast(int) w);
}

private __m128i splat64(ulong v)
{
    const lo = cast(uint) v;
    const hi = cast(uint)(v >> 32);
    return set4(lo, hi, lo, hi);
}

private __m128i loadBe64(const(ubyte)* p)
{
    const shuf = set4(0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B);
    return _mm_shuffle_epi8(_mm_loadu_si128(cast(const(__m128i)*) p), shuf);
}

private void storeBe64(ubyte* p, __m128i v)
{
    const shuf = set4(0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B);
    _mm_storeu_si128(cast(__m128i*) p, _mm_shuffle_epi8(v, shuf));
}

private __m128i camelliaF(__m128i x)
{
    ensureTables();
    auto mask_s2 = set4(0xFF000000, 0x00FF0000, 0xFF000000, 0x00FF0000);
    auto mask_s3 = set4(0x00FF0000, 0x0000FF00, 0x00FF0000, 0x0000FF00);
    auto mask_s4 = set4(0x0000FF00, 0x000000FF, 0x0000FF00, 0x000000FF);
    auto pre123 = affine(g_pre123, x);
    auto pre4 = affine(g_pre4, x);
    auto sub = hwAesSbox(byteBlend(mask_s4, pre4, pre123));
    auto s14 = affine(g_post14, sub);
    auto s2 = affine(g_post2, sub);
    auto s3 = affine(g_post3, sub);
    auto sbox = byteBlend(mask_s3, s3, byteBlend(mask_s2, s2, s14));
    auto P1 = set4(0x00000001, 0x00000001, 0x08080809, 0x08080809);
    auto P2 = set4(0x01010202, 0x01010202, 0x09090A0A, 0x09090A0A);
    auto P3 = set4(0x02030303, 0x02030303, 0x0A0B0B0B, 0x0A0B0B0B);
    auto P4 = set4(0x06050404, 0x04040504, 0x0E0D0C0C, 0x0C0C0D0C);
    auto P5 = set4(0x07060507, 0x05060605, 0x0F0E0D0F, 0x0D0E0E0D);
    auto P6 = set4(0xFFFFFFFF, 0x07070706, 0xFFFFFFFF, 0x0F0F0F0E);
    auto r = _mm_shuffle_epi8(sbox, P1);
    r = _mm_xor_si128(r, _mm_shuffle_epi8(sbox, P2));
    r = _mm_xor_si128(r, _mm_shuffle_epi8(sbox, P3));
    r = _mm_xor_si128(r, _mm_shuffle_epi8(sbox, P4));
    r = _mm_xor_si128(r, _mm_shuffle_epi8(sbox, P5));
    r = _mm_xor_si128(r, _mm_shuffle_epi8(sbox, P6));
    return r;
}

private __m128i FL2(__m128i v, ulong K)
{
    const k1 = cast(uint)(K >> 32);
    const k2 = cast(uint) K;
    auto shuf_hi = set4(0x07060504, 0x07060504, 0x0F0E0D0C, 0x0F0E0D0C);
    auto shuf_lo = set4(0x03020100, 0x03020100, 0x0B0A0908, 0x0B0A0908);
    auto x1 = _mm_shuffle_epi8(v, shuf_hi);
    auto x2 = _mm_shuffle_epi8(v, shuf_lo);
    x2 = _mm_xor_si128(x2, rotl1(_mm_and_si128(x1, splat32(k1))));
    x1 = _mm_xor_si128(x1, _mm_or_si128(x2, splat32(k2)));
    auto mask_hi = set4(0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF);
    return byteBlend(mask_hi, x1, x2);
}

private __m128i FLINV2(__m128i v, ulong K)
{
    const k1 = cast(uint)(K >> 32);
    const k2 = cast(uint) K;
    auto shuf_hi = set4(0x07060504, 0x07060504, 0x0F0E0D0C, 0x0F0E0D0C);
    auto shuf_lo = set4(0x03020100, 0x03020100, 0x0B0A0908, 0x0B0A0908);
    auto x1 = _mm_shuffle_epi8(v, shuf_hi);
    auto x2 = _mm_shuffle_epi8(v, shuf_lo);
    x1 = _mm_xor_si128(x1, _mm_or_si128(x2, splat32(k2)));
    x2 = _mm_xor_si128(x2, rotl1(_mm_and_si128(x1, splat32(k1))));
    auto mask_hi = set4(0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF);
    return byteBlend(mask_hi, x1, x2);
}

private void loadDeint(const(ubyte)* inn, ref __m128i L, ref __m128i R)
{
    auto A = loadBe64(inn);
    auto B = loadBe64(inn + 16);
    auto mask_upper = set4(0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);
    L = byteBlend(mask_upper, swapHalves(B), A);
    R = byteBlend(mask_upper, B, swapHalves(A));
}

private void storeInt(ubyte* outp, __m128i L, __m128i R)
{
    auto mask_upper = set4(0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);
    auto A = byteBlend(mask_upper, swapHalves(L), R);
    auto B = byteBlend(mask_upper, L, swapHalves(R));
    storeBe64(outp, A);
    storeBe64(outp + 16, B);
}

private void sixE(ref __m128i L, ref __m128i R, const(ulong)* SK)
{
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[0]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[1]))));
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[2]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[3]))));
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[4]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[5]))));
}

private void sixD(ref __m128i L, ref __m128i R, const(ulong)* SK)
{
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[5]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[4]))));
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[3]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[2]))));
    R = _mm_xor_si128(R, camelliaF(_mm_xor_si128(L, splat64(SK[1]))));
    L = _mm_xor_si128(L, camelliaF(_mm_xor_si128(R, splat64(SK[0]))));
}

private void encryptX2_18(const(ubyte)* inn, ubyte* outp, const(ulong)* SK)
{
    __m128i L, R;
    loadDeint(inn, L, R);
    L = _mm_xor_si128(L, splat64(SK[0]));
    R = _mm_xor_si128(R, splat64(SK[1]));
    sixE(L, R, SK + 2);
    L = FL2(L, SK[8]);
    R = FLINV2(R, SK[9]);
    sixE(L, R, SK + 10);
    L = FL2(L, SK[16]);
    R = FLINV2(R, SK[17]);
    sixE(L, R, SK + 18);
    R = _mm_xor_si128(R, splat64(SK[24]));
    L = _mm_xor_si128(L, splat64(SK[25]));
    storeInt(outp, L, R);
}

private void decryptX2_18(const(ubyte)* inn, ubyte* outp, const(ulong)* SK)
{
    __m128i L, R;
    loadDeint(inn, L, R);
    R = _mm_xor_si128(R, splat64(SK[25]));
    L = _mm_xor_si128(L, splat64(SK[24]));
    sixD(L, R, SK + 18);
    L = FL2(L, SK[17]);
    R = FLINV2(R, SK[16]);
    sixD(L, R, SK + 10);
    L = FL2(L, SK[9]);
    R = FLINV2(R, SK[8]);
    sixD(L, R, SK + 2);
    L = _mm_xor_si128(L, splat64(SK[1]));
    R = _mm_xor_si128(R, splat64(SK[0]));
    storeInt(outp, L, R);
}

private void encryptX2_24(const(ubyte)* inn, ubyte* outp, const(ulong)* SK)
{
    __m128i L, R;
    loadDeint(inn, L, R);
    L = _mm_xor_si128(L, splat64(SK[0]));
    R = _mm_xor_si128(R, splat64(SK[1]));
    sixE(L, R, SK + 2);
    L = FL2(L, SK[8]);
    R = FLINV2(R, SK[9]);
    sixE(L, R, SK + 10);
    L = FL2(L, SK[16]);
    R = FLINV2(R, SK[17]);
    sixE(L, R, SK + 18);
    L = FL2(L, SK[24]);
    R = FLINV2(R, SK[25]);
    sixE(L, R, SK + 26);
    R = _mm_xor_si128(R, splat64(SK[32]));
    L = _mm_xor_si128(L, splat64(SK[33]));
    storeInt(outp, L, R);
}

private void decryptX2_24(const(ubyte)* inn, ubyte* outp, const(ulong)* SK)
{
    __m128i L, R;
    loadDeint(inn, L, R);
    R = _mm_xor_si128(R, splat64(SK[33]));
    L = _mm_xor_si128(L, splat64(SK[32]));
    sixD(L, R, SK + 26);
    L = FL2(L, SK[25]);
    R = FLINV2(R, SK[24]);
    sixD(L, R, SK + 18);
    L = FL2(L, SK[17]);
    R = FLINV2(R, SK[16]);
    sixD(L, R, SK + 10);
    L = FL2(L, SK[9]);
    R = FLINV2(R, SK[8]);
    sixD(L, R, SK + 2);
    L = _mm_xor_si128(L, splat64(SK[1]));
    R = _mm_xor_si128(R, splat64(SK[0]));
    storeInt(outp, L, R);
}

private void transformN(alias x2)(const(ubyte)* inn, ubyte* outp, size_t blocks, const(ulong)* SK)
{
    while (blocks >= 2)
    {
        x2(inn, outp, SK);
        inn += 32;
        outp += 32;
        blocks -= 2;
    }
    if (blocks)
    {
        ubyte[32] ibuf;
        ubyte[32] obuf;
        copyMem(ibuf.ptr, inn, 16);
        x2(ibuf.ptr, obuf.ptr, SK);
        copyMem(outp, obuf.ptr, 16);
    }
}

package void camelliaHwaesEncrypt(const(ubyte)* inn, ubyte* outp, size_t blocks, const(ulong)* SK, size_t sk_len)
{
    if (sk_len == 26)
        transformN!encryptX2_18(inn, outp, blocks, SK);
    else
        transformN!encryptX2_24(inn, outp, blocks, SK);
}

package void camelliaHwaesDecrypt(const(ubyte)* inn, ubyte* outp, size_t blocks, const(ulong)* SK, size_t sk_len)
{
    if (sk_len == 26)
        transformN!decryptX2_18(inn, outp, blocks, SK);
    else
        transformN!decryptX2_24(inn, outp, blocks, SK);
}

static if (BOTAN_HAS_TESTS && !SKIP_BLOCK_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.block.camellia;

    auto gs = globalState();
    size_t fails;
    ensureTables();

    void checkOne(T)(size_t klen)
    {
        Unique!T c = new T;
        Unique!T p = new T;
        auto key = new ubyte[klen];
        foreach (i; 0 .. klen)
            key[i] = cast(ubyte)(0x11 + i * 3);
        c.setKey(key.ptr, klen);
        p.setKey(key.ptr, klen);
        ubyte[48] pt;
        foreach (i; 0 .. pt.length)
            pt[i] = cast(ubyte)(i * 5 + 2);
        ubyte[48] c_hw, c_pt, p_hw;
        foreach (n; [1, 2, 3])
        {
            camelliaPortableEncrypt(pt.ptr, c_pt.ptr, n, p.sk());
            camelliaHwaesEncrypt(pt.ptr, c_hw.ptr, n, c.sk().ptr, c.sk().length);
            if (c_pt[0 .. n * 16] != c_hw[0 .. n * 16])
            {
                logError(T.stringof, " HWAES enc mismatch blocks ", n);
                ++fails;
            }
            camelliaHwaesDecrypt(c_hw.ptr, p_hw.ptr, n, c.sk().ptr, c.sk().length);
            if (p_hw[0 .. n * 16] != pt[0 .. n * 16])
            {
                logError(T.stringof, " HWAES dec mismatch blocks ", n);
                ++fails;
            }
        }
    }

    checkOne!Camellia128(16);
    checkOne!Camellia192(24);
    checkOne!Camellia256(32);

    fails += checkMemutilsRepeat("camellia_hwaes", {
        Unique!Camellia128 c = new Camellia128;
        ubyte[16] key = 0x33;
        c.setKey(key.ptr, key.length);
        ubyte[32] pt = 0x44;
        ubyte[32] ct;
        camelliaHwaesEncrypt(pt.ptr, ct.ptr, 2, c.sk().ptr, c.sk().length);
    });

    testReport("camellia_hwaes", 9, fails);
    assert(fails == 0);
}
