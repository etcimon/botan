/**
* ChaCha SSE2 x4 (four blocks in parallel)
*
* Copyright:
* (C) 2018 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.chacha_sse2;

import botan.constants;
static if (BOTAN_HAS_CHACHA && BOTAN_HAS_CHACHA_SIMD && BOTAN_HAS_SIMD_SSE2):

import botan.utils.simd.emmintrin;

/// Four ChaCha blocks; advances input[12]/[13] by 4.
package void chachaSse2x4(ref ubyte[64 * 4] output, ref uint[16] input, size_t rounds)
{
    assert(rounds % 2 == 0, "Valid rounds");

    const __m128i* input_mm = cast(const(__m128i*)) input;
    __m128i* output_mm = cast(__m128i*) output;

    __m128i input0 = _mm_loadu_si128(input_mm);
    __m128i input1 = _mm_loadu_si128(input_mm + 1);
    __m128i input2 = _mm_loadu_si128(input_mm + 2);
    __m128i input3 = _mm_loadu_si128(input_mm + 3);

    __m128i r0_0 = input0;
    __m128i r0_1 = input1;
    __m128i r0_2 = input2;
    __m128i r0_3 = input3;

    __m128i r1_0 = input0;
    __m128i r1_1 = input1;
    __m128i r1_2 = input2;
    __m128i r1_3 = input3;
    r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

    __m128i r2_0 = input0;
    __m128i r2_1 = input1;
    __m128i r2_2 = input2;
    __m128i r2_3 = input3;
    r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

    __m128i r3_0 = input0;
    __m128i r3_1 = input1;
    __m128i r3_2 = input2;
    __m128i r3_3 = input3;
    r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

    for (size_t r = 0; r != rounds / 2; ++r)
    {
        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = _mm_or_si128(_mm_slli_epi32!16(r0_3), _mm_srli_epi32!16(r0_3));
        r1_3 = _mm_or_si128(_mm_slli_epi32!16(r1_3), _mm_srli_epi32!16(r1_3));
        r2_3 = _mm_or_si128(_mm_slli_epi32!16(r2_3), _mm_srli_epi32!16(r2_3));
        r3_3 = _mm_or_si128(_mm_slli_epi32!16(r3_3), _mm_srli_epi32!16(r3_3));

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = _mm_or_si128(_mm_slli_epi32!12(r0_1), _mm_srli_epi32!20(r0_1));
        r1_1 = _mm_or_si128(_mm_slli_epi32!12(r1_1), _mm_srli_epi32!20(r1_1));
        r2_1 = _mm_or_si128(_mm_slli_epi32!12(r2_1), _mm_srli_epi32!20(r2_1));
        r3_1 = _mm_or_si128(_mm_slli_epi32!12(r3_1), _mm_srli_epi32!20(r3_1));

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = _mm_or_si128(_mm_slli_epi32!8(r0_3), _mm_srli_epi32!24(r0_3));
        r1_3 = _mm_or_si128(_mm_slli_epi32!8(r1_3), _mm_srli_epi32!24(r1_3));
        r2_3 = _mm_or_si128(_mm_slli_epi32!8(r2_3), _mm_srli_epi32!24(r2_3));
        r3_3 = _mm_or_si128(_mm_slli_epi32!8(r3_3), _mm_srli_epi32!24(r3_3));

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = _mm_or_si128(_mm_slli_epi32!7(r0_1), _mm_srli_epi32!25(r0_1));
        r1_1 = _mm_or_si128(_mm_slli_epi32!7(r1_1), _mm_srli_epi32!25(r1_1));
        r2_1 = _mm_or_si128(_mm_slli_epi32!7(r2_1), _mm_srli_epi32!25(r2_1));
        r3_1 = _mm_or_si128(_mm_slli_epi32!7(r3_1), _mm_srli_epi32!25(r3_1));

        r0_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r0_1);
        r0_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r0_2);
        r0_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r0_3);

        r1_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r1_1);
        r1_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r1_2);
        r1_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r1_3);

        r2_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r2_1);
        r2_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r2_2);
        r2_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r2_3);

        r3_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r3_1);
        r3_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r3_2);
        r3_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r3_3);

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = _mm_or_si128(_mm_slli_epi32!16(r0_3), _mm_srli_epi32!16(r0_3));
        r1_3 = _mm_or_si128(_mm_slli_epi32!16(r1_3), _mm_srli_epi32!16(r1_3));
        r2_3 = _mm_or_si128(_mm_slli_epi32!16(r2_3), _mm_srli_epi32!16(r2_3));
        r3_3 = _mm_or_si128(_mm_slli_epi32!16(r3_3), _mm_srli_epi32!16(r3_3));

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = _mm_or_si128(_mm_slli_epi32!12(r0_1), _mm_srli_epi32!20(r0_1));
        r1_1 = _mm_or_si128(_mm_slli_epi32!12(r1_1), _mm_srli_epi32!20(r1_1));
        r2_1 = _mm_or_si128(_mm_slli_epi32!12(r2_1), _mm_srli_epi32!20(r2_1));
        r3_1 = _mm_or_si128(_mm_slli_epi32!12(r3_1), _mm_srli_epi32!20(r3_1));

        r0_0 = _mm_add_epi32(r0_0, r0_1);
        r1_0 = _mm_add_epi32(r1_0, r1_1);
        r2_0 = _mm_add_epi32(r2_0, r2_1);
        r3_0 = _mm_add_epi32(r3_0, r3_1);

        r0_3 = _mm_xor_si128(r0_3, r0_0);
        r1_3 = _mm_xor_si128(r1_3, r1_0);
        r2_3 = _mm_xor_si128(r2_3, r2_0);
        r3_3 = _mm_xor_si128(r3_3, r3_0);

        r0_3 = _mm_or_si128(_mm_slli_epi32!8(r0_3), _mm_srli_epi32!24(r0_3));
        r1_3 = _mm_or_si128(_mm_slli_epi32!8(r1_3), _mm_srli_epi32!24(r1_3));
        r2_3 = _mm_or_si128(_mm_slli_epi32!8(r2_3), _mm_srli_epi32!24(r2_3));
        r3_3 = _mm_or_si128(_mm_slli_epi32!8(r3_3), _mm_srli_epi32!24(r3_3));

        r0_2 = _mm_add_epi32(r0_2, r0_3);
        r1_2 = _mm_add_epi32(r1_2, r1_3);
        r2_2 = _mm_add_epi32(r2_2, r2_3);
        r3_2 = _mm_add_epi32(r3_2, r3_3);

        r0_1 = _mm_xor_si128(r0_1, r0_2);
        r1_1 = _mm_xor_si128(r1_1, r1_2);
        r2_1 = _mm_xor_si128(r2_1, r2_2);
        r3_1 = _mm_xor_si128(r3_1, r3_2);

        r0_1 = _mm_or_si128(_mm_slli_epi32!7(r0_1), _mm_srli_epi32!25(r0_1));
        r1_1 = _mm_or_si128(_mm_slli_epi32!7(r1_1), _mm_srli_epi32!25(r1_1));
        r2_1 = _mm_or_si128(_mm_slli_epi32!7(r2_1), _mm_srli_epi32!25(r2_1));
        r3_1 = _mm_or_si128(_mm_slli_epi32!7(r3_1), _mm_srli_epi32!25(r3_1));

        r0_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r0_1);
        r0_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r0_2);
        r0_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r0_3);

        r1_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r1_1);
        r1_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r1_2);
        r1_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r1_3);

        r2_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r2_1);
        r2_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r2_2);
        r2_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r2_3);

        r3_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r3_1);
        r3_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r3_2);
        r3_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r3_3);
    }

    r0_0 = _mm_add_epi32(r0_0, input0);
    r0_1 = _mm_add_epi32(r0_1, input1);
    r0_2 = _mm_add_epi32(r0_2, input2);
    r0_3 = _mm_add_epi32(r0_3, input3);

    r1_0 = _mm_add_epi32(r1_0, input0);
    r1_1 = _mm_add_epi32(r1_1, input1);
    r1_2 = _mm_add_epi32(r1_2, input2);
    r1_3 = _mm_add_epi32(r1_3, input3);
    r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

    r2_0 = _mm_add_epi32(r2_0, input0);
    r2_1 = _mm_add_epi32(r2_1, input1);
    r2_2 = _mm_add_epi32(r2_2, input2);
    r2_3 = _mm_add_epi32(r2_3, input3);
    r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

    r3_0 = _mm_add_epi32(r3_0, input0);
    r3_1 = _mm_add_epi32(r3_1, input1);
    r3_2 = _mm_add_epi32(r3_2, input2);
    r3_3 = _mm_add_epi32(r3_3, input3);
    r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

    _mm_storeu_si128(output_mm + 0, r0_0);
    _mm_storeu_si128(output_mm + 1, r0_1);
    _mm_storeu_si128(output_mm + 2, r0_2);
    _mm_storeu_si128(output_mm + 3, r0_3);

    _mm_storeu_si128(output_mm + 4, r1_0);
    _mm_storeu_si128(output_mm + 5, r1_1);
    _mm_storeu_si128(output_mm + 6, r1_2);
    _mm_storeu_si128(output_mm + 7, r1_3);

    _mm_storeu_si128(output_mm + 8, r2_0);
    _mm_storeu_si128(output_mm + 9, r2_1);
    _mm_storeu_si128(output_mm + 10, r2_2);
    _mm_storeu_si128(output_mm + 11, r2_3);

    _mm_storeu_si128(output_mm + 12, r3_0);
    _mm_storeu_si128(output_mm + 13, r3_1);
    _mm_storeu_si128(output_mm + 14, r3_2);
    _mm_storeu_si128(output_mm + 15, r3_3);

    input[12] += 4;
    if (input[12] < 4)
        input[13]++;
}

static if (BOTAN_HAS_TESTS && !SKIP_STREAM_CIPHER_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.stream.chacha;
    import botan.utils.types;

    auto gs = globalState();
    size_t fails;

    void checkRounds(size_t rounds)
    {
        uint[16] st_p = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0, 0, 0x03020100, 0x07060504
        ];
        uint[16] st_s = st_p;
        ubyte[64 * 4] out_p;
        ubyte[64 * 4] out_s;
        chachaPortableX4(out_p, st_p, rounds);
        chachaSse2x4(out_s, st_s, rounds);
        if (out_p[] != out_s[])
        {
            logError("ChaCha SSE2 mismatch rounds ", rounds);
            ++fails;
        }
        if (st_p[12] != st_s[12] || st_p[13] != st_s[13])
        {
            logError("ChaCha SSE2 counter mismatch rounds ", rounds);
            ++fails;
        }
    }

    checkRounds(8);
    checkRounds(12);
    checkRounds(20);

    fails += checkMemutilsRepeat("chacha_sse2", {
        uint[16] st;
        st[0] = 0x61707865;
        st[1] = 0x3320646e;
        st[2] = 0x79622d32;
        st[3] = 0x6b206574;
        ubyte[64 * 4] outp;
        chachaSse2x4(outp, st, 20);
    });

    testReport("chacha_sse2", 3, fails);
    assert(fails == 0);
}
