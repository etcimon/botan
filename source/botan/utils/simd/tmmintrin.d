/**
* tmmintrin.h style functions
* 
* Copyright:
* (C) 2014-2015 Etienne Cimon
*
* License:
* Released under the MIT license
*/
module botan.utils.simd.tmmintrin;

import botan.constants;
static if (BOTAN_HAS_AES_SSSE3 && BOTAN_HAS_SIMD_SSE2):

public import botan.utils.simd.emmintrin;

version(GDC) {
@inline:
    // _mm_shuffle_epi8
    __m128i _mm_shuffle_epi8()(auto ref __m128i a, auto const ref __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }

    // _mm_alignr_epi8
    __m128i _mm_alignr_epi8(int n)(auto ref __m128i a, auto ref __m128i b) {
        return cast(__m128i) __builtin_ia32_palignr128(cast(long2) a, cast(long2) b, n*8); 
    }
}

version(LDC) {    
    // _mm_shuffle_epi8
    __m128i _mm_shuffle_epi8()(auto ref __m128i a, auto const ref __m128i b) {
        return cast(__m128i) __builtin_ia32_pshufb128(a, b);
    }

    __m128i _mm_alignr_epi8(int n)(auto ref __m128i a, auto ref __m128i b) {
        return cast(__m128i) __builtin_ia32_palignr128(cast(long2) a, cast(long2) b, n*8); 
    }
}

version(D_InlineAsm_X86_64) {
    // _mm_min_epi8 ; PSHUFB
    __m128i _mm_shuffle_epi8()(auto const ref __m128i a, auto const ref __m128i b) {
        
        const(__m128i)* _a = &a;
        const(__m128i)* _b = &b;
        __m128i c;
        __m128i* _c = &c;

        asm pure nothrow {
            mov RAX, _a;
            mov RBX, _b;
            mov RCX, _c;
            movdqu XMM1, [RAX];
            movdqu XMM2, [RBX];
            pshufb XMM1, XMM2;
            movdqu [RCX], XMM1;
        }
        return c;
    }

    // _mm_alignr_epi8 ; palignr
    __m128i _mm_alignr_epi8(int n)(auto const ref __m128i a, auto const ref __m128i b) {
        const(__m128i)* _a = &a;
        const(__m128i)* _b = &b;
        __m128i c;
        __m128i* _c = &c;

        mixin(`
            asm pure nothrow {
                mov RAX, _a;
                mov RBX, _b;
                mov RCX, _c;
                movdqu XMM1, [RAX];
                movdqu XMM2, [RBX];
                palignr XMM1, XMM2, ` ~ n.stringof ~ `;
                movdqu [RCX], XMM1;
            }
        `);

        return c;
    }
}