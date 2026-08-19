/**
* Intel SHA-NI wrappers (SHA256RNDS2 / SHA256MSG1 / SHA256MSG2)
*
* Copyright:
* (C) 2017,2020,2025,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.simd.shaintrin;

import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2):

import botan.utils.simd.emmintrin;
import core.simd : int4;

version (GDC)
{
    __m128i _mm_sha256rnds2_epu32()(auto ref __m128i a, auto ref __m128i b, auto ref __m128i k)
    {
        return cast(__m128i) __builtin_ia32_sha256rnds2(cast(int4) a, cast(int4) b, cast(int4) k);
    }

    __m128i _mm_sha256msg1_epu32()(auto ref __m128i a, auto ref __m128i b)
    {
        return cast(__m128i) __builtin_ia32_sha256msg1(cast(int4) a, cast(int4) b);
    }

    __m128i _mm_sha256msg2_epu32()(auto ref __m128i a, auto ref __m128i b)
    {
        return cast(__m128i) __builtin_ia32_sha256msg2(cast(int4) a, cast(int4) b);
    }
}
else version (LDC)
{
    import ldc.gccbuiltins_x86;
    import ldc.llvmasm : __asm;
    // SHA256RNDS2 has an implicit XMM0 message+K operand. LDC's
    // gccbuiltin did not keep K in XMM0 (TLS 1.3 HS MAC failed). Pin
    // it. MSG1/MSG2 have no implicit XMM0.
    pragma(inline, true) __m128i _mm_sha256rnds2_epu32()(auto ref __m128i a, auto ref __m128i b, auto ref __m128i k)
    {
        return __asm!__m128i("sha256rnds2 $2, $0", "=x,0,x,{xmm0}", a, b, k);
    }
    pragma(inline, true) __m128i _mm_sha256msg1_epu32()(auto ref __m128i a, auto ref __m128i b)
    {
        return cast(__m128i) __builtin_ia32_sha256msg1(cast(int4) a, cast(int4) b);
    }
    pragma(inline, true) __m128i _mm_sha256msg2_epu32()(auto ref __m128i a, auto ref __m128i b)
    {
        return cast(__m128i) __builtin_ia32_sha256msg2(cast(int4) a, cast(int4) b);
    }
}
else version (D_InlineAsm_X86_64)
{
    __m128i _mm_sha256rnds2_epu32(__m128i a, __m128i b, __m128i k)
    {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        const(__m128i)* _k = &k;
        asm pure nothrow
        {
            mov RAX, _k;
            movdqu XMM0, [RAX];
            mov RAX, _b;
            movdqu XMM2, [RAX];
            mov RAX, _a;
            movdqu XMM1, [RAX];
            db 0x66, 0x0F, 0x38, 0xCB, 0xCA;
            movdqu [RAX], XMM1;
        }
        return a;
    }

    __m128i _mm_sha256msg1_epu32(__m128i a, __m128i b)
    {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        asm pure nothrow
        {
            mov RAX, _b;
            movdqu XMM2, [RAX];
            mov RAX, _a;
            movdqu XMM1, [RAX];
            db 0x0F, 0x38, 0xCC, 0xCA;
            movdqu [RAX], XMM1;
        }
        return a;
    }

    __m128i _mm_sha256msg2_epu32(__m128i a, __m128i b)
    {
        __m128i* _a = &a;
        const(__m128i)* _b = &b;
        asm pure nothrow
        {
            mov RAX, _b;
            movdqu XMM2, [RAX];
            mov RAX, _a;
            movdqu XMM1, [RAX];
            db 0x0F, 0x38, 0xCD, 0xCA;
            movdqu [RAX], XMM1;
        }
        return a;
    }
}
