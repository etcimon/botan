/**
* immintrin.h style functions
* 
* Copyright:
* (C) 2014-2015 Etienne Cimon
*
* License:
* Released under the MIT license
*/
module botan.utils.simd.immintrin;


import botan.constants;

static if (BOTAN_HAS_THREEFISH_512_AVX2):

import core.simd;

alias __m256i = byte32;

pure:
nothrow:
@trusted:

int _MM_SHUFFLE(int a, int b, int c, int d)
{
    return (z<<6) | (y<<4) | (x<<2) | w;
}

version(GDC) {
    // GDC <--> immintrin => gcc/gcc/config/i386/immintrin.h
    static import gcc.attribute;
    import gcc.builtins;
    enum inline = gcc.attribute.attribute("forceinline");
    enum avx2 = gcc.attribute.attribute("target", "avx2");

    @inline @avx2
    __m256i _mm256_unpacklo_epi64(__m256i a, __m256i b) {
        return cast(__m256i) __builtin_ia32_punpcklqdq256(cast(long4) a, cast(long4) b);
    }


    @inline @avx2
    __m256i _mm256_unpackhi_epi64(__m256i a, __m256i b) {
        return cast(__m256i) __builtin_ia32_punpckhqdq256(cast(long4) a, cast(long4) b);
    }

    @inline @avx2
    __m256i _mm256_set_epi64x(long a, long b, long c, long d) {
        return cast(__m256i) long4([a, b, c, d]);
    }
    
    @inline @avx2
    void _mm256_storeu_si256(__m256i* ptr, __m256i a) {
        __builtin_ia32_storedqu256(ptr, a);
        return;
    }

    @inline @avx2
    __m256i _mm256_loadu_si256(__m256i* ptr) {
        return cast(__m256i) __builtin_ia32_loaddqu256(ptr);
    }


    @inline @avx2
    __m256i _mm256_permute4x64_epi64(__m256 X, in int M) {
        return cast(__m256i) __builtin_ia32_permdi256(cast(long4) X, M);
    }

    @inline @avx2
    __m256i _mm256_add_epi64(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_paddq256(cast(long4) a, cast(long4) b);
    }
    
    @inline @avx2
    __m256i _mm256_sub_epi64(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_psubq256(cast(long4) a, cast(long4) b);
    }

    @inline @avx2
    __m256i _mm256_xor_si256(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_pxor256(cast(long4) a, cast(long4) b);
    }

    @inline @avx2
    __m256i _mm256_or_si256(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_por256(cast(long4) a, cast(long4) b);
    }

    @inline @avx2
    __m256i _mm256_srlv_epi64(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_psrlv4di(cast(long4) a, cast(long4) b);
    }

    @inline @avx2
    __m256i _mm256_sllv_epi64(__m256 a, __m256 b) {
        return cast(__m256i) __builtin_ia32_psllv4di(cast(long4) a, cast(long4) b);
    }


}

version(LDC) {
    // LDC <--> immintrin ==> clang/test/CodeGen/avx2-builtins.c, rdrand-builtins.c

    pragma(LDC_inline_ir)
        R inlineIR(string s, R, P...)(P);

    pragma(LDC_intrinsic, "llvm.x86.rdrand.32")
        int _rdrand32_step(uint*);

    __m256i _mm256_set_epi64x(long a, long b, long c, long d) {
        return cast(__m256i) long4([a, b, c, d]);
    }

    __m256i _mm256_unpacklo_epi64(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`
            %tmp = shufflevector <4 x i64> %0, <4 x i64> %1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
            ret <4 x i64> %tmp`, 
              __m256i)(a, b);
    }

    __m256i _mm256_unpackhi_epi64(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`
            %tmp = shufflevector <4 x i64> %0, <4 x i64> %1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
            ret <4 x i64> %tmp`,
                __m256i)(a, b);
    }
    
    __m256i _mm256_loadu_si256(__m256i* a) {
        pragma(LDC_allow_inline);
        return inlineIR!(`
            %tmp = load <4 x i64>* %0, align 1
            ret <4 x i64> %tmp`,
                         __m256i)(a);
        
    }
    
    void _mm256_storeu_si256(__m256i* ptr, __m256i a) {
        pragma(LDC_allow_inline);
        return inlineIR!(`store <4 x i64> %1, <4 x i64>* %0
                             ret`,
                         void)(ptr, a);
        
    }
    
    __m256i _mm256_permute4x64_epi64(__m256i a, in int M) {
        pragma(LDC_allow_inline);

        int[4] val = [(M) & 0x3, ((M) & 0xc) >> 2, ((M) & 0x30) >> 4, ((M) & 0xc0) >> 6];
        return inlineIR!(`%tmp = shufflevector <4 x i64> %0, <4 x i64> undef, <i32 %1, i32 %2, i32 %3, i32 %4>
                             ret <4 x i64> %tmp`,
                         __m256i)(a, val[0], val[1], val[2], val[3]);        
    }
    
    __m256i _mm256_add_epi64(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`%tmp = add <4 x i64> %0, %1
                             ret <4 x i64> %tmp`,
                         __m256i)(a, b);
    }

    __m256i _mm256_sub_epi64(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`%tmp = sub <4 x i64> %0, %1
                             ret <4 x i64> %tmp`,
                         __m256i)(a, b);
    }
        
    __m256i _mm256_xor_si256(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`%tmp = xor <4 x i64> %0, %1
                             ret <4 x i64> %tmp`,
                         __m256i)(a, b);
    }
    
    __m256i _mm256_or_si256(__m256i a, __m256i b) {
        pragma(LDC_allow_inline);
        return inlineIR!(`%tmp = or <4 x i64> %0, %1
                             ret <4 x i64> %tmp`,
                         __m256i)(a, b);
    }

    pragma(LDC_intrinsic, "llvm.x86.avx2.psrlv.q.256")
        __m256i _mm256_srlv_epi64(__m256i a, __m256i b);

    pragma(LDC_intrinsic, "llvm.x86.avx2.psllv.q.256")
        __m256i _mm256_sllv_epi64(__m256i a, __m256i b);



}

version(D_InlineAsm_X86_64) {
    static assert(false, "DMD does not currently support AVX2.");

    __m256i _mm256_unpacklo_epi64(__m256i a, __m256i b) 
    {
        // http://www.felixcloutier.com/x86/PUNPCKLBW:PUNPCKLWD:PUNPCKLDQ:PUNPCKLQDQ.html

        __m256i ret;

        __m256i* _a = &a;
        __m256i* _b = &b;
        __m256i* _c = &ret;
        
        asm 
        {
            mov RAX, _a;
            mov RBX, _b;
            mov RCX, _c;
            vpunpcklqdq [RCX], [RAX], [RBX]; 
        }
        
        return ret;
        
    }

    __m256i _mm256_unpackhi_epi64(__m256i a, __m256i b) 
    {
        // http://www.felixcloutier.com/x86/PUNPCKHBW:PUNPCKHWD:PUNPCKHDQ:PUNPCKHQDQ.html

        __m256i ret;

        __m256i* _a = &a;
        __m256i* _b = &b;
        __m256i* _c = &ret;
        
        asm 
        {
            mov RAX, _a;
            mov RBX, _b;
            mov RCX, _c;
            vpunpckhqdq [RCX], [RAX], [RBX];
        }
        
        return ret;
        
    }

    __m256i _mm256_set_epi64x(long a, long b, long c, long d) {
        return cast(__m256i) long4([a, b, c, d]);
    }
    
    __m256i _mm256_loadu_si256(__m256i* a) 
    {
        // http://www.felixcloutier.com/x86/MOVDQU.html

        __m256i ret;
        __m256i* b = &ret;
        asm 
        {
            mov RAX, a;
            mov RBX, b;
            vmovdqu YMM0, [RAX];
            vmovdqu [RBX], YMM0;
        }
        
        return ret;
        
    }

    void _mm256_storeu_si256(__m256i* ptr, __m256i a) {

        __m256i ret;
        __m256i* _a = &a;
        __m256i* _b = &ret;
        asm 
        {
            mov RAX, _a;
            mov RBX, _b;
            vmovdqu YMM0, [RAX];
            vmovdqu [RBX], YMM0;
        }

        *ptr = ret;
                
    }

    __m256i _mm256_permute4x64_epi64(__m256i a, in int M) {
        __m256i ret;
        __m256i* _a = &a;
        __m256i* _b = &ret;
        ubyte[4] val = [cast(ubyte) ((M) & 0x3), cast(ubyte) (((M) & 0xc) >> 2), cast(ubyte) (((M) & 0x30) >> 4), cast(ubyte) (((M) & 0xc0) >> 6)];

        ubyte _imm8;
        _imm8 |= (val >> 0) & 0x3;
        _imm8 |= (val >> 2) & 0x3;
        _imm8 |= (val >> 4) & 0x3;
        _imm8 |= (val >> 6) & 0x3;

        asm 
        {
            mov imm8, _imm8;
            mov RAX, _a;
            mov RBX, _b;
            vmovdqu YMM0, [RAX];
            vmovdqu [RBX], YMM0;
        }
        
        *ptr = ret;    
    }

    // todo: Prepare the rest of the assembly. Use GDC/LDC in the meantime

}

// _mm256_unpacklo_epi64
// _mm256_unpackhi_epi64
// _mm256_set_epi64x
// _mm256_loadu_si256
// _mm256_storeu_si256
// _mm256_permute4x64_epi64
// _mm256_add_epi64
// _mm256_sub_epi64
// _mm256_xor_si256
// _mm256_or_si256
// _mm256_srlv_epi64
// _mm256_sllv_epi64
// _rdrand32_step => asm(".ubyte 0x0F, 0xC7, 0xF0; adcl $0,%1" : "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");