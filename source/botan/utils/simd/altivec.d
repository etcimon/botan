/**
* altivec style functions
* 
* Copyright:
* (C) 2014-2015 Etienne Cimon
*
* License:
* Released under the MIT license
*/
module botan.utils.simd.altivec;
 
import botan.constants;
static if (BOTAN_HAS_SIMD_ALTIVEC):

import core.simd;

pure:
nothrow:
@trusted:

alias vector_uint = uint4;
alias vector_byte = byte16;

// todo: LDC & DMD
// warning: untested
version(GDC) {
    // GDC <--> immintrin => gcc/gcc/config/i386/immintrin.h
    static import gcc.attribute;
    import gcc.builtins;
    enum inline = gcc.attribute.attribute("forceinline");
    enum altivec = gcc.attribute.attribute("target", "powerpc_altivec_ok");
    
    @inline @altivec
    vector_uint vec_ld(int a1, in uint* a2) {
        return cast(vector_uint) __builtin_altivec_lvx(a1, cast(void*) a2);
    }

    @inline @altivec
    vector_byte vec_lvsl(int a1, in uint* a2) {
        if (!a2) {
            vector_uint a2_;
            return cast(vector_byte) __builtin_altivec_lvsl(a1, cast(void *) &a2_);
        }
        return cast(vector_byte) __builtin_altivec_lvsl(a1, cast(void *) a2);
    }

    @inline @altivec
    vector_byte vec_xor(vector_byte a1, in ubyte16 a2) {
        return cast(vector_byte) __builtin_altivec_vxor(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_perm(vector_uint a1, vector_uint a2, ubyte16 a3) {
        return cast(vector_uint) __builtin_altivec_vperm_4si(cast(int4) a1, cast(int4) a2, cast(vector_byte) a3);
    }

    @inline @altivec
    ubyte16 vec_splat_u8(in int a1) {
        return cast(ubyte16) __builtin_altivec_vspltisb(a1);
    }

    @inline @altivec
    vector_uint vec_rl(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vrlw(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_add(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vadduwm(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_sub(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vsubuwm(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_or(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vor(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_and(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vand(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_sl(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vslw(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_sr(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vsrw(cast(int4) a1, cast(int4) a2);
    }
    
    @inline @altivec
    vector_uint vec_nor(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vnor(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_andc(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vandc(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_mergeh(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vmrghw(cast(int4) a1, cast(int4) a2);
    }

    @inline @altivec
    vector_uint vec_mergel(vector_uint a1, vector_uint a2) {
        return cast(vector_uint) __builtin_altivec_vmrglw(cast(int4) a1, cast(int4) a2);
    }
}
