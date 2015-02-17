/**
* Lightweight wrappers for SIMD operations
* 
* Copyright:
* (C) 2009,2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.simd.simd_32;
import botan.utils.types;
import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2) {
    import botan.simd.simd_sse2;
    alias SIMD32 = SIMDSSE2; 
}
else static if (BOTAN_HAS_SIMD_ALTIVEC) {
      import botan.simd.simd_altivec;
    alias SIMD32 = SIMDAltivec;
}
else static if (BOTAN_HAS_SIMD_SCALAR) {
    import botan.simd.simd_scalar;
    alias SIMD32 = SIMDScalar!(uint,4); 
}