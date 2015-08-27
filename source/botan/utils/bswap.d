/**
* Byte Swapping Operations
* 
* Copyright:
* (C) 1999-2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
* (C) 2007 Yves Jerschow
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.bswap;

import botan.utils.types;
import botan.utils.rotate;

import botan.constants;
static if (BOTAN_HAS_SIMD_SSE2) {
  import botan.utils.simd.emmintrin;
}
/**
* Swap a 16 bit integer
*/
ushort reverseBytes(ushort val)
{
    return rotateLeft(val, 8);
}

/**
* Swap a 32 bit integer
*/
uint reverseBytes(uint val)
{
    import core.bitop : bswap;
    return bswap(val);
}

/**
* Swap a 64 bit integer
*/
ulong reverseBytes(ulong val)
{
    static if (is(typeof(bswap64)))
        return bswap64(val);
    else {
        union T { ulong u64; uint[2] u32; }
        T input, output;
        input.u64 = val;
        output.u32[0] = reverseBytes(input.u32[1]);
        output.u32[1] = reverseBytes(input.u32[0]);
        return output.u64;
    }
}

/**
* Swap 4 Ts in an array
*/
void bswap4(T)(ref T[4] x)
{
    x[0] = reverseBytes(x[0]);
    x[1] = reverseBytes(x[1]);
    x[2] = reverseBytes(x[2]);
    x[3] = reverseBytes(x[3]);
}

static if (BOTAN_HAS_SIMD_SSE2) {

    /**
    * Swap 4 uints in an array using SSE2 shuffle instructions
    */
    void bswap4(ref uint[4] x)
    {
        __m128i T = _mm_loadu_si128(cast(const(__m128i*))(x.ptr));

        const SHUF = _MM_SHUFFLE(2, 3, 0, 1);
        T = _mm_shufflehi_epi16!SHUF(T);
        T = _mm_shufflelo_epi16!SHUF(T);

        T =  _mm_or_si128(_mm_srli_epi16!8(T), _mm_slli_epi16!8(T));

        _mm_storeu_si128(cast(__m128i*)(x.ptr), T);
    }
}