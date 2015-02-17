/**
* IDEA in SSE2
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.idea_sse2;

import botan.constants;
static if (BOTAN_HAS_IDEA_SSE2 && BOTAN_HAS_SIMD_SSE2):

import botan.block.idea;
import botan.utils.simd.emmintrin;
import botan.block.block_cipher;
import botan.utils.mem_ops;
/**
* IDEA in SSE2
*/
final class IDEASSE2 : IDEA, SymmetricAlgorithm
{
public:
    override @property size_t parallelism() const { return 8; }
    override void clear()
    {
        super.clear();
    }

    /*
    * IDEA Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const ushort* KS = super.getEK().ptr;
        
        while (blocks >= 8)
        {
            idea_op_8(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(ushort[52]*) KS);
            input += 8 * BLOCK_SIZE;
            output += 8 * BLOCK_SIZE;
            blocks -= 8;
        }
        
        if (blocks)
            super.encryptN(input, output, blocks);
    }

    /*
    * IDEA Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const ushort* KS = this.getDK().ptr;
        
        while (blocks >= 8)
        {
            idea_op_8(*cast(ubyte[64]*) input, *cast(ubyte[64]*) output, *cast(ushort[52]*) KS);
            input += 8 * BLOCK_SIZE;
            output += 8 * BLOCK_SIZE;
            blocks -= 8;
        }
        
        if (blocks)
            super.decryptN(input, output, blocks);
    }
    override void keySchedule(const(ubyte)* key, size_t sz) { return super.keySchedule(key, sz); }
    override @property string name() const { return "IDEA"; }
    override BlockCipher clone() const { return new IDEASSE2; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
}

package:

__m128i mul(__m128i X, ushort K_16) pure
{
    const(__m128i) zeros = _mm_set1_epi16!(0)();
    const(__m128i) ones = _mm_set1_epi16!(1)();
    
    const(__m128i) K = _mm_set1_epi16(K_16);
    
    const(__m128i) X_is_zero = _mm_cmpeq_epi16(X, zeros);
    const(__m128i) K_is_zero = _mm_cmpeq_epi16(K, zeros);
    
    const(__m128i) mul_lo = _mm_mullo_epi16(X, K);
    const(__m128i) mul_hi = _mm_mulhi_epu16(X, K);
    
    __m128i T = _mm_sub_epi16(mul_lo, mul_hi);
    
    // Unsigned compare; cmp = 1 if mul_lo < mul_hi else 0
    const(__m128i) subs = _mm_subs_epu16(mul_hi, mul_lo);
    const(__m128i) cmp = _mm_min_epu8(_mm_or_si128(subs, _mm_srli_epi16!8(subs)), ones);
    
    T = _mm_add_epi16(T, cmp);
    
    /* Selection: if X[i] is zero then assign 1-K
                  if K is zero then assign 1-X[i]

        Could if () off value of K_16 for the second, but this gives a
        constant time implementation which is a nice bonus.
    */
    
    T = _mm_or_si128(
        _mm_andnot_si128(X_is_zero, T),
        _mm_and_si128(_mm_sub_epi16(ones, K), X_is_zero));
    
    T = _mm_or_si128(
        _mm_andnot_si128(K_is_zero, T),
        _mm_and_si128(_mm_sub_epi16(ones, X), K_is_zero));
    
    return T;
}

/*
* 4x8 matrix transpose
*
* FIXME: why do I need the extra set of unpack_epi32 here? Inverse in
* transpose_out doesn't need it. Something with the shuffle? Removing
* that extra unpack could easily save 3-4 cycles per block, and would
* also help a lot with register pressure on 32-bit x86
*/
void transpose_in(__m128i* B0, __m128i* B1, __m128i* B2, __m128i* B3) pure
{
    const SHUF = _MM_SHUFFLE(1, 3, 0, 2);
    const SHUF2 = _MM_SHUFFLE(3, 1, 2, 0);

    __m128i T0;
    __m128i T1;
    __m128i T2;
    __m128i T3;
    {
        __m128i B0_ = *B0;
        __m128i B1_ = *B1;
        __m128i B2_ = *B2;
        __m128i B3_ = *B3;
        T0 = _mm_unpackhi_epi32(B0_, B1_);
        T1 = _mm_unpacklo_epi32(B0_, B1_);
        T2 = _mm_unpackhi_epi32(B2_, B3_);
        T3 = _mm_unpacklo_epi32(B2_, B3_);
    }

    {
        __m128i T4 = _mm_unpacklo_epi32(T0, T1);
        __m128i T5 = _mm_unpackhi_epi32(T0, T1);
        __m128i T6 = _mm_unpacklo_epi32(T2, T3);
        __m128i T7 = _mm_unpackhi_epi32(T2, T3);
        
        T0 = _mm_shufflehi_epi16!SHUF(T4);
        T1 = _mm_shufflehi_epi16!SHUF(T5);
        T2 = _mm_shufflehi_epi16!SHUF(T6);
        T3 = _mm_shufflehi_epi16!SHUF(T7);
    }

    T0 = _mm_shufflelo_epi16!SHUF(T0);
    T1 = _mm_shufflelo_epi16!SHUF(T1);
    T2 = _mm_shufflelo_epi16!SHUF(T2);
    T3 = _mm_shufflelo_epi16!SHUF(T3);
    
    T0 = _mm_shuffle_epi32!SHUF2(T0);
    T1 = _mm_shuffle_epi32!SHUF2(T1);
    T2 = _mm_shuffle_epi32!SHUF2(T2);
    T3 = _mm_shuffle_epi32!SHUF2(T3);
    
    *B0 = _mm_unpacklo_epi64(T0, T2);
    *B1 = _mm_unpackhi_epi64(T0, T2);
    *B2 = _mm_unpacklo_epi64(T1, T3);
    *B3 = _mm_unpackhi_epi64(T1, T3);
}

/*
* 4x8 matrix transpose (reverse)
*/
void transpose_out(__m128i* B0, __m128i* B1, __m128i* B2, __m128i* B3) pure
{
    __m128i T0;
    __m128i T1;
    __m128i T2;
    __m128i T3;
    
    {
        __m128i B0_ = *B0;
        __m128i B1_ = *B1;
        __m128i B2_ = *B2;
        __m128i B3_ = *B3;
        T0 = _mm_unpacklo_epi64(B0_, B1_);
        T1 = _mm_unpacklo_epi64(B2_, B3_);
        T2 = _mm_unpackhi_epi64(B0_, B1_);
        T3 = _mm_unpackhi_epi64(B2_, B3_);
    }

    const SHUF = _MM_SHUFFLE(3, 1, 2, 0);

    T0 = _mm_shuffle_epi32!SHUF(T0);
    T1 = _mm_shuffle_epi32!SHUF(T1);
    T2 = _mm_shuffle_epi32!SHUF(T2);
    T3 = _mm_shuffle_epi32!SHUF(T3);
    
    T0 = _mm_shufflehi_epi16!SHUF(T0);
    T1 = _mm_shufflehi_epi16!SHUF(T1);
    T2 = _mm_shufflehi_epi16!SHUF(T2);
    T3 = _mm_shufflehi_epi16!SHUF(T3);
    
    T0 = _mm_shufflelo_epi16!SHUF(T0);
    T1 = _mm_shufflelo_epi16!SHUF(T1);
    T2 = _mm_shufflelo_epi16!SHUF(T2);
    T3 = _mm_shufflelo_epi16!SHUF(T3);
    
    *B0 = _mm_unpacklo_epi32(T0, T1);
    *B1 = _mm_unpackhi_epi32(T0, T1);
    *B2 = _mm_unpacklo_epi32(T2, T3);
    *B3 = _mm_unpackhi_epi32(T2, T3);
}

/*
* IDEA encryption/decryption in SSE2
*/
void idea_op_8(in ubyte[64] input, ref ubyte[64] output, in ushort[52] EK) pure
{
    const(__m128i*) in_mm = cast(const(__m128i*))(input.ptr);
    
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);
    
    transpose_in(&B0, &B1, &B2, &B3);
    
    // ubyte swap
    B0 = _mm_or_si128(_mm_slli_epi16!8(B0), _mm_srli_epi16!8(B0));
    B1 = _mm_or_si128(_mm_slli_epi16!8(B1), _mm_srli_epi16!8(B1));
    B2 = _mm_or_si128(_mm_slli_epi16!8(B2), _mm_srli_epi16!8(B2));
    B3 = _mm_or_si128(_mm_slli_epi16!8(B3), _mm_srli_epi16!8(B3));
    
    foreach (size_t i; 0 .. 8)
    {
        B0 = mul(B0, EK[6*i+0]);
        B1 = _mm_add_epi16(B1, _mm_set1_epi16(EK[6*i+1]));
        B2 = _mm_add_epi16(B2, _mm_set1_epi16(EK[6*i+2]));
        B3 = mul(B3, EK[6*i+3]);
        
        __m128i T0 = B2;
        
        B2 = _mm_xor_si128(B2, B0);
        B2 = mul(B2, EK[6*i+4]);
        
        __m128i T1 = B1;
        
        B1 = _mm_xor_si128(B1, B3);
        B1 = _mm_add_epi16(B1, B2);
        B1 = mul(B1, EK[6*i+5]);
        
        B2 = _mm_add_epi16(B2, B1);
        
        B0 = _mm_xor_si128(B0, B1);
        B1 = _mm_xor_si128(B1, T0);
        B3 = _mm_xor_si128(B3, B2);
        B2 = _mm_xor_si128(B2, T1);
    }
    
    B0 = mul(B0, EK[48]);
    B1 = _mm_add_epi16(B1, _mm_set1_epi16(EK[50]));
    B2 = _mm_add_epi16(B2, _mm_set1_epi16(EK[49]));
    B3 = mul(B3, EK[51]);
    
    // ubyte swap
    B0 = _mm_or_si128(_mm_slli_epi16!8(B0), _mm_srli_epi16!8(B0));
    B1 = _mm_or_si128(_mm_slli_epi16!8(B1), _mm_srli_epi16!8(B1));
    B2 = _mm_or_si128(_mm_slli_epi16!8(B2), _mm_srli_epi16!8(B2));
    B3 = _mm_or_si128(_mm_slli_epi16!8(B3), _mm_srli_epi16!8(B3));
    
    transpose_out(&B0, &B2, &B1, &B3);
    
    __m128i* out_mm = cast(__m128i*)(output.ptr);
    
    _mm_storeu_si128(out_mm + 0, B0);
    _mm_storeu_si128(out_mm + 1, B2);
    _mm_storeu_si128(out_mm + 2, B1);
    _mm_storeu_si128(out_mm + 3, B3);
}