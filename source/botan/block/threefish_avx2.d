/**
* Threefish-512 in AVX2
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.threefish_avx2;

import botan.constants;
static if (BOTAN_HAS_THREEFISH_512_AVX2):

import botan.block.threefish;
import botan.utils.simd.immintrin;
import botan.block.block_cipher;
import botan.utils.mem_ops;

/**
* Threefish-512
*/
final class Threefish512AVX2 : Threefish512
{
public:
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const ulong* K = &getK()[0];
        const ulong* T_64 = &getT()[0];
        
        const __m256i ROTATE_1 = _mm256_set_epi64x(37,19,36,46);
        const __m256i ROTATE_2 = _mm256_set_epi64x(42,14,27,33);
        const __m256i ROTATE_3 = _mm256_set_epi64x(39,36,49,17);
        const __m256i ROTATE_4 = _mm256_set_epi64x(56,54, 9,44);
        const __m256i ROTATE_5 = _mm256_set_epi64x(24,34,30,39);
        const __m256i ROTATE_6 = _mm256_set_epi64x(17,10,50,13);
        const __m256i ROTATE_7 = _mm256_set_epi64x(43,39,29,25);
        const __m256i ROTATE_8 = _mm256_set_epi64x(22,56,35, 8);
        
        
        /*
        v1.0 key schedule: 9 ymm registers (only need 2 or 3)
        (0,1,2,3),(4,5,6,7) [8]
        then mutating with vpermq
        */
        const __m256i K0 = _mm256_set_epi64x(K[6], K[4], K[2], K[0]);
        const __m256i K1 = _mm256_set_epi64x(K[7], K[5], K[3], K[1]);
        const __m256i K2 = _mm256_set_epi64x(K[8], K[6], K[4], K[2]);
        const __m256i K3 = _mm256_set_epi64x(K[0], K[7], K[5], K[3]);
        const __m256i K4 = _mm256_set_epi64x(K[1], K[8], K[6], K[4]);
        const __m256i K5 = _mm256_set_epi64x(K[2], K[0], K[7], K[5]);
        const __m256i K6 = _mm256_set_epi64x(K[3], K[1], K[8], K[6]);
        const __m256i K7 = _mm256_set_epi64x(K[4], K[2], K[0], K[7]);
        const __m256i K8 = _mm256_set_epi64x(K[5], K[3], K[1], K[8]);
        
        const __m256i ONE = _mm256_set_epi64x(1, 0, 0, 0);
        
        const __m256i* in_mm = cast(const __m256i*)(input);
        __m256i* out_mm = cast(__m256i*)(output);
        
        while (blocks >= 2)
        {
            __m256i X0 = _mm256_loadu_si256(in_mm++);
            __m256i X1 = _mm256_loadu_si256(in_mm++);
            __m256i X2 = _mm256_loadu_si256(in_mm++);
            __m256i X3 = _mm256_loadu_si256(in_mm++);
            
            const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);
            
            __m256i R = _mm256_set_epi64x(0, 0, 0, 0);
            
            interleave_epi64(X0, X1);
            interleave_epi64(X2, X3);
            
            mixin(THREEFISH_INJECT_KEY_2!(K0, K1, 2, 3)());
            
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K1,K2,K3, 1, 2, 3)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K3,K4,K5, 2, 3, 1)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K5,K6,K7, 3, 1, 2)());
            
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K7,K8,K0, 1, 2, 3)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K0,K1,K2, 2, 3, 1)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K2,K3,K4, 3, 1, 2)());
            
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K4,K5,K6, 1, 2, 3)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K6,K7,K8, 2, 3, 1)());
            mixin(THREEFISH_ENC_2_8_ROUNDS!(K8,K0,K1, 3, 1, 2)());
            
            deinterleave_epi64(X0, X1);
            deinterleave_epi64(X2, X3);
            
            _mm256_storeu_si256(out_mm++, X0);
            _mm256_storeu_si256(out_mm++, X1);
            _mm256_storeu_si256(out_mm++, X2);
            _mm256_storeu_si256(out_mm++, X3);
            
            blocks -= 2;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m256i X0 = _mm256_loadu_si256(in_mm++);
            __m256i X1 = _mm256_loadu_si256(in_mm++);
            
            const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);
            
            __m256i R = _mm256_set_epi64x(0, 0, 0, 0);
            
            interleave_epi64(X0, X1);
            
            mixin(THREEFISH_ENC_INJECT_KEY!(K0, K1, 2, 3)());
            
            mixin(THREEFISH_ENC_8_ROUNDS!(K1,K2,K3, 1, 2, 3)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K3,K4,K5, 2, 3, 1)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K5,K6,K7, 3, 1, 2)());
            
            mixin(THREEFISH_ENC_8_ROUNDS!(K7,K8,K0, 1, 2, 3)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K0,K1,K2, 2, 3, 1)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K2,K3,K4, 3, 1, 2)());
            
            mixin(THREEFISH_ENC_8_ROUNDS!(K4,K5,K6, 1, 2, 3)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K6,K7,K8, 2, 3, 1)());
            mixin(THREEFISH_ENC_8_ROUNDS!(K8,K0,K1, 3, 1, 2)());
            
            deinterleave_epi64(X0, X1);
            
            _mm256_storeu_si256(out_mm++, X0);
            _mm256_storeu_si256(out_mm++, X1);
        }
    }

    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        const ulong* K = &getK()[0];
        const ulong* T_64 = &getT()[0];
        
        const __m256i ROTATE_1 = _mm256_set_epi64x(37,19,36,46);
        const __m256i ROTATE_2 = _mm256_set_epi64x(42,14,27,33);
        const __m256i ROTATE_3 = _mm256_set_epi64x(39,36,49,17);
        const __m256i ROTATE_4 = _mm256_set_epi64x(56,54, 9,44);
        const __m256i ROTATE_5 = _mm256_set_epi64x(24,34,30,39);
        const __m256i ROTATE_6 = _mm256_set_epi64x(17,10,50,13);
        const __m256i ROTATE_7 = _mm256_set_epi64x(43,39,29,25);
        const __m256i ROTATE_8 = _mm256_set_epi64x(22,56,35, 8);
        
        /*
        v1.0 key schedule: 9 ymm registers (only need 2 or 3)
        (0,1,2,3),(4,5,6,7) [8]
        then mutating with vpermq
        */
        const __m256i K0 = _mm256_set_epi64x(K[6], K[4], K[2], K[0]);
        const __m256i K1 = _mm256_set_epi64x(K[7], K[5], K[3], K[1]);
        const __m256i K2 = _mm256_set_epi64x(K[8], K[6], K[4], K[2]);
        const __m256i K3 = _mm256_set_epi64x(K[0], K[7], K[5], K[3]);
        const __m256i K4 = _mm256_set_epi64x(K[1], K[8], K[6], K[4]);
        const __m256i K5 = _mm256_set_epi64x(K[2], K[0], K[7], K[5]);
        const __m256i K6 = _mm256_set_epi64x(K[3], K[1], K[8], K[6]);
        const __m256i K7 = _mm256_set_epi64x(K[4], K[2], K[0], K[7]);
        const __m256i K8 = _mm256_set_epi64x(K[5], K[3], K[1], K[8]);
        
        const __m256i ONE = _mm256_set_epi64x(1, 0, 0, 0);
        
        const __m256i* in_mm = cast(const __m256i*)(input);
        __m256i* out_mm = cast(__m256i*)(output);
        
        foreach (size_t i; 0 .. blocks)
        {
            __m256i X0 = _mm256_loadu_si256(in_mm++);
            __m256i X1 = _mm256_loadu_si256(in_mm++);
            
            const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);
            
            __m256i R = _mm256_set_epi64x(18, 0, 0, 0);
            
            interleave_epi64(X0, X1);

            mixin(THREEFISH_DEC_8_ROUNDS!(K8,K0,K1, 3, 1, 2)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K6,K7,K8, 2, 3, 1)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K4,K5,K6, 1, 2, 3)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K2,K3,K4, 3, 1, 2)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K0,K1,K2, 2, 3, 1)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K7,K8,K0, 1, 2, 3)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K5,K6,K7, 3, 1, 2)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K3,K4,K5, 2, 3, 1)());
            mixin(THREEFISH_DEC_8_ROUNDS!(K1,K2,K3, 1, 2, 3)());

            mixin(THREEFISH_DEC_INJECT_KEY!(K0, K1, 2, 3)());
            
            deinterleave_epi64(X0, X1);
            
            _mm256_storeu_si256(out_mm++, X0);
            _mm256_storeu_si256(out_mm++, X1);
        }
        
    }

    override BlockCipher clone() const { return new Threefish512AVX2; }
}

private:
    
void interleave_epi64(ref __m256i X0, ref __m256i X1) pure
{
    // interleave X0 and X1 qwords
    // (X0,X1,X2,X3),(X4,X5,X6,X7) . (X0,X2,X4,X6),(X1,X3,X5,X7)
    
    const __m256i T0 = _mm256_unpacklo_epi64(X0, X1);
    const __m256i T1 = _mm256_unpackhi_epi64(X0, X1);
    
    X0 = _mm256_permute4x64_epi64(T0, _MM_SHUFFLE(3,1,2,0));
    X1 = _mm256_permute4x64_epi64(T1, _MM_SHUFFLE(3,1,2,0));
}

void deinterleave_epi64(ref __m256i X0, ref __m256i X1) pure
{
    const __m256i T0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3,1,2,0));
    const __m256i T1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3,1,2,0));
    
    X0 = _mm256_unpacklo_epi64(T0, T1);
    X1 = _mm256_unpackhi_epi64(T0, T1);
}



string THREEFISH_ENC_ROUND(alias _SHL)()
{
    const SHL = __traits(identifier, _SHL);

    return `{const __m256i SHR = _mm256_sub_epi64(_mm256_set1_epi64x(64), ` ~ SHL ~ `);
            X0 = _mm256_add_epi64(X0, X1);
            X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, ` ~ SHL ~ `), _mm256_srlv_epi64(X1, SHR));
            X1 = _mm256_xor_si256(X1, X0);
            X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(0, 3, 2, 1));
            X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));}`;
}

string THREEFISH_ENC_ROUND_2(alias _SHL)()
{
    const SHL = __traits(identifier, _SHL);

    return `{const __m256i SHR = _mm256_sub_epi64(_mm256_set1_epi64x(64), ` ~ SHL ~ `);
            X0 = _mm256_add_epi64(X0, X1);
            X2 = _mm256_add_epi64(X2, X3);
            X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, ` ~ SHL ~ `), _mm256_srlv_epi64(X1, SHR));
            X3 = _mm256_or_si256(_mm256_sllv_epi64(X3, ` ~ SHL ~ `), _mm256_srlv_epi64(X3, SHR));
            X1 = _mm256_xor_si256(X1, X0);
            X3 = _mm256_xor_si256(X3, X2);
            X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(0, 3, 2, 1));
            X2 = _mm256_permute4x64_epi64(X2, _MM_SHUFFLE(0, 3, 2, 1));
            X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));
            X3 = _mm256_permute4x64_epi64(X3, _MM_SHUFFLE(1, 2, 3, 0));}`;
}

string THREEFISH_ENC_INJECT_KEY(alias _K0, alias _K1, ubyte _T0I, ubyte _T1I)()
{
    const K0 = __traits(identifier, _K0);
    const K1 = __traits(identifier, _K1);
    const T0I = _T0I.stringof;
    const T1I = _T1I.stringof;

    return `{const __m256i T0_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(` ~ T0I ~ `, 0, 0, 0));
            const __m256i T1_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, ` ~ T1I ~ `, 0, 0));
            X0 = _mm256_add_epi64(X0, ` ~ K0 ~ `);
            X1 = _mm256_add_epi64(X1, ` ~ K1 ~ `);
            X1 = _mm256_add_epi64(X1, R);
            X0 = _mm256_add_epi64(X0, T0_);
            X1 = _mm256_add_epi64(X1, T1_);
            R = _mm256_add_epi64(R, ONE);}`;
}

string THREEFISH_ENC_INJECT_KEY_2(alias _K0, alias _K1, ubyte _T0I, ubyte _T1I)()    
{
    const K0 = __traits(identifier, _K0);
    const K1 = __traits(identifier, _K1);
    const K2 = __traits(identifier, _K2);
    const T0I = _T0I.stringof;
    const T1I = _T1I.stringof;

    return `{const __m256i T0_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(` ~ T0I ~ `, 0, 0, 0));
            __m256i T1_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, ` ~ T1I ~ `, 0, 0));
            X0 = _mm256_add_epi64(X0, ` ~ K0 ~ `);
            X2 = _mm256_add_epi64(X2, ` ~ K0 ~ `);
            X1 = _mm256_add_epi64(X1, ` ~ K1 ~ `);
            X3 = _mm256_add_epi64(X3, ` ~ K1 ~ `);
            T1_ = _mm256_add_epi64(T1_, R);
            X0 = _mm256_add_epi64(X0, T0_);
            X2 = _mm256_add_epi64(X2, T0_);
            X1 = _mm256_add_epi64(X1, T1_);
            X3 = _mm256_add_epi64(X3, T1_);
            R = _mm256_add_epi64(R, ONE);}`;
}

string THREEFISH_ENC_8_ROUNDS(alias _K1, alias _K2, alias _K3, ubyte _T0, ubyte _T1, ubyte _T2)()
{
    const K1 = __traits(identifier, _K1);
    const K2 = __traits(identifier, _K2);
    const K3 = __traits(identifier, _K3);
    const T0 = _T0.stringof;
    const T1 = _T1.stringof;
    const T2 = _T2.stringof;

    return `mixin(THREEFISH_ENC_ROUND!(ROTATE_1)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_2)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_3)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_4)());
            mixin(THREEFISH_ENC_INJECT_KEY!(` ~ K1 ~ `, ` ~ K2 ~ `, ` ~ T0 ~ `, ` ~ T1 ~ `)());

            mixin(THREEFISH_ENC_ROUND!(ROTATE_5)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_6)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_7)());
            mixin(THREEFISH_ENC_ROUND!(ROTATE_8)());
            mixin(THREEFISH_ENC_INJECT_KEY!(` ~ K2 ~ `, ` ~ K3 ~ `, ` ~ T2 ~ `, ` ~ T0 ~ `)());`;
}

string THREEFISH_ENC_2_8_ROUNDS(alias _K1, alias _K2, alias _K3, ubyte _T0, ubyte _T1, ubyte _T2)()
{
    const K1 = __traits(identifier, _K1);
    const K2 = __traits(identifier, _K2);
    const K3 = __traits(identifier, _K3);
    const T0 = _T0.stringof;
    const T1 = _T1.stringof;
    const T2 = _T2.stringof;

    return `mixin(THREEFISH_ENC_ROUND_2!(ROTATE_1)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_2)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_3)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_4)());
            mixin(THREEFISH_ENC_INJECT_KEY_2!(` ~ K1 ~ `, ` ~ K2 ~ `, ` ~ T0 ~ `, ` ~ T1 ~ `)());

            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_5)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_6)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_7)());
            mixin(THREEFISH_ENC_ROUND_2!(ROTATE_8)());
            mixin(THREEFISH_ENC_INJECT_KEY_2!(` ~ K2 ~ `, ` ~ K3 ~ `, ` ~ T2 ~ `, ` ~ T0 ~ `)());`;
}

string THREEFISH_DEC_ROUND(alias _SHR)()
{
    const SHR = __traits(identifier, _SHR);

    return `{const __m256i SHL = _mm256_sub_epi64(_mm256_set1_epi64x(64), ` ~ SHR ~ `);
            X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(2, 1, 0, 3));
            X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));
            X1 = _mm256_xor_si256(X1, X0);
            X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, SHL), _mm256_srlv_epi64(X1, ` ~ SHR ~ `));
            X0 = _mm256_sub_epi64(X0, X1);}`;
}

string THREEFISH_DEC_INJECT_KEY(alias _K0, alias _K1, ubyte _T0I, ubyte _T1I)()
{
    const K0 = __traits(identifier, _K0);
    const K1 = __traits(identifier, _K1);
    const T0I = _T0I.stringof;
    const T1I = _T1I.stringof;
    return `{const __m256i T0_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(` ~ T0I ~ `, 0, 0, 0));
            const __m256i T1_ = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, ` ~ T1I ~ `, 0, 0));
            X0 = _mm256_sub_epi64(X0, ` ~ K0 ~ `);
            X1 = _mm256_sub_epi64(X1, ` ~ K1 ~ `);
            X1 = _mm256_sub_epi64(X1, R);
            R = _mm256_sub_epi64(R, ONE);
            X0 = _mm256_sub_epi64(X0, T0_);
            X1 = _mm256_sub_epi64(X1, T1_);}`;                    
}

string THREEFISH_DEC_8_ROUNDS(alias _K1, alias _K2, alias _K3, ubyte _T0, ubyte _T1, ubyte _T2)()
{
    const K1 = __traits(identifier, _K1);
    const K2 = __traits(identifier, _K2);
    const K3 = __traits(identifier, _K3);
    const T0 = _T0.stringof;
    const T1 = _T1.stringof;
    const T2 = _T2.stringof;

    return `mixin(THREEFISH_DEC_INJECT_KEY!(` ~ K2 ~ `, ` ~ K3 ~ `, ` ~ T2 ~ `, ` ~ T0 ~ `)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_8)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_7)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_6)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_5)());

            mixin(THREEFISH_DEC_INJECT_KEY!(` ~ K1 ~ `, ` ~ K2 ~ `, ` ~ T0 ~ `, ` ~ T1 ~ `)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_4)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_3)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_2)());
            mixin(THREEFISH_DEC_ROUND!(ROTATE_1)());`;
}
