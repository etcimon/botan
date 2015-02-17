/**
* AES using AES-NI instructions
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.block.aes_ni;

import botan.constants;
static if (BOTAN_HAS_AES_NI):
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.simd.wmmintrin;
import botan.utils.mem_ops;

/**
* AES-128 using AES-NI
*/
final class AES128NI : BlockCipherFixedParams!(16, 16), BlockCipher, SymmetricAlgorithm
{
public:
    override @property size_t parallelism() const { return 4; }

    /*
    * AES-128 Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_EK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_ENC_4_ROUNDS!(K1)());
            mixin(AES_ENC_4_ROUNDS!(K2)());
            mixin(AES_ENC_4_ROUNDS!(K3)());
            mixin(AES_ENC_4_ROUNDS!(K4)());
            mixin(AES_ENC_4_ROUNDS!(K5)());
            mixin(AES_ENC_4_ROUNDS!(K6)());
            mixin(AES_ENC_4_ROUNDS!(K7)());
            mixin(AES_ENC_4_ROUNDS!(K8)());
            mixin(AES_ENC_4_ROUNDS!(K9)());
            mixin(AES_ENC_4_LAST_ROUNDS!(K10)());

            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);

            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesenc_si128(B, K1);
            B = _mm_aesenc_si128(B, K2);
            B = _mm_aesenc_si128(B, K3);
            B = _mm_aesenc_si128(B, K4);
            B = _mm_aesenc_si128(B, K5);
            B = _mm_aesenc_si128(B, K6);
            B = _mm_aesenc_si128(B, K7);
            B = _mm_aesenc_si128(B, K8);
            B = _mm_aesenc_si128(B, K9);
            B = _mm_aesenclast_si128(B, K10);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }

    /*
    * AES-128 Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_DK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_DEC_4_ROUNDS!(K1)());
            mixin(AES_DEC_4_ROUNDS!(K2)());
            mixin(AES_DEC_4_ROUNDS!(K3)());
            mixin(AES_DEC_4_ROUNDS!(K4)());
            mixin(AES_DEC_4_ROUNDS!(K5)());
            mixin(AES_DEC_4_ROUNDS!(K6)());
            mixin(AES_DEC_4_ROUNDS!(K7)());
            mixin(AES_DEC_4_ROUNDS!(K8)());
            mixin(AES_DEC_4_ROUNDS!(K9)());
            mixin(AES_DEC_4_LAST_ROUNDS!(K10)());
            
            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);
            
            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesdec_si128(B, K1);
            B = _mm_aesdec_si128(B, K2);
            B = _mm_aesdec_si128(B, K3);
            B = _mm_aesdec_si128(B, K4);
            B = _mm_aesdec_si128(B, K5);
            B = _mm_aesdec_si128(B, K6);
            B = _mm_aesdec_si128(B, K7);
            B = _mm_aesdec_si128(B, K8);
            B = _mm_aesdec_si128(B, K9);
            B = _mm_aesdeclast_si128(B, K10);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }


    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    @property string name() const { return "AES-128"; }
    override BlockCipher clone() const { return new AES128NI; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /*
    * AES-128 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(44);
        m_DK.resize(44);
        
        __m128i K0  = _mm_loadu_si128(cast(const(__m128i*))(key));
        mixin(`__m128i K1  = ` ~ AES_128_key_exp!("K0", 0x01)());
        mixin(`__m128i K2  = ` ~ AES_128_key_exp!("K1", 0x02)());
        mixin(`__m128i K3  = ` ~  AES_128_key_exp!("K2", 0x04)());
        mixin(`__m128i K4  = ` ~  AES_128_key_exp!("K3", 0x08)());
        mixin(`__m128i K5  = ` ~  AES_128_key_exp!("K4", 0x10)());
        mixin(`__m128i K6  = ` ~  AES_128_key_exp!("K5", 0x20)());
        mixin(`__m128i K7  = ` ~  AES_128_key_exp!("K6", 0x40)());
        mixin(`__m128i K8  = ` ~  AES_128_key_exp!("K7", 0x80)());
        mixin(`__m128i K9  = ` ~  AES_128_key_exp!("K8", 0x1B)());
        mixin(`__m128i K10 = ` ~  AES_128_key_exp!("K9", 0x36)());
        __m128i* EK_mm = cast(__m128i*)(m_EK.ptr);
        _mm_storeu_si128(EK_mm      , K0);
        mixin( q{
            _mm_storeu_si128(EK_mm +  1, K1);
            _mm_storeu_si128(EK_mm +  2, K2);
            _mm_storeu_si128(EK_mm +  3, K3);
            _mm_storeu_si128(EK_mm +  4, K4);
            _mm_storeu_si128(EK_mm +  5, K5);
            _mm_storeu_si128(EK_mm +  6, K6);
            _mm_storeu_si128(EK_mm +  7, K7);
            _mm_storeu_si128(EK_mm +  8, K8);
            _mm_storeu_si128(EK_mm +  9, K9);
            _mm_storeu_si128(EK_mm + 10, K10);
        });
        // Now generate decryption keys
        
        __m128i* DK_mm = cast(__m128i*)(m_DK.ptr);
        _mm_storeu_si128(DK_mm      , K10);
        _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K9));
        _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K8));
        _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K7));
        _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K6));
        _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K5));
        _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K4));
        _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K3));
        _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K2));
        _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K1));
        _mm_storeu_si128(DK_mm + 10, K0);
    }


    SecureVector!uint m_EK, m_DK;
}

/**
* AES-192 using AES-NI
*/
final class AES192NI : BlockCipherFixedParams!(16, 24), BlockCipher, SymmetricAlgorithm
{
public:
    override @property size_t parallelism() const { return 4; }

    /*
    * AES-192 Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_EK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        __m128i K11 = _mm_loadu_si128(key_mm + 11);
        __m128i K12 = _mm_loadu_si128(key_mm + 12);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_ENC_4_ROUNDS!(K1)());
            mixin(AES_ENC_4_ROUNDS!(K2)());
            mixin(AES_ENC_4_ROUNDS!(K3)());
            mixin(AES_ENC_4_ROUNDS!(K4)());
            mixin(AES_ENC_4_ROUNDS!(K5)());
            mixin(AES_ENC_4_ROUNDS!(K6)());
            mixin(AES_ENC_4_ROUNDS!(K7)());
            mixin(AES_ENC_4_ROUNDS!(K8)());
            mixin(AES_ENC_4_ROUNDS!(K9)());
            mixin(AES_ENC_4_ROUNDS!(K10)());
            mixin(AES_ENC_4_ROUNDS!(K11)());
            mixin(AES_ENC_4_LAST_ROUNDS!(K12)());
            
            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);
            
            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesenc_si128(B, K1);
            B = _mm_aesenc_si128(B, K2);
            B = _mm_aesenc_si128(B, K3);
            B = _mm_aesenc_si128(B, K4);
            B = _mm_aesenc_si128(B, K5);
            B = _mm_aesenc_si128(B, K6);
            B = _mm_aesenc_si128(B, K7);
            B = _mm_aesenc_si128(B, K8);
            B = _mm_aesenc_si128(B, K9);
            B = _mm_aesenc_si128(B, K10);
            B = _mm_aesenc_si128(B, K11);
            B = _mm_aesenclast_si128(B, K12);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }

    /*
    * AES-192 Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_DK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        __m128i K11 = _mm_loadu_si128(key_mm + 11);
        __m128i K12 = _mm_loadu_si128(key_mm + 12);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_DEC_4_ROUNDS!(K1)());
            mixin(AES_DEC_4_ROUNDS!(K2)());
            mixin(AES_DEC_4_ROUNDS!(K3)());
            mixin(AES_DEC_4_ROUNDS!(K4)());
            mixin(AES_DEC_4_ROUNDS!(K5)());
            mixin(AES_DEC_4_ROUNDS!(K6)());
            mixin(AES_DEC_4_ROUNDS!(K7)());
            mixin(AES_DEC_4_ROUNDS!(K8)());
            mixin(AES_DEC_4_ROUNDS!(K9)());
            mixin(AES_DEC_4_ROUNDS!(K10)());
            mixin(AES_DEC_4_ROUNDS!(K11)());
            mixin(AES_DEC_4_LAST_ROUNDS!(K12)());
            
            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);
            
            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesdec_si128(B, K1);
            B = _mm_aesdec_si128(B, K2);
            B = _mm_aesdec_si128(B, K3);
            B = _mm_aesdec_si128(B, K4);
            B = _mm_aesdec_si128(B, K5);
            B = _mm_aesdec_si128(B, K6);
            B = _mm_aesdec_si128(B, K7);
            B = _mm_aesdec_si128(B, K8);
            B = _mm_aesdec_si128(B, K9);
            B = _mm_aesdec_si128(B, K10);
            B = _mm_aesdec_si128(B, K11);
            B = _mm_aesdeclast_si128(B, K12);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }



    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }
    @property string name() const { return "AES-192"; }
    override BlockCipher clone() const { return new AES192NI; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /*
    * AES-192 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(52);
        m_DK.resize(52);
        
        __m128i K0 = _mm_loadu_si128(cast(const(__m128i*))(key));
        __m128i K1 = _mm_loadu_si128(cast(const(__m128i*))(key + 8));
        K1 = _mm_srli_si128!8(K1);
        
        loadLittleEndian(m_EK.ptr, key, 6);
        
        mixin(AES_192_key_exp!(0x01, 6)());
        mixin(AES_192_key_exp!(0x02, 12)());
        mixin(AES_192_key_exp!(0x04, 18)());
        mixin(AES_192_key_exp!(0x08, 24)());
        mixin(AES_192_key_exp!(0x10, 30)());
        mixin(AES_192_key_exp!(0x20, 36)());
        mixin(AES_192_key_exp!(0x40, 42)());
        mixin(AES_192_key_exp!(0x80, 48)());
        
        // Now generate decryption keys
        const(__m128i*) EK_mm = cast(const(__m128i*))(m_EK.ptr);
        
        __m128i* DK_mm = cast(__m128i*)(m_DK.ptr);
        _mm_storeu_si128(DK_mm      , _mm_loadu_si128(EK_mm + 12));
        _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 11)));
        _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 10)));
        _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 9)));
        _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 8)));
        _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 7)));
        _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 6)));
        _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 5)));
        _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 4)));
        _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 3)));
        _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 2)));
        _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 1)));
        _mm_storeu_si128(DK_mm + 12, _mm_loadu_si128(EK_mm + 0));
    }


    SecureVector!uint m_EK, m_DK;
}

/**
* AES-256 using AES-NI
*/
final class AES256NI : BlockCipherFixedParams!(16, 32), BlockCipher, SymmetricAlgorithm
{
public:
    override @property size_t parallelism() const { return 4; }

    /*
    * AES-256 Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        assert(m_EK.length >= 60);
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_EK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        __m128i K11 = _mm_loadu_si128(key_mm + 11);
        __m128i K12 = _mm_loadu_si128(key_mm + 12);
        __m128i K13 = _mm_loadu_si128(key_mm + 13);
        __m128i K14 = _mm_loadu_si128(key_mm + 14);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_ENC_4_ROUNDS!(K1)());
            mixin(AES_ENC_4_ROUNDS!(K2)());
            mixin(AES_ENC_4_ROUNDS!(K3)());
            mixin(AES_ENC_4_ROUNDS!(K4)());
            mixin(AES_ENC_4_ROUNDS!(K5)());
            mixin(AES_ENC_4_ROUNDS!(K6)());
            mixin(AES_ENC_4_ROUNDS!(K7)());
            mixin(AES_ENC_4_ROUNDS!(K8)());
            mixin(AES_ENC_4_ROUNDS!(K9)());
            mixin(AES_ENC_4_ROUNDS!(K10)());
            mixin(AES_ENC_4_ROUNDS!(K11)());
            mixin(AES_ENC_4_ROUNDS!(K12)());
            mixin(AES_ENC_4_ROUNDS!(K13)());
            mixin(AES_ENC_4_LAST_ROUNDS!(K14)());
            
            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);
            
            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesenc_si128(B, K1);
            B = _mm_aesenc_si128(B, K2);
            B = _mm_aesenc_si128(B, K3);
            B = _mm_aesenc_si128(B, K4);
            B = _mm_aesenc_si128(B, K5);
            B = _mm_aesenc_si128(B, K6);
            B = _mm_aesenc_si128(B, K7);
            B = _mm_aesenc_si128(B, K8);
            B = _mm_aesenc_si128(B, K9);
            B = _mm_aesenc_si128(B, K10);
            B = _mm_aesenc_si128(B, K11);
            B = _mm_aesenc_si128(B, K12);
            B = _mm_aesenc_si128(B, K13);
            B = _mm_aesenclast_si128(B, K14);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }

    /*
    * AES-256 Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        __m128i* in_mm = cast(__m128i*)(input);
        __m128i* out_mm = cast(__m128i*)(output);
        
        const(__m128i*) key_mm = cast(const(__m128i*))(m_DK.ptr);
        
        __m128i K0  = _mm_loadu_si128(key_mm);
        __m128i K1  = _mm_loadu_si128(key_mm + 1);
        __m128i K2  = _mm_loadu_si128(key_mm + 2);
        __m128i K3  = _mm_loadu_si128(key_mm + 3);
        __m128i K4  = _mm_loadu_si128(key_mm + 4);
        __m128i K5  = _mm_loadu_si128(key_mm + 5);
        __m128i K6  = _mm_loadu_si128(key_mm + 6);
        __m128i K7  = _mm_loadu_si128(key_mm + 7);
        __m128i K8  = _mm_loadu_si128(key_mm + 8);
        __m128i K9  = _mm_loadu_si128(key_mm + 9);
        __m128i K10 = _mm_loadu_si128(key_mm + 10);
        __m128i K11 = _mm_loadu_si128(key_mm + 11);
        __m128i K12 = _mm_loadu_si128(key_mm + 12);
        __m128i K13 = _mm_loadu_si128(key_mm + 13);
        __m128i K14 = _mm_loadu_si128(key_mm + 14);
        
        while (blocks >= 4)
        {
            __m128i B0 = _mm_loadu_si128(in_mm + 0);
            __m128i B1 = _mm_loadu_si128(in_mm + 1);
            __m128i B2 = _mm_loadu_si128(in_mm + 2);
            __m128i B3 = _mm_loadu_si128(in_mm + 3);
            
            B0 = _mm_xor_si128(B0, K0);
            B1 = _mm_xor_si128(B1, K0);
            B2 = _mm_xor_si128(B2, K0);
            B3 = _mm_xor_si128(B3, K0);
            
            mixin(AES_DEC_4_ROUNDS!(K1)());
            mixin(AES_DEC_4_ROUNDS!(K2)());
            mixin(AES_DEC_4_ROUNDS!(K3)());
            mixin(AES_DEC_4_ROUNDS!(K4)());
            mixin(AES_DEC_4_ROUNDS!(K5)());
            mixin(AES_DEC_4_ROUNDS!(K6)());
            mixin(AES_DEC_4_ROUNDS!(K7)());
            mixin(AES_DEC_4_ROUNDS!(K8)());
            mixin(AES_DEC_4_ROUNDS!(K9)());
            mixin(AES_DEC_4_ROUNDS!(K10)());
            mixin(AES_DEC_4_ROUNDS!(K11)());
            mixin(AES_DEC_4_ROUNDS!(K12)());
            mixin(AES_DEC_4_ROUNDS!(K13)());
            mixin(AES_DEC_4_LAST_ROUNDS!(K14)());
            
            _mm_storeu_si128(out_mm + 0, B0);
            _mm_storeu_si128(out_mm + 1, B1);
            _mm_storeu_si128(out_mm + 2, B2);
            _mm_storeu_si128(out_mm + 3, B3);
            
            blocks -= 4;
            in_mm += 4;
            out_mm += 4;
        }
        
        foreach (size_t i; 0 .. blocks)
        {
            __m128i B = _mm_loadu_si128(in_mm + i);
            
            B = _mm_xor_si128(B, K0);
            
            B = _mm_aesdec_si128(B, K1);
            B = _mm_aesdec_si128(B, K2);
            B = _mm_aesdec_si128(B, K3);
            B = _mm_aesdec_si128(B, K4);
            B = _mm_aesdec_si128(B, K5);
            B = _mm_aesdec_si128(B, K6);
            B = _mm_aesdec_si128(B, K7);
            B = _mm_aesdec_si128(B, K8);
            B = _mm_aesdec_si128(B, K9);
            B = _mm_aesdec_si128(B, K10);
            B = _mm_aesdec_si128(B, K11);
            B = _mm_aesdec_si128(B, K12);
            B = _mm_aesdec_si128(B, K13);
            B = _mm_aesdeclast_si128(B, K14);
            
            _mm_storeu_si128(out_mm + i, B);
        }
    }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        zap(m_EK);
        zap(m_DK);
    }

    @property string name() const { return "AES-256"; }
    override BlockCipher clone() const { return new AES256NI; }
    override size_t blockSize() const { return super.blockSize(); }
    override KeyLengthSpecification keySpec() const { return super.keySpec(); }
protected:
    /*
    * AES-256 Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        m_EK.resize(60);
        m_DK.resize(60);
        
        __m128i K0 = _mm_loadu_si128(cast(const(__m128i*))(key));
        __m128i K1 = _mm_loadu_si128(cast(const(__m128i*))(key + 16));
        
        __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128!0x01(K1));
        __m128i K3 = aes_256_key_expansion(K1, K2);
        
        __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128!0x02(K3));
        __m128i K5 = aes_256_key_expansion(K3, K4);
        
        __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128!0x04(K5));
        __m128i K7 = aes_256_key_expansion(K5, K6);
        
        __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128!0x08(K7));
        __m128i K9 = aes_256_key_expansion(K7, K8);
        
        __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128!0x10(K9));
        __m128i K11 = aes_256_key_expansion(K9, K10);
        
        __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128!0x20(K11));
        __m128i K13 = aes_256_key_expansion(K11, K12);
        
        __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128!0x40(K13));
        
        __m128i* EK_mm = cast(__m128i*)(m_EK.ptr);
        _mm_storeu_si128(EK_mm      , K0);
        _mm_storeu_si128(EK_mm +  1, K1);
        _mm_storeu_si128(EK_mm +  2, K2);
        _mm_storeu_si128(EK_mm +  3, K3);
        _mm_storeu_si128(EK_mm +  4, K4);
        _mm_storeu_si128(EK_mm +  5, K5);
        _mm_storeu_si128(EK_mm +  6, K6);
        _mm_storeu_si128(EK_mm +  7, K7);
        _mm_storeu_si128(EK_mm +  8, K8);
        _mm_storeu_si128(EK_mm +  9, K9);
        _mm_storeu_si128(EK_mm + 10, K10);
        _mm_storeu_si128(EK_mm + 11, K11);
        _mm_storeu_si128(EK_mm + 12, K12);
        _mm_storeu_si128(EK_mm + 13, K13);
        _mm_storeu_si128(EK_mm + 14, K14);
        
        // Now generate decryption keys
        __m128i* DK_mm = cast(__m128i*)(m_DK.ptr);
        _mm_storeu_si128(DK_mm      , K14);
        _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K13));
        _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K12));
        _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K11));
        _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K10));
        _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K9));
        _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K8));
        _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K7));
        _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K6));
        _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K5));
        _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
        _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
        _mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
        _mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
        _mm_storeu_si128(DK_mm + 14, K0);
    }


    SecureVector!uint m_EK, m_DK;
}

__m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon)
{
    key_with_rcon = _mm_shuffle_epi32!(_MM_SHUFFLE(3,3,3,3))(key_with_rcon);
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    return _mm_xor_si128(key, key_with_rcon);
}

void aes_192_key_expansion(__m128i* K1, __m128i* K2, __m128i key2_with_rcon,
                           uint* output, bool last)
{
    __m128i key1 = *K1;
    __m128i key2 = *K2;
    
    key2_with_rcon  = _mm_shuffle_epi32!(_MM_SHUFFLE(1,1,1,1))(key2_with_rcon);
    key1 = _mm_xor_si128(key1, _mm_slli_si128!4(key1));
    key1 = _mm_xor_si128(key1, _mm_slli_si128!4(key1));
    key1 = _mm_xor_si128(key1, _mm_slli_si128!4(key1));
    key1 = _mm_xor_si128(key1, key2_with_rcon);
    
    *K1 = key1;
    _mm_storeu_si128(cast(__m128i*)(output), key1);
    
    if (last)
        return;
    
    key2 = _mm_xor_si128(key2, _mm_slli_si128!4(key2));
    key2 = _mm_xor_si128(key2, _mm_shuffle_epi32!(_MM_SHUFFLE(3,3,3,3))(key1));
    
    *K2 = key2;
    output[4] = _mm_cvtsi128_si32(key2);
    output[5] = _mm_cvtsi128_si32(_mm_srli_si128!4(key2));
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
__m128i aes_256_key_expansion(__m128i key, __m128i key2)
{
    __m128i key_with_rcon = _mm_aeskeygenassist_si128!0x00(key2);
    key_with_rcon = _mm_shuffle_epi32!(_MM_SHUFFLE(2,2,2,2))(key_with_rcon);
    
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    key = _mm_xor_si128(key, _mm_slli_si128!4(key));
    return _mm_xor_si128(key, key_with_rcon);
}

string AES_ENC_4_ROUNDS(alias K)()
{ 
    const K2 = __traits(identifier, K);
    return `B0 = _mm_aesenc_si128(B0, ` ~ K2 ~ `);
            B1 = _mm_aesenc_si128(B1, ` ~ K2 ~ `);
            B2 = _mm_aesenc_si128(B2, ` ~ K2 ~ `);
            B3 = _mm_aesenc_si128(B3, ` ~ K2 ~ `);`;
}

string AES_ENC_4_LAST_ROUNDS(alias K)()
{
    const K2 = __traits(identifier, K);
    return `B0 = _mm_aesenclast_si128(B0, ` ~ K2 ~ `);
            B1 = _mm_aesenclast_si128(B1, ` ~ K2 ~ `);
            B2 = _mm_aesenclast_si128(B2, ` ~ K2 ~ `);
            B3 = _mm_aesenclast_si128(B3, ` ~ K2 ~ `);`;
}

string AES_DEC_4_ROUNDS(alias K)()
{
    const K2 = __traits(identifier, K);
    return `B0 = _mm_aesdec_si128(B0, ` ~ K2 ~ `);
            B1 = _mm_aesdec_si128(B1, ` ~ K2 ~ `);
            B2 = _mm_aesdec_si128(B2, ` ~ K2 ~ `);
            B3 = _mm_aesdec_si128(B3, ` ~ K2 ~ `);`;
}

string AES_DEC_4_LAST_ROUNDS(alias K)()
{
    const K2 = __traits(identifier, K);
    return `B0 = _mm_aesdeclast_si128(B0, ` ~ K2 ~ `);
            B1 = _mm_aesdeclast_si128(B1, ` ~ K2 ~ `);
            B2 = _mm_aesdeclast_si128(B2, ` ~ K2 ~ `);
            B3 = _mm_aesdeclast_si128(B3, ` ~ K2 ~ `);`;
}

string AES_128_key_exp(string K, ubyte RCON)() {
    return `aes_128_key_expansion(` ~ K ~ `, _mm_aeskeygenassist_si128!` ~ RCON.to!string ~ `(` ~ K ~ `));`;
}

string AES_192_key_exp(ubyte RCON, size_t EK_OFF)() {
    return `aes_192_key_expansion(&K0, &K1, 
                                  _mm_aeskeygenassist_si128! ` ~ RCON.to!string ~ `(K1),
                                  &m_EK[` ~ EK_OFF.stringof ~ `], ` ~ EK_OFF.stringof ~ ` == 48);`;
}
