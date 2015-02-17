/**
* GCM Mode
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.gcm;

import botan.constants;

static if (BOTAN_HAS_AEAD_GCM):

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.stream.ctr;
import botan.utils.xor_buf;
import botan.utils.loadstor;
import botan.utils.mem_ops;

import botan.utils.simd.immintrin;
import botan.utils.simd.wmmintrin;

import botan.utils.types;

import std.conv : to;

static if (BOTAN_HAS_GCM_CLMUL) {
    import botan.utils.simd.wmmintrin;
    import botan.utils.cpuid;
}

/**
* GCM Mode
*/
abstract class GCMMode : AEADMode, Transformation
{
public:
    ~this() { destroy(m_ctr); destroy(m_ghash); } // TODO: for some reason CTR needs to be destroyed before ghash

    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        SecureVector!ubyte y0 = SecureVector!ubyte(BS);
        
        if (nonce_len == 12)
        {
            copyMem(y0.ptr, nonce, nonce_len);
            y0[15] = 1;
        }
        else
        {
            y0 = m_ghash.nonceHash(nonce, nonce_len);
        }
        
        m_ctr.setIv(y0.ptr, y0.length);
        
        SecureVector!ubyte m_enc_y0 = SecureVector!ubyte(BS);
        m_ctr.encipher(m_enc_y0);
        
        m_ghash.start(m_enc_y0.ptr, m_enc_y0.length);
        
        return SecureVector!ubyte();
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        m_ghash.setAssociatedData(ad, ad_len);
    }

    override @property string name() const
    {
        return (m_cipher_name ~ "/GCM");
    }

    override size_t updateGranularity() const
    {
        return 4096; // CTR-BE's internal block size
    }

    override KeyLengthSpecification keySpec() const
    {
        return m_ctr.keySpec();
    }

    // GCM supports arbitrary nonce lengths
    override bool validNonceLength(size_t) const { return true; }

    override size_t tagSize() const { return m_tag_size; }

    override void clear()
    {
        m_ctr.clear();
        m_ghash.clear();

    }

    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_ctr.setKey(key, length);
        
        const Vector!ubyte zeros = Vector!ubyte(BS);
        m_ctr.setIv(zeros.ptr, zeros.length);
        
        SecureVector!ubyte H = SecureVector!ubyte(BS);
        m_ctr.encipher(H);
        m_ghash.setKey(H);
    }

    /*
    * GCMMode Constructor
    */
    this(BlockCipher cipher, size_t tag_size)
    { 
        m_tag_size = tag_size;
        m_cipher_name = cipher.name;
        if (cipher.blockSize() != BS)
            throw new InvalidArgument("GCM requires a 128 bit cipher so cannot be used with " ~ cipher.name);
        
        m_ghash = new GHASH;

        m_ctr = new CTRBE(cipher); // CTR_BE takes ownership of cipher
        
        if (m_tag_size != 8 && m_tag_size != 16)
            throw new InvalidArgument(name ~ ": Bad tag size " ~ to!string(m_tag_size));
    }

    __gshared immutable size_t BS = 16;

    const size_t m_tag_size;
    const string m_cipher_name;

    Unique!StreamCipher m_ctr;
    Unique!GHASH m_ghash;
}

/**
* GCM Encryption
*/
final class GCMEncryption : GCMMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = the 128 bit block cipher to use
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 16) 
    {
        super(cipher, tag_size);
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        m_ctr.cipher(buf, buf, sz);
        m_ghash.update(buf, sz);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        import std.algorithm : max;
        update(buffer, offset);
        auto mac = m_ghash.finished();
        buffer ~= mac.ptr[0 .. tagSize()];
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}

/**
* GCM Decryption
*/
final class GCMDecryption : GCMMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = the 128 bit block cipher to use
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 16)
    {
        super(cipher, tag_size);
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length > tagSize(), "Sufficient input");
        return input_length - tagSize();
    }

    override size_t minimumFinalSize() const { return tagSize(); }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        m_ghash.update(buf, sz);
        m_ctr.cipher(buf, buf, sz);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;

        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= tagSize(), "Have the tag as part of final input");
        
        const size_t remaining = sz - tagSize();
        
        // handle any final input before the tag
        if (remaining)
        {
            m_ghash.update(buf, remaining);

            m_ctr.cipher(buf, buf, remaining);
        }
        
        auto mac = m_ghash.finished();
        
        const(ubyte)* included_tag = &buffer[remaining];
        
        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("GCM tag check failed");
        
        buffer.resize(offset + remaining);
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}

/**
* GCM's GHASH
* Maybe a Transform?
*/
final class GHASH : SymmetricAlgorithm
{
public:
    void setAssociatedData(const(ubyte)* input, size_t length)
    {
        zeroise(m_H_ad);
        ghashUpdate(m_H_ad, input, length);
        m_ad_len = length;
    }

    SecureVector!ubyte nonceHash(const(ubyte)* nonce, size_t nonce_len)
    {
        assert(m_ghash.length == 0, "nonceHash called during wrong time");
        SecureVector!ubyte y0 = SecureVector!ubyte(16);
        
        ghashUpdate(y0, nonce, nonce_len);
        addFinalBlock(y0, 0, nonce_len);
        
        return y0.move;
    }

    void start(const(ubyte)* nonce, size_t len)
    {
        m_nonce[] = nonce[0 .. len];
        m_ghash = m_H_ad.dup;
    }

    /*
    * Assumes input len is multiple of 16
    */
    void update(const(ubyte)* input, size_t length)
    {
        assert(m_ghash.length == 16, "Key was set");
        
        m_text_len += length;
        
        ghashUpdate(m_ghash, input, length);
    }

    SecureVector!ubyte finished()
    {
        addFinalBlock(m_ghash, m_ad_len, m_text_len);
        m_ghash ^= m_nonce;
        m_text_len = 0;
        return m_ghash.move;
    }

    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(16); }

    override void clear()
    {
        zeroise(m_H);
        zeroise(m_H_ad);
        m_ghash.clear();
        m_text_len = m_ad_len = 0;
    }

    @property string name() const { return "GHASH"; }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_H[] = key[0 .. length];
        m_H_ad.resize(16);
        m_ad_len = 0;
        m_text_len = 0;
    }

private:
    void gcmMultiply(ref SecureVector!ubyte x)
    {
        import std.algorithm : max;
        static if (BOTAN_HAS_GCM_CLMUL) {
            if (CPUID.hasClmul()) {
                return gcmMultiplyClmul(*cast(ubyte[16]*) x.ptr, *cast(ubyte[16]*) m_H.ptr);
            }
        }
        
        __gshared immutable ulong R = 0xE100000000000000;
        
        ulong[2] H = [ loadBigEndian!ulong(m_H.ptr, 0), loadBigEndian!ulong(m_H.ptr, 1) ];
        ulong[2] Z = [ 0, 0 ];
        
        // SSE2 might be useful here        
        foreach (size_t i; 0 .. 2)
        {
            const ulong X = loadBigEndian!ulong(x.ptr, i);
            
            foreach (size_t j; 0 .. 64)
            {
                if ((X >> (63-j)) & 1)
                {
                    Z[0] ^= H[0];
                    Z[1] ^= H[1];
                }
                
                const ulong r = (H[1] & 1) ? R : 0;
                
                H[1] = (H[0] << 63) | (H[1] >> 1);
                H[0] = (H[0] >> 1) ^ r;
            }
        }
        
        storeBigEndian!ulong(x.ptr, Z[0], Z[1]);
    }

    void ghashUpdate(ref SecureVector!ubyte ghash, const(ubyte)* input, size_t length)
    {
        __gshared immutable size_t BS = 16;
        
        /*
        This assumes if less than block size input then we're just on the
        final block and should pad with zeros
        */
        while (length)
        {
            const size_t to_proc = std.algorithm.min(length, BS);
            
            xorBuf(ghash.ptr, input, to_proc);
            gcmMultiply(ghash);
            
            input += to_proc;
            length -= to_proc;
        }
    }

    void addFinalBlock(ref SecureVector!ubyte hash,
                       size_t ad_len, size_t text_len)
    {
        SecureVector!ubyte final_block = SecureVector!ubyte(16);
        storeBigEndian!ulong(final_block.ptr, 8*ad_len, 8*text_len);
        ghashUpdate(hash, final_block.ptr, final_block.length);
    }

    SecureVector!ubyte m_H;
    SecureVector!ubyte m_H_ad;
    SecureVector!ubyte m_nonce;
    SecureVector!ubyte m_ghash;
    size_t m_ad_len = 0, m_text_len = 0;
}



static if (BOTAN_HAS_GCM_CLMUL)
    void gcmMultiplyClmul(ref ubyte[16] x, in ubyte[16] H) 
{
    __gshared immutable(__m128i) BSWAP_MASK = _mm_set1_epi8!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])();
    version(D_InlineAsm_X86_64) {
        __m128i* a = cast(__m128i*) x.ptr;
        __m128i* b = cast(__m128i*) H.ptr;
        __m128i* c = cast(__m128i*) &BSWAP_MASK;

        asm pure nothrow {
            mov RAX, a;
            mov RBX, b;
            mov RCX, c;
            movdqu XMM13, [RAX];                        // __m128i a = _mm_loadu_si128(cast(const(__m128i*)) x.ptr);
            movdqu XMM14, [RBX];                        // __m128i b = _mm_loadu_si128(cast(const(__m128i*)) H.ptr);
            movdqu XMM15, [RCX];
            pshufb XMM13, XMM15;                         // a = _mm_shuffle_epi8(a, BSWAP_MASK);
            pshufb XMM14, XMM15;                         // b = _mm_shuffle_epi8(b, BSWAP_MASK);
            movdqa XMM0, XMM13; // XMM0 => T0
            movdqa XMM1, XMM13; // XMM1 => T1
            movdqa XMM2, XMM13; // XMM2 => T2
            movdqa XMM3, XMM13; // XMM3 => T3

            db 0x66, 0x41, 0x0F, 0x3A, 0x44, 0xC6, 0x00; // T0 = _mm_clmulepi64_si128!"0x00"(a, b);
            db 0x66, 0x41, 0x0F, 0x3A, 0x44, 0xCE, 0x01; // T1 = _mm_clmulepi64_si128!"0x01"(a, b);
            db 0x66, 0x41, 0x0F, 0x3A, 0x44, 0xD6, 0x10; // T2 = _mm_clmulepi64_si128!"0x10"(a, b);
            db 0x66, 0x41, 0x0F, 0x3A, 0x44, 0xDE, 0x11; // T3 = _mm_clmulepi64_si128!"0x11"(a, b);
            pxor XMM1, XMM2;                             // T1 = _mm_xor_si128(T1, T2);
            movdqa XMM6, XMM1;
            pslldq XMM6, 8;                                 // T2 = _mm_slli_si128!8(T1);
            movdqa XMM2, XMM6;
            psrldq XMM1, 8;                                 // T1 = _mm_srli_si128!8(T1);
            pxor XMM0, XMM2;                             // T0 = _mm_xor_si128(T0, T2);
            pxor XMM3, XMM1;                             // T3 = _mm_xor_si128(T3, T1);
            movdqa XMM6, XMM0;
            psrld XMM6, 31;                                 // T4 = _mm_srli_epi32!31(T0)
            movdqa XMM4, XMM6;
            pslld XMM0, 1;                                 // T0 = _mm_slli_epi32!1(T0);
            movdqa XMM6, XMM3;
            psrld XMM6, 31;
            movdqa XMM5, XMM6;                             // T5 = _mm_srli_epi32!31(T3);
            pslld XMM3, 1;                                 // T3 = _mm_slli_epi32!1(T3);
            movdqa XMM6, XMM4;
            psrldq XMM6, 12;                             // T2 = _mm_srli_si128!12(T4);
            movdqa XMM2, XMM6;
            pslldq XMM5, 4;                                 // T5 = _mm_slli_si128!4(T5);
            pslldq XMM4, 4;                                 // T4 = _mm_slli_si128!4(T4);
            por XMM0, XMM4;                                  // T0 = _mm_or_si128(T0, T4);
            por XMM3, XMM5;                                 // T3 = _mm_or_si128(T3, T5);
            por XMM3, XMM2;                                 // T3 = _mm_or_si128(T3, T2);
            movdqa XMM6, XMM0;
            pslld XMM6, 31;                                 // T4 = _mm_slli_epi32!31(T0);
            movdqa XMM4, XMM6;
            movdqa XMM6, XMM0;
            pslld XMM6, 30;                                 // T5 = _mm_slli_epi32!30(T0);
            movdqa XMM5, XMM6;
            movdqa XMM6, XMM0;
            pslld XMM6, 25;                                 // T2 = _mm_slli_epi32!25(T0);
            movdqa XMM2, XMM6;
            pxor XMM4, XMM5;                             // T4 = _mm_xor_si128(T4, T5);
            pxor XMM4, XMM2;                             // T4 = _mm_xor_si128(T4, T2);
            movdqa XMM6, XMM4;
            psrldq XMM6, 4;                                 // T5 = _mm_srli_si128!4(T4);
            movdqa XMM5, XMM6;
            pxor XMM3, XMM5;                             // T3 = _mm_xor_si128(T3, T5);
            pslldq XMM4, 12;                             // T4 = _mm_slli_si128!12(T4);
            pxor XMM0, XMM4;                             // T0 = _mm_xor_si128(T0, T4);
            pxor XMM3, XMM0;                             // T3 = _mm_xor_si128(T3, T0);
            movdqa XMM6, XMM0;
            psrld XMM6, 1;                                 // T4 = _mm_srli_epi32!1(T0);
            movdqa XMM4, XMM6;
            movdqa XMM6, XMM0;
            psrld XMM6, 2;                                 // T1 = _mm_srli_epi32!2(T0);
            movdqa XMM1, XMM6;
            movdqa XMM6, XMM0;
            psrld XMM6, 7;                                 // T2 = _mm_srli_epi32!7(T0);
            movdqa XMM2, XMM6;
            pxor XMM3, XMM1;                             // T3 = _mm_xor_si128(T3, T1);
            pxor XMM3, XMM2;                             // T3 = _mm_xor_si128(T3, T2);
            pxor XMM3, XMM4;                             // T3 = _mm_xor_si128(T3, T4);
            mov RCX, c;
            movdqu XMM15, [RCX];
            pshufb XMM3, XMM15;                             // T3 = _mm_shuffle_epi8(T3, BSWAP_MASK);
            mov RAX, a;
            movdqu [RAX], XMM3;                             // _mm_storeu_si128(cast(__m128i*) x.ptr, T3);
        }
    }
    else {
        /*
        * Algorithms 1 and 5 from Intel's CLMUL guide
        */        
        __m128i a = _mm_loadu_si128(cast(const(__m128i*)) x.ptr);
        __m128i b = _mm_loadu_si128(cast(const(__m128i*)) H.ptr);
        
        a = _mm_shuffle_epi8(a, BSWAP_MASK);
        b = _mm_shuffle_epi8(b, BSWAP_MASK);
        
        __m128i T0, T1, T2, T3, T4, T5;
        
        T0 = _mm_clmulepi64_si128!"0x00"(a, b);
        T1 = _mm_clmulepi64_si128!"0x01"(a, b);
        T2 = _mm_clmulepi64_si128!"0x10"(a, b);
        T3 = _mm_clmulepi64_si128!"0x11"(a, b);
        
        T1 = _mm_xor_si128(T1, T2);
        T2 = _mm_slli_si128!8(T1);
        T1 = _mm_srli_si128!8(T1);
        T0 = _mm_xor_si128(T0, T2);
        T3 = _mm_xor_si128(T3, T1);
        
        T4 = _mm_srli_epi32!31(T0);
        T0 = _mm_slli_epi32!1(T0);
        
        T5 = _mm_srli_epi32!31(T3);
        T3 = _mm_slli_epi32!1(T3);
        
        T2 = _mm_srli_si128!12(T4);
        T5 = _mm_slli_si128!4(T5);
        T4 = _mm_slli_si128!4(T4);
        T0 = _mm_or_si128(T0, T4);
        T3 = _mm_or_si128(T3, T5);
        T3 = _mm_or_si128(T3, T2);
        
        T4 = _mm_slli_epi32!31(T0);
        T5 = _mm_slli_epi32!30(T0);
        T2 = _mm_slli_epi32!25(T0);
        
        T4 = _mm_xor_si128(T4, T5);
        T4 = _mm_xor_si128(T4, T2);
        T5 = _mm_srli_si128!4(T4);
        T3 = _mm_xor_si128(T3, T5);
        T4 = _mm_slli_si128!12(T4);
        T0 = _mm_xor_si128(T0, T4);
        T3 = _mm_xor_si128(T3, T0);
        
        T4 = _mm_srli_epi32!1(T0);
        T1 = _mm_srli_epi32!2(T0);
        T2 = _mm_srli_epi32!7(T0);
        T3 = _mm_xor_si128(T3, T1);
        T3 = _mm_xor_si128(T3, T2);
        T3 = _mm_xor_si128(T3, T4);
        
        T3 = _mm_shuffle_epi8(T3, BSWAP_MASK);
        
        _mm_storeu_si128(cast(__m128i*) x.ptr, T3);
    }
}