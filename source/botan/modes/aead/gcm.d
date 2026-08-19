/**
* GCM Mode
* 
* Copyright:
* (C) 2013,2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
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
import core.stdc.string : memset;

import botan.utils.simd.immintrin;
import botan.utils.simd.wmmintrin;

import botan.utils.types;

import std.conv : to;
import std.algorithm : min;

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
    ~this()
    {
        // Member dtor order is m_ghash then m_ctr; CTR must go first. Skip in a
        // GC finalizer — Unique!(T,void) also refuses to .destroy payloads there.
        if (botanInGcFinalizer())
            return;
        m_ctr.free();
        m_ghash.free();
    }

    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);

        if (m_y0.length != BS) m_y0.resize(BS);
        if (m_enc_y0.length != BS) m_enc_y0.resize(BS);

        if (nonce_len == 12)
        {
            copyMem(m_y0.ptr, nonce, nonce_len);
            memset(m_y0.ptr + nonce_len, 0, BS - nonce_len);
            m_y0[15] = 1;
        }
        else
        {
            m_y0 = m_ghash.nonceHash(nonce, nonce_len);
        }

        m_ctr.setIv(m_y0.ptr, m_y0.length);
        memset(m_enc_y0.ptr, 0, BS);
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

        // 32-bit CTR (C++); 32-block pad (512 B) matches the 128-byte CTR+GHASH
        // stripe. pad=256 skip-LSB increment is only valid for 256-block pads.
        m_ctr = new CTRBE(cipher, 4, 32);
        
        if (m_tag_size != 8 && (m_tag_size < 12 || m_tag_size > 16))
            throw new InvalidArgument(name ~ ": Bad tag size " ~ to!string(m_tag_size));
    }

    __gshared immutable size_t BS = 16;

    const size_t m_tag_size;
    const string m_cipher_name;

    Unique!StreamCipher m_ctr;
    Unique!GHASH m_ghash;
    SecureVector!ubyte m_y0;
    SecureVector!ubyte m_enc_y0;
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
        auto mac = m_ghash.finishTag();
        buffer ~= mac[0 .. tagSize()];
    }

    /**
    * Encrypt `len` bytes in place and write the tag at `tag_out`.
    * Params:
    *  buf = plaintext (overwritten with ciphertext)
    *  len = length of buf
    *  tag_out = tagSize() bytes for the authentication tag
    */
    void processRaw(ubyte* buf, size_t len, ubyte* tag_out)
    {
        processRaw(buf, buf, len, tag_out);
    }

    /**
    * CTR from `input` into `output` (may alias), then GHASH `output`.
    * Params:
    *  input = plaintext
    *  output = ciphertext (may alias input)
    *  len = length
    *  tag_out = tagSize() bytes for the authentication tag
    */
    void processRaw(const(ubyte)* input, ubyte* output, size_t len, ubyte* tag_out)
    {
        stripeCtrGhash(input, output, len);
        auto mac = m_ghash.finishTag();
        copyMem(tag_out, mac.ptr, tagSize());
    }

    /// CTR+GHASH `len` bytes, append `extra` as a 1-byte inner type, write tag.
    void processRaw(const(ubyte)* input, ubyte* output, size_t len, ubyte extra, ubyte* tag_out)
    {
        stripeCtrGhash(input, output, len);
        output[len] = extra;
        stripeCtrGhash(output + len, output + len, 1);
        auto mac = m_ghash.finishTag();
        copyMem(tag_out, mac.ptr, tagSize());
    }

    private void stripeCtrGhash(const(ubyte)* input, ubyte* output, size_t len)
    {
        // Stripe CTR and GHASH so each 128-byte chunk stays in L1.
        // Pull Unique/interface thunks once (callgrind Unique.fallthrough ~1%).
        GHASH gh = *m_ghash;
        if (auto ctr = cast(CTRBE)(*m_ctr))
        {
            while (len >= 128)
            {
                ctr.cipher(input, output, 128);
                gh.update(output, 128);
                input += 128;
                output += 128;
                len -= 128;
            }
            if (len)
            {
                ctr.cipher(input, output, len);
                gh.update(output, len);
            }
            return;
        }
        StreamCipher ctr = *m_ctr;
        while (len >= 128)
        {
            ctr.cipher(input, output, 128);
            gh.update(output, 128);
            input += 128;
            output += 128;
            len -= 128;
        }
        if (len)
        {
            ctr.cipher(input, output, len);
            gh.update(output, len);
        }
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
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
        
        auto mac = m_ghash.finishTag();

        const(ubyte)* included_tag = &buffer[remaining];

        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("GCM tag check failed");
        
        buffer.resize(offset + remaining);
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
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
        if (m_nonce.length != len) m_nonce.resize(len);
        copyMem(m_nonce.ptr, nonce, len);
        if (m_ghash.length != m_H_ad.length) m_ghash.resize(m_H_ad.length);
        if (m_H_ad.length)
            copyMem(m_ghash.ptr, m_H_ad.ptr, m_H_ad.length);
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

    const(ubyte)[] finishTag()
    {
        addFinalBlock(m_ghash, m_ad_len, m_text_len);
        m_ghash ^= m_nonce;
        m_text_len = 0;
        return m_ghash[];
    }

    SecureVector!ubyte finished()
    {
        auto tag = finishTag();
        return SecureVector!ubyte(tag);
    }

    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(16); }

    override void clear()
    {
        zeroise(m_H);
        zeroise(m_H_ad);
        m_ghash.clear();
        m_text_len = m_ad_len = 0;
        static if (BOTAN_HAS_GCM_CLMUL)
        {
            m_H2[] = 0;
            m_H3[] = 0;
            m_H4[] = 0;
            m_H5[] = 0;
            m_H6[] = 0;
            m_H7[] = 0;
            m_H8[] = 0;
            version (LDC)
                m_Hb = m_Hb.init;
        }
    }

    @property string name() const { return "GHASH"; }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_H[] = key[0 .. length];
        m_H_ad.resize(16);
        m_ad_len = 0;
        m_text_len = 0;
        static if (BOTAN_HAS_GCM_CLMUL)
        {
            m_clmul = CPUID.hasGcmClmul();
            if (m_clmul)
            {
                m_H2 = *cast(ubyte[16]*) m_H.ptr;
                gcmMultiplyClmul(m_H2, *cast(ubyte[16]*) m_H.ptr);
                m_H3 = m_H2;
                gcmMultiplyClmul(m_H3, *cast(ubyte[16]*) m_H.ptr);
                m_H4 = m_H2;
                gcmMultiplyClmul(m_H4, m_H2);
                m_H5 = m_H4;
                gcmMultiplyClmul(m_H5, *cast(ubyte[16]*) m_H.ptr);
                m_H6 = m_H4;
                gcmMultiplyClmul(m_H6, m_H2);
                m_H7 = m_H4;
                gcmMultiplyClmul(m_H7, m_H3);
                m_H8 = m_H4;
                gcmMultiplyClmul(m_H8, m_H4);
                version (LDC)
                {
                    void storeHb(size_t i, in ubyte[16] src)
                    {
                        auto v = gcmBswap(gcmLoadu(src.ptr));
                        m_Hb[i][] = (cast(ubyte*) &v)[0 .. 16];
                    }
                    storeHb(0, *cast(ubyte[16]*) m_H.ptr);
                    storeHb(1, m_H2);
                    storeHb(2, m_H3);
                    storeHb(3, m_H4);
                    storeHb(4, m_H5);
                    storeHb(5, m_H6);
                    storeHb(6, m_H7);
                    storeHb(7, m_H8);
                }
            }
        }
    }

private:
    void gcmMultiply(ref SecureVector!ubyte x)
    {
        import std.algorithm : max;
        static if (BOTAN_HAS_GCM_CLMUL) {
            if (CPUID.hasGcmClmul()) {
                gcmMultiplyClmul(*cast(ubyte[16]*) x.ptr, *cast(ubyte[16]*) m_H.ptr);
                return;
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
        enum size_t BS = 16;
        static if (BOTAN_HAS_GCM_CLMUL)
        {
            if (m_clmul)
            {
                auto yp = ghash.ptr;
                const h = *cast(ubyte[16]*) m_H.ptr;
                version (LDC)
                {
                    while (length >= 128)
                    {
                        gcmMultiplyClmul8(yp, input, m_Hb[0], m_Hb[1], m_Hb[2], m_Hb[3],
                                          m_Hb[4], m_Hb[5], m_Hb[6], m_Hb[7]);
                        input += 128;
                        length -= 128;
                    }
                    while (length >= 64)
                    {
                        gcmMultiplyClmul4(yp, input, m_Hb[0], m_Hb[1], m_Hb[2], m_Hb[3]);
                        input += 64;
                        length -= 64;
                    }
                }
                else
                {
                    while (length >= 128)
                    {
                        gcmMultiplyClmul8(yp, input, h, m_H2, m_H3, m_H4,
                                          m_H5, m_H6, m_H7, m_H8);
                        input += 128;
                        length -= 128;
                    }
                    while (length >= 64)
                    {
                        gcmMultiplyClmul4(yp, input, h, m_H2, m_H3, m_H4);
                        input += 64;
                        length -= 64;
                    }
                }
                while (length >= BS)
                {
                    *cast(ulong*) yp ^= *cast(const ulong*) input;
                    *cast(ulong*)(yp + 8) ^= *cast(const ulong*)(input + 8);
                    gcmMultiplyClmul(*cast(ubyte[16]*) yp, h);
                    input += BS;
                    length -= BS;
                }
                if (length)
                {
                    xorBuf(yp, input, length);
                    gcmMultiplyClmul(*cast(ubyte[16]*) yp, h);
                }
                return;
            }
        }
        while (length)
        {
            const size_t to_proc = min(length, BS);
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
    static if (BOTAN_HAS_GCM_CLMUL)
    {
        bool m_clmul;
        ubyte[16] m_H2, m_H3, m_H4, m_H5, m_H6, m_H7, m_H8;
        version (LDC)
            ubyte[16][8] m_Hb;
    }
}



static if (BOTAN_HAS_GCM_CLMUL)
    void gcmMultiplyClmul(ref ubyte[16] x, in ubyte[16] H) 
{
    __gshared immutable(__m128i) BSWAP_MASK = _mm_set1_epi8!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])();
	version (D_InlineAsm_X86_64)
		enum USE_ASM = true;
	else
		enum USE_ASM = false;

    static if (USE_ASM) {
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

static if (BOTAN_HAS_GCM_CLMUL) version (LDC)
{
    import ldc.gccbuiltins_x86;
    import core.simd : byte16, long2, int4;

    pragma(inline, true) byte16 gcmLoadu(const(ubyte)* p)
    {
        auto q = cast(const long*) p;
        long2 v = void;
        v.array[0] = q[0];
        v.array[1] = q[1];
        return cast(byte16) v;
    }
    pragma(inline, true) byte16 gcmBswap(byte16 v)
    {
        immutable byte16 m = byte16([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        return __builtin_ia32_pshufb128(v, m);
    }
    // Byte shifts: long2 move for 8, SSSE3 pshufb otherwise. ldc.llvmasm
    // psrldq/pslldq does not inline (callgrind _mm_srli_si128!(8) ~15% Ir).
    private template gcmPshufbSrliStr(int n)
    {
        enum string gcmPshufbSrliStr = {
            string s = "byte16([";
            foreach (i; 0 .. 16)
            {
                if (i) s ~= ",";
                immutable src = i + n;
                s ~= src >= 16 ? "cast(byte)0x80" : to!string(src);
            }
            return s ~ "])";
        }();
    }
    private template gcmPshufbSlliStr(int n)
    {
        enum string gcmPshufbSlliStr = {
            string s = "byte16([";
            foreach (i; 0 .. 16)
            {
                if (i) s ~= ",";
                s ~= (i < n) ? "cast(byte)0x80" : to!string(i - n);
            }
            return s ~ "])";
        }();
    }
    pragma(inline, true) byte16 gcmSlliBytes(int n)(byte16 v)
    {
        static if (n == 0) return v;
        else static if (n >= 16) { long2 z = 0; return cast(byte16) z; }
        else static if (n == 8)
        {
            long2 r = void;
            auto s = cast(long2) v;
            r.array[0] = 0;
            r.array[1] = s.array[0];
            return cast(byte16) r;
        }
        else
        {
            enum byte16 mask = mixin(gcmPshufbSlliStr!n);
            return __builtin_ia32_pshufb128(v, mask);
        }
    }
    pragma(inline, true) byte16 gcmSrliBytes(int n)(byte16 v)
    {
        static if (n == 0) return v;
        else static if (n >= 16) { long2 z = 0; return cast(byte16) z; }
        else static if (n == 8)
        {
            long2 r = void;
            auto s = cast(long2) v;
            r.array[0] = s.array[1];
            r.array[1] = 0;
            return cast(byte16) r;
        }
        else
        {
            enum byte16 mask = mixin(gcmPshufbSrliStr!n);
            return __builtin_ia32_pshufb128(v, mask);
        }
    }
    pragma(inline, true) byte16 gcmSlli32(int n)(byte16 v)
    {
        return cast(byte16) __builtin_ia32_pslldi128(cast(int4) v, n);
    }
    pragma(inline, true) byte16 gcmSrli32(int n)(byte16 v)
    {
        return cast(byte16) __builtin_ia32_psrldi128(cast(int4) v, n);
    }
    pragma(inline, true) void gcmAccClmul(ref byte16 t0, ref byte16 t1, ref byte16 t2, ref byte16 t3, byte16 a, byte16 b)
    {
        auto aa = cast(long2) a;
        auto bb = cast(long2) b;
        auto lo = cast(byte16) __builtin_ia32_pclmulqdq128(aa, bb, 0);
        auto hi = cast(byte16) __builtin_ia32_pclmulqdq128(aa, bb, 17);
        t0 = t0 ^ lo;
        t3 = t3 ^ hi;
        auto mid = cast(byte16) __builtin_ia32_pclmulqdq128(
            cast(long2)(a ^ gcmSrliBytes!8(a)),
            cast(long2)(b ^ gcmSrliBytes!8(b)), 0);
        t1 = t1 ^ mid ^ lo ^ hi;
    }
    pragma(inline, true) void gcmReduceStore(ubyte* y, byte16 t0, byte16 t1, byte16 t2, byte16 t3)
    {
        t1 = t1 ^ t2;
        t2 = gcmSlliBytes!8(t1);
        t1 = gcmSrliBytes!8(t1);
        t0 = t0 ^ t2;
        t3 = t3 ^ t1;

        auto t4 = gcmSrli32!31(t0);
        t0 = gcmSlli32!1(t0);
        auto t5 = gcmSrli32!31(t3);
        t3 = gcmSlli32!1(t3);
        t2 = gcmSrliBytes!12(t4);
        t5 = gcmSlliBytes!4(t5);
        t4 = gcmSlliBytes!4(t4);
        t0 = t0 | t4;
        t3 = t3 | t5;
        t3 = t3 | t2;
        t4 = gcmSlli32!31(t0);
        t5 = gcmSlli32!30(t0);
        t2 = gcmSlli32!25(t0);
        t4 = t4 ^ t5;
        t4 = t4 ^ t2;
        t5 = gcmSrliBytes!4(t4);
        t3 = t3 ^ t5;
        t4 = gcmSlliBytes!12(t4);
        t0 = t0 ^ t4;
        t3 = t3 ^ t0;
        t4 = gcmSrli32!1(t0);
        t1 = gcmSrli32!2(t0);
        t2 = gcmSrli32!7(t0);
        t3 = t3 ^ t1 ^ t2 ^ t4;
        t3 = gcmBswap(t3);
        auto d = cast(long*) y;
        auto s = cast(long2) t3;
        d[0] = s.array[0];
        d[1] = s.array[1];
    }
}

/// Y := (Y xor X0)*H^4 xor X1*H^3 xor X2*H^2 xor X3*H  (64-byte GHASH step).
static if (BOTAN_HAS_GCM_CLMUL)
void gcmMultiplyClmul4(ubyte* y, const(ubyte)* x,
                       in ubyte[16] H, in ubyte[16] H2,
                       in ubyte[16] H3, in ubyte[16] H4)
{
    version (LDC)
    {
        byte16 t0, t1, t2, t3;
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(y) ^ gcmLoadu(x)), gcmLoadu(H4.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 16)), gcmLoadu(H3.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 32)), gcmLoadu(H2.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 48)), gcmLoadu(H.ptr));
        gcmReduceStore(y, t0, t1, t2, t3);
    }
    else
    {
        *cast(ulong*) y ^= *cast(const ulong*) x;
        *cast(ulong*)(y + 8) ^= *cast(const ulong*)(x + 8);
        gcmMultiplyClmul(*cast(ubyte[16]*) y, H4);
        ubyte[16] t = void;
        t[] = x[16 .. 32];
        gcmMultiplyClmul(t, H3);
        xorBuf(y, t.ptr, 16);
        t[] = x[32 .. 48];
        gcmMultiplyClmul(t, H2);
        xorBuf(y, t.ptr, 16);
        t[] = x[48 .. 64];
        gcmMultiplyClmul(t, H);
        xorBuf(y, t.ptr, 16);
    }
}

/// Y := (Y xor X0)*H^8 xor X1*H^7 xor … xor X7*H  (128-byte GHASH step).
static if (BOTAN_HAS_GCM_CLMUL)
void gcmMultiplyClmul8(ubyte* y, const(ubyte)* x,
                       in ubyte[16] H, in ubyte[16] H2, in ubyte[16] H3, in ubyte[16] H4,
                       in ubyte[16] H5, in ubyte[16] H6, in ubyte[16] H7, in ubyte[16] H8)
{
    version (LDC)
    {
        byte16 t0, t1, t2, t3;
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(y) ^ gcmLoadu(x)), gcmLoadu(H8.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 16)), gcmLoadu(H7.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 32)), gcmLoadu(H6.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 48)), gcmLoadu(H5.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 64)), gcmLoadu(H4.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 80)), gcmLoadu(H3.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 96)), gcmLoadu(H2.ptr));
        gcmAccClmul(t0, t1, t2, t3, gcmBswap(gcmLoadu(x + 112)), gcmLoadu(H.ptr));
        gcmReduceStore(y, t0, t1, t2, t3);
    }
    else
    {
        gcmMultiplyClmul4(y, x, H, H2, H3, H4);
        gcmMultiplyClmul4(y, x + 64, H, H2, H3, H4);
    }
}