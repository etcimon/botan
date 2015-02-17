/**
* CCM Mode
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.ccm;

import botan.constants;
static if (BOTAN_HAS_AEAD_CCM):

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.mac.mac;
import botan.utils.parsing;
import botan.utils.xor_buf;
import botan.utils.get_byte;
import std.conv : to;
import std.algorithm;

/**
* Base class for CCM encryption and decryption
* @see RFC 3610
*/
abstract class CCMMode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        m_nonce[] = nonce[0 .. nonce_len];
        m_msg_buf.clear();
        
        return SecureVector!ubyte();
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        m_msg_buf ~= buf[0 .. sz];
        buffer.length = offset; // truncate msg
    }

    override void setAssociatedData(const(ubyte)* ad, size_t length)
    {
        m_ad_buf.clear();
        if (length)
        {
            // FIXME: support larger AD using length encoding rules
            assert(length < (0xFFFF - 0xFF), "Supported CCM AD length");
            
            m_ad_buf.pushBack(get_byte(0, cast(ushort) length));
            m_ad_buf.pushBack(get_byte(1, cast(ushort) length));
            m_ad_buf ~= ad[0 .. length];
            while (m_ad_buf.length % BS)
                m_ad_buf.pushBack(cast(ubyte)0); // pad with zeros to full block size
        }
    }

    override @property string name() const
    {
        return (m_cipher.name ~ "/CCM(" ~ to!string(tagSize()) ~ "," ~ to!string(L())) ~ ")";
    }

    size_t updateGranularity() const
    {
        /*
        This value does not particularly matter as regardless update
        buffers all input, so in theory this could be 1. However as for instance
        TransformationFilter creates updateGranularity() ubyte buffers, use a
        somewhat large size to avoid bouncing on a tiny buffer.
        */
        return m_cipher.parallelBytes();
    }


    override KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == (15-L()));
    }

    override size_t defaultNonceLength() const
    {
        return (15-L());
    }

    override void clear()
    {
        m_cipher.clear();
        m_msg_buf.clear();
        m_ad_buf.clear();
    }

    override size_t tagSize() const { return m_tag_size; }

protected:
    __gshared immutable size_t BS = 16; // intrinsic to CCM definition

    /*
    * CCMMode Constructor
    */
    this(BlockCipher cipher, size_t tag_size, size_t L)
    { 
        m_tag_size = tag_size;
        m_L = L;
        m_cipher = cipher;
        if (m_cipher.blockSize() != BS)
            throw new InvalidArgument(m_cipher.name ~ " cannot be used with CCM mode");
        
        if (L < 2 || L > 8)
            throw new InvalidArgument("Invalid CCM L value " ~ to!string(L));
        
        if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0)
            throw new InvalidArgument("invalid CCM tag length " ~ to!string(tag_size));
    }

    final size_t L() const { return m_L; }

    final BlockCipher cipher() const { return cast()*m_cipher; }

    final void encodeLength(size_t len, ubyte* output)
    {
        const size_t len_bytes = L();
        
        assert(len_bytes < (size_t).sizeof, "Length field fits");
        
        foreach (size_t i; 0 .. len_bytes)
            output[len_bytes-1-i] = get_byte((size_t).sizeof-1-i, len);
        
        assert((len >> (len_bytes*8)) == 0, "Message length fits in field");
    }

    final void inc(ref SecureVector!ubyte C)
    {
        for (size_t i = 0; i != C.length; ++i)
            if (++(C[$-i-1]))
                break;
    }

    final ref const(SecureVector!ubyte) adBuf() const { return m_ad_buf; }

    final ref const(SecureVector!ubyte) msgBuf() const { return m_msg_buf; }

    final SecureVector!ubyte formatB0(size_t sz)
    {
        SecureVector!ubyte B0 = SecureVector!ubyte(BS);
        
        const ubyte b_flags = cast(ubyte) ((m_ad_buf.length ? 64 : 0) + (((tagSize()/2)-1) << 3) + (L()-1));
        
        B0[0] = b_flags;
        assert(B0.length >= m_nonce.length);
        copyMem(&B0[1], m_nonce.ptr, m_nonce.length);
        encodeLength(sz, &B0[m_nonce.length+1]);
        
        return B0.move;
    }

    final SecureVector!ubyte formatC0()
    {
        SecureVector!ubyte C = SecureVector!ubyte(BS);
        
        const ubyte a_flags = cast(ubyte)(L()-1);
        
        C[0] = a_flags;
        assert(C.length >= m_nonce.length + 1);
        copyMem(&C[1], m_nonce.ptr, m_nonce.length);
        
        return C.move;
    }

    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

protected:
    const size_t m_tag_size;
    const size_t m_L;

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_nonce, m_msg_buf, m_ad_buf;
}

/**
* CCM Encryption
*/
final class CCMEncryption : CCMMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    *  tag_size = is how big the auth tag will be (even values
    *                      between 4 and 16 are accepted)
    *  L = length of L parameter. The total message length
    *              must be less than 2**L bytes, and the nonce is 15-L bytes.
    */
    this(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) 
    {
        super(cipher, tag_size, L);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        import std.algorithm : max;
        assert(buffer.length >= offset, "Offset is sane");
        buffer.resize(max(buffer.length, offset + msgBuf().length));
        buffer.ptr[offset .. offset + msgBuf().length] = msgBuf().ptr[0 .. msgBuf().length];
        
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const SecureVector!ubyte* ad = &adBuf();
        assert(ad.length % BS == 0, "AD is block size multiple");
        
        BlockCipher E = cipher();
        
        SecureVector!ubyte T = SecureVector!ubyte(BS);
        E.encrypt(formatB0(sz), T);
        
        for (size_t i = 0; i != ad.length; i += BS)
        {
            xorBuf(T.ptr, &(*ad)[i], BS);
            E.encrypt(T);
        }
        
        SecureVector!ubyte C = formatC0();
        SecureVector!ubyte S0 = SecureVector!ubyte(BS);
        E.encrypt(C, S0);
        inc(C);
        
        SecureVector!ubyte X = SecureVector!ubyte(BS);
        
        const(ubyte)* buf_end = &buf[sz];
        
        while (buf != buf_end)
        {
            const size_t to_proc = std.algorithm.min(BS, buf_end - buf);
            
            xorBuf(T.ptr, buf, to_proc);
            E.encrypt(T);
            
            E.encrypt(C, X);
            xorBuf(buf, X.ptr, to_proc);
            inc(C);
            
            buf += to_proc;
        }
        
        T ^= S0;
        
        buffer ~= T.ptr[0 .. tagSize()];
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }

}

/**
* CCM Decryption
*/
final class CCMDecryption : CCMMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    *  tag_size = is how big the auth tag will be (even values
    *                      between 4 and 16 are accepted)
    *  L = length of L parameter. The total message length
    *              must be less than 2**L bytes, and the nonce is 15-L bytes.
    */
    this(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) 
    {
        super(cipher, tag_size, L);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        import std.algorithm : max;
        assert(buffer.length >= offset, "Offset is sane");
        buffer.resize(max(buffer.length, offset + msgBuf().length));
        buffer.ptr[offset .. offset + msgBuf().length] = msgBuf().ptr[0 .. msgBuf().length];
        
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= tagSize(), "We have the tag");
        
        const SecureVector!ubyte* ad = &adBuf();
        assert(ad.length % BS == 0, "AD is block size multiple");
        
        BlockCipher E = cipher();
        
        SecureVector!ubyte T = SecureVector!ubyte(BS);
        E.encrypt(formatB0(sz - tagSize()), T);
        
        for (size_t i = 0; i != ad.length; i += BS)
        {
            xorBuf(T.ptr, &(*ad)[i], BS);
            E.encrypt(T);
        }
        
        SecureVector!ubyte C = formatC0();
        
        SecureVector!ubyte S0 = SecureVector!ubyte(BS);
        E.encrypt(C, S0);
        inc(C);
        
        SecureVector!ubyte X = SecureVector!ubyte(BS);
        
        const(ubyte)* buf_end = &buf[sz - tagSize()];
        
        while (buf < buf_end)
        {
            const size_t to_proc = std.algorithm.min(BS, buf_end - buf);
            
            E.encrypt(C, X);
            xorBuf(buf, X.ptr, to_proc);
            inc(C);
            
            xorBuf(T.ptr, buf, to_proc);
            E.encrypt(T);
            
            buf += to_proc;
        }
        
        T ^= S0;
        
        if (!sameMem(T.ptr, buf_end, tagSize()))
            throw new IntegrityFailure("CCM tag check failed");
        
        buffer.resize(buffer.length - tagSize());
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length > tagSize(), "Sufficient input");
        return input_length - tagSize();
    }

    override size_t minimumFinalSize() const { return tagSize(); }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}