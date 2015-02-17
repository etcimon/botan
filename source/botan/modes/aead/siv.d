/**
* SIV Mode
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.siv;

import botan.constants;
static if (BOTAN_HAS_AEAD_SIV):
import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.mac.mac;
import botan.mac.cmac;
import botan.stream.ctr;
import botan.utils.parsing;
import botan.utils.xor_buf;
import std.algorithm;

/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
abstract class SIVMode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        if (nonce_len)
            m_nonce = m_cmac.process(nonce, nonce_len);
        else
            m_nonce.clear();
        
        m_msg_buf.clear();
        
        return SecureVector!ubyte();
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        //logTrace("Update: ", cast(ubyte[])buffer[]);
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        m_msg_buf ~= buf[0 .. sz];
        buffer.resize(offset); // truncate msg
    }

    final void setAssociatedDataN(size_t n, const(ubyte)* ad, size_t length)
    {
        if (n >= m_ad_macs.length)
            m_ad_macs.resize(n+1);
        
        m_ad_macs[n] = m_cmac.process(ad, length);
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        setAssociatedDataN(0, ad, ad_len);
    }

    override @property string name() const
    {
        return m_name;
    }

    override size_t updateGranularity() const
    {
        /*
        This value does not particularly matter as regardless update
        buffers all input, so in theory this could be 1. However as for instance
        TransformationFilter creates updateGranularity() ubyte buffers, use a
        somewhat large size to avoid bouncing on a tiny buffer.
        */
        return 128;
    }

    override KeyLengthSpecification keySpec() const
    {
        return m_cmac.keySpec().multiple(2);
    }

    override bool validNonceLength(size_t) const
    {
        return true;
    }

    override void clear()
    {
        m_ctr.clear();
        m_nonce.clear();
        m_msg_buf.clear();
        m_ad_macs.clear();
    }

    override size_t tagSize() const { return 16; }
    
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }

protected:
    this(BlockCipher cipher) 
    {
        m_name = cipher.name ~ "/SIV";
        m_ctr = new CTRBE(cipher.clone());
        m_cmac = new CMAC(cipher);
    }

    final StreamCipher ctr() { return *m_ctr; }

    final void setCtrIv(SecureVector!ubyte V)
    {
        V[8] &= 0x7F;
        V[12] &= 0x7F;
        
        ctr().setIv(V.ptr, V.length);
    }

    final ref const(SecureVector!ubyte) msgBuf() { return m_msg_buf; }

    final SecureVector!ubyte S2V(const(ubyte)* text, size_t text_len)
    {
        const ubyte[16] zero;
        
        SecureVector!ubyte V = cmac().process(zero.ptr, 16);
        
        for (size_t i = 0; i != m_ad_macs.length; ++i)
        {
            V = CMAC.polyDouble(V);
            V ^= m_ad_macs[i];
        }
        
        if (m_nonce.length > 0)
        {
            V = CMAC.polyDouble(V);
            V ^= m_nonce;
        }
        
        if (text_len < 16)
        {
            V = CMAC.polyDouble(V);
            xorBuf(V.ptr, text, text_len);
            V[text_len] ^= 0x80;
            return cmac().process(V);
        }
        
        cmac().update(text, text_len - 16);
        xorBuf(V.ptr, text + text_len - 16, 16);
        cmac().update(V);
        
        return cmac().finished();
    }
protected:
    final MessageAuthenticationCode cmac() { return *m_cmac; }

    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        const size_t keylen = length / 2;
        m_cmac.setKey(key, keylen);
        m_ctr.setKey(key + keylen, keylen);
        m_ad_macs.clear();
    }

private:

    const string m_name;

    Unique!StreamCipher m_ctr;
    Unique!MessageAuthenticationCode m_cmac;
    SecureVector!ubyte m_nonce, m_msg_buf;
    Vector!( SecureArray!ubyte ) m_ad_macs;
}

/**
* SIV Encryption
*/
final class SIVEncryption : SIVMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a block cipher
    */
    this(BlockCipher cipher)
    {
        super(cipher);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        import std.algorithm : max;
        assert(buffer.length >= offset, "Offset is sane");
        
        if (msgBuf().length > 0)
        {
            auto buffer2 = msgBuf().dup;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }

        SecureVector!ubyte V = S2V(buffer.ptr + offset, buffer.length - offset);
        if (V.length > 0) {
            auto buffer2 = V.dup;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }
        setCtrIv(V.dup);
        ctr().cipher1(buffer.ptr + offset + V.length, buffer.length - offset - V.length);
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
* SIV Decryption
*/
final class SIVDecryption : SIVMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    */
    this(BlockCipher cipher)
    {
        super(cipher);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset)
    {
        import std.algorithm : max;
        assert(buffer.length >= offset, "Offset is sane");

        if (msgBuf().length > 0) {
            auto buffer2 = msgBuf().dup;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }

        const size_t sz = buffer.length - offset;
        
        assert(sz >= tagSize(), "We have the tag");

        SecureVector!ubyte V = SecureVector!ubyte(buffer.ptr[offset .. offset + 16]);
        
        setCtrIv(V.dup);
        
        ctr().cipher(buffer.ptr + offset + V.length, buffer.ptr + offset, buffer.length - offset - V.length);
        
        SecureVector!ubyte T = S2V(buffer.ptr + offset, buffer.length - offset - V.length);
        
        if (T != V)
            throw new IntegrityFailure("SIV tag check failed");
        
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