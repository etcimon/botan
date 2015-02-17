/**
* EAX Mode
* 
* Copyright:
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.eax;

import botan.constants;
static if (BOTAN_HAS_AEAD_EAX):

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.mac.mac;
import botan.mac.cmac;
import botan.stream.ctr;
import botan.utils.parsing;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import std.algorithm;

/**
* EAX base class
*/
abstract class EAXMode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        m_nonce_mac[] = eaxPrf(0, this.blockSize(), *m_cmac, nonce, nonce_len)[];
        
        m_ctr.setIv(m_nonce_mac.ptr, m_nonce_mac.length);
        
        for (size_t i = 0; i != this.blockSize() - 1; ++i)
            m_cmac.update(0);
        m_cmac.update(2);
        
        return SecureVector!ubyte();
    }


    override void setAssociatedData(const(ubyte)* ad, size_t length)
    {
        m_ad_mac[] = eaxPrf(1, this.blockSize(), *m_cmac, ad, length)[];
    }

    override @property string name() const
    {
        return (m_cipher.name ~ "/EAX");
    }

    override size_t updateGranularity() const
    {
        return 8 * m_cipher.parallelBytes();
    }

    override KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    // EAX supports arbitrary nonce lengths
    override bool validNonceLength(size_t) const { return true; }

    override size_t tagSize() const { return m_tag_size; }

    override void clear()
    {
        m_cipher.clear();
        m_ctr.clear();
        m_cmac.clear();
        zeroise(m_ad_mac);
        zeroise(m_nonce_mac);
    }

    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }

protected:
    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        /*
        * These could share the key schedule, which is one nice part of EAX,
        * but it's much easier to ignore that here...
        */
        m_ctr.setKey(key, length);
        m_cmac.setKey(key, length);
        
        m_ad_mac = eaxPrf(1, this.blockSize(), *m_cmac, null, 0);
    }

    /**
    * Params:
    *  cipher = the cipher to use
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size) 
    {
        m_tag_size = tag_size ? tag_size : cipher.blockSize();
        m_cipher = cipher;
        m_ctr = new CTRBE(m_cipher.clone());
        m_cmac = new CMAC(m_cipher.clone());
        if (m_tag_size < 8 || m_tag_size > m_cmac.outputLength)
            throw new InvalidArgument(name ~ ": Bad tag size " ~ to!string(tag_size));
    }

    final size_t blockSize() const { return m_cipher.blockSize(); }

    size_t m_tag_size;

    Unique!BlockCipher m_cipher;
    Unique!StreamCipher m_ctr;
    Unique!MessageAuthenticationCode m_cmac;

    SecureVector!ubyte m_ad_mac;

    SecureVector!ubyte m_nonce_mac;
}

/**
* EAX Encryption
*/
final class EAXEncryption : EAXMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 0) 
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
        m_cmac.update(buf, sz);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset)
    {
        update(buffer, offset);
        
        SecureVector!ubyte data_mac = m_cmac.finished();
        xorBuf(data_mac, m_nonce_mac, data_mac.length);
        xorBuf(data_mac, m_ad_mac, data_mac.length);

        buffer ~= data_mac[0 .. tagSize()];
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
* EAX Decryption
*/
final class EAXDecryption : EAXMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 0) 
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
        
        m_cmac.update(buf, sz);
        m_ctr.cipher(buf, buf, sz);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= tagSize(), "Have the tag as part of final input");
        
        const size_t remaining = sz - tagSize();
        
        if (remaining)
        {
            m_cmac.update(buf, remaining);
            m_ctr.cipher(buf, buf, remaining);
        }
        
        const(ubyte)* included_tag = &buf[remaining];
        
        SecureVector!ubyte mac = m_cmac.finished();
        mac ^= m_nonce_mac;
        mac ^= m_ad_mac;
        
        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("EAX tag check failed");
        
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


/*
* EAX MAC-based PRF
*/
SecureVector!ubyte eaxPrf(ubyte tag, size_t block_size,
                          MessageAuthenticationCode mac,
                          const(ubyte)* input,
                          size_t length)
{
    foreach (size_t i; 0 .. (block_size - 1))
        mac.update(0);
    mac.update(tag);
    mac.update(input, length);
    return mac.finished();
}