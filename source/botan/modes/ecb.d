/**
* ECB Mode
* 
* Copyright:
* (C) 1999-2009,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.ecb;

import botan.constants;
static if (BOTAN_HAS_MODE_ECB):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;
import botan.utils.types;

/**
* ECB mode
*/
abstract class ECBMode : CipherMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)*, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);
        
        return SecureVector!ubyte();
    }

    override @property string name() const
    {
        return cipher().name ~ "/ECB/" ~ padding().name;
    }

    override size_t updateGranularity() const
    {
        return cipher().parallelBytes();
    }

    override KeyLengthSpecification keySpec() const
    {
        return cipher().keySpec();
    }

    override size_t defaultNonceLength() const
    {
        return 0;
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == 0);
    }

    override void clear()
    {
        m_cipher.clear();
    }

    override bool authenticated() const { return true; }
protected:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
    {
        m_cipher = cipher;
        m_padding = padding;
        if (!m_padding.validBlocksize(m_cipher.blockSize()))
            throw new InvalidArgument("Padding " ~ m_padding.name ~ " cannot be used with " ~ m_cipher.name ~ "/ECB");
    }

    final BlockCipher cipher() const { return cast()*m_cipher; }

    final const(BlockCipherModePaddingMethod) padding() const { return *m_padding; }

protected:
    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    Unique!BlockCipherModePaddingMethod m_padding;
}

/**
* ECB Encryption
*/
final class ECBEncryption : ECBMode, Transformation
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
    {
        super(cipher, padding);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "ECB input is full blocks");
        const size_t blocks = sz / BS;
        
        cipher().encryptN(buf, buf, blocks);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        const size_t bytes_in_final_block = sz % BS;
        
        padding().addPadding(buffer, bytes_in_final_block, BS);
        
        if (buffer.length % BS)
            throw new Exception("Did not pad to full block size in " ~ name);
        
        update(buffer, offset);
    }

    override size_t outputLength(size_t input_length) const
    {
        return roundUp(input_length, cipher().blockSize());
    }

    override size_t minimumFinalSize() const
    {
        return 0;
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}

/**
* ECB Decryption
*/
final class ECBDecryption : ECBMode, Transformation
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
    {
        super(cipher, padding);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        cipher().decryptN(buf, buf, blocks);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        if (sz == 0 || sz % BS)
            throw new DecodingError(name ~ ": Ciphertext not a multiple of block size");
        
        update(buffer, offset);
        
        const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.length-BS], BS);
        buffer.resize(buffer.length - pad_bytes); // remove padding
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length;
    }

    override size_t minimumFinalSize() const
    {
        return cipher().blockSize();
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}