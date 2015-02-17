/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.cbc;

import botan.constants;
static if (BOTAN_HAS_MODE_CBC):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;
import botan.utils.mem_ops;

/**
* CBC Mode
*/
abstract class CBCMode : CipherMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);
        
        /*
        * A nonce of zero length means carry the last ciphertext value over
        * as the new IV, as unfortunately some protocols require this. If
        * this is the first message then we use an IV of all zeros.
        */
        if (nonce_len)
            m_state[] = nonce[0 .. nonce_len];
        
        return SecureVector!ubyte();
    }

    override @property string name() const
    {
        if (m_padding)
            return cipher().name ~ "/CBC/" ~ padding().name;
        else
            return cipher().name ~ "/CBC/CTS";
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
        return cipher().blockSize();
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == 0 || n == cipher().blockSize());
    }

    override void clear()
    {
        m_cipher.clear();
        m_state.clear();
    }

    final override bool authenticated() const { return true; }
protected:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
    {
        m_cipher = cipher;
        m_padding = padding;
        m_state = SecureVector!ubyte(m_cipher.blockSize());
        if (!m_padding.isEmpty && !m_padding.validBlocksize(m_cipher.blockSize()))
            throw new InvalidArgument("Padding " ~ m_padding.name ~ " cannot be used with " ~ m_cipher.name ~ "/CBC");
    }

    final BlockCipher cipher() const { return cast()*m_cipher; }

    final const(BlockCipherModePaddingMethod) padding() const
    {
        assert(m_padding, "No padding defined");
        return *m_padding;
    }

    final ref SecureVector!ubyte state() { return m_state; }

    final ubyte* statePtr() { return m_state.ptr; }

    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

private:
    Unique!BlockCipher m_cipher;
    Unique!BlockCipherModePaddingMethod m_padding;
    SecureVector!ubyte m_state;
}

/**
* CBC Encryption
*/
class CBCEncryption : CBCMode, Transformation
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
        
        assert(sz % BS == 0, "CBC input is full blocks");
        const size_t blocks = sz / BS;
        
        const(ubyte)* prev_block = statePtr();
        
        if (blocks)
        {
            foreach (size_t i; 0 .. blocks)
            {
                assert(buffer.length >= BS*i);
                xorBuf(buf + BS*i, prev_block, BS);
                cipher().encrypt(buf + BS*i);
                prev_block = buf + BS*i;
            }
            
            assert(buffer.length >= BS*blocks);
            state()[] = buf[BS*(blocks-1) .. BS*blocks];
        }

    }


    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        
        const size_t BS = cipher().blockSize();
        
        const size_t bytes_in_final_block = (buffer.length-offset) % BS;
        
        padding().addPadding(buffer, bytes_in_final_block, BS);
        
        if ((buffer.length-offset) % BS)
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
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
final class CTSEncryption : CBCEncryption
{
public:
    this(BlockCipher cipher)
    {
        super(cipher, null);
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length; // no ciphertext expansion in CTS
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        ubyte* buf = buffer.ptr + offset;
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        if (sz < BS + 1)
            throw new EncodingError(name() ~ ": insufficient data to encrypt");
        
        if (sz % BS == 0)
        {
            update(buffer, offset);
            
            // swap last two blocks
            foreach (size_t i; 0 .. BS)
                std.algorithm.swap(buffer[buffer.length-BS+i], buffer[buffer.length-2*BS+i]);
        }
        else
        {
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            assert(buffer.length >= full_blocks+final_bytes);
            SecureVector!ubyte last = SecureVector!ubyte(buf[full_blocks .. full_blocks + final_bytes]);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            xorBuf(last.ptr, statePtr(), BS);
            cipher().encrypt(last.ptr);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
            {
                last[i] ^= last[i + BS];
                last[i + BS] ^= last[i];
            }
            
            cipher().encrypt(last.ptr);
            
            buffer ~= last[];
        }
    }

    override size_t minimumFinalSize() const
    {
        return cipher().blockSize() + 1;
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == cipher().blockSize());
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }

}

/**
* CBC Decryption
*/
class CBCDecryption : CBCMode, Transformation
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)  
    {
        super(cipher, padding);
        m_tempbuf = SecureVector!ubyte(updateGranularity());
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        while (blocks)
        {
            const size_t to_proc = std.algorithm.min(BS * blocks, m_tempbuf.length);
            cipher().decryptN(buf, m_tempbuf.ptr, to_proc / BS);
            
            assert(m_tempbuf.length >= BS);
            xorBuf(m_tempbuf.ptr, statePtr(), BS);
            xorBuf(m_tempbuf.ptr + BS, buf, to_proc - BS);
                        
            assert(state().length >= BS);
            copyMem(statePtr(), buf + (to_proc - BS), BS);
            
            assert(buffer.length >= to_proc);
            copyMem(buf, m_tempbuf.ptr, to_proc);
            
            buf += to_proc;
            blocks -= to_proc / BS;
        }
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        if (sz == 0 || sz % BS)
            throw new DecodingError(name() ~ ": Ciphertext not a multiple of block size");
        
        update(buffer, offset);
        assert(buffer.length >= BS);
        const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.length-BS], BS);
        buffer.resize(buffer.length - pad_bytes); // remove padding
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length; // precise for CTS, worst case otherwise
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
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
private:
    SecureVector!ubyte m_tempbuf;
}

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
final class CTSDecryption : CBCDecryption, Transformation
{
public:
    this(BlockCipher cipher)
    {
        super(cipher, null);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        if (sz < BS + 1)
            throw new EncodingError(name() ~ ": insufficient data to decrypt");
        
        if (sz % BS == 0)
        {
            // swap last two blocks
            
            foreach (size_t i; 0 .. BS)
                std.algorithm.swap(buffer[buffer.length-BS+i], buffer[buffer.length-2*BS+i]);
            
            update(buffer, offset);
        }
        else
        {
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            
            SecureVector!ubyte last = SecureVector!ubyte(buf[full_blocks .. full_blocks + final_bytes]);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            cipher().decrypt(last.ptr);
            
            xorBuf(last.ptr, &last[BS], final_bytes - BS);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
                std.algorithm.swap(last[i], last[i + BS]);
            
            cipher().decrypt(last.ptr);
            xorBuf(last.ptr, statePtr(), BS);
            
            buffer ~= last;
        }
    }

    override size_t minimumFinalSize() const
    {
        return cipher().blockSize() + 1;
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == cipher().blockSize());
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
}