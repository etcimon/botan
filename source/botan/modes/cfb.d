/**
* CFB mode
* 
* Copyright:
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.cfb;

import botan.constants;
static if (BOTAN_HAS_MODE_CFB):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.parsing;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;
import std.conv : to;

/**
* CFB Mode
*/
abstract class CFBMode : CipherMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        m_shift_register[] = nonce[0 .. nonce_len];
        m_keystream_buf.length = m_shift_register.length;
        cipher().encrypt(m_shift_register, m_keystream_buf);
        
        return SecureVector!ubyte();
    }

    override @property string name() const
    {
        if (feedback() == cipher().blockSize())
            return cipher().name ~ "/CFB";
        else
            return cipher().name ~ "/CFB(" ~ to!string(feedback()*8) ~ ")";
    }

    override size_t updateGranularity() const
    {
        return feedback();
    }

    override size_t minimumFinalSize() const
    {
        return 0;
    }

    override KeyLengthSpecification keySpec() const
    {
        return cipher().keySpec();
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length;
    }

    override size_t defaultNonceLength() const
    {
        return cipher().blockSize();
    }

    override bool validNonceLength(size_t n) const
    {
        return (n == cipher().blockSize());
    }

    override void clear()
    {
        m_cipher.clear();
        m_shift_register.clear();
    }

    override bool authenticated() const { return true; }
protected:
    this(BlockCipher cipher, size_t feedback_bits)
    { 
        m_cipher = cipher;
        m_feedback_bytes = feedback_bits ? feedback_bits / 8 : m_cipher.blockSize();
        if (feedback_bits % 8 || feedback() > m_cipher.blockSize())
            throw new InvalidArgument(name() ~ ": feedback bits " ~
                                       to!string(feedback_bits) ~ " not supported");
    }

    final BlockCipher cipher() const { return cast()*m_cipher; }

    final size_t feedback() const { return m_feedback_bytes; }

    final ref SecureVector!ubyte shiftRegister() { return m_shift_register; }

    final ref SecureVector!ubyte keystreamBuf() { return m_keystream_buf; }

protected:
    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_shift_register;
    SecureVector!ubyte m_keystream_buf;
    size_t m_feedback_bytes;
}

/**
* CFB Encryption
*/
final class CFBEncryption : CFBMode, Transformation
{
public:
    this(BlockCipher cipher, size_t feedback_bits)
    {
        super(cipher, feedback_bits);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        SecureVector!ubyte* state = &shiftRegister();
        const size_t shift = feedback();
        
        while (sz)
        {
            const size_t took = std.algorithm.min(shift, sz);
            xorBuf(buf, &keystreamBuf()[0], took);
            // Assumes feedback-sized block except for last input
            if (BS - shift > 0) copyMem(state.ptr, &(*state)[shift], BS - shift);
            copyMem(&(*state)[BS-shift], buf, took);
            cipher().encrypt(*state, keystreamBuf());
            
            buf += took;
            sz -= took;
        }
    }


    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override size_t minimumFinalSize() const { return super.minimumFinalSize(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}

/**
* CFB Decryption
*/
final class CFBDecryption : CFBMode, Transformation
{
public:
    this(BlockCipher cipher, size_t feedback_bits) 
    {
        super(cipher, feedback_bits);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        SecureVector!ubyte* state = &shiftRegister();
        const size_t shift = feedback();
        
        while (sz)
        {
            const size_t took = std.algorithm.min(shift, sz);
            
            // first update shift register with ciphertext
            if (BS - shift > 0) copyMem(state.ptr, &(*state)[shift], BS - shift);
            copyMem(&(*state)[BS-shift], buf, took);
            
            // then decrypt
            xorBuf(buf, &keystreamBuf()[0], took);
            
            // then update keystream
            cipher().encrypt(*state, keystreamBuf());
            
            buf += took;
            sz -= took;
        }
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override size_t minimumFinalSize() const { return super.minimumFinalSize(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}