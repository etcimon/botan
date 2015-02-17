/**
* XTS mode, from IEEE P1619
* 
* Copyright:
* (C) 2009,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.xts;

import botan.constants;
static if (BOTAN_HAS_MODE_XTS):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.xts;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;
import botan.utils.mem_ops;

/**
* IEEE P1619 XTS Mode
*/
abstract class XTSMode : CipherMode, Transformation
{
public:
    override @property string name() const
    {
        return cipher().name ~ "/XTS";
    }

    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        copyMem(m_tweak.ptr, nonce, nonce_len);
        m_tweak_cipher.encrypt(m_tweak.ptr);
        
        updateTweak(0);
        
        return SecureVector!ubyte();
    }

    override size_t updateGranularity() const
    {
        return cipher().parallelBytes();
    }

    override size_t minimumFinalSize() const
    {
        return cipher().blockSize() + 1;
    }

    override KeyLengthSpecification keySpec() const
    {
        return cipher().keySpec().multiple(2);
    }

    override size_t defaultNonceLength() const
    {
        return cipher().blockSize();
    }

    override bool validNonceLength(size_t n) const
    {
        return cipher().blockSize() == n;
    }

    override void clear()
    {
        m_cipher.clear();
        m_tweak_cipher.clear();
        zeroise(m_tweak);
    }

    override bool authenticated() const { return true; }
protected:
    this(BlockCipher cipher) 
    {
        m_cipher = cipher;
        if (m_cipher.blockSize() != 8 && m_cipher.blockSize() != 16)
            throw new InvalidArgument("Bad cipher for XTS: " ~ m_cipher.name);
        
        m_tweak_cipher = m_cipher.clone();
        m_tweak.resize(updateGranularity());
    }

    final ubyte* tweak() const { return m_tweak.ptr; }

    final BlockCipher cipher() const { return cast()*m_cipher; }

    final void updateTweak(size_t which)
    {
        const size_t BS = m_tweak_cipher.blockSize();
        
        if (which > 0)
            polyDouble(m_tweak.ptr, &m_tweak[(which-1)*BS], BS);
        
        const size_t blocks_in_tweak = updateGranularity() / BS;
        
        for (size_t i = 1; i < blocks_in_tweak; ++i)
            polyDouble(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
    }

    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        const size_t key_half = length / 2;
        
        if (length % 2 == 1 || !m_cipher.validKeylength(key_half))
            throw new InvalidKeyLength(name, length);
        
        m_cipher.setKey(key, key_half);
        m_tweak_cipher.setKey(&key[key_half], key_half);
    }

private:
    Unique!BlockCipher m_cipher, m_tweak_cipher;
    SecureVector!ubyte m_tweak;
}

/**
* IEEE P1619 XTS Encryption
*/
final class XTSEncryption : XTSMode, Transformation
{
public:
    this(BlockCipher cipher) 
    {
        super(cipher);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        const size_t blocks_in_tweak = updateGranularity() / BS;
        
        while (blocks)
        {
            const size_t to_proc = std.algorithm.min(blocks, blocks_in_tweak);
            const size_t to_proc_bytes = to_proc * BS;
            
            xorBuf(buf, tweak(), to_proc_bytes);
            cipher().encryptN(buf, buf, to_proc);
            xorBuf(buf, tweak(), to_proc_bytes);
            
            buf += to_proc * BS;
            blocks -= to_proc;
            
            updateTweak(to_proc);
        }
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= minimumFinalSize(), "Have sufficient final input");
        
        const size_t BS = cipher().blockSize();
        
        if (sz % BS == 0)
        {
            update(buffer, offset);
        }
        else
        {
            // steal ciphertext
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            
            SecureVector!ubyte last = SecureVector!ubyte(buf[full_blocks .. full_blocks + final_bytes]);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            xorBuf(last, tweak(), BS);
            cipher().encrypt(last);
            xorBuf(last, tweak(), BS);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
            {
                last[i] ^= last[i + BS];
                last[i + BS] ^= last[i];
                last[i] ^= last[i + BS];
            }
            
            xorBuf(last, tweak() + BS, BS);
            cipher().encrypt(last);
            xorBuf(last, tweak() + BS, BS);
            
            buffer ~= last;
        }
    }

    override size_t outputLength(size_t input_length) const
    {
        return roundUp(input_length, cipher().blockSize());
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override size_t minimumFinalSize() const { return super.minimumFinalSize(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}

/**
* IEEE P1619 XTS Decryption
*/
final class XTSDecryption : XTSMode, Transformation
{
public:
    this(BlockCipher cipher)
    {
        super(cipher);
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        const size_t blocks_in_tweak = updateGranularity() / BS;
        
        while (blocks)
        {
            const size_t to_proc = std.algorithm.min(blocks, blocks_in_tweak);
            const size_t to_proc_bytes = to_proc * BS;
            
            xorBuf(buf, tweak(), to_proc_bytes);
            cipher().decryptN(buf, buf, to_proc);
            xorBuf(buf, tweak(), to_proc_bytes);
            
            buf += to_proc * BS;
            blocks -= to_proc;
            
            updateTweak(to_proc);
        }
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= minimumFinalSize(), "Have sufficient final input");
        
        const size_t BS = cipher().blockSize();
        
        if (sz % BS == 0)
        {
            update(buffer, offset);
        }
        else
        {
            // steal ciphertext
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            
            SecureVector!ubyte last = SecureVector!ubyte(buf[full_blocks .. full_blocks + final_bytes]);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            xorBuf(last, tweak() + BS, BS);
            cipher().decrypt(last);
            xorBuf(last, tweak() + BS, BS);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
            {
                last[i] ^= last[i + BS];
                last[i + BS] ^= last[i];
                last[i] ^= last[i + BS];
            }
            
            xorBuf(last, tweak(), BS);
            cipher().decrypt(last);
            xorBuf(last, tweak(), BS);
            
            buffer ~= last;
        }
    }

    override size_t outputLength(size_t input_length) const
    {
        // might be less
        return input_length;
    }

    // Interface fallthrough
    override string provider() const { return "core"; }
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len) { return super.start(nonce, nonce_len); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
    override size_t minimumFinalSize() const { return super.minimumFinalSize(); }
    override bool validNonceLength(size_t n) const {
        return super.validNonceLength(n);
    }
}


private:

void polyDouble128(ubyte* output, const(ubyte)* input)
{
    ulong X0 = loadLittleEndian!ulong(input, 0);
    ulong X1 = loadLittleEndian!ulong(input, 1);
    
    const bool carry = (X1 >> 63);
    
    X1 = (X1 << 1) | (X0 >> 63);
    X0 = (X0 << 1);
    
    if (carry)
        X0 ^= 0x87;
    
    storeLittleEndian(output, X0, X1);
}

void polyDouble64(ubyte* output, const(ubyte)* input)
{
    ulong X = loadLittleEndian!ulong(input, 0);
    const bool carry = (X >> 63);
    X <<= 1;
    if (carry)
        X ^= 0x1B;
    storeLittleEndian(X, output);
}

void polyDouble(ubyte* output, const(ubyte)* input, size_t size)
{
    if (size == 8)
        polyDouble64(output, input);
    else
        polyDouble128(output, input);
}