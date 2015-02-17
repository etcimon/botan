/**
* OCB Mode
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.ocb;

import botan.constants;
static if (BOTAN_HAS_AEAD_OCB):

import botan.modes.aead.aead;
import botan.block.block_cipher;

import botan.mac.cmac;
import botan.utils.xor_buf;
import botan.utils.bit_ops;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm;

/**
* OCB Mode (base class for OCBEncryption and OCBDecryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
          http://tools.ietf.org/html/draft-irtf-cfrg-ocb-03
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
abstract class OCBMode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        assert(m_L, "A key was set");
        
        m_offset = updateNonce(nonce, nonce_len);
        zeroise(m_checksum);
        m_block_index = 0;
        
        return SecureVector!ubyte();
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        assert(m_L, "A key was set");
        m_ad_hash = ocbHash(*m_L, *m_cipher, ad, ad_len);
    }

    override @property string name() const
    {
        return m_cipher.name ~ "/OCB"; // include tag size
    }

    override size_t updateGranularity() const
    {
        return m_cipher.parallelBytes();
    }

    override KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    override bool validNonceLength(size_t length) const
    {
        return (length > 0 && length < 16);
    }

    override size_t tagSize() const { return m_tag_size; }

    override void clear()
    {
        m_cipher.free();
        m_L.free();
        
        zeroise(m_ad_hash);
        zeroise(m_offset);
        zeroise(m_checksum);
    }

    ~this() { /* for unique_ptr destructor */ }

    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
protected:
    /**
    * Params:
    *  cipher = the 128-bit block cipher to use
    *  tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size)
    {     
        m_cipher = cipher;
        m_checksum = m_cipher.parallelBytes();
        m_offset = BS;
        m_ad_hash = BS;
        m_tag_size = tag_size;
        if (m_cipher.blockSize() != BS)
            throw new InvalidArgument("OCB requires a 128 bit cipher so cannot be used with " ~ m_cipher.name);
        
        if (m_tag_size != 8 && m_tag_size != 12 && m_tag_size != 16)
            throw new InvalidArgument("OCB cannot produce a " ~ to!string(m_tag_size) ~ " ubyte tag");
        
    }

    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
        m_L = new LComputer(*m_cipher);
    }

    // fixme make these private
    Unique!BlockCipher m_cipher;
    Unique!LComputer m_L;

    size_t m_block_index = 0;

    SecureVector!ubyte m_checksum;
    SecureVector!ubyte m_offset;
    SecureVector!ubyte m_ad_hash;
private:
    final SecureVector!ubyte
            updateNonce(const(ubyte)* nonce, size_t nonce_len)
    {
        assert(nonce_len < BS, "Nonce is less than 128 bits");
        
        SecureVector!ubyte nonce_buf = SecureVector!ubyte(BS);
        
        copyMem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
        nonce_buf[0] = ((tagSize() * 8) % 128) << 1;
        nonce_buf[BS - nonce_len - 1] = 1;
        
        const ubyte bottom = nonce_buf[15] & 0x3F;
        nonce_buf[15] &= 0xC0;
        
        const bool need_new_stretch = (m_last_nonce != nonce_buf);

        if (need_new_stretch)
        {
            m_last_nonce = nonce_buf.dup;
            
            m_cipher.encrypt(nonce_buf);
            
            foreach (size_t i; 0 .. 8)
                nonce_buf.pushBack(nonce_buf[i] ^ nonce_buf[i+1]);
            
            m_stretch = nonce_buf.move;
        }
        
        // now set the offset from stretch and bottom
        
        const size_t shift_bytes = bottom / 8;
        const size_t shift_bits  = bottom % 8;
        
        SecureVector!ubyte offset = SecureVector!ubyte(BS);
        foreach (size_t i; 0 .. BS)
        {
            offset[i]  = cast(ubyte)(m_stretch[i+shift_bytes] << shift_bits);
            offset[i] |= cast(ubyte)(m_stretch[i+shift_bytes+1] >> (8-shift_bits));
        }
        
        return offset.move;
    }


    size_t m_tag_size = 0;
    SecureVector!ubyte m_last_nonce;
    SecureVector!ubyte m_stretch;
}

final class OCBEncryption : OCBMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = the 128-bit block cipher to use
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
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        encrypt(buf, sz / BS);
    }


    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        if (sz)
        {
            const size_t final_full_blocks = sz / BS;
            const size_t remainder_bytes = sz - (final_full_blocks * BS);
            
            encrypt(buf, final_full_blocks);
            
            if (remainder_bytes)
            {
                assert(remainder_bytes < BS, "Only a partial block left");
                ubyte* remainder = &buf[sz - remainder_bytes];
                
                xorBuf(m_checksum.ptr, remainder, remainder_bytes);
                m_checksum[remainder_bytes] ^= 0x80;
                
                m_offset ^= m_L.star(); // Offset_*
                
                SecureVector!ubyte buf_ = SecureVector!ubyte(BS);
                m_cipher.encrypt(m_offset, buf_);
                xorBuf(remainder, buf_.ptr, remainder_bytes);
            }
        }
        
        SecureVector!ubyte checksum = SecureVector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // now compute the tag
        SecureVector!ubyte mac = m_offset.move();
        mac ^= checksum;
        mac ^= m_L.dollar();
        
        m_cipher.encrypt(mac);
        
        mac ^= m_ad_hash;
        
        buffer ~= mac.ptr[0 .. tagSize()];
        
        zeroise(m_checksum);
        m_block_index = 0;
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
    void encrypt(ubyte* buffer, size_t blocks)
    {
        LComputer L = *m_L; // convenient name
        
        const size_t par_blocks = m_checksum.length / BS;
        
        while (blocks)
        {
            const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
            const size_t proc_bytes = proc_blocks * BS;
            
            const SecureVector!ubyte* offsets = &L.computeOffsets(m_offset, m_block_index, proc_blocks);
            
            xorBuf(m_checksum.ptr, buffer, proc_bytes);
            
            xorBuf(buffer, offsets.ptr, proc_bytes);
            m_cipher.encryptN(buffer, buffer, proc_blocks);
            xorBuf(buffer, offsets.ptr, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }
}

final class OCBDecryption : OCBMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = the 128-bit block cipher to use
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

    override void update(ref SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        decrypt(buf, sz / BS);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = buffer.ptr + offset;
        
        assert(sz >= tagSize(), "We have the tag");
        
        const size_t remaining = sz - tagSize();
        
        if (remaining)
        {
            const size_t final_full_blocks = remaining / BS;
            const size_t final_bytes = remaining - (final_full_blocks * BS);
            
            decrypt(buf, final_full_blocks);
            
            if (final_bytes)
            {
                assert(final_bytes < BS, "Only a partial block left");
                
                ubyte* remainder = &buf[remaining - final_bytes];
                
                m_offset ^= m_L.star(); // Offset_*
                
                SecureVector!ubyte pad = SecureVector!ubyte(BS);
                m_cipher.encrypt(m_offset, pad); // P_*
                
                xorBuf(remainder, pad.ptr, final_bytes);
                
                xorBuf(m_checksum.ptr, remainder, final_bytes);
                m_checksum[final_bytes] ^= 0x80;
            }
        }
        
        SecureVector!ubyte checksum = SecureVector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // compute the mac
        SecureVector!ubyte mac = m_offset.move();
        mac ^= checksum;
        mac ^= m_L.dollar();
        
        m_cipher.encrypt(mac);
        
        mac ^= m_ad_hash;
        
        // reset state
        zeroise(m_checksum);
        m_block_index = 0;
        
        // compare mac
        const(ubyte)* included_tag = &buf[remaining];
        
        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("OCB tag check failed");
        
        // remove tag from end of message
        buffer.length = remaining + offset;
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
    void decrypt(ubyte* buffer, size_t blocks)
    {
        LComputer L = *m_L; // convenient name
        
        const size_t par_bytes = m_cipher.parallelBytes();
        
        assert(par_bytes % BS == 0, "Cipher is parallel in full blocks");
        
        const size_t par_blocks = par_bytes / BS;
        
        while (blocks)
        {
            const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
            const size_t proc_bytes = proc_blocks * BS;
            
            const SecureVector!ubyte* offsets = &L.computeOffsets(m_offset, m_block_index, proc_blocks);
            
            xorBuf(buffer, offsets.ptr, proc_bytes);
            m_cipher.decryptN(buffer, buffer, proc_blocks);
            xorBuf(buffer, offsets.ptr, proc_bytes);
            
            xorBuf(m_checksum.ptr, buffer, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }

}

private:

__gshared immutable size_t BS = 16; // intrinsic to OCB definition

// Has to be in Botan namespace so unique_ptr can reference it
final class LComputer
{
public:
    this(BlockCipher cipher)
    {
        m_L_star.resize(cipher.blockSize());
        cipher.encrypt(m_L_star);
        m_L_dollar = polyDouble(star());
        m_L ~= polyDouble(dollar());
    }
    
    ref const(SecureVector!ubyte) star() const { return m_L_star; }
    
    ref const(SecureVector!ubyte) dollar() const { return m_L_dollar; }
    
    ref const(SecureVector!ubyte) opIndex(size_t i) { return get(i); }
    
    ref const(SecureVector!ubyte) computeOffsets(ref SecureVector!ubyte offset,
                                                  size_t block_index,
                                                  size_t blocks)
    {
        m_offset_buf.resize(blocks*BS);
        
        foreach (size_t i; 0 .. blocks)
        { // could be done in parallel
            offset ^= get(ctz(block_index + 1 + i));
            copyMem(&m_offset_buf[BS*i], offset.ptr, BS);
        }
        
        return m_offset_buf;
    }
    
private:
    ref SecureVector!ubyte get(size_t i)
    {
        while (m_L.length <= i)
            m_L.pushBack(polyDouble(m_L.back()));
        
        return m_L[i];
    }
    
    SecureVector!ubyte polyDouble(const ref SecureVector!ubyte input)
    {
        import botan.mac.cmac : CMAC;
        return CMAC.polyDouble(input);
    }
    
    SecureVector!ubyte m_L_dollar, m_L_star;
    Vector!( SecureArray!ubyte ) m_L;
    SecureVector!ubyte m_offset_buf;
}

/*
* OCB's HASH
*/
SecureVector!ubyte ocbHash(LComputer L,
                           BlockCipher cipher,
                           const(ubyte)* ad, size_t ad_len)
{
    SecureVector!ubyte sum = SecureVector!ubyte(BS);
    SecureVector!ubyte offset = SecureVector!ubyte(BS);
    
    SecureVector!ubyte buf = SecureVector!ubyte(BS);
    
    const size_t ad_blocks = (ad_len / BS);
    const size_t ad_remainder = (ad_len % BS);
    
    foreach (size_t i; 0 .. ad_blocks)
    {
        // this loop could run in parallel
        offset ^= L[ctz(i+1)];
        
        buf = offset.dup;
        xorBuf(buf.ptr, &ad[BS*i], BS);
        
        cipher.encrypt(buf);
        
        sum ^= buf;
    }
    
    if (ad_remainder)
    {
        offset ^= L.star();
        
        buf = offset.dup;
        xorBuf(buf.ptr, &ad[BS*ad_blocks], ad_remainder);
        buf[ad_len % BS] ^= 0x80;
        
        cipher.encrypt(buf);
        
        sum ^= buf;
    }
    
    return sum;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.hash.sha2_32;
import botan.block.aes;

Vector!ubyte ocbDecrypt(in SymmetricKey key,
                         const ref Vector!ubyte nonce,
                         const(ubyte)* ct, size_t ct_len,
                         const(ubyte)* ad, size_t ad_len)
{
    auto ocb = scoped!OCBDecryption(new AES128);
    
    ocb.setKey(key);
    ocb.setAssociatedData(ad, ad_len);
    
    ocb.start(nonce.ptr, nonce.length);
    
    SecureVector!ubyte buf = SecureVector!ubyte(ct[0 .. ct_len]);
    ocb.finish(buf, 0);
    
    return unlock(buf);
}

Vector!ubyte ocbEncrypt(in SymmetricKey key,
                         const ref Vector!ubyte nonce,
                         const(ubyte)* pt, size_t pt_len,
                         const(ubyte)* ad, size_t ad_len)
{
    auto ocb = scoped!OCBEncryption(new AES128);
    
    ocb.setKey(key);
    ocb.setAssociatedData(ad, ad_len);
    
    ocb.start(nonce.ptr, nonce.length);
    
    SecureVector!ubyte buf = SecureVector!ubyte(pt[0 .. pt_len]);
    ocb.finish(buf, 0);
    
    try
    {
        Vector!ubyte pt2 = ocbDecrypt(key, nonce, buf.ptr, buf.length, ad, ad_len);
        if (pt_len != pt2.length || !sameMem(pt, &pt2[0], pt_len))
            logTrace("OCB failed to decrypt correctly");
    }
    catch(Exception e)
    {
        logTrace("OCB round trip error - " ~ e.msg);
    }
    
    return unlock(buf);
}

Vector!ubyte ocbEncrypt(Alloc, Alloc2)(in SymmetricKey key,
                                       const ref Vector!ubyte nonce,
                                       const ref Vector!(ubyte, Alloc) pt,
                                       const ref Vector!(ubyte, Alloc2) ad)
{
    return ocbEncrypt(key, nonce, pt.ptr, pt.length, ad.ptr, ad.length);
}

Vector!ubyte ocbDecrypt(Alloc, Alloc2)(in SymmetricKey key,
                                       const ref Vector!ubyte nonce,
                                       const ref Vector!(ubyte, Alloc) pt,
                                       const ref Vector!(ubyte, Alloc2) ad)
{
    return ocbDecrypt(key, nonce, pt.ptr, pt.length, ad.ptr, ad.length);
}

Vector!ubyte ocbEncrypt(OCBEncryption ocb,
                        const ref Vector!ubyte nonce,
                        const ref Vector!ubyte pt,
                        const ref Vector!ubyte ad)
{
    ocb.setAssociatedData(ad.ptr, ad.length);
    
    ocb.start(nonce.ptr, nonce.length);

    SecureVector!ubyte buf = SecureVector!ubyte(pt.ptr[0 .. pt.length]);
    ocb.finish(buf, 0);
    return unlock(buf);
}

size_t testOcbLong(size_t taglen, in string expected)
{
    Unique!OCBEncryption ocb = new OCBEncryption(new AES128, taglen/8);
    
    ocb.setKey(SymmetricKey("00000000000000000000000000000000"));
    
    const Vector!ubyte empty;
    Vector!ubyte N = Vector!ubyte(12);
    Vector!ubyte C;
    
    for(size_t i = 0; i != 128; ++i)
    {
        Vector!ubyte S = Vector!ubyte(i);
        N[11] = i;
        
        C ~= ocbEncrypt(*ocb, N, S, S)[];
        C ~= ocbEncrypt(*ocb, N, S, empty)[];
        C ~= ocbEncrypt(*ocb, N, empty, S)[];
    }
    
    N[11] = 0;
    const Vector!ubyte cipher = ocbEncrypt(*ocb, N, empty, C);
    
    const string cipher_hex = hexEncode(cipher);
    
    if (cipher_hex != expected)
    {
        logTrace("OCB AES-128 long test mistmatch " ~ cipher_hex ~ " != " ~ expected);
        return 1;
    }
    
    return 0;
}

static if (!SKIP_OCB_TEST) unittest
{
    import botan.libstate.libstate;
    globalState();
    logDebug("Testing ocb.d ...");
    size_t fails = 0;
    
    fails += testOcbLong(128, "B2B41CBF9B05037DA7F16C24A35C1C94");
    fails += testOcbLong(96, "1A4F0654277709A5BDA0D380");
    fails += testOcbLong(64, "B7ECE9D381FE437F");
    
    testReport("OCB long", 3, fails);
}