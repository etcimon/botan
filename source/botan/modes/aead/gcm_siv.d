/**
* GCM-SIV Mode (RFC 8452)
*
* Copyright:
* (C) 2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.gcm_siv;

import botan.constants;
static if (BOTAN_HAS_AEAD_GCM_SIV):

import botan.modes.aead.aead;
import botan.modes.aead.polyval;
import botan.block.block_cipher;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.xor_buf;
import botan.utils.loadstor;
import std.algorithm : min;

private KeyLengthSpecification gcmSivKeySpec(BlockCipher cipher)
{
    if (cipher.blockSize() != 16)
        throw new InvalidArgument("GCM-SIV requires a 128 bit block cipher");

    const bool k16 = cipher.validKeylength(16);
    const bool k32 = cipher.validKeylength(32);

    if (k16 && k32)
        return KeyLengthSpecification(16, 32, 16);
    else if (k16)
        return KeyLengthSpecification(16);
    else if (k32)
        return KeyLengthSpecification(32);
    else
        throw new InvalidArgument("GCM-SIV requires a cipher supporting 128 or 256 bit keys");
}

/**
* GCM-SIV (RFC 8452). SCAN: "AES-128/GCM-SIV", "AES-256/GCM-SIV".
* Distinct from AES-SIV (RFC 5297 / AEAD_SIV).
*/
abstract class GCMSIVMode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        if (m_kgk_len == 0)
            throw new InvalidState("GCM-SIV start without key");
        if (m_in_msg)
            throw new InvalidState("GCM-SIV start while a message is in progress");

        m_nonce[0 .. 12] = nonce[0 .. nonce_len];

        /*
        Per-nonce keys, RFC 8452 §4: encrypt counter||nonce and take the
        first 8 bytes of each ciphertext block.
        */
        const size_t blocks = (m_kgk_len == 16) ? 4 : 6;
        SecureVector!ubyte kb = SecureVector!ubyte(blocks * BS);
        foreach (size_t i; 0 .. blocks)
        {
            storeLittleEndian(cast(uint) i, kb.ptr + BS * i);
            copyMem(kb.ptr + BS * i + 4, m_nonce.ptr, 12);
        }
        m_cipher.encrypt(kb);

        ubyte[16] auth_key;
        SecureVector!ubyte enc_key = SecureVector!ubyte(m_kgk_len);
        foreach (size_t i; 0 .. 2)
            copyMem(auth_key.ptr + 8 * i, kb.ptr + BS * i, 8);
        foreach (size_t i; 0 .. blocks - 2)
            copyMem(enc_key.ptr + 8 * i, kb.ptr + BS * (i + 2), 8);

        m_polyval.setKey(auth_key.ptr, auth_key.length);
        m_msg_cipher.setKey(enc_key);
        zeroise(kb);
        auth_key[] = 0;

        m_msg_buf.clear();
        m_in_msg = true;
        return SecureVector!ubyte();
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        if (sz)
            m_msg_buf ~= buffer.ptr[offset .. offset + sz];
        buffer.resize(offset);
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        if (m_in_msg)
            throw new InvalidState("GCM-SIV AD cannot change after start");
        m_ad.clear();
        if (ad_len)
            m_ad ~= ad[0 .. ad_len];
    }

    override @property string name() const
    {
        return m_cipher_name ~ "/GCM-SIV";
    }

    override size_t updateGranularity() const { return 128; }
    override KeyLengthSpecification keySpec() const { return m_key_spec; }
    override bool validNonceLength(size_t len) const { return len == 12; }
    override size_t tagSize() const { return BS; }
    override size_t defaultNonceLength() const { return 12; }

    override void clear()
    {
        m_cipher.clear();
        m_kgk_len = 0;
        m_ad.clear();
        reset();
    }

protected:
    /**
    * Params:
    *  cipher = a 128-bit block cipher (typically AES-128 or AES-256)
    */
    this(BlockCipher cipher)
    {
        if (cipher.blockSize() != BS)
            throw new InvalidArgument("GCM-SIV requires a 128 bit block cipher");
        m_cipher_name = cipher.name;
        m_key_spec = gcmSivKeySpec(cipher);
        m_msg_cipher = cipher.clone();
        m_cipher = cipher;
        m_polyval = new Polyval;
    }

    enum size_t BS = 16;

    final void reset()
    {
        m_msg_cipher.clear();
        m_polyval.clear();
        m_nonce[] = 0;
        m_msg_buf.clear();
        m_in_msg = false;
    }

    final bool inMsg() const { return m_in_msg; }
    final ref SecureVector!ubyte msgBuf() { return m_msg_buf; }

    final ubyte[BS] computeTag(const(ubyte)* ptext, size_t ptext_len)
    {
        m_polyval.update(m_ad.ptr, m_ad.length);
        m_polyval.zeroPad();
        m_polyval.update(ptext, ptext_len);
        m_polyval.zeroPad();

        ubyte[16] lens;
        storeLittleEndian(8UL * m_ad.length, lens.ptr);
        storeLittleEndian(8UL * ptext_len, lens.ptr + 8);
        m_polyval.update(lens.ptr, 16);

        ubyte[BS] S;
        m_polyval.finalResult(S.ptr);

        xorBuf(S.ptr, m_nonce.ptr, 12);
        S[15] &= 0x7f;
        m_msg_cipher.encryptN(S.ptr, S.ptr, 1);
        return S;
    }

    final void ctrXor(ref const ubyte[BS] tag, ubyte* buf, size_t len)
    {
        ubyte[BS] ctr_block = tag;
        ctr_block[15] |= 0x80;
        uint ctr32 = loadLittleEndian!uint(ctr_block.ptr, 0);
        ubyte[BS] ks;

        while (len)
        {
            ks[] = ctr_block[];
            storeLittleEndian(ctr32, ks.ptr);
            ctr32 += 1;
            m_msg_cipher.encryptN(ks.ptr, ks.ptr, 1);
            const size_t todo = min(len, BS);
            xorBuf(buf, ks.ptr, todo);
            buf += todo;
            len -= todo;
        }
    }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
        m_kgk_len = length;
        reset();
    }

private:
    const string m_cipher_name;
    const KeyLengthSpecification m_key_spec;
    Unique!BlockCipher m_cipher;
    Unique!BlockCipher m_msg_cipher;
    Unique!Polyval m_polyval;
    size_t m_kgk_len;
    ubyte[12] m_nonce;
    SecureVector!ubyte m_ad;
    SecureVector!ubyte m_msg_buf;
    bool m_in_msg;
}

/**
* GCM-SIV encryption
*/
final class GCMSIVEncryption : GCMSIVMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher (typically AES-128 or AES-256)
    */
    this(BlockCipher cipher) { super(cipher); }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        if (!inMsg())
            throw new InvalidState("GCM-SIV finish without start");
        assert(buffer.length >= offset, "Offset is sane");

        if (msgBuf().length > 0)
        {
            auto buffer2 = msgBuf().clone;
            buffer2 ~= buffer;
            buffer = buffer2.move;
            msgBuf().clear();
        }

        const size_t ptext_len = buffer.length - offset;
        ubyte[BS] tag = computeTag(buffer.ptr + offset, ptext_len);
        ctrXor(tag, buffer.ptr + offset, ptext_len);
        buffer ~= tag[];
        reset();
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }

    override string provider() const { return "core"; }
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}

/**
* GCM-SIV decryption
*/
final class GCMSIVDecryption : GCMSIVMode, Transformation
{
public:
    /**
    * Params:
    *  cipher = a 128-bit block cipher (typically AES-128 or AES-256)
    */
    this(BlockCipher cipher) { super(cipher); }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        if (!inMsg())
            throw new InvalidState("GCM-SIV finish without start");
        assert(buffer.length >= offset, "Offset is sane");

        if (msgBuf().length > 0)
        {
            auto buffer2 = msgBuf().clone;
            buffer2 ~= buffer;
            buffer = buffer2.move;
            msgBuf().clear();
        }

        const size_t sz = buffer.length - offset;
        if (sz < tagSize())
            throw new IntegrityFailure("GCM-SIV input did not include the tag");

        const size_t ctext_len = sz - tagSize();
        ubyte* buf = buffer.ptr + offset;

        ubyte[BS] included_tag;
        copyMem(included_tag.ptr, buf + ctext_len, BS);
        ctrXor(included_tag, buf, ctext_len);

        ubyte[BS] expected = computeTag(buf, ctext_len);
        reset();

        if (!sameMem(expected.ptr, included_tag.ptr, BS))
        {
            foreach (i; 0 .. ctext_len)
                buf[i] = 0;
            throw new IntegrityFailure("GCM-SIV tag check failed");
        }

        buffer.resize(offset + ctext_len);
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length >= tagSize(), "Sufficient input");
        return input_length - tagSize();
    }

    override size_t minimumFinalSize() const { return tagSize(); }

    override string provider() const { return "core"; }
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}
