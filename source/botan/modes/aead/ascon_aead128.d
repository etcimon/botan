/**
* Ascon-AEAD128 (NIST SP.800-232 §5.3)
*
* Copyright:
* (C) 2025 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.ascon_aead128;

import botan.constants;
static if (BOTAN_HAS_AEAD_ASCON128):

import botan.modes.aead.aead;
import botan.hash.ascon_p;
import botan.algo_base.transform;
import botan.algo_base.key_spec;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.loadstor;

/**
* Ascon-AEAD128. SCAN: "Ascon-AEAD128".
*/
abstract class AsconAEAD128Mode : AEADMode, Transformation
{
public:
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        if (!m_keyed)
            throw new InvalidState("Ascon-AEAD128 start without key");
        if (m_has_nonce)
            throw new InvalidState("Ascon-AEAD128 start while a message is in progress");

        m_p.reset(ZEROS);
        m_p.S[0] = IV;
        m_p.S[1] = m_key0;
        m_p.S[2] = m_key1;
        m_p.S[3] = loadLittleEndian!ulong(nonce, 0);
        m_p.S[4] = loadLittleEndian!ulong(nonce, 1);
        m_p.initialPermute();
        m_p.S[3] ^= m_key0;
        m_p.S[4] ^= m_key1;
        m_has_nonce = true;
        m_started = false;
        m_msg_buf.clear();
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
        if (m_has_nonce)
            throw new InvalidState("Ascon-AEAD128 AD cannot change after start");
        m_ad.clear();
        if (ad_len)
            m_ad ~= ad[0 .. ad_len];
    }

    override @property string name() const { return "Ascon-AEAD128"; }
    override size_t updateGranularity() const { return 16; }
    override KeyLengthSpecification keySpec() const { return KeyLengthSpecification(16); }
    override bool validNonceLength(size_t n) const { return n == 16; }
    override size_t defaultNonceLength() const { return 16; }
    override size_t tagSize() const { return 16; }

    override void clear()
    {
        m_key0 = m_key1 = 0;
        m_keyed = false;
        m_ad.clear();
        reset();
    }

protected:
    /// Empty Ascon-AEAD128 sponge.
    this()
    {
        m_p = AsconP(12, 8, 128, ZEROS);
        reset();
    }

    enum ulong IV = 0x00001000808c0001;
    enum ulong DOMAIN = 0x8000000000000000;
    enum ulong[5] ZEROS = [0, 0, 0, 0, 0];

    final void reset()
    {
        m_p.reset(ZEROS);
        m_has_nonce = false;
        m_started = false;
        m_msg_buf.clear();
    }

    final void maybeAbsorbAD()
    {
        if (m_started)
            return;
        if (m_ad.length)
        {
            m_p.absorb(m_ad.ptr, m_ad.length);
            m_p.intermediateFinish();
        }
        m_p.S[4] ^= DOMAIN;
        m_started = true;
    }

    final ubyte[16] tagAndFinish()
    {
        m_p.S[2] ^= m_key0;
        m_p.S[3] ^= m_key1;
        m_p.finish();
        m_p.S[3] ^= m_key0;
        m_p.S[4] ^= m_key1;
        ubyte[16] tag;
        storeLittleEndian(tag.ptr, m_p.S[3], m_p.S[4]);
        reset();
        return tag;
    }

    final ref SecureVector!ubyte msgBuf() { return m_msg_buf; }
    final bool inMsg() const { return m_has_nonce; }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        reset();
        m_key0 = loadLittleEndian!ulong(key, 0);
        m_key1 = loadLittleEndian!ulong(key, 1);
        m_keyed = true;
        cast(void) length;
    }

    AsconP m_p;
    ulong m_key0, m_key1;
    bool m_keyed;
    bool m_has_nonce;
    bool m_started;
    SecureVector!ubyte m_ad;
    SecureVector!ubyte m_msg_buf;
}

final class AsconAEAD128Encryption : AsconAEAD128Mode, Transformation
{
public:
    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        if (!inMsg())
            throw new InvalidState("Ascon-AEAD128 finish without start");
        if (msgBuf().length)
        {
            auto tmp = msgBuf().clone;
            tmp ~= buffer;
            buffer = tmp.move;
            msgBuf().clear();
        }
        maybeAbsorbAD();
        const size_t n = buffer.length - offset;
        if (n)
            m_p.percolateIn(buffer.ptr + offset, n);
        auto tag = tagAndFinish();
        buffer ~= tag[];
    }

    override size_t outputLength(size_t input_length) const { return input_length + tagSize(); }
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

final class AsconAEAD128Decryption : AsconAEAD128Mode, Transformation
{
public:
    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        if (!inMsg())
            throw new InvalidState("Ascon-AEAD128 finish without start");
        if (msgBuf().length)
        {
            auto tmp = msgBuf().clone;
            tmp ~= buffer;
            buffer = tmp.move;
            msgBuf().clear();
        }
        const size_t sz = buffer.length - offset;
        if (sz < tagSize())
            throw new IntegrityFailure("Ascon-AEAD128 input did not include the tag");

        const size_t ctext_len = sz - tagSize();
        ubyte* buf = buffer.ptr + offset;
        maybeAbsorbAD();
        if (ctext_len)
            m_p.percolateOut(buf, ctext_len);

        ubyte[16] included;
        copyMem(included.ptr, buf + ctext_len, 16);
        auto expected = tagAndFinish();
        if (!sameMem(expected.ptr, included.ptr, 16))
        {
            foreach (i; 0 .. ctext_len)
                buf[i] = 0;
            throw new IntegrityFailure("Ascon-AEAD128 tag check failed");
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
