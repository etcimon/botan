/**
* SIV Mode
* 
* Copyright:
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
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
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
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

    override void setAssociatedDataN(size_t n, const(ubyte)* ad, size_t length)
    {
        const size_t max_ads = 16 * 8 - 2;
        if (n >= max_ads)
            throw new InvalidArgument(name ~ " allows no more than " ~ max_ads.to!string ~ " ADs");

        if (n >= m_ad_macs.length)
        {
            const size_t old = m_ad_macs.length;
            m_ad_macs.resize(n + 1);
            if (n > old)
            {
                auto empty_mac = m_cmac.process(cast(const(ubyte)* )null, 0);
                foreach (size_t i; old .. n)
                    m_ad_macs[i] = empty_mac.clone;
            }
        }

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
    /**
    * Params:
    *  cipher = a 128-bit block cipher
    */
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
        
        SecureVector!ubyte V = m_cmac.process(zero.ptr, 16);
        
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
            return m_cmac.process(V);
        }
        
        m_cmac.update(text, text_len - 16);
        xorBuf(V.ptr, text + text_len - 16, 16);
        m_cmac.update(V);
        
        return m_cmac.finished();
    }
protected:

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
            auto buffer2 = msgBuf().clone;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }

        SecureVector!ubyte V = S2V(buffer.ptr + offset, buffer.length - offset);
        if (V.length > 0) {
            auto buffer2 = V.clone;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }
        setCtrIv(V.clone);
        ctr().cipher1(buffer.ptr + offset + V.length, buffer.length - offset - V.length);
    }
    
    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }

    // Interface fallthrough
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
            auto buffer2 = msgBuf().clone;
            buffer2 ~= buffer;
            buffer = buffer2.move;
        }

        const size_t sz = buffer.length - offset;
        
        assert(sz >= tagSize(), "We have the tag");

        SecureVector!ubyte V = SecureVector!ubyte(buffer.ptr[offset .. offset + 16]);
        
        setCtrIv(V.clone);
        
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
    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
    override void update(ref SecureVector!ubyte blocks, size_t offset = 0) { super.update(blocks, offset); }
    override size_t updateGranularity() const { return super.updateGranularity(); }
    override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
    override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
    override @property string name() const { return super.name; }
    override void clear() { return super.clear(); }
}

static if (BOTAN_HAS_TESTS && !SKIP_AEAD_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;

    auto state = globalState();
    logDebug("Testing siv.d ...");
    size_t fails = 0;

    void applyAds(AEADMode mode, string ads)
    {
        if (!ads.length)
            return;
        auto parts = botan.utils.parsing.splitter(ads, ',');
        foreach (size_t i; 0 .. parts.length)
        {
            auto ad = hexDecode(parts[i]);
            mode.setAssociatedDataN(i, ad.ptr, ad.length);
        }
    }

    File vec = File("test_data/siv_ad.vec", "r");
    fails += runTestsBb(vec, "SIV", "Out", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Key" in m) || !("Out" in m))
                return 0;
            const string algo = m["SIV"] ~ "/SIV";
            Unique!AEADMode enc = getAead(algo, ENCRYPTION);
            Unique!AEADMode dec = getAead(algo, DECRYPTION);
            if (!enc || !dec)
                throw new Exception("Unknown AEAD " ~ algo);
            auto key = hexDecode(m["Key"]);
            enc.setKey(key.ptr, key.length);
            dec.setKey(key.ptr, key.length);
            const string ads = ("ADs" in m) ? m["ADs"] : "";
            applyAds(enc, ads);
            applyAds(dec, ads);
            auto input = hexDecode(("In" in m) ? m["In"] : "");
            auto expect = hexDecode(m["Out"]);
            auto nonce = hexDecode(("Nonce" in m) ? m["Nonce"] : "");
            enc.start(nonce.ptr, nonce.length);
            auto buf = SecureVector!ubyte(input[]);
            enc.finish(buf);
            if (buf[] != expect[])
            {
                logError(algo, " got ", hexEncode(buf), " expected ", m["Out"]);
                return 1;
            }
            dec.start(nonce.ptr, nonce.length);
            dec.finish(buf);
            if (buf[] != input[])
            {
                logError(algo, " decrypt mismatch");
                return 1;
            }
            return 0;
        });

    {
        Unique!AEADMode gapped = getAead("AES-128/SIV", ENCRYPTION);
        Unique!AEADMode enc = getAead("AES-128/SIV", ENCRYPTION);
        ubyte[32] key;
        ubyte[32] ad0;
        ubyte[48] ad2;
        ubyte[10] input;
        key[0] = 1;
        ad0[0] = 2;
        ad2[0] = 3;
        input[0] = 4;
        gapped.setKey(key.ptr, key.length);
        enc.setKey(key.ptr, key.length);
        gapped.setAssociatedDataN(0, ad0.ptr, ad0.length);
        gapped.setAssociatedDataN(2, ad2.ptr, ad2.length);
        auto buf_gapped = SecureVector!ubyte(input[]);
        gapped.start();
        gapped.finish(buf_gapped);

        enc.setAssociatedDataN(0, ad0.ptr, ad0.length);
        enc.setAssociatedDataN(1, null, 0);
        enc.setAssociatedDataN(2, ad2.ptr, ad2.length);
        auto buf_explicit = SecureVector!ubyte(input[]);
        enc.start();
        enc.finish(buf_explicit);
        if (buf_gapped[] != buf_explicit[])
        {
            logError("SIV AD gap mismatch");
            ++fails;
        }

        Unique!AEADMode dec = getAead("AES-128/SIV", DECRYPTION);
        dec.setKey(key.ptr, key.length);
        dec.setAssociatedDataN(0, ad0.ptr, ad0.length);
        dec.setAssociatedDataN(2, ad2.ptr, ad2.length);
        dec.start();
        dec.finish(buf_gapped);
        if (buf_gapped[] != input[])
        {
            logError("SIV gapped AD round-trip fail");
            ++fails;
        }
    }

    fails += checkMemutilsRepeat("siv_ad", {
        Unique!AEADMode siv = getAead("AES-128/SIV", ENCRYPTION);
        ubyte[32] key;
        ubyte[16] pt;
        key[0] = 1;
        siv.setKey(key.ptr, key.length);
        siv.setAssociatedDataN(0, key.ptr, 8);
        siv.start();
        auto buf = SecureVector!ubyte(pt[]);
        siv.finish(buf);
    });

    if (fails)
        logError("siv failures: ", fails);
    assert(fails == 0);
}