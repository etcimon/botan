/**
* TLS NULL+HMAC AEAD (GenericStreamCipher)
*
* Copyright:
* (C) 2024 Sebastian Ahrens, Dirk Dobkowitz, André Schomburg (Volkswagen AG)
* (C) 2024 Lars Dürkop (CARIAD SE)
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls_null;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_NULL):

import botan.modes.aead.aead;
import botan.mac.mac;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.types;

/**
* TLS 1.2 NULL+HMAC record transform (RFC 5246 6.2.3.1 GenericStreamCipher).
* No confidentiality — HMAC only. Off unless `version(TLS_NULL)`.
*/
abstract class TlsNullHmacAeadMode : AEADMode, Transformation
{
public:
    this(MessageAuthenticationCode mac, size_t mac_keylen)
    {
        // Unique.opAssign nulls its source — copy names/sizes first.
        m_mac_name = mac.name;
        m_mac_keylen = mac_keylen;
        m_tag_size = mac.outputLength;
        m_mac = mac;
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        if (ad_len != 13)
            throw new InvalidArgument("TLS 1.2 NULL/HMAC: invalid TLS AEAD associated data length");
        m_ad.length = 13;
        m_ad[] = ad[0 .. 13];
    }

    override @property string name() const
    {
        return "TLS_NULL(" ~ m_mac_name ~ ")";
    }

    override size_t tagSize() const { return m_tag_size; }

    override size_t defaultNonceLength() const { return 0; }

    override bool validNonceLength(size_t nl) const { return nl == 0; }

    override KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(m_mac_keylen);
    }

    override size_t updateGranularity() const { return 1; }

    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        m_msg.clear();
        return SecureVector!ubyte();
    }

    override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        m_msg ~= buffer.ptr[offset .. buffer.length];
        buffer.resize(offset);
    }

    override void clear()
    {
        m_mac.clear();
        m_key.clear();
        m_ad.clear();
        m_msg.clear();
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length;
    }

    override size_t minimumFinalSize() const { return 0; }

    override string provider() const { return "core"; }

protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        if (length != m_mac_keylen)
            throw new InvalidKeyLength(name, length);
        m_key.length = length;
        m_key[] = key[0 .. length];
        m_mac.setKey(key, length);
    }

    Unique!MessageAuthenticationCode m_mac;
    SecureVector!ubyte m_key, m_ad, m_msg;
    string m_mac_name;
    size_t m_mac_keylen, m_tag_size;
}

final class TlsNullHmacAeadEncryption : TlsNullHmacAeadMode
{
public:
    this(MessageAuthenticationCode mac, size_t mac_keylen)
    {
        super(mac, mac_keylen);
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length + m_tag_size;
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
        m_mac.update(m_ad.ptr, m_ad.length);
        if (m_msg.length)
            m_mac.update(m_msg.ptr, m_msg.length);
        auto tag = m_mac.finished();
        buffer ~= m_msg[];
        buffer ~= tag[];
        m_msg.clear();
    }
}

final class TlsNullHmacAeadDecryption : TlsNullHmacAeadMode
{
public:
    this(MessageAuthenticationCode mac, size_t mac_keylen)
    {
        super(mac, mac_keylen);
    }

    override size_t outputLength(size_t input_length) const
    {
        if (input_length < m_tag_size)
            throw new InvalidArgument("Message too short to be valid");
        return input_length - m_tag_size;
    }

    override size_t minimumFinalSize() const { return m_tag_size; }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
        if (m_msg.length < m_tag_size)
            throw new InvalidArgument("TLS_NULL_HMAC_AEAD_Decryption needs at least tag_size() bytes in final buffer");
        const size_t pt_len = m_msg.length - m_tag_size;
        m_mac.update(m_ad.ptr, m_ad.length);
        if (pt_len)
            m_mac.update(m_msg.ptr, pt_len);
        if (!m_mac.verifyMac(m_msg.ptr + pt_len, m_tag_size))
            throw new IntegrityFailure("Message authentication failure");
        buffer ~= m_msg.ptr[0 .. pt_len];
        m_msg.clear();
    }
}

TlsNullHmacAeadMode makeTlsNullHmacAead(in string hash_name, CipherDir dir, size_t mac_keylen)
{
    auto ma = retrieveMac("HMAC(" ~ hash_name ~ ")").clone();
    if (dir == ENCRYPTION)
        return new TlsNullHmacAeadEncryption(ma, mac_keylen);
    return new TlsNullHmacAeadDecryption(ma, mac_keylen);
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;

    auto state = globalState();
    logDebug("Testing tls_null.d ...");
    size_t fails = 0;

    File vec = File("test_data/tls/tls_null.vec", "r");
    fails += runTestsBb(vec, "TLS_NULL", "Fragment", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Hash" in m) || !("Key" in m) || !("AssociatedData" in m)
                || !("Message" in m) || !("Fragment" in m))
                return 0;
            const string header = m["TLS_NULL"];
            auto key = hexDecode(m["Key"]);
            auto ad = hexDecode(m["AssociatedData"]);
            auto msg = hexDecode(m["Message"]);
            auto frag = hexDecode(m["Fragment"]);

            if (header == "InvalidAssociatedDataLength")
            {
                Unique!TlsNullHmacAeadMode dec = makeTlsNullHmacAead(
                    m["Hash"], DECRYPTION, key.length);
                bool threw = false;
                try
                    dec.setAssociatedData(ad.ptr, ad.length);
                catch (InvalidArgument)
                    threw = true;
                if (!threw)
                {
                    logError("tls_null expected InvalidArgument on AD length ", ad.length);
                    return 1;
                }
                return 0;
            }

            if (header == "InvalidMAC")
            {
                Unique!TlsNullHmacAeadMode dec = makeTlsNullHmacAead(
                    m["Hash"], DECRYPTION, key.length);
                dec.setKey(key.ptr, key.length);
                dec.setAssociatedData(ad.ptr, ad.length);
                dec.start();
                auto buf = SecureVector!ubyte(frag[]);
                bool threw = false;
                try
                    dec.finish(buf);
                catch (IntegrityFailure)
                    threw = true;
                if (!threw)
                {
                    logError("tls_null InvalidMAC accepted");
                    return 1;
                }
                return 0;
            }

            Unique!TlsNullHmacAeadMode enc = makeTlsNullHmacAead(
                m["Hash"], ENCRYPTION, key.length);
            Unique!TlsNullHmacAeadMode dec = makeTlsNullHmacAead(
                m["Hash"], DECRYPTION, key.length);
            enc.setKey(key.ptr, key.length);
            dec.setKey(key.ptr, key.length);
            enc.setAssociatedData(ad.ptr, ad.length);
            dec.setAssociatedData(ad.ptr, ad.length);
            enc.start();
            auto buf = SecureVector!ubyte(msg[]);
            enc.finish(buf);
            if (buf[] != frag[])
            {
                logError("tls_null encrypt got ", hexEncode(buf), " expected ", m["Fragment"]);
                return 1;
            }
            dec.start();
            dec.finish(buf);
            if (buf[] != msg[])
            {
                logError("tls_null decrypt mismatch");
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("tls_null", {
        Unique!TlsNullHmacAeadMode enc = makeTlsNullHmacAead(
            "SHA-256", ENCRYPTION, 32);
        ubyte[32] key;
        ubyte[13] ad;
        ubyte[8] pt;
        enc.setKey(key.ptr, key.length);
        enc.setAssociatedData(ad.ptr, ad.length);
        enc.start();
        auto buf = SecureVector!ubyte(pt[]);
        enc.finish(buf);
    });

    if (fails)
        logError("tls_null failures: ", fails);
    assert(fails == 0);
}
