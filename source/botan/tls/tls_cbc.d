/**
* TLS CBC+HMAC AEAD (GenericBlockCipher)
*
* Copyright:
* (C) 2012,2013,2014,2015,2016,2020 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls_cbc;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_MODE_CBC):

import botan.modes.aead.aead;
import botan.modes.cbc;
import botan.modes.mode_pad;
import botan.block.block_cipher;
import botan.mac.mac;
import botan.libstate.lookup;
import botan.tls.record;
import botan.tls.version_;
import botan.utils.exceptn;
import botan.utils.get_byte;
import botan.utils.rounding;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.ct;

/**
* TLS 1.2 CBC+HMAC record transform (MAC-then-encrypt or encrypt-then-MAC).
*/
abstract class TlsCbcHmacAeadMode : AEADMode, Transformation
{
public:
    this(CipherDir dir, BlockCipher cipher, MessageAuthenticationCode mac,
         size_t cipher_keylen, size_t mac_keylen, bool datagram, bool encrypt_then_mac)
    {
        // Unique.opAssign nulls its source — copy names/sizes first.
        m_cipher_name = cipher.name;
        m_mac_name = mac.name;
        m_cipher_keylen = cipher_keylen;
        m_mac_keylen = mac_keylen;
        m_block_size = cipher.blockSize();
        m_iv_size = m_block_size;
        m_tag_size = mac.outputLength;
        m_use_etm = encrypt_then_mac;
        m_datagram = datagram;
        m_mac = mac;
        if (dir == ENCRYPTION)
            m_cbc_enc = new CBCEncryption(cipher, new NullPadding);
        else
            m_cbc_dec = new CBCDecryption(cipher, new NullPadding);
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        if (ad_len != 13)
            throw new InvalidArgument("Invalid TLS AEAD associated data length");
        m_ad.length = 13;
        m_ad[] = ad[0 .. 13];
    }

    override @property string name() const
    {
        return "TLS_CBC(" ~ m_cipher_name ~ "," ~ m_mac_name ~ ")";
    }

    override size_t tagSize() const { return m_tag_size; }

    override size_t defaultNonceLength() const { return m_iv_size; }

    override bool validNonceLength(size_t nl) const
    {
        return nl == m_block_size;
    }

    override KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(m_cipher_keylen + m_mac_keylen);
    }

    override size_t updateGranularity() const { return 1; }

    override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        m_msg.clear();
        m_cbc_state.length = nonce_len;
        m_cbc_state[] = nonce[0 .. nonce_len];
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
        if (m_cbc_enc)
            m_cbc_enc.clear();
        if (m_cbc_dec)
            m_cbc_dec.clear();
        m_mac.clear();
        m_cbc_state.clear();
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
        if (length != m_cipher_keylen + m_mac_keylen)
            throw new InvalidKeyLength(name, length);
        m_mac.setKey(key, m_mac_keylen);
        if (m_cbc_enc)
            m_cbc_enc.setKey(key + m_mac_keylen, m_cipher_keylen);
        if (m_cbc_dec)
            m_cbc_dec.setKey(key + m_mac_keylen, m_cipher_keylen);
    }

    final void assocDataWithLen(ushort len, ref ubyte[13] ad) const
    {
        ad[] = m_ad[];
        ad[11] = get_byte(0, len);
        ad[12] = get_byte(1, len);
    }

    Unique!CBCEncryption m_cbc_enc;
    Unique!CBCDecryption m_cbc_dec;
    Unique!MessageAuthenticationCode m_mac;
    SecureVector!ubyte m_cbc_state, m_ad, m_msg;
    string m_cipher_name, m_mac_name;
    size_t m_cipher_keylen, m_mac_keylen, m_block_size, m_iv_size, m_tag_size;
    bool m_use_etm, m_datagram;
}

final class TlsCbcHmacAeadEncryption : TlsCbcHmacAeadMode
{
public:
    this(BlockCipher cipher, MessageAuthenticationCode mac,
         size_t cipher_keylen, size_t mac_keylen, bool datagram, bool encrypt_then_mac)
    {
        super(ENCRYPTION, cipher, mac, cipher_keylen, mac_keylen, datagram, encrypt_then_mac);
    }

    override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        super.setAssociatedData(ad, ad_len);
        if (m_use_etm)
        {
            const ushort pt_size = (cast(ushort)m_ad[11] << 8) | m_ad[12];
            const ushort enc_size = cast(ushort)roundUp(m_iv_size + pt_size + 1, m_block_size);
            m_ad[11] = get_byte(0, enc_size);
            m_ad[12] = get_byte(1, enc_size);
        }
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
        const size_t msg_size = m_msg.length;
        const size_t input_size = msg_size + (m_use_etm ? 0 : m_tag_size) + 1;
        const size_t enc_size = roundUp(input_size, m_block_size);
        const size_t padding_length = enc_size - input_size + 1;
        const ubyte padding_val = cast(ubyte)(padding_length - 1);

        buffer.resize(offset + msg_size);
        if (msg_size)
            buffer.ptr[offset .. offset + msg_size] = m_msg[];

        if (!m_use_etm)
        {
            m_mac.update(m_ad.ptr, m_ad.length);
            if (msg_size)
                m_mac.update(buffer.ptr + offset, msg_size);
            auto tag = m_mac.finished();
            buffer ~= tag[];
        }

        const size_t pad_start = buffer.length;
        buffer.length = buffer.length + padding_length;
        foreach (size_t i; pad_start .. buffer.length)
            buffer[i] = padding_val;

        m_cbc_enc.start(m_cbc_state);
        m_cbc_enc.update(buffer, offset);

        if (m_use_etm)
        {
            m_mac.update(m_ad.ptr, m_ad.length);
            if (m_iv_size)
                m_mac.update(m_cbc_state.ptr, m_cbc_state.length);
            m_mac.update(buffer.ptr + offset, enc_size);
            auto tag = m_mac.finished();
            buffer ~= tag[];
        }

        if (enc_size >= m_block_size)
        {
            m_cbc_state.length = m_block_size;
            m_cbc_state[] = buffer.ptr[offset + enc_size - m_block_size .. offset + enc_size];
        }
        m_msg.clear();
    }

    override size_t outputLength(size_t input_length) const
    {
        const size_t mac_in_pt = m_use_etm ? 0 : m_tag_size;
        const size_t mac_app = m_use_etm ? m_tag_size : 0;
        return roundUp(input_length + mac_in_pt + 1, m_block_size) + mac_app;
    }
}

final class TlsCbcHmacAeadDecryption : TlsCbcHmacAeadMode
{
public:
    this(BlockCipher cipher, MessageAuthenticationCode mac,
         size_t cipher_keylen, size_t mac_keylen, bool datagram, bool encrypt_then_mac)
    {
        super(DECRYPTION, cipher, mac, cipher_keylen, mac_keylen, datagram, encrypt_then_mac);
    }

    override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
        buffer.resize(offset);
        const size_t record_len = m_msg.length;
        if (record_len < m_tag_size ||
            (record_len - (m_use_etm ? m_tag_size : 0)) % m_block_size != 0)
            throw new IntegrityFailure("TLS CBC message authentication failure");

        if (m_use_etm)
        {
            const size_t enc_size = record_len - m_tag_size;
            const ushort enc_iv_size = cast(ushort)(enc_size + m_iv_size);
            ubyte[13] ad;
            assocDataWithLen(enc_iv_size, ad);
            m_mac.update(ad.ptr, 13);
            if (m_iv_size)
                m_mac.update(m_cbc_state.ptr, m_cbc_state.length);
            m_mac.update(m_msg.ptr, enc_size);
            auto expect = m_mac.finished();
            if (!constantTimeCompare(expect.ptr, m_msg.ptr + enc_size, m_tag_size))
                throw new IntegrityFailure("TLS CBC message authentication failure");
            cbcDecryptRecord(m_msg.ptr, enc_size);
            const ushort pad_size = checkTlsCbcPadding(m_msg.ptr, enc_size);
            // MAC already passed — no Lucky13 oracle on the pad check.
            if (pad_size == 0)
                throw new IntegrityFailure("TLS CBC message authentication failure");
            buffer ~= m_msg.ptr[0 .. enc_size - pad_size];
        }
        else
        {
            cbcDecryptRecord(m_msg.ptr, record_len);
            auto rec = SecureVector!ubyte(m_msg[]);
            ushort pad_size = checkTlsCbcPadding(rec.ptr, record_len);
            // Zero pad_size when the record is too short for MAC+pad (C++ size_ok_mask).
            const auto size_ok_mask = CTMask!ushort.isLte(
                cast(ushort)(m_tag_size + pad_size), cast(ushort)record_len);
            pad_size = size_ok_mask.ifSetReturn(pad_size);
            const ushort pt_len = cast(ushort)(record_len - m_tag_size - pad_size);
            ubyte[13] ad;
            assocDataWithLen(pt_len, ad);
            m_mac.update(ad.ptr, 13);
            if (pt_len)
                m_mac.update(rec.ptr, pt_len);
            auto expect = m_mac.finished();
            const size_t mac_offset = record_len - (m_tag_size + pad_size);
            const bool mac_ok = constantTimeCompare(rec.ptr + mac_offset, expect.ptr, m_tag_size);
            const auto ok_mask = size_ok_mask
                & CTMask!ushort.expand(cast(ushort)(mac_ok ? 1 : 0))
                & CTMask!ushort.expand(pad_size);
            if (ok_mask.asBool())
                buffer ~= rec.ptr[0 .. pt_len];
            else
            {
                performAdditionalCompressions(record_len, pad_size);
                if (m_datagram)
                    m_mac.finished();
                throw new IntegrityFailure("TLS CBC message authentication failure");
            }
        }
        m_msg.clear();
    }

    override size_t minimumFinalSize() const { return m_tag_size; }

private:
    /**
    * Lucky13: dummy HMAC updates so a failed MAC-then-encrypt record
    * always burns the same number of hash compressions as a max-pad record.
    * C++ `TLS_CBC_HMAC_AEAD_Decryption::perform_additional_compressions`.
    */
    void performAdditionalCompressions(size_t plen, size_t padlen)
    {
        const bool is_sha384 = m_mac_name == "HMAC(SHA-384)";
        const ushort hash_block = is_sha384 ? 128 : 64;
        const ushort max_first = is_sha384 ? 111 : 55;
        const ushort L1 = cast(ushort)(13 + plen - m_tag_size);
        const ushort L2 = cast(ushort)(13 + plen - padlen - m_tag_size);
        const ushort max_compressions = cast(ushort)((L1 + hash_block - 1 - max_first) / hash_block);
        const ushort current_compressions = cast(ushort)((L2 + hash_block - 1 - max_first) / hash_block);
        const ushort add_compressions = cast(ushort)(max_compressions - current_compressions);
        const ushort equal = CTMask!ushort.isEqual(max_compressions, current_compressions).ifSetReturn(1);
        const ushort data_len = cast(ushort)(hash_block * add_compressions + equal * max_first);
        auto dummy = SecureVector!ubyte(data_len);
        if (data_len)
            m_mac.update(dummy.ptr, data_len);
    }

    void cbcDecryptRecord(ubyte* record_contents, size_t record_len)
    {
        if (record_len == 0 || record_len % m_block_size != 0)
            throw new DecodingError("Received TLS CBC ciphertext with invalid length");
        m_cbc_dec.start(m_cbc_state);
        if (record_len >= m_block_size)
        {
            m_cbc_state.length = m_block_size;
            m_cbc_state[] = record_contents[record_len - m_block_size .. record_len];
        }
        auto rec = SecureVector!ubyte(record_contents[0 .. record_len]);
        m_cbc_dec.update(rec, 0);
        record_contents[0 .. record_len] = rec[];
    }
}

static if (BOTAN_HAS_TESTS)
{
private final class TlsCbcZeroMac : MessageAuthenticationCode
{
    this(size_t mac_len) { m_mac_len = mac_len; }
    override void clear() {}
    override @property string name() const { return "ZeroMac"; }
    override @property size_t outputLength() const { return m_mac_len; }
    override MessageAuthenticationCode clone() const { return new TlsCbcZeroMac(m_mac_len); }
    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(0, 0, 1); }
protected:
    override void addData(const(ubyte)* , size_t ) {}
    override void finalResult(ubyte* mac)
    {
        foreach (size_t i; 0 .. m_mac_len)
            mac[i] = 0;
    }
    override void keySchedule(const(ubyte)* , size_t ) {}
private:
    size_t m_mac_len;
}

private final class TlsCbcNoopCipher : BlockCipher, SymmetricAlgorithm
{
    this(size_t bs) { m_bs = bs; }
    override size_t blockSize() const { return m_bs; }
    override @property size_t parallelism() const { return 1; }
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        if (input !is output)
            copyMem(output, input, blocks * m_bs);
    }
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        if (input !is output)
            copyMem(output, input, blocks * m_bs);
    }
    override void clear() {}
    override @property string name() const { return "noop"; }
    override BlockCipher clone() const { return new TlsCbcNoopCipher(m_bs); }
    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(0, 0, 1); }
protected:
    override void keySchedule(const(ubyte)* , size_t ) {}
private:
    size_t m_bs;
}
}

TlsCbcHmacAeadMode makeTlsCbcHmacAead(in string cipher_name, in string mac_name,
                                       size_t cipher_keylen, size_t mac_keylen,
                                       CipherDir dir, bool datagram, bool encrypt_then_mac)
{
    auto c = retrieveBlockCipher(cipher_name).clone();
    auto ma = retrieveMac(mac_name).clone();
    if (dir == ENCRYPTION)
        return new TlsCbcHmacAeadEncryption(c, ma, cipher_keylen, mac_keylen, datagram, encrypt_then_mac);
    return new TlsCbcHmacAeadDecryption(c, ma, cipher_keylen, mac_keylen, datagram, encrypt_then_mac);
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;
    import std.conv : to;

    auto state = globalState();
    logDebug("Testing tls_cbc.d ...");
    size_t fails = 0;

    File vec = File("test_data/tls/tls_cbc_kat.vec", "r");
    fails += runTestsBb(vec, "TLS_CBC", "Ciphertext", true,
        (ref HashMap!(string, string) m)
        {
            if (!("BlockCipher" in m) || !("MAC" in m) || !("Ciphertext" in m))
                return 0;
            const size_t ck = to!size_t(m["KeylenCipher"]);
            const size_t mk = to!size_t(m["KeylenMAC"]);
            const bool etm = m["EncryptThenMAC"] == "true";
            const bool dtls = m["Protocol"] == "DTLS";
            Unique!TlsCbcHmacAeadMode enc = makeTlsCbcHmacAead(
                m["BlockCipher"], m["MAC"], ck, mk, ENCRYPTION, dtls, etm);
            Unique!TlsCbcHmacAeadMode dec = makeTlsCbcHmacAead(
                m["BlockCipher"], m["MAC"], ck, mk, DECRYPTION, dtls, etm);
            auto key = hexDecode(m["Key"]);
            auto ad = hexDecode(m["AssociatedData"]);
            auto nonce = hexDecode(m["Nonce"]);
            auto pt = hexDecode(m["Plaintext"]);
            auto ct = hexDecode(m["Ciphertext"]);
            enc.setKey(key.ptr, key.length);
            dec.setKey(key.ptr, key.length);
            enc.setAssociatedData(ad.ptr, ad.length);
            dec.setAssociatedData(ad.ptr, ad.length);
            enc.start(nonce.ptr, nonce.length);
            auto buf = SecureVector!ubyte(pt[]);
            enc.finish(buf);
            if (buf[] != ct[])
            {
                logError("tls_cbc encrypt got ", hexEncode(buf), " expected ", m["Ciphertext"]);
                return 1;
            }
            dec.start(nonce.ptr, nonce.length);
            dec.finish(buf);
            if (buf[] != pt[])
            {
                logError("tls_cbc decrypt mismatch");
                return 1;
            }
            return 0;
        });

    File valid_vec = File("test_data/tls/tls_cbc.vec", "r");
    fails += runTestsBb(valid_vec, "tls_cbc", "Valid", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Blocksize" in m) || !("MACsize" in m) || !("Record" in m) || !("Valid" in m))
                return 0;
            const size_t block_size = to!size_t(m["Blocksize"]);
            const size_t mac_size = to!size_t(m["MACsize"]);
            auto rec = hexDecode(m["Record"]);
            const bool expect_valid = m["Valid"] == "1";
            Unique!TlsCbcHmacAeadMode dec = new TlsCbcHmacAeadDecryption(
                new TlsCbcNoopCipher(block_size), new TlsCbcZeroMac(mac_size),
                0, 0, false, false);
            dec.setKey(cast(const(ubyte)*)null, 0);
            ubyte[13] ad;
            dec.setAssociatedData(ad.ptr, ad.length);
            auto buf = SecureVector!ubyte(rec[]);
            bool accepted = true;
            try
                dec.finish(buf);
            catch (Exception)
                accepted = false;
            if (accepted != expect_valid)
            {
                logError("tls_cbc Valid=", m["Valid"], " accepted=", accepted,
                         " len=", rec.length, " mac=", mac_size);
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("tls_cbc", {
        Unique!TlsCbcHmacAeadMode enc = makeTlsCbcHmacAead(
            "AES-128", "HMAC(SHA-256)", 16, 32, ENCRYPTION, false, false);
        ubyte[48] key;
        ubyte[13] ad;
        ubyte[16] n;
        ubyte[16] pt;
        ad[12] = 16;
        enc.setKey(key.ptr, key.length);
        enc.setAssociatedData(ad.ptr, ad.length);
        enc.start(n.ptr, n.length);
        auto buf = SecureVector!ubyte(pt[]);
        enc.finish(buf);
    });

    if (fails)
        logError("tls_cbc failures: ", fails);
    assert(fails == 0);
}
