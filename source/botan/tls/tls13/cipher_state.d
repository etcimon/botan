/**
* TLS 1.3 per-record AEAD state (RFC 8446 5.2–5.3)
*
* Copyright:
* (C) 2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.cipher_state;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.modes.aead.aead;
import botan.kdf.kdf;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.algo_base.sym_algo;

enum size_t TLS13_NONCE_LEN = 12;

/// C++ `hkdf_expand_label`: info = length || label || context (no TLS prefix).
SecureVector!ubyte hkdfExpandLabel(string hash_name,
                                   const(ubyte)* secret, size_t secret_len,
                                   string label,
                                   const(ubyte)* context, size_t context_len,
                                   size_t length)
{
    Unique!KDF exp = getKdf("HKDF-Expand(" ~ hash_name ~ ")");
    Vector!ubyte prefix;
    prefix.pushBack(cast(ubyte)(length >> 8));
    prefix.pushBack(cast(ubyte)(length));
    prefix.pushBack(cast(ubyte) label.length);
    prefix ~= cast(const(ubyte)[]) label;
    prefix.pushBack(cast(ubyte) context_len);
    return exp.deriveKey(length, secret, secret_len,
                         context, context_len, prefix.ptr, prefix.length);
}

/// RFC 8446 7.1 HKDF-Expand-Label. Label field is `"tls13 " ~ label`.
SecureVector!ubyte tls13HkdfExpandLabel(string hash_name,
                                        const(ubyte)* secret, size_t secret_len,
                                        string label,
                                        const(ubyte)* context, size_t context_len,
                                        size_t length)
{
    return hkdfExpandLabel(hash_name, secret, secret_len,
                           "tls13 " ~ label, context, context_len, length);
}

/**
* Traffic keys + sequence numbers for one direction pair.
* Construct from raw key/IV (tests) or from traffic secrets via HKDF-Expand-Label.
*/
final class TLS13CipherState
{
public:
    this(string aead_name,
         const(ubyte)* write_key, size_t write_key_len,
         const(ubyte)* write_iv, size_t write_iv_len,
         const(ubyte)* read_key, size_t read_key_len,
         const(ubyte)* read_iv, size_t read_iv_len)
    {
        if (write_iv_len != TLS13_NONCE_LEN || read_iv_len != TLS13_NONCE_LEN)
            throw new InvalidArgument("TLS 1.3 IV must be 12 bytes");
        m_encrypt = getAead(aead_name, ENCRYPTION);
        m_decrypt = getAead(aead_name, DECRYPTION);
        if (!m_encrypt || !m_decrypt)
            throw new AlgorithmNotFound(aead_name);
        m_encrypt.setKey(write_key, write_key_len);
        m_decrypt.setKey(read_key, read_key_len);
        m_write_iv = Vector!ubyte(write_iv[0 .. write_iv_len]);
        m_read_iv = Vector!ubyte(read_iv[0 .. read_iv_len]);
    }

    static TLS13CipherState fromTrafficSecrets(string aead_name, string hash_name,
                                               const(ubyte)* write_secret, size_t write_secret_len,
                                               const(ubyte)* read_secret, size_t read_secret_len)
    {
        Unique!AEADMode probe = getAead(aead_name, ENCRYPTION);
        if (!probe)
            throw new AlgorithmNotFound(aead_name);
        const size_t klen = (*probe).keySpec().minimumKeylength();
        auto wkey = tls13HkdfExpandLabel(hash_name, write_secret, write_secret_len, "key", null, 0, klen);
        auto wiv = tls13HkdfExpandLabel(hash_name, write_secret, write_secret_len, "iv", null, 0, TLS13_NONCE_LEN);
        auto rkey = tls13HkdfExpandLabel(hash_name, read_secret, read_secret_len, "key", null, 0, klen);
        auto riv = tls13HkdfExpandLabel(hash_name, read_secret, read_secret_len, "iv", null, 0, TLS13_NONCE_LEN);
        auto cs = new TLS13CipherState(aead_name, wkey.ptr, wkey.length, wiv.ptr, wiv.length,
                                       rkey.ptr, rkey.length, riv.ptr, riv.length);
        cs.m_aead_name = aead_name;
        cs.m_hash_name = hash_name;
        cs.m_write_secret = SecureVector!ubyte(write_secret[0 .. write_secret_len]);
        cs.m_read_secret = SecureVector!ubyte(read_secret[0 .. read_secret_len]);
        return cs;
    }

    /// RFC 8446 7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(..., "traffic upd").
    void updateWriteKeys()
    {
        if (!m_hash_name.length || !m_write_secret.length)
            throw new InvalidState("TLS 1.3 KeyUpdate requires traffic secrets");
        m_write_secret = tls13HkdfExpandLabel(m_hash_name, m_write_secret.ptr, m_write_secret.length,
                                              "traffic upd", null, 0, m_write_secret.length);
        Unique!AEADMode probe = getAead(m_aead_name, ENCRYPTION);
        const size_t klen = (*probe).keySpec().minimumKeylength();
        auto wkey = tls13HkdfExpandLabel(m_hash_name, m_write_secret.ptr, m_write_secret.length,
                                         "key", null, 0, klen);
        auto wiv = tls13HkdfExpandLabel(m_hash_name, m_write_secret.ptr, m_write_secret.length,
                                        "iv", null, 0, TLS13_NONCE_LEN);
        m_encrypt.setKey(wkey.ptr, wkey.length);
        m_write_iv = Vector!ubyte(wiv[]);
        m_write_seq = 0;
        ++m_write_key_update_count;
    }

    void updateReadKeys()
    {
        if (!m_hash_name.length || !m_read_secret.length)
            throw new InvalidState("TLS 1.3 KeyUpdate requires traffic secrets");
        m_read_secret = tls13HkdfExpandLabel(m_hash_name, m_read_secret.ptr, m_read_secret.length,
                                             "traffic upd", null, 0, m_read_secret.length);
        Unique!AEADMode probe = getAead(m_aead_name, ENCRYPTION);
        const size_t klen = (*probe).keySpec().minimumKeylength();
        auto rkey = tls13HkdfExpandLabel(m_hash_name, m_read_secret.ptr, m_read_secret.length,
                                         "key", null, 0, klen);
        auto riv = tls13HkdfExpandLabel(m_hash_name, m_read_secret.ptr, m_read_secret.length,
                                        "iv", null, 0, TLS13_NONCE_LEN);
        m_decrypt.setKey(rkey.ptr, rkey.length);
        m_read_iv = Vector!ubyte(riv[]);
        m_read_seq = 0;
        ++m_read_key_update_count;
    }

    uint writeKeyUpdateCount() const { return m_write_key_update_count; }
    uint readKeyUpdateCount() const { return m_read_key_update_count; }

    size_t encryptOutputLength(size_t input_len) const { return m_encrypt.outputLength(input_len); }
    size_t decryptOutputLength(size_t input_len) const { return m_decrypt.outputLength(input_len); }
    size_t minimumDecryptionInputLength() const { return m_decrypt.minimumFinalSize(); }

    ulong encryptRecordFragment(const(ubyte)* header, size_t header_len, ref SecureVector!ubyte fragment)
    {
        if (m_write_seq == ulong.max)
            throw new InvalidState("TLS write sequence number overflow");
        if (m_encrypt.isEmpty)
            throw new InvalidState("TLS 1.3 encrypt AEAD missing");
        // Pull the class ref out. Unique alias-this + template start() AVs
        // on Win32 DMD (this==null inside GCM/GHASH).
        AEADMode enc = *m_encrypt;
        enc.setAssociatedData(header, header_len);
        auto nonce = nonceFor(m_write_seq, m_write_iv);
        enc.start(nonce.ptr, nonce.length);
        enc.finish(fragment);
        return m_write_seq++;
    }

    ulong decryptRecordFragment(const(ubyte)* header, size_t header_len, ref SecureVector!ubyte fragment)
    {
        if (m_decrypt.isEmpty)
            throw new InvalidState("TLS 1.3 decrypt AEAD missing");
        if (fragment.length < (*m_decrypt).minimumFinalSize())
            throw new DecodingError("TLS 1.3 fragment too short to decrypt");
        if (m_read_seq == ulong.max)
            throw new InvalidState("TLS read sequence number overflow");
        AEADMode dec = *m_decrypt;
        dec.setAssociatedData(header, header_len);
        auto nonce = nonceFor(m_read_seq, m_read_iv);
        dec.start(nonce.ptr, nonce.length);
        dec.finish(fragment);
        return m_read_seq++;
    }

private:
    static Vector!ubyte nonceFor(ulong seq, const ref Vector!ubyte iv)
    {
        Vector!ubyte nonce = Vector!ubyte(TLS13_NONCE_LEN);
        storeBigEndian(seq, nonce.ptr + 4);
        xorBuf(nonce.ptr, iv.ptr, TLS13_NONCE_LEN);
        return nonce.move();
    }

    Unique!AEADMode m_encrypt;
    Unique!AEADMode m_decrypt;
    Vector!ubyte m_write_iv;
    Vector!ubyte m_read_iv;
    ulong m_write_seq;
    ulong m_read_seq;
    string m_aead_name, m_hash_name;
    SecureVector!ubyte m_write_secret, m_read_secret;
    uint m_write_key_update_count, m_read_key_update_count;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import memutils.hashmap;
import std.stdio : File;
import std.string : toLower;

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing tls13/hkdf_label ...");
    size_t fails = 0;

    File vec = File("test_data/hkdf_label.vec", "r");
    fails += runTestsBb(vec, "Hash", "Output", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Secret" in m) || !("Label" in m) || !("HashValue" in m) || !("Output" in m))
                return 0;
            auto secret = hexDecode(m["Secret"]);
            auto ctx = hexDecode(m["HashValue"]);
            auto expect = hexDecode(m["Output"]);
            auto got = hkdfExpandLabel(m["Hash"], secret.ptr, secret.length,
                m["Label"], ctx.ptr, ctx.length, expect.length);
            if (got[] != expect[])
            {
                logError("hkdf_label got ", hexEncode(got).toLower, " want ", m["Output"].toLower);
                return 1;
            }
            return 0;
        });

    static if (BOTAN_HAS_AEAD_GCM && BOTAN_HAS_SHA2_32)
    {
        ubyte[32] ws = 3;
        ubyte[32] rs = 4;
        Unique!TLS13CipherState w = TLS13CipherState.fromTrafficSecrets(
            "AES-128/GCM", "SHA-256", ws.ptr, ws.length, rs.ptr, rs.length);
        Unique!TLS13CipherState r = TLS13CipherState.fromTrafficSecrets(
            "AES-128/GCM", "SHA-256", rs.ptr, rs.length, ws.ptr, ws.length);
        ubyte[5] hdr = [23, 3, 3, 0, 0];
        auto pt = SecureVector!ubyte(cast(ubyte[])[1, 2, 3, 4, 5]);
        auto ct = pt.clone;
        hdr[3] = cast(ubyte)(w.encryptOutputLength(ct.length) >> 8);
        hdr[4] = cast(ubyte) w.encryptOutputLength(ct.length);
        w.encryptRecordFragment(hdr.ptr, hdr.length, ct);
        r.decryptRecordFragment(hdr.ptr, hdr.length, ct);
        if (ct[] != pt[])
            ++fails;
        w.updateWriteKeys();
        r.updateReadKeys();
        if (w.writeKeyUpdateCount() != 1 || r.readKeyUpdateCount() != 1)
            ++fails;
        auto ct2 = pt.clone;
        hdr[3] = cast(ubyte)(w.encryptOutputLength(ct2.length) >> 8);
        hdr[4] = cast(ubyte) w.encryptOutputLength(ct2.length);
        w.encryptRecordFragment(hdr.ptr, hdr.length, ct2);
        r.decryptRecordFragment(hdr.ptr, hdr.length, ct2);
        if (ct2[] != pt[])
            ++fails;
    }

    fails += checkMemutilsRepeat("hkdf_label", {
        ubyte[32] secret = 1;
        ubyte[32] ctx = 2;
        auto got = hkdfExpandLabel("SHA-256", secret.ptr, secret.length,
            "tls13 test", ctx.ptr, ctx.length, 16);
        if (got.length != 16)
            throw new Exception("hkdf_label leak probe");
    });

    if (fails)
        logError("hkdf_label failures: ", fails);
    assert(fails == 0);
}
