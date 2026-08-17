/**
* RFC 9258 imported PSK (TLS 1.3)
*
* Copyright:
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2025,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.psk_importer;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.tls.tls13.cipher_state;
import botan.tls.tls13.handshake;
import botan.tls.version_;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.types;

/**
* RFC 9258 PSK importer. EPSK hash is `hash` (SHA-256 or SHA-384);
* target hash may differ and only sets ImportedIdentity.target_kdf
* and the Expand-Label output length.
*/
final class PSKImporter
{
public:
    this(const(ubyte)* key, size_t key_len,
         const(ubyte)* identity, size_t identity_len,
         const(ubyte)* context, size_t context_len,
         string hash)
    {
        if (hash != "SHA-256" && hash != "SHA-384")
            throw new InvalidArgument("PSK importer hash must be SHA-256 or SHA-384");
        if (identity_len == 0)
            throw new InvalidArgument("PSK importer identity must not be empty");
        if (identity_len + context_len + 8 > 0xFFFF)
            throw new InvalidArgument("PSK importer identity + context too long for a TLS PSK identity");
        m_key = SecureVector!ubyte(key[0 .. key_len]);
        m_identity = Vector!ubyte(identity[0 .. identity_len]);
        m_context = Vector!ubyte(context[0 .. context_len]);
        m_hash = hash;
    }

    /// RFC 9258 5.1: HKDF-Extract(0, epsk) then HKDF-Expand-Label(..., "derived psk", Hash(ImportedIdentity), L).
    SecureVector!ubyte deriveImportedPsk(TLSProtocolVersion ver, string target_hash) const
    {
        if (ver != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
            throw new InvalidArgument("PSK importer is only defined for TLS 1.3");
        if (target_hash != "SHA-256" && target_hash != "SHA-384")
            throw new InvalidArgument("PSK importer target hash must be SHA-256 or SHA-384");

        const ushort target_protocol = TLSProtocolVersion.TLS_V13;
        const ushort target_kdf = (target_hash == "SHA-256") ? 0x0001 : 0x0002;

        auto imported = Vector!ubyte();
        const ushort id_len = cast(ushort) m_identity.length;
        const ushort ctx_len = cast(ushort) m_context.length;
        imported.pushBack(cast(ubyte)(id_len >> 8));
        imported.pushBack(cast(ubyte) id_len);
        imported ~= m_identity[];
        imported.pushBack(cast(ubyte)(ctx_len >> 8));
        imported.pushBack(cast(ubyte) ctx_len);
        imported ~= m_context[];
        imported.pushBack(cast(ubyte)(target_protocol >> 8));
        imported.pushBack(cast(ubyte) target_protocol);
        imported.pushBack(cast(ubyte)(target_kdf >> 8));
        imported.pushBack(cast(ubyte) target_kdf);

        Unique!HashFunction h = retrieveHash(m_hash).clone();
        const size_t psk_hash_len = h.outputLength;
        h.update(imported.ptr, imported.length);
        auto identity_hash = h.finished();

        const size_t target_len = retrieveHash(target_hash).outputLength;

        auto salt = SecureVector!ubyte(psk_hash_len);
        auto epskx = tls13HkdfExtract(m_hash, salt.ptr, salt.length, m_key.ptr, m_key.length);
        return tls13HkdfExpandLabel(m_hash, epskx.ptr, epskx.length, "derived psk",
                                    identity_hash.ptr, identity_hash.length, target_len);
    }

private:
    SecureVector!ubyte m_key;
    Vector!ubyte m_identity;
    Vector!ubyte m_context;
    string m_hash;
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.utils.mem_ops;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing tls13/psk_importer ...");
    size_t fails;

    if (exists("test_data/tls/tls_13_psk_import.vec"))
    {
        File vec = File("test_data/tls/tls_13_psk_import.vec", "r");
        fails += runTestsBb(vec, "Hash", "Output", false,
            (ref HashMap!(string, string) m)
            {
                if (!("Key" in m) || !("Identity" in m) || !("TargetHash" in m) || !("Output" in m))
                    return 0;
                auto key = hexDecode(m["Key"]);
                auto identity = hexDecode(m["Identity"]);
                auto context = hexDecode(m.get("Context", ""));
                auto want = hexDecode(m["Output"]);
                Unique!PSKImporter importer = new PSKImporter(key.ptr, key.length,
                                                              identity.ptr, identity.length,
                                                              context.ptr, context.length,
                                                              m["Hash"]);
                auto got = importer.deriveImportedPsk(
                    TLSProtocolVersion(TLSProtocolVersion.TLS_V13), m["TargetHash"]);
                if (got.length != want.length || !sameMem(got.ptr, want.ptr, want.length))
                {
                    logError("psk_import ", m["Hash"], " -> ", m["TargetHash"],
                             " got ", hexEncode(got), " != ", hexEncode(want));
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("psk_import", {
        ubyte[32] key = 0x41;
        ubyte[4] id = [0x70, 0x73, 0x6b, 0x31];
        Unique!PSKImporter importer = new PSKImporter(key.ptr, key.length, id.ptr, id.length,
                                                      null, 0, "SHA-256");
        auto got = importer.deriveImportedPsk(
            TLSProtocolVersion(TLSProtocolVersion.TLS_V13), "SHA-256");
        if (got.length != 32)
            throw new Exception("psk_import leak probe");
    });

    if (fails)
        logError("psk_import failures: ", fails);
    assert(fails == 0);
}
