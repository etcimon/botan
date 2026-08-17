/**
* TLS 1.3 ClientHello / ServerHello parse tests (RFC 8448)
*
* Copyright:
* (C) 2004-2011,2015,2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.hello13;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13 && BOTAN_TEST):

import botan.test;
import botan.tls.messages;
import botan.tls.magic;
import botan.tls.version_;
import botan.tls.exceptn;
import botan.tls.extensions;
import botan.codec.hex;
import botan.libstate.global_state;
import botan.utils.types;
import memutils.hashmap;
import std.algorithm : sort;
import std.array : replace;
import std.string : toLower, indexOf;
import std.stdio : File;

/// C++ KATs emit std::set order (sorted type codes).
private string extTypesHex()(const auto ref Vector!HandshakeExtensionType types)
{
    ushort[] tmp;
    tmp.length = types.length;
    foreach (i, t; types[])
        tmp[i] = t;
    tmp.sort();
    Vector!ubyte buf;
    foreach (t; tmp)
    {
        buf.pushBack(cast(ubyte)(t >> 8));
        buf.pushBack(cast(ubyte) t);
    }
    return hexEncode(buf, false);
}

private bool exceptionMatches(string got, string want)
{
    if (!want.length)
        return false;
    if (got.indexOf(want) >= 0)
        return true;
    return got.replace("_", "").indexOf(want.replace("_", "")) >= 0;
}

private string suitesHex()(const auto ref Vector!ushort suites)
{
    Vector!ubyte buf;
    foreach (s; suites[])
    {
        buf.pushBack(cast(ubyte)(s >> 8));
        buf.pushBack(cast(ubyte) s);
    }
    return hexEncode(buf, false);
}

private string versionHex(TLSProtocolVersion v)
{
    ubyte[2] b = [v.majorVersion(), v.minorVersion()];
    return hexEncode(b.ptr, 2, false);
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing tls13/hello.d ...");
    size_t fails = 0;

    File ch = File("test_data/tls_13/client_hello.vec", "r");
    fails += runTestsBb(ch, "client_hello", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            const string expect_ex = m["Exception"];
            try
            {
                Unique!ClientHello hello = new ClientHello(buf, CLIENT_HELLO);
                if (expect_ex.length)
                    return 1;
                if ("Protocol" in m && versionHex(hello.Version()) != m["Protocol"].toLower)
                    return 2;
                const bool is13 = hello.Version() == TLSProtocolVersion(TLSProtocolVersion.TLS_V13);
                if ("Message_Type" in m)
                {
                    const string mt = m["Message_Type"];
                    if (is13 && mt != "client_hello_13")
                        return 3;
                    if (!is13 && mt != "client_hello_12")
                        return 3;
                }
                if ("AdditionalData" in m)
                {
                    const string got = extTypesHex(hello.extensionTypes());
                    const string want = m["AdditionalData"].toLower;
                    // D synthesizes empty renegotiation_info from SCSV; C++ KATs omit it.
                    if (got != want &&
                        !(got.length >= 4 && got[$-4 .. $] == "ff01" &&
                          ((got.length == 4 && want.length == 0) || got[0 .. $-4] == want)))
                        return 4;
                }
                if ("Ciphersuite" in m && suitesHex(hello.ciphersuites()) != m["Ciphersuite"].toLower)
                    return 5;
                return 0;
            }
            catch (Exception e)
            {
                if (!expect_ex.length)
                    return 6;
                if (!exceptionMatches(e.msg, expect_ex))
                {
                    logError("client_hello exception got='", e.msg, "' want='", expect_ex, "'");
                    return 7;
                }
                return 0;
            }
        });

    File sh = File("test_data/tls_13/server_hello.vec", "r");
    fails += runTestsBb(sh, "server_hello", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            const string expect_ex = m["Exception"];
            try
            {
                Unique!ServerHello hello = new ServerHello(buf);
                if (expect_ex.length)
                    return 1;
                if ("Protocol" in m && versionHex(hello.Version()) != m["Protocol"].toLower)
                    return 2;
                if ("Message_Type" in m)
                {
                    const string mt = m["Message_Type"];
                    if (hello.isHelloRetryRequest())
                    {
                        if (mt != "hello_retry_request")
                            return 3;
                    }
                    else if (hello.Version() == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                    {
                        if (mt != "server_hello_13")
                            return 3;
                    }
                    else if (mt != "server_hello_12")
                        return 3;
                }
                if ("AdditionalData" in m && extTypesHex(hello.extensionTypes()) != m["AdditionalData"].toLower)
                    return 4;
                if ("Ciphersuite" in m)
                {
                    auto cs = hexDecode(m["Ciphersuite"]);
                    if (cs.length != 2)
                        return 5;
                    const ushort want = cast(ushort)((cs[0] << 8) | cs[1]);
                    if (hello.ciphersuite() != want)
                        return 5;
                }
                return 0;
            }
            catch (Exception e)
            {
                if (!expect_ex.length)
                    return 6;
                if (!exceptionMatches(e.msg, expect_ex))
                    return 7;
                return 0;
            }
        });

    // Repeat-parse after the vec HashMap is live: Unique-destroy must not grow DebugAllocator.
    {
        auto pin = hexDecode(
            "0303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7" ~
            "000006130113031302010000910000000b0009000006736572766572ff01000100" ~
            "000a00140012001d00170018001901000101010201030104002300000033002600" ~
            "24001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e" ~
            "529aaf2c002b0003020304000d0020001e04030503060302030804080508060401" ~
            "0501060102010402050206020202002d00020101001c00024001");
        {
            Unique!ClientHello warm = new ClientHello(pin, CLIENT_HELLO);
        }
        auto snap = takeMemutilsSnap();
        {
            Unique!ClientHello hello = new ClientHello(pin, CLIENT_HELLO);
            if (hello.Version() != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                ++fails;
        }
        if (memutilsGrowth(snap, "tls13 hello parse repeat"))
            ++fails;
    }

    // T13d: emit 1.3 ClientHello (legacy 1.2 + supported_versions + key_share).
    {
        import botan.tls.handshake_io;
        import botan.tls.handshake_hash;
        import botan.tls.policy;
        import botan.rng.auto_rng;
        class Offer13Policy : TLSPolicy
        {
            override bool acceptableProtocolVersion(TLSProtocolVersion v) const
            {
                return !v.isDatagramProtocol() &&
                    (v == TLSProtocolVersion(TLSProtocolVersion.TLS_V12) ||
                     v == TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
            }
        }
        Unique!Offer13Policy pol = new Offer13Policy;
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        auto io = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
        HandshakeHash hh;
        ClientHello offered = new ClientHello(io, hh,
            TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
            *pol, *rng, Vector!ubyte(), Vector!string(), "server", "");
        scope(exit) botanDestroyIfLive(offered);
        if (offered.Version() != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
            ++fails;
        const(ubyte)[] fmt = hh.getContents()[];
        if (fmt.length < 4)
            ++fails;
        else
        {
            Vector!ubyte body;
            foreach (b; fmt[4 .. $])
                body.pushBack(b);
            Unique!ClientHello parsed = new ClientHello(body, CLIENT_HELLO);
        if (parsed.Version() != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
            ++fails;
        if (parsed.ciphersuites().length == 0 || parsed.ciphersuites()[0] != 0x1301)
            ++fails;
        bool saw_sv, saw_ks;
        foreach (t; parsed.extensionTypes()[])
        {
            if (t == TLSEXT_SUPPORTED_VERSIONS) saw_sv = true;
            if (t == TLSEXT_KEY_SHARE) saw_ks = true;
        }
        if (!saw_sv)
            ++fails;
        static if (BOTAN_HAS_CURVE25519)
            if (!saw_ks)
                ++fails;
        }

        // T13d: ServerHello 1.3 emit (legacy 0x0303 + SV + key_share).
        {
            import botan.tls.handshake_io;
            import botan.tls.handshake_hash;
            ubyte[32] dummy_pub;
            dummy_pub[] = 0x11;
            HandshakeHash shh;
            auto sio = new StreamHandshakeIO((ubyte, const ref Vector!ubyte) {});
            Unique!ServerHello sh_msg = new ServerHello(sio, shh, *pol,
                Vector!ubyte(),
                TLSProtocolVersion(TLSProtocolVersion.TLS_V13),
                0x1301, 0, 0, false, false, Vector!ubyte(),
                false, false, "", false, *rng,
                0x001d, dummy_pub[]);
            if (sh_msg.Version() != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                ++fails;
            const(ubyte)[] sfmt = shh.getContents()[];
            if (sfmt.length < 6)
                ++fails;
            else
            {
                if (sfmt[4] != 0x03 || sfmt[5] != 0x03)
                    ++fails;
                Vector!ubyte sbody;
                foreach (b; sfmt[4 .. $])
                    sbody.pushBack(b);
                Unique!ServerHello parsed_sh = new ServerHello(sbody);
                if (parsed_sh.Version() != TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                    ++fails;
                if (parsed_sh.ciphersuite() != 0x1301)
                    ++fails;
                auto et = parsed_sh.extensionTypes();
                bool sh_sv, sh_ks;
                foreach (t; et[])
                {
                    if (t == TLSEXT_SUPPORTED_VERSIONS) sh_sv = true;
                    if (t == TLSEXT_KEY_SHARE) sh_ks = true;
                }
                if (parsed_sh.tls13KeyShare() !is null)
                    sh_ks = true;
                if (!sh_sv || !sh_ks)
                    ++fails;
            }
        }

        // EncryptedExtensions emit/parse (empty list is 00 00).
        {
            Unique!TLS13EncryptedExtensions empty_ee = new TLS13EncryptedExtensions();
            auto eew = empty_ee.serialize();
            if (eew.length != 2 || eew[0] != 0 || eew[1] != 0)
                ++fails;
            Unique!TLS13EncryptedExtensions parsed_ee = new TLS13EncryptedExtensions(eew);
            Unique!TLS13EncryptedExtensions from_ch = new TLS13EncryptedExtensions(offered);
            auto ch_ee = from_ch.serialize();
            Unique!TLS13EncryptedExtensions parsed_ch_ee = new TLS13EncryptedExtensions(ch_ee);
        }
    }

    if (fails)
        logError("tls13 hello failures: ", fails);
    assert(fails == 0);
}
