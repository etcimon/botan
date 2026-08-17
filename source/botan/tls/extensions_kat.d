/**
* C++ `tls_extensions/parsing` KATs.
*
* Copyright:
* (C) 2011,2012,2015,2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.extensions_kat;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TESTS && !SKIP_TLS_TEST):

import botan.test;
import botan.tls.extensions;
import botan.tls.reader;
import botan.tls.version_;
import botan.tls.exceptn;
import botan.codec.hex;
import botan.libstate.global_state;
import botan.utils.types;
import botan.utils.parsing;
import memutils.hashmap;
import std.stdio : File;
import std.string : indexOf, toLower, strip;
import std.array : replace;
import std.conv : to;

static if (BOTAN_HAS_TLS_13)
{
    import botan.tls.tls13.hello_ext;
    import botan.tls.tls13.key_share_gen;
    import botan.rng.test;
}

private bool exceptionMatches(string got, string want)
{
    if (!want.length)
        return false;
    if (got.indexOf(want) >= 0)
        return true;
    return got.replace("_", "").indexOf(want.replace("_", "")) >= 0;
}

private size_t expectThrow(string got, string want)
{
    if (exceptionMatches(got, want))
        return 0;
    logError("tls ext exception got='", got, "' want='", want, "'");
    return 1;
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing tls extensions parsing ...");
    size_t fails = 0;

    void runFile(string path, string name_key)
    {
        File vec = File(path, "r");
        fails += runTestsBb(vec, name_key, "Exception", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Buffer" in m) || !("Exception" in m))
                    return 0;
                auto buf = hexDecode(("Buffer" in m) ? m["Buffer"] : "");
                const string expect_ex = m["Exception"];
                const string ext = m[name_key];
                try
                {
                    if (ext == "alpn")
                    {
                        auto reader = TLSDataReader("ClientHello", buf);
                        Unique!ApplicationLayerProtocolNotification alpn =
                            new ApplicationLayerProtocolNotification(reader, cast(ushort)buf.length);
                        if (expect_ex.length)
                            return 1;
                        string joined;
                        foreach (p; alpn.protocols()[])
                        {
                            if (joined.length)
                                joined ~= ",";
                            joined ~= p;
                        }
                        const string want = ("Expected_Content" in m) ? m["Expected_Content"] : "";
                        if (joined != want)
                        {
                            logError("alpn got '", joined, "' want '", want, "'");
                            return 1;
                        }
                        return 0;
                    }
                    if (ext == "supported_groups")
                    {
                        auto reader = TLSDataReader("ClientHello", buf);
                        Unique!SupportedEllipticCurves groups =
                            new SupportedEllipticCurves(reader, cast(ushort)buf.length);
                        if (expect_ex.length)
                            return 1;
                        auto expect = hexDecode(m["Expected_Content"]);
                        if (groups.groupIds().length * 2 != expect.length)
                            return 1;
                        auto ser = groups.serialize();
                        if (ser[] != buf[])
                        {
                            logError("supported_groups serialize mismatch");
                            return 1;
                        }
                        return 0;
                    }
                    if (ext == "signature_algorithms_cert")
                    {
                        auto reader = TLSDataReader("Extension", buf);
                        Unique!SignatureAlgorithmsCert sig =
                            new SignatureAlgorithmsCert(reader, cast(ushort)buf.length);
                        if (expect_ex.length)
                            return 1;
                        auto expect = hexDecode(m["Expected_Content"]);
                        if (sig.schemes().length * 2 != expect.length)
                            return 1;
                        auto ser = sig.serialize();
                        if (ser[] != buf[])
                        {
                            logError("signature_algorithms_cert serialize mismatch");
                            return 1;
                        }
                        return 0;
                    }
                    static if (BOTAN_HAS_TLS_13)
                    {
                        if (ext == "supported_version")
                        {
                            auto reader = TLSDataReader("ClientHello", buf);
                            Unique!TLS13SupportedVersions sv =
                                new TLS13SupportedVersions(reader, cast(ushort)buf.length, false);
                            if (expect_ex.length)
                                return 1;
                            auto parts = splitter(m["Expected_Content"], ',');
                            foreach (part; parts[])
                            {
                                auto vhex = hexDecode(part.strip);
                                if (vhex.length != 2)
                                    return 1;
                                auto ver = TLSProtocolVersion(vhex[0], vhex[1]);
                                if (!sv.supports(ver))
                                {
                                    logError("supported_versions missing ", part);
                                    return 1;
                                }
                            }
                            auto ser = sv.serialize();
                            if (ser[] != buf[])
                            {
                                logError("supported_versions serialize mismatch");
                                return 1;
                            }
                            return 0;
                        }
                        if (ext == "cookie")
                        {
                            auto reader = TLSDataReader("HelloRetryRequest", buf);
                            Unique!TLS13Cookie cookie =
                                new TLS13Cookie(reader, cast(ushort)buf.length);
                            if (expect_ex.length)
                                return 1;
                            auto expect = hexDecode(m["Expected_Content"]);
                            if (cookie.cookie()[] != expect[])
                            {
                                logError("cookie mismatch");
                                return 1;
                            }
                            return 0;
                        }
                        if (ext == "key_share_CH" || ext == "key_share_SH" || ext == "key_share_HRR")
                        {
                            auto kind = TLS13KeyShare.Kind.Client;
                            string rname = "ClientHello";
                            if (ext == "key_share_SH")
                            {
                                kind = TLS13KeyShare.Kind.Server;
                                rname = "ServerHello";
                            }
                            else if (ext == "key_share_HRR")
                            {
                                kind = TLS13KeyShare.Kind.HelloRetry;
                                rname = "HelloRetryRequest";
                            }
                            auto reader = TLSDataReader(rname, buf);
                            Unique!TLS13KeyShare ks =
                                new TLS13KeyShare(reader, cast(ushort)buf.length, kind);
                            if (expect_ex.length)
                                return 1;
                            auto ser = ks.serialize();
                            auto expect = hexDecode(m["Expected_Content"]);
                            if (ser[] != expect[])
                            {
                                logError(ext, " serialize mismatch");
                                return 1;
                            }
                            return 0;
                        }
                    }
                    throw new Exception("Unknown TLS extension KAT " ~ ext);
                }
                catch (Exception e)
                {
                    if (!expect_ex.length)
                    {
                        logError(ext, " unexpected: ", e.msg);
                        return 1;
                    }
                    return expectThrow(e.msg, expect_ex);
                }
            });
    }

    runFile("test_data/tls/extensions/parsing/alpn.vec", "alpn");
    runFile("test_data/tls/extensions/parsing/supported_groups.vec", "supported_groups");
    runFile("test_data/tls/extensions/parsing/signature_algorithms_cert.vec", "signature_algorithms_cert");
    static if (BOTAN_HAS_TLS_13)
    {
        runFile("test_data/tls/extensions/parsing/supported_versions.vec", "supported_version");
        runFile("test_data/tls/extensions/parsing/cookie.vec", "cookie");
        runFile("test_data/tls/extensions/parsing/key_share_CH.vec", "key_share_CH");
        runFile("test_data/tls/extensions/parsing/key_share_SH.vec", "key_share_SH");
        runFile("test_data/tls/extensions/parsing/key_share_HRR.vec", "key_share_HRR");
    }

    static if (BOTAN_HAS_TLS_13)
    {
        import std.file : exists;
        if (exists("test_data/tls/extensions/generation/key_share_CH_offers.vec"))
        {
            File vec = File("test_data/tls/extensions/generation/key_share_CH_offers.vec", "r");
            fails += runTestsBb(vec, "key_share_CH_offers", "Expected_Content", true,
                (ref HashMap!(string, string) m)
                {
                    if (!("Groups" in m) || !("Expected_Content" in m))
                        return 0;
                    const string offered = ("Offered_Groups" in m) ? m["Offered_Groups"] : "";
                    auto seed = hexDecode(m.get("Rng_Data", ""));
                    Unique!FixedOutputRNG rng = new FixedOutputRNG(seed);
                    auto got = generateTls13ClientHelloKeyShare(m["Groups"], offered, *rng);
                    auto want = hexDecode(m["Expected_Content"]);
                    if (got[] != want[])
                    {
                        logError("key_share_CH_offers ", m["Groups"],
                                 " got ", hexEncode(got), " != ", hexEncode(want));
                        return 1;
                    }
                    return 0;
                });
        }
    }

    fails += checkMemutilsRepeat("tls_ext_alpn", {
        auto buf = hexDecode("0003026832");
        auto reader = TLSDataReader("ClientHello", buf);
        Unique!ApplicationLayerProtocolNotification alpn =
            new ApplicationLayerProtocolNotification(reader, cast(ushort)buf.length);
        if (alpn.protocols().length != 1)
            throw new Exception("alpn leak probe");
    });

    if (fails)
        logError("tls extension parse failures: ", fails);
    assert(fails == 0);
}
