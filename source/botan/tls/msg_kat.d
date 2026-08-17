/**
* TLS 1.2 handshake / alert message KATs (C++ src/tests/data/tls)
*
* Copyright:
* (C) 2004-2011,2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.msg_kat;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_TEST):

import botan.test;
import botan.tls.messages;
import botan.tls.alert;
import botan.tls.version_;
import botan.tls.exceptn;
import botan.tls.record;
import botan.codec.hex;
import botan.libstate.global_state;
import botan.utils.types;
import memutils.hashmap;
import std.array : replace;
import std.string : indexOf;
import std.algorithm : canFind;
import std.stdio : File;

private bool exceptionMatches(string got, string want)
{
    if (!want.length)
        return false;
    if (got.indexOf(want) >= 0)
        return true;
    return got.replace("_", "").indexOf(want.replace("_", "")) >= 0;
}

private size_t parseExpect(string expect_ex, void delegate() dg)
{
    try
    {
        dg();
        if (expect_ex.length)
            return 1;
        return 0;
    }
    catch (Exception e)
    {
        if (!expect_ex.length)
            return 2;
        if (!exceptionMatches(e.msg, expect_ex))
        {
            logError("tls msg exception got='", e.msg, "' want='", expect_ex, "'");
            return 3;
        }
        return 0;
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing tls/msg_kat.d ...");
    size_t fails = 0;

    File alert = File("test_data/tls/alert.vec", "r");
    fails += runTestsBb(alert, "alert", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecodeLocked(m["Buffer"]);
            return parseExpect(m["Exception"], {
                TLSAlert msg = TLSAlert(buf);
                if (msg.serialize().length != 2)
                    throw new Exception("alert serialize size");
            });
        });

    File hr = File("test_data/tls/hello_request.vec", "r");
    fails += runTestsBb(hr, "hello_request", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            return parseExpect(m["Exception"], {
                Unique!HelloRequest msg = new HelloRequest(buf);
            });
        });

    File hv = File("test_data/tls/hello_verify.vec", "r");
    fails += runTestsBb(hv, "hello_verify", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            return parseExpect(m["Exception"], {
                Unique!HelloVerifyRequest msg = new HelloVerifyRequest(buf);
            });
        });

    File nst = File("test_data/tls/new_session_ticket.vec", "r");
    fails += runTestsBb(nst, "new_session_ticket", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            return parseExpect(m["Exception"], {
                Unique!NewSessionTicket msg = new NewSessionTicket(buf);
            });
        });

    File cv = File("test_data/tls/cert_verify.vec", "r");
    fails += runTestsBb(cv, "cert_verify", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            auto ver = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
            return parseExpect(m["Exception"], {
                Unique!CertificateVerify msg = new CertificateVerify(buf, ver);
            });
        });

    File cs = File("test_data/tls/cert_status.vec", "r");
    fails += runTestsBb(cs, "cert_status", "Exception", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Buffer" in m) || !("Exception" in m))
                return 0;
            auto buf = hexDecode(m["Buffer"]);
            return parseExpect(m["Exception"], {
                Unique!CertificateStatus msg = new CertificateStatus(buf);
                auto wire = msg.serialize();
                Unique!CertificateStatus again = new CertificateStatus(wire);
                if (again.response()[] != msg.response()[])
                    throw new Exception("CertificateStatus round-trip mismatch");
                if ("Name" in m && m["Name"].length)
                {
                    if (!canFind(cast(const(char)[]) msg.response()[], m["Name"]))
                        throw new Exception("OCSP response missing signer name " ~ m["Name"]);
                }
            });
        });

    File cbc_pad = File("test_data/tls/tls_cbc_padding.vec", "r");
    fails += runTestsBb(cbc_pad, "tls_cbc_padding", "Output", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Record" in m) || !("Output" in m))
                return 0;
            auto rec = hexDecode(m["Record"]);
            import std.conv : to;
            const ushort got = checkTlsCbcPadding(rec.ptr, rec.length);
            if (got != to!ushort(m["Output"]))
                return 1;
            return 0;
        });

    fails += checkMemutilsRepeat("tls msg_kat parse", {
        auto empty = Vector!ubyte();
        Unique!HelloRequest hr = new HelloRequest(empty);
        auto nst_buf = hexDecode("000000000000");
        Unique!NewSessionTicket nst = new NewSessionTicket(nst_buf);
        auto cs_buf = hexDecode("01000000");
        try { Unique!CertificateStatus bad = new CertificateStatus(cs_buf); }
        catch (Exception) {}
        auto ok = hexDecode("0130");
        auto locked = hexDecodeLocked("0130");
        TLSAlert alert = TLSAlert(locked);
        auto ser = alert.serialize();
        if (ser.length != 2)
            throw new Exception("tls msg leak probe");
    });

    if (fails)
        logError("tls msg_kat failures: ", fails);
    assert(fails == 0);
}
