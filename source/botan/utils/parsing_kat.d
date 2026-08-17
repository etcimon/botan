/**
* Parsing KAT driver (`read_kv`)
*
* Lives in its own module so `parsing.d` can stay below `botan.test`
* in the import graph (exceptn/types cycle).
*
* Copyright:
* (C) 2018 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.parsing_kat;

import botan.constants;
static if (BOTAN_HAS_TESTS && !SKIP_PARSING_TEST):

import botan.test;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.codec.hex;
import memutils.hashmap;
import std.stdio : File;

unittest
{
    logDebug("Testing parsing read_kv ...");
    size_t fails = 0;

    File vec = File("test_data/read_kv.vec", "r");
    fails += runTestsBb(vec, "Kind", "Expected", true,
        (ref HashMap!(string, string) m)
        {
            const string input = ("Input" in m) ? m["Input"] : "";
            const string expect = ("Expected" in m) ? m["Expected"] : "";
            const string kind = m["Kind"];
            if (kind == "Invalid")
            {
                try
                {
                    auto kv = readKv(input);
                    logError("read_kv accepted invalid '", input, "'");
                    return 1;
                }
                catch (InvalidArgument e)
                {
                    if (expect.length && e.msg.indexOf(expect) < 0)
                    {
                        logTrace("read_kv leftover msg '", e.msg, "' expected '", expect, "'");
                    }
                    return 0;
                }
            }
            auto kv = readKv(input);
            Vector!string pairs;
            string cur;
            foreach (char c; expect)
            {
                if (c == '|')
                {
                    pairs.pushBack(cur);
                    cur = "";
                }
                else
                    cur ~= c;
            }
            if (cur.length || (expect.length && expect[$-1] == '|'))
                pairs.pushBack(cur);
            if (pairs.length % 2)
            {
                logError("read_kv expected odd pair list ", expect);
                return 1;
            }
            if (kv.length != pairs.length / 2)
            {
                logError("read_kv size ", kv.length, " != ", pairs.length / 2, " for '", input, "'");
                return 1;
            }
            for (size_t i = 0; i != pairs.length; i += 2)
            {
                if (!(pairs[i] in kv) || kv[pairs[i]] != pairs[i + 1])
                {
                    logError("read_kv mismatch key ", pairs[i], " input '", input, "'");
                    return 1;
                }
            }
            return 0;
        });

    fails += checkMemutilsRepeat("read_kv", {
        auto kv = readKv("K=V,K2=W");
        if (kv.length != 2)
            throw new Exception("read_kv leak probe");
    });

    File ipv4 = File("test_data/ipv4.vec", "r");
    fails += runTestsBb(ipv4, "Kind", "IPv4", true,
        (ref HashMap!(string, string) m)
        {
            const string input = m["IPv4"];
            const bool valid = m["Kind"] == "Valid";
            uint ip;
            const bool ok = tryStringToIpv4(input, ip);
            if (ok != valid)
            {
                logError("ipv4 ", valid ? "rejected" : "accepted", " ", input);
                return 1;
            }
            if (ok && ipv4ToString(ip) != input)
            {
                logError("ipv4 round-trip ", input, " -> ", ipv4ToString(ip));
                return 1;
            }
            return 0;
        });

    File sub = File("test_data/ipv4_subnet.vec", "r");
    fails += runTestsBb(sub, "Kind", "IPv4Subnet", true,
        (ref HashMap!(string, string) m)
        {
            const string input = m["IPv4Subnet"];
            const bool valid = m["Kind"] == "Valid";
            uint addr;
            ubyte prefix;
            const bool ok = tryParseIpv4Subnet(input, addr, prefix);
            if (ok != valid)
            {
                logError("ipv4 subnet ", valid ? "rejected" : "accepted", " ", input);
                return 1;
            }
            if (ok && ipv4SubnetToString(addr, prefix) != input)
            {
                logError("ipv4 subnet round-trip ", input, " -> ", ipv4SubnetToString(addr, prefix));
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("ipv4", {
        uint ip;
        if (!tryStringToIpv4("127.0.0.1", ip) || ipv4ToString(ip) != "127.0.0.1")
            throw new Exception("ipv4 leak probe");
    });

    File ipv6 = File("test_data/ipv6.vec", "r");
    fails += runTestsBb(ipv6, "Kind", "IPv6", true,
        (ref HashMap!(string, string) m)
        {
            const string input = ("IPv6" in m) ? m["IPv6"] : "";
            const bool valid = m["Kind"] == "Valid";
            ubyte[16] ip;
            const bool ok = tryStringToIpv6(input, ip);
            if (ok != valid)
            {
                logError("ipv6 ", valid ? "rejected" : "accepted", " ", input);
                return 1;
            }
            if (ok && ipv6ToString(ip) != input)
            {
                logError("ipv6 round-trip ", input, " -> ", ipv6ToString(ip));
                return 1;
            }
            return 0;
        });

    File v6sub = File("test_data/ipv6_subnet.vec", "r");
    fails += runTestsBb(v6sub, "Kind", "IPv6Subnet", true,
        (ref HashMap!(string, string) m)
        {
            const string input = m["IPv6Subnet"];
            const bool valid = m["Kind"] == "Valid";
            ubyte[16] addr;
            ubyte prefix;
            const bool ok = tryParseIpv6Subnet(input, addr, prefix);
            if (ok != valid)
            {
                logError("ipv6 subnet ", valid ? "rejected" : "accepted", " ", input);
                return 1;
            }
            if (ok && ipv6SubnetToString(addr, prefix) != input)
            {
                logError("ipv6 subnet round-trip ", input, " -> ", ipv6SubnetToString(addr, prefix));
                return 1;
            }
            return 0;
        });

    File dns = File("test_data/dns.vec", "r");
    fails += runTestsBb(dns, "Kind", "DNS", true,
        (ref HashMap!(string, string) m)
        {
            const string input = m["DNS"];
            const string kind = m["Kind"];
            string canon;
            const bool from_string = tryParseDnsName(input, canon);
            string san;
            const bool from_san = tryParseDnsSanName(input, san);
            if (kind == "Valid")
            {
                if (!from_string || !from_san)
                {
                    logError("dns rejected valid ", input);
                    return 1;
                }
                return 0;
            }
            if (kind == "ValidWildcard")
            {
                if (from_string || !from_san)
                {
                    logError("dns wildcard ", input, " from_string=", from_string, " from_san=", from_san);
                    return 1;
                }
                return 0;
            }
            if (from_string || from_san)
            {
                logError("dns accepted invalid ", input);
                return 1;
            }
            return 0;
        });

    File wild = File("test_data/dns_wildcards.vec", "r");
    fails += runTestsBb(wild, "Kind", "Hostname", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Issued" in m) || !("Hostname" in m))
                return 0;
            const bool expect = m["Kind"] != "Invalid";
            if (hostWildcardMatch(m["Issued"], m["Hostname"]) != expect)
            {
                logError("dns wildcard ", m["Issued"], " vs ", m["Hostname"]);
                return 1;
            }
            return 0;
        });

    File nc = File("test_data/ipv6_nc.vec", "r");
    fails += runTestsBb(nc, "IPv6Nc", "Canonical", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Input" in m) || !("Canonical" in m))
                return 0;
            ubyte[16] got;
            ubyte[16] canon;
            if (!tryStringToIpv6(m["Input"], got) || !tryStringToIpv6(m["Canonical"], canon))
            {
                logError("ipv6_nc parse fail ", m["Input"]);
                return 1;
            }
            if (got[] != canon[] || ipv6ToString(got) != m["Canonical"])
            {
                logError("ipv6_nc ", m["Input"], " -> ", ipv6ToString(got), " expected ", m["Canonical"]);
                return 1;
            }
            return 0;
        });

    File gnip = File("test_data/general_name_ip.vec", "r");
    fails += runTestsBb(gnip, "Kind", "Netmask", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Address" in m) || !("Netmask" in m))
                return 0;
            auto addr = hexDecode(m["Address"]);
            auto mask = hexDecode(m["Netmask"]);
            const bool expect = m["Kind"] == "Valid";
            if (tryParseIpConstraintMask(addr[], mask[]) != expect)
            {
                logError("ip constraint mask ", m["Kind"], " ", m["Address"], "/", m["Netmask"]);
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("ipv6", {
        ubyte[16] ip;
        if (!tryStringToIpv6("::1", ip) || ipv6ToString(ip) != "::1")
            throw new Exception("ipv6 leak probe");
    });

    if (fails)
        logError("parsing kat failures: ", fails);
    assert(fails == 0);
}
