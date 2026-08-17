/**
* Charset KAT driver
*
* Lives in its own module so `charset.d` can stay below `botan.test`
* in the import graph (parsing/exceptn/types cycle).
*
* Copyright:
* (C) 1999-2007,2021 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.charset_kat;

import botan.constants;
static if (BOTAN_HAS_TESTS && !SKIP_CHARSET_TEST):

import botan.test;
import botan.utils.charset;
import botan.codec.hex;
import botan.utils.exceptn;
import memutils.hashmap;
import std.stdio : File;

unittest
{
    logDebug("Testing charset.d ...");
    size_t fails = 0;

    File vec = File("test_data/charset.vec", "r");
    fails += runTestsBb(vec, "Charset", "Out", true,
        (ref HashMap!(string, string) m)
        {
            auto input = hexDecode(("In" in m) ? m["In"] : "");
            const string typ = m["Charset"];
            if (typ == "UTF8-UCS2-INVALID")
            {
                try
                {
                    cast(void)utf8ToUcs2(input[]);
                    logError("utf8ToUcs2 accepted invalid ", m["In"]);
                    return 1;
                }
                catch (DecodingError)
                {
                    return 0;
                }
            }
            if (typ == "UTF8-UCS4-INVALID")
            {
                try
                {
                    cast(void)utf8ToUcs4(input[]);
                    logError("utf8ToUcs4 accepted invalid ", m["In"]);
                    return 1;
                }
                catch (DecodingError)
                {
                    return 0;
                }
            }
            auto expect = hexDecode(("Out" in m) ? m["Out"] : "");
            Vector!ubyte got;
            if (typ == "UCS2-UTF8")
                got = ucs2ToUtf8(input[]);
            else if (typ == "UCS4-UTF8")
                got = ucs4ToUtf8(input[]);
            else if (typ == "UTF8-UCS2")
                got = utf8ToUcs2(input[]);
            else if (typ == "UTF8-UCS4")
                got = utf8ToUcs4(input[]);
            else if (typ == "LATIN1-UTF8")
                got = latin1ToUtf8Bytes(input[]);
            else
                throw new Exception("Unexpected charset header " ~ typ);
            if (got[] != expect[])
            {
                logError(typ, " got ", hexEncode(got), " expected ", m["Out"]);
                return 1;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("charset", {
        auto inb = hexDecode("0042006F00740061006E");
        auto outb = ucs2ToUtf8(inb[]);
        auto back = utf8ToUcs2(outb[]);
        if (back[] != inb[])
            throw new Exception("charset leak probe");
    });

    if (fails)
        logError("charset failures: ", fails);
    assert(fails == 0);
}
