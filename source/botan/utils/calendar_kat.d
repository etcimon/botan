/**
* Calendar KAT driver (`dates.vec`)
*
* Lives in its own module so `calendar.d` stays below `botan.test`.
*
* Copyright:
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.calendar_kat;

import botan.constants;
static if (BOTAN_HAS_TESTS && !SKIP_CALENDAR_TEST):

import botan.test;
import botan.utils.calendar;
import botan.utils.exceptn;
import memutils.hashmap;
import std.stdio : File;
import std.conv : to;
import std.algorithm : splitter;
import std.array : array;
import core.stdc.time : time_t;

unittest
{
    logDebug("Testing calendar.d ...");
    size_t fails = 0;

    uint[] parseDate(string s)
    {
        auto parts = s.splitter(',').array;
        if (parts.length != 6)
            throw new Exception("Bad date format '" ~ s ~ "'");
        uint[] u;
        foreach (p; parts)
            u ~= to!uint(p);
        return u;
    }

    File vec = File("test_data/dates.vec", "r");
    fails += runTestsBb(vec, "Kind", "Date", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Date" in m))
                return 0;
            const string kind = m["Kind"];
            const auto d = parseDate(m["Date"]);
            if (kind == "valid" || kind == "valid.not_std" || kind == "valid.64_bit_time_t")
            {
                auto c = CalendarPoint(d[0], d[1], d[2], d[3], d[4], d[5]);
                if (c.year != d[0] || c.month != d[1] || c.day != d[2]
                    || c.hour != d[3] || c.minutes != d[4] || c.seconds != d[5])
                {
                    logError("calendar field mismatch ", m["Date"]);
                    return 1;
                }
                const bool out_of_std = (kind == "valid.not_std")
                    || (kind == "valid.64_bit_time_t" && c.year > 2037 && time_t.sizeof == 4);
                if (out_of_std)
                {
                    try
                    {
                        cast(void) c.toUnixTime();
                        logError("calendar expected throw for ", m["Date"]);
                        return 1;
                    }
                    catch (InvalidArgument) {}
                }
                else
                {
                    auto c2 = CalendarPoint.fromUnixTime(c.toUnixTime());
                    if (c2.year != d[0] || c2.month != d[1] || c2.day != d[2]
                        || c2.hour != d[3] || c2.minutes != d[4] || c2.seconds != d[5])
                    {
                        logError("calendar round-trip mismatch ", m["Date"]);
                        return 1;
                    }
                }
                return 0;
            }
            if (kind == "invalid")
            {
                try
                {
                    auto c = CalendarPoint(d[0], d[1], d[2], d[3], d[4], d[5]);
                    logError("calendar accepted invalid ", m["Date"]);
                    return 1;
                }
                catch (InvalidArgument) {}
                return 0;
            }
            return 0;
        });

    fails += checkMemutilsRepeat("calendar", {
        auto c = CalendarPoint(1998, 4, 23, 14, 37, 28);
        auto c2 = CalendarPoint.fromUnixTime(c.toUnixTime());
        if (c2.year != 1998)
            throw new Exception("calendar leak probe");
    });

    if (fails)
        logError("calendar failures: ", fails);
    assert(fails == 0);
}
