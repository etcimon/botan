/**
* Calendar point (C++ `calendar_point`)
*
* Copyright:
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.calendar;

import botan.utils.exceptn;
import core.stdc.time : time_t;

/**
* A civil date/time. Year 1–9999, month 1–12, day 1–31 (not month-checked).
* Epoch conversion requires year >= 1950 (same as ASN.1 Time).
*/
struct CalendarPoint
{
    ushort year;
    ubyte month;
    ubyte day;
    ubyte hour;
    ubyte minutes;
    ubyte seconds;

    this(uint y, uint mon, uint d, uint h, uint min, uint sec)
    {
        if (y > 9999)
            throw new InvalidArgument("Year is outside representable range");
        if (mon < 1 || mon > 12)
            throw new InvalidArgument("Month is outside range");
        if (d < 1 || d > 31)
            throw new InvalidArgument("Day is outside range");
        if (h >= 24)
            throw new InvalidArgument("Hour is outside range");
        if (min >= 60)
            throw new InvalidArgument("Minute is outside range");
        if (sec >= 60)
            throw new InvalidArgument("Seconds is outside range");
        year = cast(ushort) y;
        month = cast(ubyte) mon;
        day = cast(ubyte) d;
        hour = cast(ubyte) h;
        minutes = cast(ubyte) min;
        seconds = cast(ubyte) sec;
    }

    /// Seconds since Unix epoch. Negative before 1970. Year must be >= 1950.
    long secondsSinceEpoch() const
    {
        return daysSinceEpoch(year, month, day) * 86400
            + (cast(long) hour * 3600) + (cast(long) minutes * 60) + seconds;
    }

    /// C++ `to_std_timepoint`: throws if the instant is not a `time_t`.
    long toUnixTime() const
    {
        const long seconds_64 = secondsSinceEpoch();
        const time_t seconds_time_t = cast(time_t) seconds_64;
        if (seconds_64 - seconds_time_t != 0)
            throw new InvalidArgument("calendar_point::to_std_timepoint time is outside the representable range");
        return seconds_64;
    }

    /// Inverse of `toUnixTime` (C++ `calendar_point(time_point)`).
    static CalendarPoint fromUnixTime(long t)
    {
        long days = t / 86400;
        long tod = t % 86400;
        if (tod < 0)
        {
            tod += 86400;
            days -= 1;
        }

        const long z = days + 719468;
        const long era = (z >= 0 ? z : z - 146096) / 146097;
        const long doe = z - era * 146097;
        const long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        const long y = yoe + era * 400;
        const long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        const long mp = (5 * doy + 2) / 153;
        const long d = doy - (153 * mp + 2) / 5 + 1;
        const long mon = mp < 10 ? mp + 3 : mp - 9;
        const long yr = y + (mon <= 2 ? 1 : 0);

        if (yr > 9999 || yr < 0)
            throw new InvalidArgument("Year is outside representable range");

        return CalendarPoint(cast(uint) yr, cast(uint) mon, cast(uint) d,
                             cast(uint)(tod / 3600),
                             cast(uint)((tod % 3600) / 60),
                             cast(uint)(tod % 60));
    }
}

/// Howard Hinnant days-from-civil. Year must be >= 1950.
long daysSinceEpoch(uint year, uint month, uint day)
{
    if (year < 1950)
        throw new InvalidArgument("Years before 1950 not supported");
    if (month <= 2)
        year -= 1;
    const uint era = year / 400;
    const uint yoe = year - era * 400;
    const uint doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const uint doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return cast(long) era * 146097 + cast(long) doe - 719468;
}
