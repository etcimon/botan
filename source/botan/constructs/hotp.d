/**
* HOTP (RFC 4226) and TOTP (RFC 6238)
*
* Copyright:
* (C) 2017,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.hotp;

import botan.constants;
static if (BOTAN_HAS_HOTP):

static assert(BOTAN_HAS_HMAC, "HOTP/TOTP requires HMAC");

import botan.mac.mac;
import botan.libstate.lookup;
import botan.algo_base.symkey;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.types;
import std.typecons : Tuple;

private uint hotpTruncate(uint code, size_t digits)
{
    if (digits == 6) return code % 1_000_000;
    if (digits == 7) return code % 10_000_000;
    if (digits == 8) return code % 100_000_000;
    throw new InvalidArgument("Invalid HOTP digits");
}

/// HOTP one-time passwords (RFC 4226). Hash may be SHA-1, SHA-256, or SHA-512.
final class HOTP
{
public:
    /**
    * Params:
    *  key = HMAC key
    *  key_len = length of key
    *  hash_algo = "SHA-1", "SHA-256", or "SHA-512"
    *  digits = 6, 7, or 8
    */
    this(const(ubyte)* key, size_t key_len, string hash_algo = "SHA-1", size_t digits = 6)
    {
        if (digits != 6 && digits != 7 && digits != 8)
            throw new InvalidArgument("Invalid HOTP digits");
        string mac_name;
        if (hash_algo == "SHA-1" || hash_algo == "SHA-160")
            mac_name = "HMAC(SHA-1)";
        else if (hash_algo == "SHA-256")
            mac_name = "HMAC(SHA-256)";
        else if (hash_algo == "SHA-512")
            mac_name = "HMAC(SHA-512)";
        else
            throw new InvalidArgument("Unsupported HOTP hash function");
        m_mac = retrieveMac(mac_name).clone();
        m_mac.setKey(key, key_len);
        m_digits = digits;
    }

    this()(const auto ref SymmetricKey key, string hash_algo = "SHA-1", size_t digits = 6)
    {
        this(key.ptr, key.length, hash_algo, digits);
    }

    /**
    * Params:
    *  counter = moving factor
    * Returns: digits-long OTP
    */
    uint generateHotp(ulong counter)
    {
        ubyte[8] be;
        storeBigEndian(counter, be.ptr);
        m_mac.update(be.ptr, 8);
        auto mac = m_mac.finished();
        const size_t offset = mac[mac.length - 1] & 0x0F;
        const uint code = loadBigEndian!uint(mac.ptr + offset, 0) & 0x7FFFFFFF;
        return hotpTruncate(code, m_digits);
    }

    /// Returns (valid, next_counter). On failure next_counter is starting_counter.
    Tuple!(bool, ulong) verifyHotp(uint otp, ulong starting_counter, size_t resync_range = 0)
    {
        if (resync_range > 100000)
            throw new InvalidArgument("HOTP resync_range too large");
        foreach (size_t i; 0 .. resync_range + 1)
        {
            const ulong ctr = starting_counter + i;
            if (ctr == ulong.max)
                throw new InvalidState("HOTP counter has been exhausted");
            if (generateHotp(ctr) == otp)
                return typeof(return)(true, ctr + 1);
        }
        return typeof(return)(false, starting_counter);
    }

private:
    Unique!MessageAuthenticationCode m_mac;
    size_t m_digits;
}

/// TOTP time-based one-time passwords (RFC 6238).
final class TOTP
{
public:
    /**
    * Params:
    *  key = HMAC key
    *  key_len = length of key
    *  hash_algo = "SHA-1", "SHA-256", or "SHA-512"
    *  digits = 6, 7, or 8
    *  time_step = seconds per step (default 30)
    */
    this(const(ubyte)* key, size_t key_len, string hash_algo = "SHA-1",
         size_t digits = 6, size_t time_step = 30)
    {
        if (time_step == 0 || time_step > 300)
            throw new InvalidArgument("Invalid TOTP time step");
        m_hotp = new HOTP(key, key_len, hash_algo, digits);
        m_time_step = time_step;
    }

    this()(const auto ref SymmetricKey key, string hash_algo = "SHA-1",
           size_t digits = 6, size_t time_step = 30)
    {
        this(key.ptr, key.length, hash_algo, digits, time_step);
    }

    /**
    * Params:
    *  unix_time = seconds since Unix epoch
    * Returns: digits-long OTP
    */
    uint generateTotp(ulong unix_time)
    {
        return m_hotp.generateHotp(unix_time / m_time_step);
    }

    /**
    * Params:
    *  otp = candidate code
    *  unix_time = seconds since Unix epoch
    *  clock_drift_accepted = extra steps to search backward
    * Returns: true if otp matches this or a previous step
    */
    bool verifyTotp(uint otp, ulong unix_time, size_t clock_drift_accepted = 0)
    {
        if (clock_drift_accepted > 10000)
            throw new InvalidArgument("TOTP clock_drift_accepted too large");
        if (unix_time < 1_000_000_000)
            throw new InvalidArgument("TOTP unix_time argument is implausibly small");
        const ulong t = unix_time / m_time_step;
        foreach (size_t i; 0 .. clock_drift_accepted + 1)
        {
            if (i > t)
                break;
            if (m_hotp.generateHotp(t - i) == otp)
                return true;
        }
        return false;
    }

private:
    Unique!HOTP m_hotp;
    size_t m_time_step;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import memutils.hashmap;
import std.conv : to;
import std.stdio : File;
import std.datetime.date : DateTime;
import std.datetime.systime : SysTime;
import std.datetime.timezone : UTC;

private ulong totpUnixTime(string stamp)
{
    if (stamp.length != 19)
        throw new Exception("Invalid TOTP timestamp " ~ stamp);
    const int y = to!int(stamp[0 .. 4]);
    const int mo = to!int(stamp[5 .. 7]);
    const int d = to!int(stamp[8 .. 10]);
    const int h = to!int(stamp[11 .. 13]);
    const int mi = to!int(stamp[14 .. 16]);
    const int se = to!int(stamp[17 .. 19]);
    return SysTime(DateTime(y, mo, d, h, mi, se), UTC()).toUnixTime();
}

static if (BOTAN_HAS_TESTS && !SKIP_HOTP_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing hotp.d ...");
    size_t fails = 0;

    File hotp_vec = File("test_data/otp/hotp.vec", "r");
    fails += runTestsBb(hotp_vec, "HOTP", "OTP", false,
        (ref HashMap!(string, string) m)
        {
            if (!("OTP" in m) || !("Key" in m) || !("Counter" in m) || !("Digits" in m))
                return 0;
            auto key = SymmetricKey(hexDecode(m["Key"]));
            const uint otp = to!uint(m["OTP"]);
            const ulong counter = to!ulong(m["Counter"]);
            const size_t digits = to!size_t(m["Digits"]);
            Unique!HOTP hotp = new HOTP(key, m["HOTP"], digits);
            if (hotp.generateHotp(counter) != otp)
                return 1;
            auto ok = hotp.verifyHotp(otp, counter, 0);
            if (!ok[0] || ok[1] != counter + 1)
                return 2;
            auto bad = hotp.verifyHotp(otp + 1, counter, 0);
            if (bad[0] || bad[1] != counter)
                return 3;
            auto bad_long = hotp.verifyHotp(otp + 1, counter, 100);
            if (bad_long[0] || bad_long[1] != counter)
                return 4;
            const ulong start = (counter >= 90) ? (counter - 90) : 0;
            auto ranged = hotp.verifyHotp(otp, start, 100);
            if (!ranged[0] || ranged[1] != counter + 1)
                return 5;
            return 0;
        });

    File totp_vec = File("test_data/otp/totp.vec", "r");
    fails += runTestsBb(totp_vec, "TOTP", "OTP", false,
        (ref HashMap!(string, string) m)
        {
            if (!("OTP" in m) || !("Key" in m) || !("Timestamp" in m))
                return 0;
            auto key = SymmetricKey(hexDecode(m["Key"]));
            const uint otp = to!uint(m["OTP"]);
            const size_t digits = to!size_t(m["Digits"]);
            const size_t step = to!size_t(m["Timestep"]);
            Unique!TOTP totp = new TOTP(key, m["TOTP"], digits, step);
            const ulong unix_time = totpUnixTime(m["Timestamp"]);
            if (totp.generateTotp(unix_time) != otp)
                return 1;
            if (!totp.verifyTotp(otp, unix_time, 0))
                return 2;
            if (totp.verifyTotp(otp ^ 1, unix_time, 0))
                return 3;
            if (totp.verifyTotp(otp, unix_time + step, 0))
                return 4;
            if (!totp.verifyTotp(otp, unix_time + step, 1))
                return 5;
            if (totp.verifyTotp(otp, unix_time + 2 * step, 1))
                return 6;
            return 0;
        });

    fails += checkMemutilsRepeat("hotp", {
        ubyte[20] k = 1;
        Unique!HOTP h = new HOTP(k.ptr, k.length, "SHA-1", 6);
        cast(void) h.generateHotp(0);
    });

    testReport("hotp", 0, fails);
    assert(fails == 0);
}
