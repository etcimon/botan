/**
* Public Key Work Factor Functions
* 
* Copyright:
* (C) 1999-2007,2012,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.workfactor;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
import botan.utils.exceptn;
import std.algorithm : max;
import std.math : pow, log;

/**
* Estimate work factor for discrete logarithm
* Params:
*  prime_group_size = size of the group in bits
* Returns: estimated security level for this group
*/
size_t dlWorkFactor(size_t prime_group_size)
{
    /*
    Based on GNFS work factors. Constant is 1.43 times the asymptotic
    value; I'm not sure but I believe that came from a paper on 'real
    world' runtimes, but I don't remember where now.

    Sample return values:
        |512|  . 64
        |1024| . 86
        |1536| . 102
        |2048| . 116
        |3072| . 138
        |4096| . 155
        |8192| . 206

    For DL algos, we use an exponent of twice the size of the result;
    the assumption is that an arbitrary discrete log on a group of size
    bits would take about 2^n effort, and thus using an exponent of
    size 2^(2*n) implies that all available attacks are about as easy
    (as e.g Pollard's kangaroo algorithm can compute the DL in sqrt(x)
    operations) while minimizing the exponent size for performance
    reasons.
    */
    
    __gshared immutable size_t MIN_WORKFACTOR = 64;
    
    // approximates natural logarithm of p
    const double log_p = prime_group_size / 1.4426;

    const double strength =    2.76 * pow(log_p, 1.0/3.0) * pow(log(log_p), 2.0/3.0);
    
    return max(cast(size_t)(strength), MIN_WORKFACTOR);
}

/**
* RFC 3766 IFC work factor (C++ `if_work_factor`). Additive; existing
* `dlWorkFactor` call sites stay on the 1.12 estimate.
*/
size_t ifWorkFactor(size_t bits)
{
    if (bits < 512)
        return 0;
    enum double log2_k = -5.6438; // log2(0.02)
    enum double log2e = 1.4426950408889634;
    const double log_p = bits / log2e;
    const double log_log_p = log(log_p);
    const double est = 1.92 * pow(log_p * log_log_p * log_log_p, 1.0 / 3.0);
    return cast(size_t)(log2_k + log2e * est);
}

/**
* NIST SP 800-56B Rev 2 exponent size (C++ `dl_exponent_size`).
*/
size_t dlExponentSize(size_t p_bits)
{
    if (p_bits <= 1)
        throw new InvalidArgument("dlExponentSize: Invalid prime length");
    if (p_bits <= 256)
        return p_bits - 1;
    if (p_bits <= 1024)
        return 192;
    if (p_bits <= 2048)
        return 224;
    if (p_bits <= 3072)
        return 256;
    if (p_bits <= 4096)
        return 304;
    if (p_bits <= 6144)
        return 352;
    if (p_bits <= 8192)
        return 400;
    return 512;
}

static if (BOTAN_HAS_TESTS && !SKIP_WORKFACTOR_TEST) unittest
{
    import botan.test;
    import memutils.hashmap;
    import std.stdio : File;
    import std.conv : to;

    logDebug("Testing workfactor.d ...");
    size_t fails = 0;

    File vec = File("test_data/pubkey/workfactor.vec", "r");
    fails += runTestsBb(vec, "Kind", "Workfactor", false,
        (ref HashMap!(string, string) m)
        {
            if (!("ParamSize" in m) || !("Workfactor" in m) || !("Kind" in m))
                return 0;
            const size_t n = to!size_t(m["ParamSize"]);
            const size_t expect = to!size_t(m["Workfactor"]);
            size_t got = 0;
            if (m["Kind"] == "RSA_Strength")
                got = ifWorkFactor(n);
            else if (m["Kind"] == "DL_Exponent_Size")
                got = dlExponentSize(n);
            else
                return 0;
            return got == expect ? 0 : 1;
        });

    fails += checkMemutilsRepeat("workfactor", {
        if (ifWorkFactor(2048) < 100 || dlExponentSize(2048) != 224)
            throw new Exception("workfactor leak probe");
    });

    testReport("workfactor", 0, fails);
}
