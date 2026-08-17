/**
* Base58 and Base58Check encoding
*
* Copyright:
* (C) 2018,2020,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.codec.base58;

import botan.constants;
static if (BOTAN_HAS_BASE58):

import memutils.vector;
import botan.math.bigint.bigint;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.loadstor;
import botan.utils.types;
static if (BOTAN_HAS_CT) import botan.utils.ct;

static if (BOTAN_HAS_CT)
{
    /// C++ `lookup_base58_char` — offset table via `CT::Mask::is_gt`.
    private char lookupBase58Char(ubyte x)
    {
        size_t offset = 49;
        offset += CTMask!ubyte.isGt(x, 8).ifSetReturn(7);
        offset += CTMask!ubyte.isGt(x, 16).ifSetReturn(1);
        offset += CTMask!ubyte.isGt(x, 21).ifSetReturn(1);
        offset += CTMask!ubyte.isGt(x, 32).ifSetReturn(6);
        offset += CTMask!ubyte.isGt(x, 43).ifSetReturn(1);
        return cast(char)(x + offset);
    }

    /// CT range decode (C++ `base58_value_of` is SWAR; same ranges / 0xFF invalid).
    private ubyte base58ValueOf(char input)
    {
        const ubyte x = cast(ubyte) input;
        immutable ubyte[2] ws = [' ', '\n'];
        const auto is_ws = CTMask!ubyte.isAnyOf(x, ws[]);
        const auto r1 = CTMask!ubyte.isWithinRange(x, '1', '9');
        const auto r2 = CTMask!ubyte.isWithinRange(x, 'A', 'H');
        const auto r3 = CTMask!ubyte.isWithinRange(x, 'J', 'N');
        const auto r4 = CTMask!ubyte.isWithinRange(x, 'P', 'Z');
        const auto r5 = CTMask!ubyte.isWithinRange(x, 'a', 'k');
        const auto r6 = CTMask!ubyte.isWithinRange(x, 'm', 'z');
        ubyte ret = 0xFF;
        ret = r1.select(cast(ubyte)(x - '1'), ret);
        ret = r2.select(cast(ubyte)(x - 'A' + 9), ret);
        ret = r3.select(cast(ubyte)(x - 'J' + 17), ret);
        ret = r4.select(cast(ubyte)(x - 'P' + 22), ret);
        ret = r5.select(cast(ubyte)(x - 'a' + 33), ret);
        ret = r6.select(cast(ubyte)(x - 'm' + 44), ret);
        return is_ws.select(0x80, ret);
    }
}
else
{
    private __gshared immutable char[58] BASE58_ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private char lookupBase58Char(ubyte x)
    {
        return BASE58_ALPHABET[x];
    }

    private ubyte base58ValueOf(char input)
    {
        if (input == ' ' || input == '\n')
            return 0x80;
        foreach (ubyte i; 0 .. 58)
            if (BASE58_ALPHABET[i] == input)
                return i;
        return 0xFF;
    }
}

private size_t countLeading(T, Z)(const(T)* input, size_t length, Z zero)
{
    size_t n = 0;
    while (n < length && input[n] == zero)
        ++n;
    return n;
}

private string base58EncodeValue(ref BigInt v, size_t leading_zeros)
{
    ubyte[] digits;
    while (!v.isZero())
    {
        // v = q*58 + r
        BigInt fifty_eight = BigInt(58);
        BigInt q;
        word r = 0;
        // Schoolbook: convert to bytes and divide
        auto enc = BigInt.encodeLocked(&v);
        ulong acc = 0;
        SecureVector!ubyte qbytes;
        qbytes.reserve(enc.length);
        foreach (b; enc[])
        {
            acc = (acc << 8) | b;
            qbytes ~= cast(ubyte)(acc / 58);
            acc %= 58;
        }
        digits ~= cast(ubyte) acc;
        // strip leading zero bytes of quotient
        size_t start = 0;
        while (start < qbytes.length && qbytes[start] == 0)
            ++start;
        if (start == qbytes.length)
            v = BigInt(0);
        else
            v = BigInt(qbytes.ptr + start, qbytes.length - start);
    }

    char[] result;
    result.length = digits.length + leading_zeros;
    size_t pos = 0;
    foreach (i; 0 .. leading_zeros)
        result[pos++] = '1';
    foreach_reverse (d; digits)
        result[pos++] = lookupBase58Char(d);
    return cast(string) result;
}

string base58Encode(const(ubyte)* input, size_t input_length)
{
    auto v = BigInt(input, input_length);
    return base58EncodeValue(v, countLeading(input, input_length, 0));
}

string base58Encode(Alloc)(const auto ref Vector!(ubyte, Alloc) input)
{
    return base58Encode(input.ptr, input.length);
}

private uint sha256dChecksum(const(ubyte)* input, size_t length)
{
    Unique!HashFunction h = retrieveHash("SHA-256").clone();
    h.update(input, length);
    auto d1 = h.finished();
    h.update(d1.ptr, d1.length);
    auto d2 = h.finished();
    return loadBigEndian!uint(d2.ptr, 0);
}

string base58CheckEncode(const(ubyte)* input, size_t input_length)
{
    auto v = BigInt(input, input_length);
    v <<= 32;
    v += sha256dChecksum(input, input_length);
    return base58EncodeValue(v, countLeading(input, input_length, 0));
}

string base58CheckEncode(Alloc)(const auto ref Vector!(ubyte, Alloc) input)
{
    return base58CheckEncode(input.ptr, input.length);
}

Vector!ubyte base58Decode(const(char)* input, size_t input_length)
{
    const size_t leading_ones = countLeading(input, input_length, '1');
    ubyte[] digits;
    foreach (i; leading_ones .. input_length)
    {
        const ubyte idx = base58ValueOf(input[i]);
        if (idx == 0x80)
            continue;
        if (idx == 0xFF)
            throw new DecodingError("Invalid base58");
        digits ~= idx;
    }

    BigInt v = BigInt(0);
    size_t i = 0;
    while (i + 4 <= digits.length)
    {
        const uint accum = 58 * 58 * 58 * digits[i] + 58 * 58 * digits[i + 1]
                         + 58 * digits[i + 2] + digits[i + 3];
        v *= (58 * 58 * 58 * 58);
        v += accum;
        i += 4;
    }
    while (i < digits.length)
    {
        v *= 58;
        v += digits[i];
        ++i;
    }

    Vector!ubyte outbuf;
    if (v.isZero())
    {
        outbuf.resize(leading_ones);
        return outbuf.move();
    }
    auto enc = BigInt.encodeLocked(&v);
    outbuf.resize(enc.length + leading_ones);
    foreach (j; 0 .. leading_ones)
        outbuf[j] = 0;
    foreach (j; 0 .. enc.length)
        outbuf[leading_ones + j] = enc[j];
    return outbuf.move();
}

Vector!ubyte base58Decode(string input)
{
    return base58Decode(input.ptr, input.length);
}

Vector!ubyte base58CheckDecode(const(char)* input, size_t input_length)
{
    auto dec = base58Decode(input, input_length);
    if (dec.length < 4)
        throw new DecodingError("Invalid base58 too short for checksum");
    const uint computed = sha256dChecksum(dec.ptr, dec.length - 4);
    const uint checksum = loadBigEndian!uint(dec.ptr + dec.length - 4, 0);
    if (checksum != computed)
        throw new DecodingError("Invalid base58 checksum");
    dec.resize(dec.length - 4);
    return dec.move();
}

Vector!ubyte base58CheckDecode(string input)
{
    return base58CheckDecode(input.ptr, input.length);
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import memutils.hashmap;
import std.stdio : File;

private size_t codecRoundtrip(string encoded, string bin_hex, bool valid,
                              string function(const(ubyte)*, size_t) enc,
                              Vector!ubyte function(string) dec)
{
    try
    {
        auto got = dec(encoded);
        if (!valid)
            return 1;
        auto bin = hexDecode(bin_hex);
        if (got[] != bin[])
            return 2;
        if (enc(bin.ptr, bin.length) != encoded)
            return 3;
    }
    catch (Exception)
    {
        if (valid)
            return 4;
    }
    return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_BASE58_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing base58.d ...");
    size_t fails = 0;

    File raw = File("test_data/codec/base58.vec", "r");
    fails += runTestsBb(raw, "Type", "Base58", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Base58" in m))
                return 0;
            return codecRoundtrip(m["Base58"], m.get("Binary"), m["Type"] == "valid",
                                  &base58Encode, &base58Decode);
        });

    File chk = File("test_data/codec/base58c.vec", "r");
    fails += runTestsBb(chk, "Type", "Base58", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Base58" in m))
                return 0;
            return codecRoundtrip(m["Base58"], m.get("Binary"), m["Type"] == "valid",
                                  &base58CheckEncode, &base58CheckDecode);
        });

    if (lookupBase58Char(0) != '1')
        ++fails;
    if (lookupBase58Char(9) != 'A')
        ++fails;
    if (lookupBase58Char(57) != 'z')
        ++fails;
    if (base58ValueOf('1') != 0)
        ++fails;
    if (base58ValueOf('z') != 57)
        ++fails;
    if (base58ValueOf('0') != 0xFF)
        ++fails;
    if (base58ValueOf(' ') != 0x80)
        ++fails;

    testReport("base58", 0, fails);
    assert(fails == 0);
}
