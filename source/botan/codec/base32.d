/**
* Base32 Encoding and Decoding (RFC 4648)
*
* Copyright:
* (C) 2018 Erwan Chaussy
* (C) 2018,2020,2025 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.codec.base32;

import botan.constants;
static if (BOTAN_HAS_BASE32):

import memutils.vector;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
static if (BOTAN_HAS_CT) import botan.utils.ct;
import std.conv : to;

private __gshared immutable char[32] BIN_TO_BASE32 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static if (BOTAN_HAS_CT)
{
    /// C++ `Base32::lookup_binary_value` — CT range/eq masks, no table.
    private ubyte base32LookupBinaryValue(char input)
    {
        const ubyte c = cast(ubyte) input;
        const auto is_alpha_upper = CTMask!ubyte.isWithinRange(c, 'A', 'Z');
        const auto is_decimal = CTMask!ubyte.isWithinRange(c, '2', '7');
        const auto is_equal = CTMask!ubyte.isEqual(c, '=');
        immutable ubyte[4] ws = [' ', '\t', '\n', '\r'];
        const auto is_whitespace = CTMask!ubyte.isAnyOf(c, ws[]);
        const ubyte c_upper = cast(ubyte)(c - 'A');
        const ubyte c_decim = cast(ubyte)(c - '2' + 26);
        ubyte ret = 0xFF;
        ret = is_alpha_upper.select(c_upper, ret);
        ret = is_decimal.select(c_decim, ret);
        ret = is_equal.select(0x81, ret);
        ret = is_whitespace.select(0x80, ret);
        return ret;
    }
}
else
{
    private __gshared immutable ubyte[256] BASE32_TO_BIN = () {
        ubyte[256] t = 0xFF;
        foreach (ubyte i; 0 .. 26)
            t['A' + i] = i;
        foreach (ubyte i; 0 .. 6)
            t['2' + i] = cast(ubyte)(26 + i);
        t['='] = 0x81;
        t[' '] = 0x80;
        t['\t'] = 0x80;
        t['\n'] = 0x80;
        t['\r'] = 0x80;
        return t;
    }();

    private ubyte base32LookupBinaryValue(char input)
    {
        return BASE32_TO_BIN[cast(ubyte) input];
    }
}

private void doBase32Encode(char[] output, const(ubyte)[] input)
{
    const ubyte b0 = (input[0] & 0xF8) >> 3;
    const ubyte b1 = cast(ubyte)(((input[0] & 0x07) << 2) | (input[1] >> 6));
    const ubyte b2 = (input[1] & 0x3E) >> 1;
    const ubyte b3 = cast(ubyte)(((input[1] & 0x01) << 4) | (input[2] >> 4));
    const ubyte b4 = cast(ubyte)(((input[2] & 0x0F) << 1) | (input[3] >> 7));
    const ubyte b5 = (input[3] & 0x7C) >> 2;
    const ubyte b6 = cast(ubyte)(((input[3] & 0x03) << 3) | (input[4] >> 5));
    const ubyte b7 = input[4] & 0x1F;
    output[0] = BIN_TO_BASE32[b0];
    output[1] = BIN_TO_BASE32[b1];
    output[2] = BIN_TO_BASE32[b2];
    output[3] = BIN_TO_BASE32[b3];
    output[4] = BIN_TO_BASE32[b4];
    output[5] = BIN_TO_BASE32[b5];
    output[6] = BIN_TO_BASE32[b6];
    output[7] = BIN_TO_BASE32[b7];
}

size_t base32Encode(char* output, const(ubyte)* input, size_t input_length,
                    ref size_t input_consumed, bool final_inputs)
{
    input_consumed = 0;
    if (input_length == 0)
        return 0;

    size_t input_remaining = input_length;
    size_t output_produced = 0;

    while (input_remaining >= 5)
    {
        doBase32Encode((output + output_produced)[0 .. 8], (input + input_consumed)[0 .. 5]);
        input_consumed += 5;
        output_produced += 8;
        input_remaining -= 5;
    }

    if (final_inputs && input_remaining)
    {
        ubyte[5] remainder;
        foreach (size_t i; 0 .. input_remaining)
            remainder[i] = input[input_consumed + i];
        doBase32Encode((output + output_produced)[0 .. 8], remainder[]);

        size_t empty_bits = 8 * (5 - input_remaining);
        size_t index = output_produced + 8 - 1;
        while (empty_bits >= 6)
        {
            output[index--] = '=';
            empty_bits -= 5;
        }

        input_consumed += input_remaining;
        output_produced += 8;
    }

    return output_produced;
}

string base32Encode(const(ubyte)* input, size_t input_length)
{
    if (input_length == 0)
        return "";
    char[] output;
    output.length = ((input_length + 4) / 5) * 8;
    size_t consumed = 0;
    const size_t produced = base32Encode(output.ptr, input, input_length, consumed, true);
    if (consumed != input_length || produced != output.length)
        throw new EncodingError("base32Encode size mismatch");
    return cast(string) output;
}

string base32Encode(Alloc)(const auto ref Vector!(ubyte, Alloc) input)
{
    return base32Encode(input.ptr, input.length);
}

size_t base32Decode(ubyte* output, const(char)* input, size_t input_length,
                    ref size_t input_consumed, bool final_inputs, bool ignore_ws = true)
{
    input_consumed = 0;
    if (input_length == 0)
        return 0;

    ubyte* out_ptr = output;
    ubyte[8] decode_buf;
    size_t decode_buf_pos = 0;
    size_t final_truncate = 0;
    bool seen_padding = false;

    clearMem(output, ((input_length + 7) / 8) * 5);

    foreach (size_t i; 0 .. input_length)
    {
        const ubyte bin = base32LookupBinaryValue(input[i]);

        if (bin <= 0x1F)
        {
            if (seen_padding)
                throw new InvalidArgument("base32 decoding failed, data follows padding");
            decode_buf[decode_buf_pos] = bin;
            decode_buf_pos += 1;
        }
        else if (bin == 0x81)
        {
            seen_padding = true;
        }
        else if (!(bin == 0x80 && ignore_ws))
        {
            throw new InvalidArgument("base32_decode: invalid character");
        }

        if (final_inputs && (i == input_length - 1))
        {
            if (decode_buf_pos)
            {
                const size_t pad_bits = (decode_buf_pos * 5) % 8;
                if (pad_bits >= 5)
                    throw new InvalidArgument("base32 decoding failed, invalid length");
                const ubyte pad_mask = cast(ubyte)((1u << pad_bits) - 1);
                if (decode_buf[decode_buf_pos - 1] & pad_mask)
                    throw new InvalidArgument("base32 decoding failed, nonzero padding bits");
                foreach (size_t j; decode_buf_pos .. 8)
                    decode_buf[j] = 0;
                final_truncate = 8 - decode_buf_pos;
                decode_buf_pos = 8;
            }
        }

        if (decode_buf_pos == 8)
        {
            out_ptr[0] = cast(ubyte)((decode_buf[0] << 3) | (decode_buf[1] >> 2));
            out_ptr[1] = cast(ubyte)((decode_buf[1] << 6) | (decode_buf[2] << 1) | (decode_buf[3] >> 4));
            out_ptr[2] = cast(ubyte)((decode_buf[3] << 4) | (decode_buf[4] >> 1));
            out_ptr[3] = cast(ubyte)((decode_buf[4] << 7) | (decode_buf[5] << 2) | (decode_buf[6] >> 3));
            out_ptr[4] = cast(ubyte)((decode_buf[6] << 5) | decode_buf[7]);
            out_ptr += 5;
            decode_buf_pos = 0;
            input_consumed = i + 1;
        }
    }

    while (input_consumed < input_length && base32LookupBinaryValue(input[input_consumed]) == 0x80)
        ++input_consumed;

    const size_t remove = (final_truncate > 0) ? (final_truncate / 2) + 1 : 0;
    return cast(size_t)(out_ptr - output) - remove;
}

size_t base32Decode(ubyte* output, const(char)* input, size_t input_length, bool ignore_ws = true)
{
    size_t consumed = 0;
    const size_t written = base32Decode(output, input, input_length, consumed, true, ignore_ws);
    if (consumed != input_length)
        throw new InvalidArgument("base32Decode: input did not have full bytes");
    return written;
}

SecureVector!ubyte base32Decode(const(char)* input, size_t input_length, bool ignore_ws = true)
{
    SecureVector!ubyte bin;
    bin.resize(((input_length + 7) / 8) * 5);
    const size_t written = base32Decode(bin.ptr, input, input_length, ignore_ws);
    bin.resize(written);
    return bin.move();
}

SecureVector!ubyte base32Decode(string input, bool ignore_ws = true)
{
    return base32Decode(input.ptr, input.length, ignore_ws);
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_BASE32_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing base32.d ...");
    size_t fails = 0;

    File vec = File("test_data/codec/base32.vec", "r");
    fails += runTestsBb(vec, "Type", "Base32", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Base32" in m))
                return 0;
            const bool valid = m["Type"] == "valid";
            try
            {
                auto dec = base32Decode(m["Base32"]);
                if (!valid)
                    return 1;
                auto bin = hexDecode(m.get("Binary"));
                if (dec[] != bin[])
                    return 2;
                if (base32Encode(bin) != m["Base32"])
                    return 3;
            }
            catch (Exception)
            {
                if (valid)
                    return 4;
            }
            return 0;
        });

    const string valid_b32 = "MY======";
    foreach (ws; [' ', '\t', '\r', '\n'])
    {
        foreach (i; 0 .. valid_b32.length + 1)
        {
            string with_ws = valid_b32[0 .. i] ~ ws ~ valid_b32[i .. $];
            try
            {
                base32Decode(with_ws, false);
                ++fails;
            }
            catch (Exception) {}
            try
            {
                auto dec = base32Decode(with_ws, true);
                if (dec.length != 1 || dec[0] != 0x66)
                    ++fails;
            }
            catch (Exception)
            {
                ++fails;
            }
        }
    }

    if (base32LookupBinaryValue('A') != 0)
        ++fails;
    if (base32LookupBinaryValue('Z') != 25)
        ++fails;
    if (base32LookupBinaryValue('2') != 26)
        ++fails;
    if (base32LookupBinaryValue('7') != 31)
        ++fails;
    if (base32LookupBinaryValue('=') != 0x81)
        ++fails;
    if (base32LookupBinaryValue(' ') != 0x80)
        ++fails;
    if (base32LookupBinaryValue('a') != 0xFF)
        ++fails;

    testReport("base32", 0, fails);
    assert(fails == 0);
}
