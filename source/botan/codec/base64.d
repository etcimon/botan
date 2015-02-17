/**
* Base64 Encoding and Decoding
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.codec.base64;
import memutils.vector;
import botan.codec.base64;
import botan.utils.mem_ops;
import botan.utils.rounding;
import botan.utils.types;
import std.exception;
// import string;

/**
* Perform base64 encoding
* Params:
*  output = an array of at least input_length*4/3 bytes
*  input = is some binary data
*  input_length = length of input in bytes
*  input_consumed = is an output parameter which says how many
*          bytes of input were actually consumed. If less than
*          input_length, then the range input[consumed:length]
*          should be passed in later along with more input.
*  final_inputs = true iff this is the last input, in which case
            padding chars will be applied if needed
* Returns: number of bytes written to output
*/
size_t base64Encode(char* output,
                     const(ubyte)* input,
                     size_t input_length,
                     ref size_t input_consumed,
                     bool final_inputs)
{
    input_consumed = 0;
    
    size_t input_remaining = input_length;
    size_t output_produced = 0;
    
    while (input_remaining >= 3)
    {
        doBase64Encode((output + output_produced)[0..4], (input + input_consumed)[0..3]);
        
        input_consumed += 3;
        output_produced += 4;
        input_remaining -= 3;
    }
    
    if (final_inputs && input_remaining)
    {
        ubyte[3] remainder;
        foreach (size_t i; 0 .. input_remaining)
            remainder[i] = input[input_consumed + i];
        
        doBase64Encode((output + output_produced)[0..4], remainder);
        
        size_t empty_bits = 8 * (3 - input_remaining);
        size_t index = output_produced + 4 - 1;
        while (empty_bits >= 8)
        {
            output[index--] = '=';
            empty_bits -= 6;
        }
        
        input_consumed += input_remaining;
        output_produced += 4;
    }
    
    return output_produced;
}

/**
* Perform base64 encoding
* Params:
*  input = some input
*  input_length = length of input in bytes
* Returns: base64adecimal representation of input
*/

string base64Encode(const(ubyte)* input,
                     size_t input_length)
{
    import std.conv : to;
    char[] output;
    output.length = roundUp!size_t(input_length, 3) / 3 * 4;
    
    size_t consumed = 0;
    size_t produced = base64Encode(output.ptr,
                                    input, input_length,
                                    consumed, true);

    assert(consumed == input_length, "Consumed the entire input");
    assert(produced == output.length, "Produced expected size");
    
    return cast(string)output;
}

/**
* Perform base64 encoding
* Params:
*  input = some input
* Returns: base64adecimal representation of input
*/
string base64Encode(Alloc)(auto const ref Vector!( ubyte, Alloc ) input)
{
    return base64Encode(input.ptr, input.length);
}

/**
* Perform base64 decoding
* Params:
*  output = an array of at least input_length*3/4 bytes
*  input = some base64 input
*  input_length = length of input in bytes
*  input_consumed = is an output parameter which says how many
*          bytes of input were actually consumed. If less than
*          input_length, then the range input[consumed:length]
*          should be passed in later along with more input.
*  final_inputs = true iff this is the last input, in which case
            padding is allowed
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t base64Decode(ubyte* output,
                     const(char)* input, size_t input_length,
                     ref size_t input_consumed,
                     bool final_inputs,
                     bool ignore_ws = true)
{
    /*
    * Base64 Decoder Lookup Table
    * Warning: assumes ASCII encodings
    */
    __gshared immutable ubyte[256] BASE64_TO_BIN = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
        0x80, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
        0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ];
    
    ubyte* out_ptr = output;
    ubyte[4] decode_buf;
    size_t decode_buf_pos = 0;
    size_t final_truncate = 0;
    
    clearMem(output, input_length * 3 / 4);
    
    foreach (size_t i; 0 .. input_length)
    {
        const ubyte bin = BASE64_TO_BIN[cast(ubyte)(input[i])];
        
        if (bin <= 0x3F)
        {
            decode_buf[decode_buf_pos] = bin;
            decode_buf_pos += 1;
        }
        else if (!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
        {
            string bad_char;
            if (input[i] == '\t')
                bad_char = "\\t";
            else if (input[i] == '\n')
                bad_char = "\\n";
            else if (input[i] == '\r')
                bad_char = "\\r";
            else
                bad_char = input[i].to!string;

            throw new InvalidArgument("base64Decode: invalid base64 character (ASCII '" ~ (cast(ubyte) bad_char[0]).to!string ~ "') in " ~ cast(string)(input[0 .. input_length]));
        }

        /*
        * If we're at the end of the input, pad with 0s and truncate
        */
        if (final_inputs && (i == input_length - 1))
        {
            if (decode_buf_pos)
            {
                foreach (size_t j; decode_buf_pos .. 4)
                    decode_buf[j] = 0;
                final_truncate = (4 - decode_buf_pos);
                decode_buf_pos = 4;
            }
        }

        if (decode_buf_pos == 4)
        {
            out_ptr[0] = cast(ubyte) ((decode_buf[0] << 2) | (decode_buf[1] >> 4));
            out_ptr[1] = cast(ubyte) ((decode_buf[1] << 4) | (decode_buf[2] >> 2));
            out_ptr[2] = cast(ubyte) ((decode_buf[2] << 6) | decode_buf[3]);

            out_ptr += 3;
            decode_buf_pos = 0;
            input_consumed = i+1;
        }
    }

    while (input_consumed < input_length && BASE64_TO_BIN[cast(ubyte)(input[input_consumed])] == 0x80)
    {
        ++input_consumed;
    }

    size_t written = (out_ptr - output) - final_truncate;

    return written;
}


/**
* Perform base64 decoding
* Params:
*  output = an array of at least input_length*3/4 bytes
*  input = some base64 input
*  input_length = length of input in bytes
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t base64Decode(ubyte* output, const(char)* input, size_t input_length, bool ignore_ws = true)
{
    size_t consumed = 0;
    size_t written = base64Decode(output, input, input_length, consumed, true, ignore_ws);
    
    if (consumed != input_length)
        throw new InvalidArgument("base64Decode: input did not have full bytes");
    
    return written;
}

/**
* Perform base64 decoding
* Params:
*  output = an array of at least input_length/3*4 bytes
*  input = some base64 input
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t base64Decode(ubyte* output, in string input, bool ignore_ws = true)
{
    return base64Decode(output, input, ignore_ws);
}


/**
* Perform base64 decoding
* Params:
*  input = some base64 input
*  input_length = the length of input in bytes
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded base64 output
*/
SecureVector!ubyte base64Decode(in string input, bool ignore_ws = true)
{
    SecureVector!ubyte bin;
    bin.resize((roundUp!size_t(input.length, 4) * 3) / 4);

    size_t written = base64Decode(bin.ptr, input.ptr, input.length, ignore_ws);
    bin.resize(written);
    return bin;
}


/**
* Perform base64 decoding
* Params:
*  input = some base64 input
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded base64 output
*/
SecureVector!ubyte base64Decode(const ref Vector!ubyte input, bool ignore_ws = true)
{
    return base64Decode(input[], ignore_ws);
}



package:
    
__gshared immutable ubyte[64] BIN_TO_BASE64 = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

void doBase64Encode(ref char[4] output, in ubyte[3] input)
{
    output[0] = BIN_TO_BASE64[((input[0] & 0xFC) >> 2)];
    output[1] = BIN_TO_BASE64[((input[0] & 0x03) << 4) | (input[1] >> 4)];
    output[2] = BIN_TO_BASE64[((input[1] & 0x0F) << 2) | (input[2] >> 6)];
    output[3] = BIN_TO_BASE64[((input[2] & 0x3F)      )];
}