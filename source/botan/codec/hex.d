/**
* Hex Encoding and Decoding
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.codec.hex;

import botan.constants;
import memutils.vector;
import botan.codec.hex;
import botan.utils.mem_ops;
import botan.utils.types;
import std.exception;
import std.conv : to;

/**
* Perform hex encoding
* Params:
*  output = an array of at least input_length*2 bytes
*  input = is some binary data
*  input_length = length of input in bytes
*  uppercase = should output be upper or lower case?
*/
void hexEncode(char* output,
                const(ubyte)* input,
                size_t input_length,
                bool uppercase = true)
{
    __gshared immutable ubyte[16] BIN_TO_HEX_UPPER = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F' ];
    
    __gshared immutable ubyte[16] BIN_TO_HEX_LOWER = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f' ];

    const(ubyte)* tbl = uppercase ? BIN_TO_HEX_UPPER.ptr : BIN_TO_HEX_LOWER.ptr;
    
    foreach (size_t i; 0 .. input_length)
    {
        ubyte x = input[i];
        output[2*i  ] = tbl[(x >> 4) & 0x0F];
        output[2*i+1] = tbl[(x     ) & 0x0F];
    }
}

/**
* Perform hex encoding
* Params:
*  input = some input
*  input_length = length of input in bytes
*  uppercase = should output be upper or lower case?
* Returns: hexadecimal representation of input
*/
string hexEncode(const(ubyte)* input, size_t input_length, bool uppercase = true)
{
    char[] output;
    output.length = 2 * input_length;
    
    if (input_length)
        hexEncode(output.ptr, input, input_length, uppercase);

    return output.to!string;
}

/**
* Perform hex encoding
* Params:
*  input = some input
*  uppercase = should output be upper or lower case?
* Returns: hexadecimal representation of input
*/
string hexEncode(Alloc)(auto const ref Vector!( ubyte, Alloc ) input, bool uppercase = true)
{
    return hexEncode(input.ptr, input.length, uppercase);
}

/// ditto
string hexEncode(Alloc)(auto const ref RefCounted!(Vector!( ubyte, Alloc ), Alloc) input, bool uppercase = true)
{
    return hexEncode(input.ptr, input.length, uppercase);
}

/**
* Perform hex decoding
* Params:
*  output = an array of at least input_length/2 bytes
*  input = some hex input
*  input_length = length of input in bytes
*  input_consumed = is an output parameter which says how many
*          bytes of input were actually consumed. If less than
*          input_length, then the range input[consumed:length]
*          should be passed in later along with more input.
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t hexDecode(ubyte* output,
                 const(char)* input,
                 size_t input_length,
                 ref size_t input_consumed,
                 bool ignore_ws = true)
{
    /*
    * Mapping of hex characters to either their binary equivalent
    * or to an error code.
    *  If valid hex (0-9 A-F a-f), the value.
    *  If whitespace, then 0x80
    *  Otherwise 0xFF
    * Warning: this table assumes ASCII character encodings
    */
    
    __gshared immutable ubyte[256] HEX_TO_BIN = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
        0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
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
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ];
    
    ubyte* out_ptr = output;
    bool top_nibble = true;
    
    clearMem(output, input_length / 2);
    
    foreach (size_t i; 0 .. input_length)
    {
        const ubyte bin = HEX_TO_BIN[(cast(ubyte*)input)[i]];
        
        if (bin >= 0x10)
        {
            if (bin == 0x80 && ignore_ws)
                continue;
            
            ubyte bad_char = input[i];
            string bad_char_;
            if (bad_char == '\t')
                bad_char_ = "\\t";
            else if (bad_char == '\n')
                bad_char_ = "\\n";
            
            throw new InvalidArgument("hexDecode: invalid hex character '" ~ bad_char_ ~ "'");
        }
        
        *out_ptr |= bin << ((top_nibble?1:0)*4);
        
        top_nibble = !top_nibble;
        if (top_nibble)
            ++out_ptr;
    }
    
    input_consumed = input_length;
    size_t written = (out_ptr - output);
    
    /*
    * We only got half of a ubyte at the end; zap the half-written
    * output and mark it as unread
    */
    if (!top_nibble)
    {
        *out_ptr = 0;
        input_consumed -= 1;
    }

    return written;
}

/**
* Perform hex decoding
* Params:
*  output = an array of at least input_length/2 bytes
*  input = some hex input
*  input_length = length of input in bytes
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t hexDecode(ubyte* output,
                 const(char)* input,
                 size_t input_length,
                 bool ignore_ws = true)
{
    size_t consumed = 0;
    size_t written = hexDecode(output, input, input_length, consumed, ignore_ws);
    
    if (consumed != input_length)
        throw new InvalidArgument("hexDecode: input did not have full bytes");
    
    return written;
}

/**
* Perform hex decoding
* Params:
*  output = an array of at least input_length/2 bytes
*  input = some hex input
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: number of bytes written to output
*/
size_t hexDecode(ubyte* output, in string input, bool ignore_ws = true)
{
    return hexDecode(output, input.ptr, input.length, ignore_ws);
}

/**
* Perform hex decoding
* Params:
*  input = some hex input
*  input_length = the length of input in bytes
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded hex output
*/
Vector!ubyte hexDecode(string input, bool ignore_ws = true)
{
    Vector!ubyte bin;
    bin.resize(1 + input.length / 2);
    
    size_t written = hexDecode(bin.ptr, input.ptr, input.length, ignore_ws);
    bin.resize(written);
    return bin.move();
}

/**
* Perform hex decoding
* Params:
*  input = some hex input
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded hex output
*/
Vector!ubyte hexDecode(const ref Vector!ubyte input, bool ignore_ws = true)
{
    return hexDecode(input[], ignore_ws);
}

/**
* Perform hex decoding
* Params:
*  input = some hex input
*  input_length = the length of input in bytes
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded hex output
*/
SecureVector!ubyte hexDecodeLocked(const(char)* input, size_t input_length, bool ignore_ws = true)
{
    SecureVector!ubyte bin = SecureVector!ubyte(1 + input_length / 2);
    size_t written = hexDecode(bin.ptr, input, input_length, ignore_ws);
    bin.resize(written);
    return bin.move();
}

/**
* Perform hex decoding
* Params:
*  input = some hex input
*  ignore_ws = ignore whitespace on input; if false, throw new an
                         exception if whitespace is encountered
* Returns: decoded hex output
*/
SecureVector!ubyte hexDecodeLocked(in string input, bool ignore_ws = true)
{
    return hexDecodeLocked(input.ptr, input.length, ignore_ws);
}
