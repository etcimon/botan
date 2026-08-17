/**
* Character Set Handling
* 
* Copyright:
* (C) 1999-2007,2021 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.charset;

import botan.constants;
import std.array : Appender;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.get_byte;
import std.conv : to;

/**
* The different charsets (nominally) supported by Botan.
*/
alias ubyte CharacterSet;
enum : CharacterSet {
    LOCAL_CHARSET,
    UCS2_CHARSET,
    UTF8_CHARSET,
    LATIN1_CHARSET,
    UCS4_CHARSET
}

/*
* Character Set Handling
*/
/*
* Convert from UCS-2 to ISO 8859-1
*/
string ucs2ToLatin1(in string ucs2)
{
    if (ucs2.length % 2 == 1)
        throw new DecodingError("UCS-2 string has an odd number of bytes");
    
    Vector!char latin1;
    latin1.reserve(ucs2.length * 2);

    for (size_t i = 0; i != ucs2.length; i += 2)
    {
        const ubyte c1 = ucs2[i];
        const ubyte c2 = ucs2[i+1];
        
        if (c1 != 0)
            throw new DecodingError("UCS-2 has non-Latin1 characters");
        
        latin1 ~= cast(char)(c2);
    }

    string ret = latin1.ptr[0 .. latin1.length].idup;

    //logDebug(ret);
    
    return ret;
}

/*
* Convert from UTF-8 to ISO 8859-1
*/
string utf8ToLatin1(in string utf8)
{
    Vector!char iso8859;
    iso8859.reserve(utf8.length);
    size_t position = 0;
    while (position != utf8.length)
    {
        const ubyte c1 = cast(ubyte)(utf8[position++]);
        
        if (c1 <= 0x7F)
            iso8859 ~= cast(char)(c1);
        else if (c1 >= 0xC0 && c1 <= 0xC7)
        {
            if (position == utf8.length)
                throw new DecodingError("UTF-8: sequence truncated");
            
            const ubyte c2 = cast(ubyte)(utf8[position++]);
            const ubyte iso_char = cast(ubyte)((c1 & 0x07) << 6) | (c2 & 0x3F);
            
            if (iso_char <= 0x7F)
                throw new DecodingError("UTF-8: sequence longer than needed");
            
            iso8859 ~= cast(char)(iso_char);
        }
        else
            throw new DecodingError("UTF-8: Unicode chars not in Latin1 used");
    }
    string ret = iso8859.ptr[0 .. iso8859.length].idup;
    //logTrace("utf8ToLatin1: ", ret);
    return ret;
}

/*
* Convert from ISO 8859-1 to UTF-8
*/
string latin1ToUtf8(in string iso8859)
{
    Vector!char utf8;
    utf8.reserve(iso8859.length);
    for (size_t i = 0; i != iso8859.length; ++i)
    {
        const ubyte c = cast(ubyte)(iso8859[i]);
        
        if (c <= 0x7F)
            utf8 ~= cast(char)(c);
        else
        {
            utf8 ~= cast(char)((0xC0 | (c >> 6)));
            utf8 ~= cast(char)((0x80 | (c & 0x3F)));
        }
    }
    string ret = utf8.ptr[0 .. utf8.length].idup;
    //logTrace("latin1ToUtf8: ", ret);
    return ret;
}

/*
* Append the UTF-8 encoding of Unicode scalar `c`.
*/
private void appendUtf8For(ref Vector!ubyte s, uint c)
{
    if (c >= 0xD800 && c < 0xE000)
        throw new DecodingError("Invalid Unicode character");

    if (c <= 0x7F)
        s ~= cast(ubyte)(c);
    else if (c <= 0x7FF)
    {
        s ~= cast(ubyte)(0xC0 | (c >> 6));
        s ~= cast(ubyte)(0x80 | (c & 0x3F));
    }
    else if (c <= 0xFFFF)
    {
        s ~= cast(ubyte)(0xE0 | (c >> 12));
        s ~= cast(ubyte)(0x80 | ((c >> 6) & 0x3F));
        s ~= cast(ubyte)(0x80 | (c & 0x3F));
    }
    else if (c <= 0x10FFFF)
    {
        s ~= cast(ubyte)(0xF0 | (c >> 18));
        s ~= cast(ubyte)(0x80 | ((c >> 12) & 0x3F));
        s ~= cast(ubyte)(0x80 | ((c >> 6) & 0x3F));
        s ~= cast(ubyte)(0x80 | (c & 0x3F));
    }
    else
        throw new DecodingError("Invalid Unicode character");
}

/**
* Decode the UTF-8 code point at utf8[pos], advancing pos past it.
* Throws DecodingError on invalid / overlong / surrogate / out-of-range input.
*/
uint nextUtf8Codepoint(const(ubyte)[] utf8, ref size_t pos)
{
    uint readContinuation()
    {
        if (pos >= utf8.length)
            throw new DecodingError("Invalid UTF-8 sequence");
        const ubyte b = utf8[pos++];
        if ((b & 0xC0) != 0x80)
            throw new DecodingError("Invalid UTF-8 sequence");
        return b & 0x3F;
    }

    if (pos >= utf8.length)
        throw new DecodingError("Invalid UTF-8 sequence");
    const ubyte lead = utf8[pos++];
    uint c = 0;

    if (lead <= 0x7F)
        c = lead;
    else if ((lead & 0xE0) == 0xC0)
    {
        c = (lead & 0x1F) << 6;
        c |= readContinuation();
        if (c < 0x80)
            throw new DecodingError("Overlong UTF-8 sequence");
    }
    else if ((lead & 0xF0) == 0xE0)
    {
        c = (lead & 0x0F) << 12;
        c |= readContinuation() << 6;
        c |= readContinuation();
        if (c < 0x800)
            throw new DecodingError("Overlong UTF-8 sequence");
    }
    else if ((lead & 0xF8) == 0xF0)
    {
        c = (lead & 0x07) << 18;
        c |= readContinuation() << 12;
        c |= readContinuation() << 6;
        c |= readContinuation();
        if (c < 0x10000)
            throw new DecodingError("Overlong UTF-8 sequence");
    }
    else
        throw new DecodingError("Invalid UTF-8 sequence");

    if (c > 0x10FFFF)
        throw new DecodingError("UTF-8 sequence encodes value outside Unicode range");
    if (c >= 0xD800 && c < 0xE000)
        throw new DecodingError("UTF-8 sequence encodes surrogate code point");
    return c;
}

bool isValidUtf8(const(ubyte)[] utf8)
{
    try
    {
        size_t pos = 0;
        while (pos < utf8.length)
            nextUtf8Codepoint(utf8, pos);
        return true;
    }
    catch (DecodingError)
    {
        return false;
    }
}

bool isValidUtf8(in string utf8)
{
    return isValidUtf8(cast(const(ubyte)[])utf8);
}

/**
* UCS-2 (big-endian BMP) to UTF-8. Used for ASN.1 BMPString.
*/
Vector!ubyte ucs2ToUtf8(const(ubyte)[] ucs2)
{
    if (ucs2.length % 2 != 0)
        throw new DecodingError("Invalid length for UCS-2 string");

    Vector!ubyte s;
    const size_t chars = ucs2.length / 2;
    foreach (size_t i; 0 .. chars)
    {
        const uint c = (cast(uint)ucs2[2 * i] << 8) | ucs2[2 * i + 1];
        appendUtf8For(s, c);
    }
    return s.move();
}

/**
* UTF-8 to UCS-2 (big-endian BMP). Rejects code points above U+FFFF.
*/
Vector!ubyte utf8ToUcs2(const(ubyte)[] utf8)
{
    Vector!ubyte outp;
    size_t pos = 0;
    while (pos < utf8.length)
    {
        const uint c = nextUtf8Codepoint(utf8, pos);
        if (c > 0xFFFF)
            throw new DecodingError("Cannot encode character in UCS-2");
        const ushort val = cast(ushort)c;
        outp ~= get_byte(0, val);
        outp ~= get_byte(1, val);
    }
    return outp.move();
}

/**
* UCS-4 (big-endian) to UTF-8. Used for ASN.1 UniversalString.
*/
Vector!ubyte ucs4ToUtf8(const(ubyte)[] ucs4)
{
    if (ucs4.length % 4 != 0)
        throw new DecodingError("Invalid length for UCS-4 string");

    Vector!ubyte s;
    const size_t chars = ucs4.length / 4;
    foreach (size_t i; 0 .. chars)
    {
        const uint c = (cast(uint)ucs4[4 * i] << 24) |
                       (cast(uint)ucs4[4 * i + 1] << 16) |
                       (cast(uint)ucs4[4 * i + 2] << 8) |
                       ucs4[4 * i + 3];
        appendUtf8For(s, c);
    }
    return s.move();
}

/**
* UTF-8 to UCS-4 (big-endian).
*/
Vector!ubyte utf8ToUcs4(const(ubyte)[] utf8)
{
    Vector!ubyte outp;
    size_t pos = 0;
    while (pos < utf8.length)
    {
        const uint val = nextUtf8Codepoint(utf8, pos);
        outp ~= get_byte(0, val);
        outp ~= get_byte(1, val);
        outp ~= get_byte(2, val);
        outp ~= get_byte(3, val);
    }
    return outp.move();
}

Vector!ubyte latin1ToUtf8Bytes(const(ubyte)[] chars)
{
    Vector!ubyte s;
    foreach (ubyte b; chars)
        appendUtf8For(s, b);
    return s.move();
}

/*
* Perform character set transcoding
*/
string transcode(in string str, CharacterSet to, CharacterSet from)
{
    if (to == LOCAL_CHARSET)
        to = LATIN1_CHARSET;
    if (from == LOCAL_CHARSET)
        from = LATIN1_CHARSET;
    
    if (to == from)
        return str;
    
    if (from == LATIN1_CHARSET && to == UTF8_CHARSET)
        return latin1ToUtf8(str);
    if (from == UTF8_CHARSET && to == LATIN1_CHARSET)
        return utf8ToLatin1(str);
    if (from == UCS2_CHARSET && to == LATIN1_CHARSET)
        return ucs2ToLatin1(str);
    if (from == UCS2_CHARSET && to == UTF8_CHARSET)
    {
        auto outb = ucs2ToUtf8(cast(const(ubyte)[])str);
        return (cast(char[])outb[]).idup;
    }
    if (from == UTF8_CHARSET && to == UCS2_CHARSET)
    {
        auto outb = utf8ToUcs2(cast(const(ubyte)[])str);
        return (cast(char[])outb[]).idup;
    }
    if (from == UCS4_CHARSET && to == UTF8_CHARSET)
    {
        auto outb = ucs4ToUtf8(cast(const(ubyte)[])str);
        return (cast(char[])outb[]).idup;
    }
    if (from == UTF8_CHARSET && to == UCS4_CHARSET)
    {
        auto outb = utf8ToUcs4(cast(const(ubyte)[])str);
        return (cast(char[])outb[]).idup;
    }
    
    throw new InvalidArgument("Unknown transcoding operation from " ~ .to!string(from) ~ " to " ~ .to!string(to));
}

/*
* Check if a character represents a digit
*/
bool isDigit(char c)
{
    if (c == '0' || c == '1' || c == '2' || c == '3' || c == '4' ||
        c == '5' || c == '6' || c == '7' || c == '8' || c == '9')
        return true;
    return false;
}

/*
* Check if a character represents whitespace
*/
bool isSpace(char c)
{
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        return true;
    return false;
}

/*
* Convert a character to a digit
*/
ubyte char2digit(char c)
{
    switch(c)
    {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        default: 
            throw new InvalidArgument("char2digit: Input is not a digit character");
    }
    
}

/*
* Convert a digit to a character
*/
char digit2char(ubyte b)
{
    switch(b)
    {
        case 0: return '0';
        case 1: return '1';
        case 2: return '2';
        case 3: return '3';
        case 4: return '4';
        case 5: return '5';
        case 6: return '6';
        case 7: return '7';
        case 8: return '8';
        case 9: return '9';
        default:
            throw new InvalidArgument("digit2char: Input is not a digit: " ~ b.to!string);
    }
    
}

/*
* Case-insensitive character comparison
*/
bool caselessCmp(T)(T a, T b)
{
    import std.ascii : toLower;
    return (toLower(a) == toLower(b));
}

private bool isUnicodeControlChar(uint cp)
{
    return cp < 0x20 || (cp >= 0x7F && cp <= 0x9F);
}

/**
* Escape C0/C1 control characters in a UTF-8 string as ``\xHH``.
* Invalid UTF-8 bytes are escaped individually.
*/
string escapeControlChars(string utf8)
{
    const ubyte[] bytes = cast(const(ubyte)[])utf8;
    Appender!string outp;
    size_t pos = 0;
    void appendHexEscape(ubyte b)
    {
        static immutable char[16] hex = "0123456789ABCDEF";
        outp ~= '\\';
        outp ~= 'x';
        outp ~= hex[b >> 4];
        outp ~= hex[b & 0x0F];
    }
    while (pos < bytes.length)
    {
        const size_t start = pos;
        uint cp = 0;
        try
        {
            cp = nextUtf8Codepoint(bytes, pos);
        }
        catch (DecodingError)
        {
            appendHexEscape(bytes[start]);
            pos = start + 1;
            continue;
        }
        if (isUnicodeControlChar(cp))
        {
            foreach (size_t i; start .. pos)
                appendHexEscape(bytes[i]);
        }
        else
            outp ~= utf8[start .. pos];
    }
    return outp.data;
}