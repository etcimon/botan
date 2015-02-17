/**
* Character Set Handling
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.charset;

import botan.constants;
import std.array : Appender;
import botan.utils.types;
import botan.utils.exceptn;
import std.conv : to;

/**
* The different charsets (nominally) supported by Botan.
*/
alias ubyte CharacterSet;
enum : CharacterSet {
    LOCAL_CHARSET,
    UCS2_CHARSET,
    UTF8_CHARSET,
    LATIN1_CHARSET
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
    latin1.resize(ucs2.length * 2);

    for (size_t i = 0; i != ucs2.length; i += 2)
    {
        const ubyte c1 = ucs2[i];
        const ubyte c2 = ucs2[i+1];
        
        if (c1 != 0)
            throw new DecodingError("UCS-2 has non-Latin1 characters");
        
        latin1[i] = cast(char)(c2);
    }

    string ret = latin1.ptr[0 .. latin1.length].idup;

    logDebug(ret);
    
    return ret;
}

/*
* Convert from UTF-8 to ISO 8859-1
*/
string utf8ToLatin1(in string utf8)
{
    Vector!char iso8859;
    iso8859.resize(utf8.length);
    size_t position = 0;
    while (position != utf8.length)
    {
        const ubyte c1 = cast(ubyte)(utf8[position++]);
        
        if (c1 <= 0x7F)
            iso8859[position] = cast(char)(c1);
        else if (c1 >= 0xC0 && c1 <= 0xC7)
        {
            if (position == utf8.length)
                throw new DecodingError("UTF-8: sequence truncated");
            
            const ubyte c2 = cast(ubyte)(utf8[position++]);
            const ubyte iso_char = cast(ubyte)((c1 & 0x07) << 6) | (c2 & 0x3F);
            
            if (iso_char <= 0x7F)
                throw new DecodingError("UTF-8: sequence longer than needed");
            
            iso8859[position] = cast(char)(iso_char);
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
    utf8.resize(iso8859.length);
    for (size_t i = 0; i != iso8859.length; ++i)
    {
        const ubyte c = cast(ubyte)(iso8859[i]);
        
        if (c <= 0x7F)
            utf8[i] = cast(char)(c);
        else
        {
            utf8[i] = cast(char)((0xC0 | (c >> 6)));
            utf8[i] = cast(char)((0x80 | (c & 0x3F)));
        }
    }
    string ret = utf8.ptr[0 .. utf8.length].idup;
    //logTrace("latin1ToUtf8: ", ret);
    return ret;
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