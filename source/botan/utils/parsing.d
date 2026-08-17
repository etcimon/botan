/**
* Various string utils and parsing functions
* 
* Copyright:
* (C) 1999-2007,2013,2014,2015,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.parsing;

import botan.constants;

import botan.utils.types;
import botan.utils.types;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.utils.charset;
import botan.utils.get_byte;
import memutils.hashmap;
/**
* Parse a SCAN-style algorithm name
* Params:
*  scan_name = the name
* Returns: the name components
*/
/*
* Parse a SCAN-style algorithm name
*/
Vector!string parseAlgorithmName(in string scan_name)
{
    import std.array : Appender;
    if (scan_name.find('(') == -1 &&
        scan_name.find(')') == -1) {
		Vector!string str = Vector!string(1);
        str[0] = scan_name;
        return str.move();
    }
    string name = scan_name;
    Vector!ubyte substring;
	substring.reserve(16);
    Vector!string elems;
	elems.reserve(16);
    size_t level = 0;
    
    elems.pushBack(name[0 .. name.find('(')].idup);
    name = name[name.find('(') .. $];
    
    foreach(size_t pos, const char c; name)
    {
        
        if (c == '(')
            ++level;
        if (c == ')')
        {
            if (level == 1 && pos == (name.length - 1))
            {
                if (elems.length == 1)
                    elems.pushBack(substring[1 .. $].idup);
                else
                    elems.pushBack(substring[].idup);
                return elems.move();
            }
            
            if (level == 0 || (level == 1 && pos != (name.length - 1)))
                throw new InvalidAlgorithmName(scan_name);
            --level;
        }
        
        if (c == ',' && level == 1)
        {
            if (elems.length == 1)
                elems.pushBack(substring[1 .. $].idup);
            else
                elems.pushBack(substring[].idup);
            substring.clear();
        }
        else
            substring ~= c;
    }
    
    if (substring.length > 0)
        throw new InvalidAlgorithmName(scan_name);
    
    return elems.move();
}

/**
* Split a string
* Params:
*  str = the input string
*  delim = the delimitor
* Returns: string split by delim
*/
Vector!string splitter(in string str, char delim)
{
    return splitOnPred(str, (char c) { return c == delim; });
}
/**
* Split a string on a character predicate
* Params:
*  str = the input string
*  pred = the predicate that returns true to split
*/
Vector!string splitOnPred(in string str,
                         bool delegate(char) pred)
{
    Vector!string elems;
	elems.reserve(8);
    if (str == "") return elems.move();
    Vector!ubyte substr;
	substr.reserve(16);
    foreach(const char c; str)
    {
        if (pred(c))
        {
            if (substr.length > 0)
                elems.pushBack(substr[].idup);
            substr.clear();
        }
        else
            substr ~= c;
    }
    
    if (substr.length == 0)
        throw new InvalidArgument("Unable to split string: " ~ str);
    elems.pushBack(substr[].idup);
    
    return elems.move();
}

/**
* Erase characters from a string
*/
string eraseChars(in string str, in char[] chars)
{
    //logTrace("eraseChars");
    import std.algorithm : canFind;
    import std.array : Appender;
    Appender!string output;
	output.reserve(16);
    foreach(const char c; str)
        if (!chars.canFind(c))
            output ~= c;
    
    return output.data;
}

/**
* Replace a character in a string
* Params:
*  str = the input string
*  from_char = the character to replace
*  to_char = the character to replace it with
* Returns: str with all instances of from_char replaced by to_char
*/
string replaceChar(in string str, in char from_char, in char to_char)
{   
    char[] output = str.dup;
    foreach (ref char c; output)
        if (c == from_char)
            c = to_char;
    
    return cast(string)output;
}

/**
* Replace a character in a string
* Params:
*  str = the input string
*  chars = the characters to replace
*  to_char = the character to replace it with
* Returns: str with all instances of chars replaced by to_char
*/

string replaceChars(in string str,
                    in char[] chars,
                    in char to_char)
{
    import std.algorithm : canFind;
    char[] output = str.dup;
    foreach (ref char c; output)
        if (chars.canFind(c))
            c = to_char;
    
    return cast(string)output;
}

/**
* Join a string
* Params:
*  strs = strings to join
*  delim = the delimitor
* Returns: string joined by delim
*/
string stringJoin(const ref Vector!string strs, char delim)
{
    import std.algorithm : joiner;
    import std.array : array;
    return strs[].joiner(delim.to!string).to!string;
}

/**
* Parse an ASN.1 OID
* Params:
*  oid = the OID in string form
* Returns: OID components
*/
Vector!uint parseAsn1Oid(in string oid)
{
    import std.array : Appender, array;
    Vector!char substring;
	substring.reserve(16);
    Vector!uint oid_elems;
	oid_elems.reserve(16);

    foreach (char c; oid)
    {
        if (c == '.')
        {
            if (substring.length == 0)
                throw new InvalidOID(oid);
            oid_elems ~= to!uint(substring[]);
            substring.clear();
        }
        else {
            substring ~= c;
        }
    }
    
    if (substring.length == 0)
        throw new InvalidOID(oid);
    oid_elems ~= to!uint(substring[]);    
    substring.clear();

    if (oid_elems.length < 2)
        throw new InvalidOID(oid);
    return oid_elems.move();
}

/**
* Compare two names using the X.509 comparison algorithm
* Params:
*  name1 = the first name
*  name2 = the second name
* Returns: true if name1 is the same as name2 by the X.509 comparison rules
*/
bool x500NameCmp(in string name1, in string name2)
{
    auto p1 = name1.ptr;
    auto p2 = name2.ptr;
    
    while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
    while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
    
    while (p1 != name1.ptr + name1.length && p2 != name2.ptr + name2.length)
    {
        if (isSpace(*p1))
        {
            if (!isSpace(*p2))
                return false;
            
            while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
            while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
            
            if (p1 == name1.ptr + name1.length && p2 == name2.ptr + name2.length)
                return true;
        }
        
        if (!caselessCmp(*p1, *p2))
            return false;
        ++p1;
        ++p2;
    }
    
    while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
    while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
    
    if ((p1 != name1.ptr + name1.length) || (p2 != name2.ptr + name2.length))
        return false;
    return true;
}

/// C++ `X500_Char_Iterator::canonicalize`: fold ASCII, collapse whitespace.
string x500Canonicalize(in string name)
{
    import std.array : Appender;
    Appender!string outp;
    size_t i = 0;
    while (i < name.length && isSpace(name[i]))
        ++i;
    bool pending_space = false;
    while (i < name.length)
    {
        if (isSpace(name[i]))
        {
            while (i < name.length && isSpace(name[i]))
                ++i;
            if (i < name.length)
                pending_space = true;
        }
        else
        {
            if (pending_space)
            {
                outp.put(' ');
                pending_space = false;
            }
            char c = name[i];
            if (c >= 'A' && c <= 'Z')
                c = cast(char)(c + ('a' - 'A'));
            outp.put(c);
            ++i;
        }
    }
    return outp.data;
}

/**
* Convert a string representation of an IPv4 address to a number
* Params:
*  str = the string representation
* Returns: integer IPv4 address
*/
uint stringToIpv4(in string str)
{
    uint ip;
    if (!tryStringToIpv4(str, ip))
        throw new DecodingError("Invalid IP string " ~ str);
    return ip;
}

/**
* C++ `string_to_ipv4`: exactly four decimal octets, no leading zeros,
* no hex/octal, no host-order integer shorthand.
*/
bool tryStringToIpv4(in string str, out uint ip)
{
    if (str.length < 7 || str.length > 15)
        return false;

    ip = 0;
    size_t dots = 0;
    uint accum = 0;
    size_t cur_digits = 0;

    foreach (char c; str)
    {
        if (c == '.')
        {
            if (cur_digits == 0)
                return false;
            if (++dots > 3)
                return false;
            cur_digits = 0;
            ip = (ip << 8) | accum;
            accum = 0;
        }
        else if (c >= '0' && c <= '9')
        {
            if (cur_digits > 0 && accum == 0)
                return false;
            accum = accum * 10 + cast(uint)(c - '0');
            if (accum > 255)
                return false;
            ++cur_digits;
        }
        else
            return false;
    }

    if (cur_digits == 0 || dots != 3)
        return false;
    ip = (ip << 8) | accum;
    return true;
}

/**
* Parse a canonical IPv4 CIDR (`a.b.c.d/p`). Host bits must be clear
* and the prefix a plain decimal in 0..32 (C++ `IPv4Subnet::from_string`).
*/
bool tryParseIpv4Subnet(in string str, out uint addr, out ubyte prefix)
{
    addr = 0;
    prefix = 0;
    ptrdiff_t slash = -1;
    foreach (size_t i, char c; str)
    {
        if (c == '/')
        {
            slash = cast(ptrdiff_t)i;
            break;
        }
    }
    if (slash < 0)
        return false;
    if (!tryStringToIpv4(str[0 .. slash], addr))
        return false;
    const string plen = str[slash + 1 .. $];
    if (!plen.length)
        return false;
    if (plen.length > 1 && plen[0] == '0')
        return false;
    uint p = 0;
    foreach (char c; plen)
    {
        if (c < '0' || c > '9')
            return false;
        p = p * 10 + cast(uint)(c - '0');
        if (p > 32)
            return false;
    }
    prefix = cast(ubyte)p;
    const uint mask = (p == 0) ? 0 : (0xFFFFFFFFu << (32 - p));
    if ((addr & ~mask) != 0)
        return false;
    return true;
}

string ipv4SubnetToString(uint addr, ubyte prefix)
{
    return ipv4ToString(addr) ~ "/" ~ prefix.to!string;
}

private int ipv6HexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

/**
* Parse an IPv6 address (RFC 4291 / 5952). On success writes 16 bytes.
*/
bool tryStringToIpv6(in string str, ref ubyte[16] outp)
{
    if (!str.length)
        return false;

    ushort[8] pre;
    ushort[8] post;
    size_t pre_count = 0;
    size_t post_count = 0;
    bool seen_double_colon = false;
    size_t idx = 0;
    bool expect_group = true;

    while (idx < str.length)
    {
        if (str[idx] == ':')
        {
            if (idx + 1 < str.length && str[idx + 1] == ':')
            {
                if (seen_double_colon)
                    return false;
                seen_double_colon = true;
                idx += 2;
                expect_group = (idx < str.length);
                continue;
            }
            if (expect_group)
                return false;
            expect_group = true;
            idx += 1;
            continue;
        }

        const size_t group_start = idx;
        uint group = 0;
        size_t hex_chars = 0;
        while (idx < str.length && hex_chars < 4)
        {
            const int digit = ipv6HexValue(str[idx]);
            if (digit < 0)
                break;
            group = (group << 4) | cast(uint)digit;
            idx += 1;
            hex_chars += 1;
        }
        if (hex_chars == 0)
            return false;
        if (hex_chars == 4 && idx < str.length && ipv6HexValue(str[idx]) >= 0)
            return false;

        if (idx < str.length && str[idx] == '.')
        {
            uint v4;
            if (!tryStringToIpv4(str[group_start .. $], v4))
                return false;
            ushort[2] v4_groups = [cast(ushort)(v4 >> 16), cast(ushort)(v4 & 0xFFFF)];
            foreach (g; v4_groups)
            {
                if (seen_double_colon)
                {
                    if (post_count >= 8)
                        return false;
                    post[post_count++] = g;
                }
                else
                {
                    if (pre_count >= 8)
                        return false;
                    pre[pre_count++] = g;
                }
            }
            idx = str.length;
            expect_group = false;
            continue;
        }

        if (seen_double_colon)
        {
            if (post_count >= 8)
                return false;
            post[post_count++] = cast(ushort)group;
        }
        else
        {
            if (pre_count >= 8)
                return false;
            pre[pre_count++] = cast(ushort)group;
        }
        expect_group = false;
    }

    if (expect_group)
        return false;

    const size_t total_groups = pre_count + post_count;
    if (seen_double_colon)
    {
        if (total_groups > 7)
            return false;
    }
    else if (total_groups != 8)
        return false;

    outp[] = 0;
    foreach (size_t i; 0 .. pre_count)
    {
        outp[2 * i] = get_byte(0, pre[i]);
        outp[2 * i + 1] = get_byte(1, pre[i]);
    }
    const size_t gap = 8 - total_groups;
    foreach (size_t i; 0 .. post_count)
    {
        const size_t target = pre_count + gap + i;
        outp[2 * target] = get_byte(0, post[i]);
        outp[2 * target + 1] = get_byte(1, post[i]);
    }
    return true;
}

string ipv6ToString(in ubyte[16] ip)
{
    ushort[8] groups;
    foreach (size_t i; 0 .. 8)
        groups[i] = cast(ushort)((ip[2 * i] << 8) | ip[2 * i + 1]);

    size_t best_start = 0;
    size_t best_len = 0;
    size_t run_len = 0;
    foreach (size_t i; 0 .. 8)
    {
        if (groups[i] == 0)
        {
            ++run_len;
            if (run_len > best_len)
            {
                best_len = run_len;
                best_start = i + 1 - run_len;
            }
        }
        else
            run_len = 0;
    }

    string outp;
    void appendGroup(ushort group)
    {
        bool started = false;
        for (int s = 12; s >= 0; s -= 4)
        {
            const uint nibble = (group >> s) & 0xF;
            if (nibble != 0 || started || s == 0)
            {
                outp ~= "0123456789abcdef"[nibble];
                started = true;
            }
        }
    }

    if (best_len < 2)
    {
        foreach (size_t i; 0 .. 8)
        {
            if (i > 0)
                outp ~= ':';
            appendGroup(groups[i]);
        }
    }
    else
    {
        foreach (size_t i; 0 .. best_start)
        {
            if (i > 0)
                outp ~= ':';
            appendGroup(groups[i]);
        }
        outp ~= "::";
        foreach (size_t i; best_start + best_len .. 8)
        {
            if (i > best_start + best_len)
                outp ~= ':';
            appendGroup(groups[i]);
        }
    }
    return outp;
}

bool tryParseIpv6Subnet(in string str, ref ubyte[16] addr, out ubyte prefix)
{
    prefix = 0;
    ptrdiff_t slash = -1;
    foreach (size_t i, char c; str)
    {
        if (c == '/')
        {
            slash = cast(ptrdiff_t)i;
            break;
        }
    }
    if (slash < 0)
        return false;
    if (!tryStringToIpv6(str[0 .. slash], addr))
        return false;
    const string plen = str[slash + 1 .. $];
    if (!plen.length)
        return false;
    if (plen.length > 1 && plen[0] == '0')
        return false;
    uint p = 0;
    foreach (char c; plen)
    {
        if (c < '0' || c > '9')
            return false;
        p = p * 10 + cast(uint)(c - '0');
        if (p > 128)
            return false;
    }
    prefix = cast(ubyte)p;
    ubyte[16] mask;
    const size_t full_bytes = p / 8;
    const size_t leftover = p % 8;
    foreach (size_t i; 0 .. full_bytes)
        mask[i] = 0xFF;
    if (leftover)
        mask[full_bytes] = cast(ubyte)(0xFF << (8 - leftover));
    foreach (size_t i; 0 .. 16)
    {
        if ((addr[i] & ~mask[i]) != 0)
            return false;
    }
    return ipv6ToString(addr) ~ "/" ~ prefix.to!string == str;
}

string ipv6SubnetToString(in ubyte[16] addr, ubyte prefix)
{
    return ipv6ToString(addr) ~ "/" ~ prefix.to!string;
}

/**
* True iff `mask` is a contiguous CIDR prefix. Writes the prefix length.
*/
bool tryIpv4PrefixLength(uint mask, out ubyte prefix)
{
    const uint inv = ~mask;
    if ((inv & (inv + 1)) != 0)
        return false;
    prefix = 0;
    foreach (int bit; 0 .. 32)
    {
        if ((mask & (0x80000000u >> bit)) == 0)
            break;
        ++prefix;
    }
    return true;
}

bool tryIpv6PrefixLength(in ubyte[16] mask, out ubyte prefix)
{
    size_t leading = 0;
    foreach (size_t i; 0 .. 16)
    {
        size_t hw = 0;
        foreach (int b; 0 .. 8)
        {
            if ((mask[i] & (0x80 >> b)) == 0)
                break;
            ++hw;
        }
        leading += hw;
        if (hw != 8)
            break;
    }
    ubyte[16] expect;
    const size_t full_bytes = leading / 8;
    const size_t leftover = leading % 8;
    foreach (size_t i; 0 .. full_bytes)
        expect[i] = 0xFF;
    if (leftover)
        expect[full_bytes] = cast(ubyte)(0xFF << (8 - leftover));
    if (expect[] != mask[])
        return false;
    prefix = cast(ubyte)leading;
    return true;
}

/**
* Name-constraint iPAddress payload: address || mask (8 or 32 bytes).
*/
bool tryParseIpConstraintMask(const(ubyte)[] address, const(ubyte)[] netmask)
{
    ubyte unused;
    if (address.length == 4 && netmask.length == 4)
    {
        const uint mask = (cast(uint)netmask[0] << 24) | (cast(uint)netmask[1] << 16) |
                          (cast(uint)netmask[2] << 8) | netmask[3];
        return tryIpv4PrefixLength(mask, unused);
    }
    if (address.length == 16 && netmask.length == 16)
    {
        ubyte[16] m;
        m[] = netmask[0 .. 16];
        return tryIpv6PrefixLength(m, unused);
    }
    return false;
}

private immutable ubyte[128] DNS_CHAR_MAPPING = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,'*',0,0,'-','.',0,'0','1','2','3','4','5','6','7','8','9',
    0,0,0,0,0,0,0,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z',0,0,0,0,0,0,'a','b','c','d','e','f','g',
    'h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',0,0,0,0,0
];

/**
* RFC 1035/1123 DNS name, lowercased. `*` is allowed in the character set
* so SAN wildcards can be validated separately.
*/
bool tryCanonicalizeDnsName(in string name, out string canon)
{
    canon = null;
    if (name.length == 0 || name.length > 253)
        return false;
    if (name[0] == '.' || name[$-1] == '.')
        return false;

    size_t current_label_length = 0;
    bool all_numeric = true;
    foreach (size_t i, char c; name)
    {
        if (c == '.')
        {
            if (i > 0 && name[i - 1] == '.')
                return false;
            if (current_label_length == 0)
                return false;
            current_label_length = 0;
        }
        else
        {
            ++current_label_length;
            if (current_label_length > 63)
                return false;
        }
        const ubyte cu = cast(ubyte)c;
        if (cu >= 128)
            return false;
        const ubyte mapped = DNS_CHAR_MAPPING[cu];
        if (mapped == 0)
            return false;
        if (mapped != '.' && (mapped < '0' || mapped > '9'))
            all_numeric = false;
        if (mapped == '-')
        {
            if (i == 0 || (i > 0 && name[i - 1] == '.'))
                return false;
            if (i == name.length - 1 || (i + 1 < name.length && name[i + 1] == '.'))
                return false;
        }
        canon ~= cast(char)mapped;
    }
    if (current_label_length == 0 || all_numeric)
        return false;
    return true;
}

bool tryParseDnsName(in string name, out string canon)
{
    if (!tryCanonicalizeDnsName(name, canon))
        return false;
    foreach (char c; canon)
        if (c == '*')
            return false;
    return true;
}

bool tryParseDnsSanName(in string name, out string canon)
{
    if (!tryCanonicalizeDnsName(name, canon))
        return false;
    ptrdiff_t first_star = -1;
    foreach (size_t i, char c; canon)
    {
        if (c == '*')
        {
            if (first_star >= 0)
                return false;
            first_star = cast(ptrdiff_t)i;
        }
    }
    if (first_star < 0)
        return true;
    ptrdiff_t first_dot = -1;
    foreach (size_t i, char c; canon)
    {
        if (c == '.')
        {
            first_dot = cast(ptrdiff_t)i;
            break;
        }
    }
    if (first_dot >= 0 && first_dot < first_star)
        return false;
    if (canon.length >= 4 && canon[0 .. 4] == "xn--")
        return false;
    size_t dots = 0;
    foreach (char c; canon)
        if (c == '.')
            ++dots;
    if (dots < 2)
        return false;
    return true;
}

bool hostWildcardMatch(in string issued, in string host)
{
    if (!issued.length || !host.length || host.length > 253)
        return false;
    if (issued.length > host.length + 1)
        return false;
    foreach (char c; issued)
        if (c == 0)
            return false;
    foreach (char c; host)
        if (c == 0 || c == '*')
            return false;
    if (host[0] == '.' || host[$-1] == '.')
        return false;
    foreach (size_t i; 1 .. host.length)
        if (host[i] == '.' && host[i - 1] == '.')
            return false;

    bool dnsCharEq(char a, char b)
    {
        if (a == b)
            return true;
        const ubyte la = cast(ubyte)(a | 0x20);
        const ubyte lb = cast(ubyte)(b | 0x20);
        return la == lb && la >= 'a' && la <= 'z';
    }
    bool dnsRangeEq(in string a, in string b)
    {
        if (a.length != b.length)
            return false;
        foreach (size_t i; 0 .. a.length)
            if (!dnsCharEq(a[i], b[i]))
                return false;
        return true;
    }
    if (dnsRangeEq(issued, host))
        return true;

    ptrdiff_t first_star = -1;
    foreach (size_t i, char c; issued)
    {
        if (c == '*')
        {
            if (first_star >= 0)
                return false;
            first_star = cast(ptrdiff_t)i;
        }
    }
    if (first_star < 0)
        return false;

    string issued_label = issued;
    foreach (size_t i, char c; issued)
    {
        if (c == '.')
        {
            issued_label = issued[0 .. i];
            break;
        }
    }
    bool idnaPrefixed(in string label)
    {
        return label.length >= 4 && dnsRangeEq(label[0 .. 4], "xn--");
    }
    if (idnaPrefixed(issued_label))
        return false;
    string host_label = host;
    foreach (size_t i, char c; host)
    {
        if (c == '.')
        {
            host_label = host[0 .. i];
            break;
        }
    }
    if (issued_label != "*" && idnaPrefixed(host_label))
        return false;

    size_t dots_seen = 0;
    size_t host_idx = 0;
    foreach (size_t i; 0 .. issued.length)
    {
        if (issued[i] == '.')
            ++dots_seen;
        if (issued[i] == '*')
        {
            if (dots_seen > 0)
                return false;
            const size_t advance = host.length - issued.length + 1;
            if (host_idx + advance > host.length)
                return false;
            foreach (size_t k; host_idx .. host_idx + advance)
                if (host[k] == '.')
                    return false;
            host_idx += advance;
        }
        else
        {
            if (host_idx >= host.length || !dnsCharEq(issued[i], host[host_idx]))
                return false;
            ++host_idx;
        }
    }
    if (dots_seen < 2)
        return false;
    return true;
}

/**
* Convert an IPv4 address to a string
* Params:
*  ip = the IPv4 address to convert
* Returns: string representation of the IPv4 address
*/
string ipv4ToString(uint ip)
{
    import std.array : Appender;
    Appender!string str;
    for (size_t i = 0; i != (ip).sizeof; ++i)
    {
        if (i)
            str ~= ".";
        str ~= to!string(get_byte(i, ip));
    }
    
    return str.data;
}

/**
* Parse a comma-separated key=value list (C++ `read_kv`).
*
* Keys must be non-empty and unique. Comma, equals, and backslash
* may be escaped with a backslash.
*/
HashMap!(string, string) readKv(in string kv)
{
    HashMap!(string, string) m;
    if (!kv.length)
        return m;

    try
    {
        splitter(kv, ',');
    }
    catch (Exception)
    {
        throw new InvalidArgument("Bad KV spec");
    }

    bool escaped = false;
    bool reading_key = true;
    string cur_key;
    string cur_val;

    foreach (char c; kv)
    {
        if (c == '\\' && !escaped)
            escaped = true;
        else if (c == ',' && !escaped)
        {
            if (!cur_key.length)
                throw new InvalidArgument("Bad KV spec empty key");
            if (cur_key in m)
                throw new InvalidArgument("Bad KV spec duplicated key");
            m[cur_key] = cur_val;
            cur_key = "";
            cur_val = "";
            reading_key = true;
        }
        else if (c == '=' && !escaped)
        {
            if (!reading_key)
                throw new InvalidArgument("Bad KV spec unexpected equals sign");
            reading_key = false;
        }
        else
        {
            if (reading_key)
                cur_key ~= c;
            else
                cur_val ~= c;
            if (escaped)
                escaped = false;
        }
    }

    if (cur_key.length)
    {
        if (!reading_key)
        {
            if (cur_key in m)
                throw new InvalidArgument("Bad KV spec duplicated key");
            m[cur_key] = cur_val;
        }
        else
            throw new InvalidArgument("Bad KV spec incomplete string");
    }

    return m;
}

private:

ptrdiff_t find(string str, char c) {
    import std.algorithm : countUntil;
    return countUntil(str, c);
}

auto end(string str) {
    return str.ptr + str.length;
}
