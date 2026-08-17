/**
* RFC 3779 IPAddrBlocks parse helpers.
*
* Copyright:
* (C) 2024 Anton Einax, Dominik Schricker
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.ip_addr_blocks;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.ber_dec;
import botan.asn1.asn1_obj;
import botan.utils.datastor.datastor;
import botan.utils.exceptn;
import botan.utils.types;
import std.conv : to;

void ipAddrAppend(ref string acc, string line)
{
    if (acc.length)
        acc ~= '\n';
    acc ~= line;
}

string ipAddrFormatV4(const(ubyte)[] a)
{
    return to!string(a[0]) ~ "." ~ to!string(a[1]) ~ "." ~ to!string(a[2]) ~ "." ~ to!string(a[3]);
}

string ipAddrFormatV6(const(ubyte)[] a)
{
    string s;
    foreach (i, b; a)
    {
        if (i)
            s ~= ':';
        s ~= "0123456789abcdef"[b >> 4];
        s ~= "0123456789abcdef"[b & 15];
    }
    return s;
}

void ipAddrExpand(const ref BERObject bits, size_t version_octets, bool is_min, ref ubyte[] out_addr)
{
    if (bits.value.empty)
        throw new DecodingError("Invalid IPAddress BIT STRING");
    const ubyte unused = bits.value[0];
    if (unused >= 8)
        throw new DecodingError("Bad unused bits in IPAddress");
    auto raw = bits.value[1 .. $];
    if (raw.length > version_octets)
        throw new DecodingError("IP address longer than AFI size");
    if (!raw.length && unused)
        throw new DecodingError("IP address unused bits without octets");
    out_addr.length = version_octets;
    foreach (i; 0 .. raw.length)
        out_addr[i] = raw[i];
    const ubyte fill = is_min ? 0 : 0xff;
    foreach (i; raw.length .. version_octets)
        out_addr[i] = fill;
    if (unused && raw.length)
    {
        const size_t last = raw.length - 1;
        foreach (i; 0 .. unused)
        {
            if (is_min)
                out_addr[last] &= cast(ubyte)(~(1 << i));
            else
                out_addr[last] |= cast(ubyte)(1 << i);
        }
    }
}

void ipAddrDecodeOrRange(ref BERDecoder list, size_t version_octets, ref string acc)
{
    BERObject n = list.getNextObject();
    ubyte[] min_a;
    ubyte[] max_a;
    if (n.type_tag == ASN1Tag.BIT_STRING)
    {
        ipAddrExpand(n, version_octets, true, min_a);
        ipAddrExpand(n, version_octets, false, max_a);
    }
    else if (n.type_tag == ASN1Tag.SEQUENCE)
    {
        auto r = BERDecoder(n.value.ptr, n.value.length);
        BERObject a = r.getNextObject();
        BERObject b = r.getNextObject();
        if (a.type_tag != ASN1Tag.BIT_STRING || b.type_tag != ASN1Tag.BIT_STRING)
            throw new DecodingError("IPAddressRange expects two BIT STRINGs");
        ipAddrExpand(a, version_octets, true, min_a);
        ipAddrExpand(b, version_octets, false, max_a);
    }
    else
        throw new DecodingError("Unexpected IPAddressOrRange");
    if (version_octets == 4)
        ipAddrAppend(acc, ipAddrFormatV4(min_a) ~ "-" ~ ipAddrFormatV4(max_a));
    else
        ipAddrAppend(acc, ipAddrFormatV6(min_a) ~ "-" ~ ipAddrFormatV6(max_a));
}

void ipAddrDecodeChoice(ref BERDecoder seq, size_t version_octets, ref string acc, ref bool inherit)
{
    BERObject n = seq.getNextObject();
    if (n.type_tag == ASN1Tag.NULL_TAG)
    {
        inherit = true;
        return;
    }
    if (n.type_tag != ASN1Tag.SEQUENCE)
        throw new DecodingError("Unexpected IPAddressChoice");
    auto list = BERDecoder(n.value.ptr, n.value.length);
    while (list.moreItems())
        ipAddrDecodeOrRange(list, version_octets, acc);
}

void ipAddrAddPacked(ref DataStore subject, string key, string packed)
{
    size_t i;
    while (i < packed.length)
    {
        size_t j = i;
        while (j < packed.length && packed[j] != '\n')
            ++j;
        if (j > i)
            subject.add(key, packed[i .. j]);
        i = j + 1;
    }
}
