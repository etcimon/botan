/**
* RFC 3779 ASIdentifiers parse helpers.
*
* Copyright:
* (C) 2024 Anton Einax, Dominik Schricker
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.as_blocks;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.ber_dec;
import botan.asn1.asn1_obj;
import botan.utils.datastor.datastor;
import botan.utils.exceptn;
import botan.utils.types;
import std.conv : to;

uint asIdentInt(const(ubyte)* p, size_t n)
{
    ulong v;
    foreach (i; 0 .. n)
        v = (v << 8) | p[i];
    if (v > uint.max)
        throw new DecodingError("ASId does not fit in 32 bits");
    return cast(uint)v;
}

void asIdentAppendRange(ref string acc, uint min_as, uint max_as)
{
    if (acc.length)
        acc ~= '\n';
    acc ~= to!string(min_as);
    acc ~= '-';
    acc ~= to!string(max_as);
}

void asIdentDecodeChoice(const(ubyte)* bits, size_t len, ref string acc, ref bool inherit)
{
    // Explicit [0] NULL is `05 00`. Implicit [0] NULL has an empty payload.
    if (!len || (len == 2 && bits[0] == 0x05 && bits[1] == 0x00))
    {
        inherit = true;
        return;
    }
    auto dec = BERDecoder(bits, len);
    BERObject n = dec.getNextObject();
    if (n.type_tag == ASN1Tag.NULL_TAG)
    {
        inherit = true;
        return;
    }
    if (n.type_tag != ASN1Tag.SEQUENCE)
        throw new DecodingError("Unexpected ASIdentifierChoice");
    auto list = BERDecoder(n.value.ptr, n.value.length);
    while (list.moreItems())
    {
        BERObject e = list.getNextObject();
        if (e.type_tag == ASN1Tag.INTEGER)
        {
            auto id = asIdentInt(e.value.ptr, e.value.length);
            asIdentAppendRange(acc, id, id);
        }
        else if (e.type_tag == ASN1Tag.SEQUENCE)
        {
            auto r = BERDecoder(e.value.ptr, e.value.length);
            BERObject a = r.getNextObject();
            BERObject b = r.getNextObject();
            if (a.type_tag != ASN1Tag.INTEGER || b.type_tag != ASN1Tag.INTEGER)
                throw new DecodingError("ASRange expects two integers");
            auto min_as = asIdentInt(a.value.ptr, a.value.length);
            auto max_as = asIdentInt(b.value.ptr, b.value.length);
            if (min_as >= max_as)
                throw new DecodingError("ASIdOrRange has min greater than max");
            asIdentAppendRange(acc, min_as, max_as);
        }
        else
            throw new DecodingError("Unexpected ASIdOrRange");
    }
}

void asIdentAddPacked(ref DataStore subject, string key, string packed)
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
