/**
* RFC 5280 NameConstraints GeneralSubtrees parse.
*
* x509test encodes permitted/excluded as implicit [0]/[1] SEQUENCE OF
* (payload starts with a GeneralSubtree). NIST uses an explicit SEQUENCE
* wrapper. Both are accepted here.
*
* Copyright:
* (C) 2015 Kai Michaelis
* (C) 2024,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.name_constraint_parse;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.ber_dec;
import botan.asn1.asn1_obj;
import botan.utils.exceptn;
import botan.utils.types;

/// True when `bits` is SEQUENCE { GeneralSubtree, ... } rather than a bare list.
bool nameConstraintListWrapped(const(ubyte)* bits, size_t len)
{
    if (len < 2 || bits[0] != 0x30)
        return false;
    size_t hdr = 2;
    const ubyte l0 = bits[1];
    if (l0 & 0x80)
    {
        const size_t n = l0 & 0x7F;
        if (n == 0 || n > 3 || 2 + n > len)
            return false;
        hdr = 2 + n;
    }
    return hdr < len && bits[hdr] == 0x30;
}

void nameConstraintAppendDns(ref string acc, const(ubyte)* p, size_t n)
{
    if (!n)
        return;
    if (acc.length)
        acc ~= '\n';
    acc ~= (cast(const(char)*)p)[0 .. n].idup;
}

void nameConstraintParseSubtree(ref BERDecoder ber, ref string dns)
{
    size_t minimum = 0;
    size_t maximum = size_t.max;
    auto seq = ber.startCons(ASN1Tag.SEQUENCE);
    BERObject base = seq.getNextObject();
    if (base.type_tag == ASN1Tag.NO_OBJECT)
        throw new DecodingError("GeneralSubtree missing base");
    if (base.type_tag == cast(ASN1Tag)2 && (base.class_tag & ASN1Tag.CONTEXT_SPECIFIC))
        nameConstraintAppendDns(dns, base.value.ptr, base.value.length);
    seq.decodeOptional(minimum, cast(ASN1Tag)0, ASN1Tag.CONTEXT_SPECIFIC, size_t(0));
    seq.decodeOptional(maximum, cast(ASN1Tag)1, ASN1Tag.CONTEXT_SPECIFIC, size_t.max);
    seq.endCons();
    if (minimum != 0)
        throw new DecodingError("GeneralSubtree minimum must be 0");
    if (maximum != size_t.max)
        throw new DecodingError("GeneralSubtree maximum must be absent");
}

size_t nameConstraintParseSubtrees(const(ubyte)* bits, size_t len, ref string dns)
{
    size_t n;
    if (nameConstraintListWrapped(bits, len))
    {
        auto seq = BERDecoder(bits, len).startCons(ASN1Tag.SEQUENCE);
        while (seq.moreItems())
        {
            nameConstraintParseSubtree(seq, dns);
            ++n;
        }
        seq.endCons();
    }
    else
    {
        auto seq = BERDecoder(bits, len);
        while (seq.moreItems())
        {
            nameConstraintParseSubtree(seq, dns);
            ++n;
        }
    }
    return n;
}
