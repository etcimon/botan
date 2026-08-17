/**
* ASN.1 pretty printer (C++ asn1_print)
*
* Copyright:
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_print;

import botan.constants;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.oids;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.math.bigint.bigint;
import botan.codec.hex;
import botan.utils.charset;
import botan.utils.types;
import botan.utils.exceptn;
import std.array : Appender, replicate;
import std.conv : to;

static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO)
    import botan.asn1.asn1_time;

private bool allPrintableChars(const(ubyte)[] bits)
{
    foreach (ubyte b; bits)
    {
        const bool ok = (b >= '0' && b <= '9') ||
                        (b >= 'A' && b <= 'Z') ||
                        (b >= 'a' && b <= 'z') ||
                        b == '.' || b == ':' || b == '/' || b == '-';
        if (!ok)
            return false;
    }
    return true;
}

private bool possiblyAGeneralName(const(ubyte)[] bits)
{
    if (bits.length <= 2)
        return false;
    if (bits[0] != 0x82 && bits[0] != 0x86)
        return false;
    if (bits[1] != bits.length - 2)
        return false;
    return allPrintableChars(bits[2 .. $]);
}

private bool isAsn1StringType(ASN1Tag tag)
{
    return tag == ASN1Tag.NUMERIC_STRING ||
           tag == ASN1Tag.PRINTABLE_STRING ||
           tag == ASN1Tag.VISIBLE_STRING ||
           tag == ASN1Tag.T61_STRING ||
           tag == ASN1Tag.IA5_STRING ||
           tag == ASN1Tag.UTF8_STRING ||
           tag == ASN1Tag.BMP_STRING ||
           tag == ASN1Tag.UNIVERSAL_STRING;
}

string asn1TagToString(ASN1Tag type)
{
    switch (type)
    {
        case ASN1Tag.SEQUENCE: return "SEQUENCE";
        case ASN1Tag.SET: return "SET";
        case ASN1Tag.PRINTABLE_STRING: return "PRINTABLE STRING";
        case ASN1Tag.NUMERIC_STRING: return "NUMERIC STRING";
        case ASN1Tag.IA5_STRING: return "IA5 STRING";
        case ASN1Tag.T61_STRING: return "T61 STRING";
        case ASN1Tag.UTF8_STRING: return "UTF8 STRING";
        case ASN1Tag.VISIBLE_STRING: return "VISIBLE STRING";
        case ASN1Tag.BMP_STRING: return "BMP STRING";
        case ASN1Tag.UNIVERSAL_STRING: return "UNIVERSAL STRING";
        case ASN1Tag.UTC_TIME: return "UTC TIME";
        case ASN1Tag.GENERALIZED_TIME: return "GENERALIZED TIME";
        case ASN1Tag.OCTET_STRING: return "OCTET STRING";
        case ASN1Tag.BIT_STRING: return "BIT STRING";
        case ASN1Tag.ENUMERATED: return "ENUMERATED";
        case ASN1Tag.INTEGER: return "INTEGER";
        case ASN1Tag.NULL_TAG: return "NULL";
        case ASN1Tag.OBJECT_ID: return "OBJECT";
        case ASN1Tag.BOOLEAN: return "BOOLEAN";
        case ASN1Tag.NO_OBJECT: return "NO_OBJECT";
        default: return "TAG(" ~ to!string(cast(uint)type) ~ ")";
    }
}

private string formatType(ASN1Tag type_tag, ASN1Tag class_tag)
{
    if (class_tag == ASN1Tag.UNIVERSAL)
        return asn1TagToString(type_tag);
    if (class_tag == ASN1Tag.CONSTRUCTED &&
        (type_tag == ASN1Tag.SEQUENCE || type_tag == ASN1Tag.SET))
        return asn1TagToString(type_tag);

    string s;
    if (class_tag & ASN1Tag.CONSTRUCTED)
        s ~= "cons ";
    s ~= "[" ~ to!string(cast(uint)type_tag) ~ "]";
    if (class_tag & ASN1Tag.APPLICATION)
        s ~= " appl";
    if (class_tag & ASN1Tag.CONTEXT_SPECIFIC)
        s ~= " context";
    return s;
}

// D 1.12 SCAN names → C++ 3 pretty-printer display names. Do not change OIDS.lookup.
private string prettyOidName(string name)
{
    if (!name.length)
        return name;
    if (name == "CertificateHolderAuthorizationTemplate" ||
        name == "CMS.SignedData" ||
        name == "CMS.EnvelopedData" ||
        name == "CMS.DigestedData" ||
        name == "CMS.EncryptedData")
        return "";
    if (name == "CMS.DataContent")
        return "PKCS7.Data";
    import std.array : replace;
    name = name.replace("EMSA3", "PKCS1v15");
    name = name.replace("SHA-160", "SHA-1");
    return name;
}

private string decodeStringValue(ASN1Tag type_tag, const(ubyte)[] raw)
{
    Vector!ubyte utf8;
    if (type_tag == ASN1Tag.UTF8_STRING)
        utf8 ~= raw;
    else if (type_tag == ASN1Tag.BMP_STRING)
        utf8 = ucs2ToUtf8(raw);
    else if (type_tag == ASN1Tag.UNIVERSAL_STRING)
        utf8 = ucs4ToUtf8(raw);
    else
        utf8 = latin1ToUtf8Bytes(raw);
    return (cast(char[])utf8[]).idup;
}

/**
* Format ASN.1 data into human-readable output. The exact form of the
* output for any particular input is not guaranteed and may change.
*/
final class ASN1PrettyPrinter
{
public:
    this(size_t print_limit = 4096,
         size_t print_binary_limit = 2048,
         bool print_context_specific = true,
         size_t initial_level = 0,
         size_t value_column = 60,
         size_t max_depth = 64,
         bool require_der = false)
    {
        m_print_limit = print_limit;
        m_print_binary_limit = print_binary_limit;
        m_print_context_specific = print_context_specific;
        m_initial_level = initial_level;
        m_value_column = value_column;
        m_max_depth = max_depth;
        m_require_der = require_der;
    }

    string print(const(ubyte)* input, size_t len) const
    {
        Appender!string output;
        printTo(output, input, len);
        return output.data;
    }

    string print(const(ubyte)[] input) const
    {
        return print(input.ptr, input.length);
    }

    string print(Alloc)(const auto ref Vector!(ubyte, Alloc) input) const
    {
        return print(input.ptr, input.length);
    }

private:
    void printTo(ref Appender!string output, const(ubyte)* input, size_t len) const
    {
        BERDecoder dec = BERDecoder(input, len);
        if (m_require_der)
            dec.setRequireDer(true);
        decode(output, dec, 0);
    }

    void decode(ref Appender!string output, ref BERDecoder decoder, size_t level) const
    {
        BERObject obj = decoder.getNextObject();
        const bool recurse_deeper = (m_max_depth == 0 || level < m_max_depth);

        while (obj.type_tag != ASN1Tag.NO_OBJECT)
        {
            const ASN1Tag type_tag = obj.type_tag;
            const ASN1Tag class_tag = obj.class_tag;
            const size_t length = obj.value.length;

            if (class_tag & ASN1Tag.CONSTRUCTED)
            {
                if (recurse_deeper)
                {
                    output ~= format(type_tag, class_tag, level, length, "");
                    BERDecoder cons = BERDecoder(obj.value);
                    if (m_require_der)
                        cons.setRequireDer(true);
                    decode(output, cons, level + 1);
                }
                else
                {
                    DEREncoder enc;
                    enc.addObject(type_tag, class_tag, obj.value.ptr, obj.value.length);
                    auto bits = enc.getContentsUnlocked();
                    output ~= format(type_tag, class_tag, level, length,
                                     formatBin(bits[]));
                }
                obj = decoder.getNextObject();
                continue;
            }

            DEREncoder enc;
            enc.addObject(type_tag, class_tag, obj.value.ptr, obj.value.length);
            Vector!ubyte bits = enc.getContentsUnlocked();
            BERDecoder data = BERDecoder(bits);
            if (m_require_der)
                data.setRequireDer(true);

            if ((class_tag & ASN1Tag.APPLICATION) || (class_tag & ASN1Tag.CONTEXT_SPECIFIC))
            {
                bool success_parsing_cs = false;
                if (m_print_context_specific)
                {
                    try
                    {
                        if (possiblyAGeneralName(bits[]))
                        {
                            output ~= format(type_tag, class_tag, level, length,
                                             cast(string)bits[2 .. $].idup);
                            success_parsing_cs = true;
                        }
                        else if (recurse_deeper)
                        {
                            Vector!ubyte inner_bits;
                            data.decode(inner_bits, type_tag);
                            BERDecoder inner = BERDecoder(inner_bits);
                            if (m_require_der)
                                inner.setRequireDer(true);
                            Appender!string inner_data;
                            decode(inner_data, inner, level + 1);
                            output ~= inner_data.data;
                            success_parsing_cs = true;
                        }
                    }
                    catch (Exception) {}
                }
                if (!success_parsing_cs)
                    output ~= format(type_tag, class_tag, level, length, formatBin(bits[]));
            }
            else if (type_tag == ASN1Tag.OBJECT_ID)
            {
                OID oid;
                data.decode(oid);
                const string oid_str = oid.toString();
                const string name = prettyOidName(OIDS.lookup(oid));
                if (name.length)
                    output ~= format(type_tag, class_tag, level, length, name ~ " [" ~ oid_str ~ "]");
                else
                    output ~= format(type_tag, class_tag, level, length, oid_str);
            }
            else if (type_tag == ASN1Tag.INTEGER || type_tag == ASN1Tag.ENUMERATED)
            {
                BigInt number;
                if (type_tag == ASN1Tag.INTEGER)
                    data.decode(number);
                else
                    data.decode(number, ASN1Tag.ENUMERATED, class_tag);
                output ~= format(type_tag, class_tag, level, length, formatBn(number));
            }
            else if (type_tag == ASN1Tag.BOOLEAN)
            {
                bool boolean = false;
                data.decode(boolean);
                output ~= format(type_tag, class_tag, level, length, boolean ? "true" : "false");
            }
            else if (type_tag == ASN1Tag.NULL_TAG)
            {
                output ~= format(type_tag, class_tag, level, length, "");
            }
            else if (type_tag == ASN1Tag.OCTET_STRING || type_tag == ASN1Tag.BIT_STRING)
            {
                Vector!ubyte decoded_bits;
                data.decode(decoded_bits, type_tag);
                bool printing_worked = false;
                if (recurse_deeper)
                {
                    try
                    {
                        BERDecoder inner = BERDecoder(decoded_bits);
                        if (m_require_der)
                            inner.setRequireDer(true);
                        Appender!string inner_data;
                        decode(inner_data, inner, level + 1);
                        output ~= format(type_tag, class_tag, level, length, "");
                        output ~= inner_data.data;
                        printing_worked = true;
                    }
                    catch (Exception) {}
                }
                if (!printing_worked)
                    output ~= format(type_tag, class_tag, level, length, formatBin(decoded_bits[]));
            }
            else if (isAsn1StringType(type_tag))
            {
                output ~= format(type_tag, class_tag, level, length,
                                 decodeStringValue(type_tag, obj.value[]));
            }
            else if (type_tag == ASN1Tag.UTC_TIME || type_tag == ASN1Tag.GENERALIZED_TIME)
            {
                static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO)
                {
                    X509Time time;
                    data.decode(time);
                    output ~= format(type_tag, class_tag, level, length, time.readableString());
                }
                else
                {
                    output ~= format(type_tag, class_tag, level, length,
                                     decodeStringValue(ASN1Tag.IA5_STRING, obj.value[]));
                }
            }
            else
            {
                output ~= "Unknown ASN.1 tag class=" ~ to!string(cast(int)class_tag) ~
                          " type=" ~ to!string(cast(int)type_tag) ~ "\n";
            }

            obj = decoder.getNextObject();
        }
    }

    string format(ASN1Tag type_tag, ASN1Tag class_tag, size_t level, size_t length, string value) const
    {
        bool should_skip = false;
        if (value.length > m_print_limit)
            should_skip = true;
        if ((type_tag == ASN1Tag.OCTET_STRING || type_tag == ASN1Tag.BIT_STRING) &&
            value.length > m_print_binary_limit)
            should_skip = true;

        level += m_initial_level;

        import std.string : rightJustify;
        const string head = "  d=" ~ rightJustify(to!string(level), 2) ~
                            ", l=" ~ rightJustify(to!string(length), 4) ~ ":" ~
                            replicate(" ", level + 1) ~ formatType(type_tag, class_tag);

        if (value.length && !should_skip)
        {
            const size_t spaces = (head.length >= m_value_column) ? 1 : (m_value_column - head.length);
            return head ~ replicate(" ", spaces) ~ escapeControlChars(value) ~ "\n";
        }
        return head ~ "\n";
    }

    string formatBin(const(ubyte)[] vec) const
    {
        if (vec.length > m_print_binary_limit)
            return "";
        if (allPrintableChars(vec))
            return cast(string)vec.idup;
        return hexEncode(vec.ptr, vec.length);
    }

    string formatBn(const ref BigInt bn) const
    {
        if (bn.bits() < 16)
        {
            auto dec = bn.toString(BigInt.Decimal);
            return dec.length ? dec : "0";
        }
        const size_t n = bn.bytes();
        Vector!ubyte bin;
        bin.length = n ? n : 1;
        if (n)
            bn.binaryEncode(bin.ptr);
        const string hex = hexEncode(bin);
        if (bn.isNegative())
            return "-0x" ~ hex;
        return "0x" ~ hex;
    }

    size_t m_print_limit;
    size_t m_print_binary_limit;
    bool m_print_context_specific;
    size_t m_initial_level;
    size_t m_value_column;
    size_t m_max_depth;
    bool m_require_der;
}

static if (BOTAN_HAS_TESTS && !SKIP_ASN1_TEST) unittest
{
    import botan.test;
    import botan.libstate.libstate;
    import std.file : read, exists;

    globalState();
    logDebug("Testing asn1_print.d ...");
    size_t fails = 0;

    Unique!ASN1PrettyPrinter printer = new ASN1PrettyPrinter;

    foreach (size_t i; 1 .. 9)
    {
        const string n = to!string(i);
        const string in_path = "test_data/asn1/asn1_print/input" ~ n ~ ".der";
        const string out_path = "test_data/asn1/asn1_print/output" ~ n ~ ".txt";
        if (!exists(in_path) || !exists(out_path))
        {
            logError("missing asn1_print KAT ", n);
            ++fails;
            continue;
        }
        auto input = cast(ubyte[])read(in_path);
        auto expected = cast(string)read(out_path);
        try
        {
            const string got = printer.print(input);
            if (got != expected)
            {
                logError("asn1_print ", n, " mismatch (got ", got.length,
                         " expected ", expected.length, ")");
                // first differing line
                import std.string : splitLines;
                auto gl = splitLines(got);
                auto el = splitLines(expected);
                const size_t lim = gl.length < el.length ? gl.length : el.length;
                foreach (size_t li; 0 .. lim)
                {
                    if (gl[li] != el[li])
                    {
                        logError("  line ", li + 1, " got='", gl[li], "'");
                        logError("         exp='", el[li], "'");
                        break;
                    }
                }
                if (gl.length != el.length)
                    logError("  line counts ", gl.length, " vs ", el.length);
                ++fails;
            }
        }
        catch (Exception e)
        {
            logError("asn1_print ", n, " exception: ", e.msg);
            ++fails;
        }
    }

    fails += checkMemutilsRepeat("asn1_print", {
        Unique!ASN1PrettyPrinter p = new ASN1PrettyPrinter;
        ubyte[5] seq = [0x30, 0x03, 0x02, 0x01, 0x05];
        cast(void)p.print(seq[]);
    });

    if (fails)
        logError("asn1_print failures: ", fails);
    assert(fails == 0);
}
