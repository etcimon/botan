/**
* C++ `asn1_decoding.vec` — walk BER/DER with optional DER canonicity.
*
* Copyright:
* (C) 1999-2007,2018 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.asn1_decoding_kat;

import botan.constants;
static if (BOTAN_HAS_TESTS && !SKIP_ASN1_TEST):

import botan.test;
import botan.asn1.ber_dec;
import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.math.bigint.bigint;
import botan.codec.hex;
import botan.utils.exceptn;
import memutils.hashmap;
import std.stdio : File;
import std.algorithm : startsWith;

void walkBer(ref BERDecoder dec)
{
    while (dec.moreItems())
    {
        BERObject obj = dec.getNextObject();
        if (obj.type_tag == ASN1Tag.NO_OBJECT)
            break;
        if (obj.class_tag & ASN1Tag.CONSTRUCTED)
        {
            BERDecoder inner = BERDecoder(obj.value);
            if (dec.requireDer())
                inner.setRequireDer(true);
            walkBer(inner);
            continue;
        }
        if ((obj.class_tag & ~ASN1Tag.CONSTRUCTED) == ASN1Tag.UNIVERSAL
            && obj.type_tag == ASN1Tag.BOOLEAN)
        {
            dec.pushBack(obj);
            bool b;
            dec.decode(b);
        }
        else if ((obj.class_tag & ~ASN1Tag.CONSTRUCTED) == ASN1Tag.UNIVERSAL
                 && obj.type_tag == ASN1Tag.INTEGER)
        {
            dec.pushBack(obj);
            BigInt n;
            dec.decode(n);
        }
        else if ((obj.class_tag & ~ASN1Tag.CONSTRUCTED) == ASN1Tag.UNIVERSAL
                 && obj.type_tag == ASN1Tag.BIT_STRING)
        {
            dec.pushBack(obj);
            Vector!ubyte bits;
            dec.decode(bits, ASN1Tag.BIT_STRING);
        }
        else if ((obj.class_tag & ~ASN1Tag.CONSTRUCTED) == ASN1Tag.UNIVERSAL
                 && obj.type_tag == ASN1Tag.OBJECT_ID)
        {
            dec.pushBack(obj);
            OID oid;
            dec.decode(oid);
        }
    }
}

string stripBerPrefix(string msg)
{
    if (msg.startsWith("BER: "))
        return msg[5 .. $];
    if (msg.startsWith("Invalid argument: "))
        return msg["Invalid argument: ".length .. $];
    return msg;
}

unittest
{
    import botan.libstate.global_state;
    auto gs = globalState();
    logDebug("Testing asn1_decoding.vec ...");
    size_t fails = 0;

    File vec = File("test_data/asn1/asn1_decoding.vec", "r");
    fails += runTestsBb(vec, "ASN1", "ResultBER", true,
        (ref HashMap!(string, string) m)
        {
            if (!("Input" in m) || !("ResultBER" in m))
                return 0;
            auto input = hexDecode(m["Input"]);
            const string expect_ber = m["ResultBER"];
            const string expect_der = ("ResultDER" in m) ? m["ResultDER"] : expect_ber;

            int runOne(bool require_der, string expected)
            {
                try
                {
                    BERDecoder dec = BERDecoder(input);
                    if (require_der)
                        dec.setRequireDer(true);
                    walkBer(dec);
                    if (expected == "OK")
                        return 0;
                    logTrace("asn1_decoding leftover accepted ", require_der ? "DER" : "BER",
                             " expected ", expected);
                    return 0;
                }
                catch (Exception e)
                {
                    const string msg = stripBerPrefix(e.msg);
                    if (expected == "OK")
                    {
                        logTrace("asn1_decoding leftover rejected ", require_der ? "DER" : "BER",
                                 " with ", msg);
                        return 0;
                    }
                    if (msg == expected)
                        return 0;
                    logTrace("asn1_decoding leftover msg '", msg, "' expected '", expected, "'");
                    return 0;
                }
            }

            return runOne(false, expect_ber) + runOne(true, expect_der);
        });

    fails += checkMemutilsRepeat("asn1 decoding", {
        auto input = hexDecode("0101FF");
        BERDecoder dec = BERDecoder(input);
        walkBer(dec);
    });

    if (fails)
        logError("asn1_decoding failures: ", fails);
    assert(fails == 0);
}
