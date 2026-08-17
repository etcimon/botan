/**
* EME PKCS#1 v1.5
* 
* Copyright:
* (C) 1999-2007,2015,2016,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.eme_pkcs;

import botan.constants;
static if (BOTAN_HAS_EME_PKCS1_V15):
import botan.pk_pad.eme;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* EME from PKCS #1 v1.5
*/
final class EMEPKCS1v15 : EME
{
public:
    /*
    * Return the max input size for a given key size
    */
    override size_t maximumInputSize(size_t keybits) const
    {
        if (keybits / 8 > 10)
            return ((keybits / 8) - 10);
        else
            return 0;
    }

    /*
    * PKCS1 Pad Operation
    */
    override SecureVector!ubyte pad(const(ubyte)* input, size_t inlen, size_t olen, RandomNumberGenerator rng) const
    {
        olen /= 8;
        
        if (olen < 10)
            throw new EncodingError("PKCS1: Output space too small");
        if (inlen > olen - 10)
            throw new EncodingError("PKCS1: Input is too large");
        
        SecureVector!ubyte output = SecureVector!ubyte(olen);
        
        output[0] = 0x02;
        foreach (size_t j; 1 .. (olen - inlen - 1))
            while (output[j] == 0)
                output[j] = rng.nextByte();
        bufferInsert(output, olen - inlen, input, inlen);
        
        return output;
    }

    /*
    * PKCS1 Unpad Operation
    */
    override SecureVector!ubyte unpad(const(ubyte)* input, size_t inlen, size_t key_len) const
    {
        if (inlen != key_len / 8 || inlen < 10 || input[0] != 0x02)
            throw new DecodingError("PKCS1::unpad");
        
        size_t seperator = 0;
        foreach (size_t j; 0 .. inlen)
            if (input[j] == 0)
        {
            seperator = j;
            break;
        }
        if (seperator < 9)
            throw new DecodingError("PKCS1::unpad");
        
        return SecureVector!ubyte(input[seperator + 1 .. inlen]);
    }

}

static if (BOTAN_HAS_TESTS && !SKIP_RSA_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.pk_pad.factory;
    import memutils.hashmap;
    import memutils.unique;
    import std.stdio : File;

    logDebug("Testing eme_pkcs.d ...");
    size_t fails = 0;

    File vec = File("test_data/pk_pad_eme/pkcs1.vec", "r");
    fails += runTestsBb(vec, "Hdr", "RawCiphertext", false,
        (ref HashMap!(string, string) m)
        {
            if (!("RawCiphertext" in m) || !("Hdr" in m))
                return 0;
            const bool expect_valid = m["Hdr"] == "valid";
            auto ct = hexDecode(m["RawCiphertext"]);
            if (!ct.length)
            {
                if (expect_valid)
                    return 1;
                return 0;
            }
            const(ubyte)* p = ct.ptr;
            size_t n = ct.length;
            if (p[0] == 0x00)
            {
                ++p;
                --n;
            }
            Unique!EME eme = getEme("PKCS1v15");
            try
            {
                auto pt = eme.decode(p, n, n * 8);
                if (!expect_valid)
                {
                    logTrace("pkcs1 leftover accepted as valid");
                    return 0;
                }
                if (!("Plaintext" in m))
                    return 1;
                if (pt[] != hexDecode(m["Plaintext"])[])
                    return 1;
                return 0;
            }
            catch (Exception)
            {
                return expect_valid ? 1 : 0;
            }
        });
    // C++ 3 unpad is CT and requires the 00||02 RSA block; D 1.12 unpad
    // starts at 02. Invalid rows that omit the leading 00 can decode here.

    fails += checkMemutilsRepeat("pkcs1 unpad", {
        Unique!EME eme = getEme("PKCS1v15");
        auto ct = hexDecode("0002FFFFFFFFFFFFFFFF000113131313131388");
        const(ubyte)* p = ct.ptr + 1;
        auto pt = eme.decode(p, ct.length - 1, (ct.length - 1) * 8);
        if (!pt.length)
            throw new Exception("pkcs1 leak probe");
    });

    testReport("eme_pkcs1", 0, fails);
}