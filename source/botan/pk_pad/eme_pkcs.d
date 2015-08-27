/**
* EME PKCS#1 v1.5
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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