/**
* EMSA-Raw
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.emsa_raw;

import botan.constants;
static if (BOTAN_HAS_EMSA_RAW):
import botan.pk_pad.emsa;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
final class EMSARaw : EMSA
{
public:
    /*
    * EMSA-Raw Encode Operation
    */
    override void update(const(ubyte)* input, size_t length)
    {
        m_message ~= input[0 .. length];
    }

    /*
    * Return the raw (unencoded) data
    */
    override SecureVector!ubyte rawData()
    {
        SecureVector!ubyte output;
        std.algorithm.swap(m_message, output);
        return output.move;
    }

    /*
    * EMSA-Raw Encode Operation
    */
    SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                  size_t,
                                  RandomNumberGenerator)
    {
        return msg.dup;
    }

    /*
    * EMSA-Raw Verify Operation
    */
    bool verify(const ref SecureVector!ubyte coded,
                const ref SecureVector!ubyte raw,
                size_t)
    {
        if (coded.length == raw.length)
            return (coded == raw);
        
        if (coded.length > raw.length)
            return false;
        
        // handle zero padding differences
        const size_t leading_zeros_expected = raw.length - coded.length;
        
        bool same_modulo_leading_zeros = true;
        
        foreach (size_t i; 0 .. leading_zeros_expected)
            if (raw[i])
                same_modulo_leading_zeros = false;
        
        if (!sameMem(coded.ptr, &raw[leading_zeros_expected], coded.length))
            same_modulo_leading_zeros = false;
        
        return same_modulo_leading_zeros;
    }

    SecureVector!ubyte m_message;
}