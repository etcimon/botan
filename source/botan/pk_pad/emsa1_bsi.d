/**
* EMSA1 BSI Variant
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*      2007 FlexSecure GmbH
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.emsa1_bsi;

import botan.constants;
static if (BOTAN_HAS_EMSA1_BSI):
import botan.pk_pad.emsa1;
import botan.hash.hash;
import botan.utils.types;

/**
* EMSA1_BSI is a variant of EMSA1 specified by the BSI. It accepts
* only hash values which are less or equal than the maximum key
* length. The implementation comes from InSiTo
*/
final class EMSA1BSI : EMSA1, EMSA
{
public:
    /**
    * Params:
    *  hash = the hash object to use
    */
    this(HashFunction hash)
    {
        super(hash);
    }

    /*
    * EMSA1 BSI Encode Operation
    */
    override SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                            size_t output_bits,
                                               RandomNumberGenerator rng)
    {
        //logDebug("EMSA1BSI Encode");
        if (msg.length != hashOutputLength())
            throw new EncodingError("EMSA1_BSI::encodingOf: Invalid size for input");
        
        if (8*msg.length <= output_bits)
            return msg.dup;
        
        throw new EncodingError("EMSA1_BSI::encodingOf: max key input size exceeded");
    }

    // Interface fallthrough
    override SecureVector!ubyte rawData() { return super.rawData(); }
    override bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw, size_t key_bits)
    {
        return super.verify(coded, raw, key_bits);
    }
    override void update(const(ubyte)* input, size_t length)
    {
        super.update(input, length);
    }
}

