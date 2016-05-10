/**
* EAC11 objects
* 
* Copyright:
* (C) 2008 Falko Strenzke
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.eac_obj;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.cert.cvc.signed_obj;
import botan.cert.cvc.ecdsa_sig;
import botan.filters.data_src;
import botan.pubkey.pubkey;
import botan.utils.types;
import botan.utils.exceptn;


/**
* TR03110 v1.1 EAC CV Certificate
*/
// CRTP is used enable the call sequence:
abstract class EAC11obj(Derived) : EACSignedObject, SignedObject
{
public:
    /**
    * Return the signature as a concatenation of the encoded parts.
    * Returns: the concatenated signature
    */
    override const(Vector!ubyte) getConcatSig() const { return m_sig.getConcatenation(); }

    bool checkSignature(PublicKey key) const
    {
        return super.checkSignature(key, m_sig.DER_encode());
    }

    ECDSASignature m_sig;

protected:

    void init(DataSource input)
    {
        try
        {
            Derived.decodeInfo(input, m_tbs_bits, m_sig);
        }
        catch(DecodingError e)
        {
            throw new DecodingError("EAC11obj decoding failed (" ~ e.msg ~ ")");
        }
    }
}