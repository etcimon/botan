/**
* EAC11 general CVC
* 
* Copyright:
* (C) 2008 Falko Strenzke
*     2008-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.cvc_gen_cert;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.asn1.ber_dec;
import botan.cert.cvc.eac_obj;
import botan.cert.cvc.eac_asn_obj;
import botan.cert.cvc.signed_obj;
import botan.filters.pipe;
import botan.pubkey.x509_key;
import botan.filters.data_src;
import botan.pubkey.algo.ecdsa;
import botan.pubkey.pubkey;
import botan.cert.cvc.ecdsa_sig;
import botan.utils.types;

/**
*  This class represents TR03110 (EAC) v1.1 generalized CV Certificates
*/
abstract class EAC11genCVC(Derived) : EAC11obj!Derived, SignedObject // CRTP continuation from EAC11obj
{
public:
    override const(Vector!ubyte) getConcatSig() const { return super.getConcatSig(); }
    /**
    * Get this certificates public key.
    * Returns: this certificates public key
    */
    final const(PublicKey) subjectPublicKey() const
    {
        return m_pk;
    }

    /**
    * Find out whether this object is self signed.
    * Returns: true if this object is self signed
    */
    final bool isSelfSigned() const
    {
        return m_self_signed;
    }


    /**
    * Get the CHR of the certificate.
    * Returns: the CHR of the certificate
    */
    final const(ASN1Chr) getChr() const {
        return m_chr;
    }

    /**
    * Put the DER encoded version of this object into a pipe. PEM
    * is not supported.
    *
    * Params:
    *  output = the pipe to push the DER encoded version into
    *  encoding = the encoding to use. Must be DER.
    */
    override void encode(Pipe output, X509Encoding encoding) const
    {
        const(Vector!ubyte) concat_sig = EAC11obj!Derived.m_sig.getConcatenation();
        auto tbsdata = tbsData();
        Vector!ubyte der = DEREncoder()
                            .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                            .startCons((cast(ASN1Tag)78), ASN1Tag.APPLICATION)
                            .rawBytes(tbsdata)
                            .endCons()
                            .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                            .endCons()
                            .getContentsUnlocked();
        
        if (encoding == PEM_)
            throw new InvalidArgument("EAC11genCVC::encode() cannot PEM encode an EAC object");
        else
            output.write(der);
    }

    /**
    * Get the to-be-signed (TBS) data of this object.
    * Returns: the TBS data of this object
    */
    override const(Vector!ubyte) tbsData() const
    {
        return buildCertBody(m_tbs_bits);
    }


    /**
    * Build the DER encoded certifcate body of an object
    * Params:
    *  tbs = the data to be signed
    * Returns: the correctly encoded body of the object
    */
    static Vector!ubyte buildCertBody(ALLOC)(auto const ref Vector!(ubyte, ALLOC) tbs)
    {
        return DEREncoder()
                .startCons((cast(ASN1Tag)78), ASN1Tag.APPLICATION)
                .rawBytes(tbs)
                .endCons().getContentsUnlocked();
    }

    /**
    * Create a signed generalized CVC object.
    *
    * Params:
    *  signer = the signer used to sign this object
    *  tbs_bits = the body the generalized CVC object to be signed
    *  rng = a random number generator
    * Returns: the DER encoded signed generalized CVC object
    */
    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                          auto const ref Vector!(ubyte, ALLOC) tbs_bits,
                                          RandomNumberGenerator rng)
    {
        const auto concat_sig = signer.signMessage(tbs_bits, rng);
        return DEREncoder()
                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                .rawBytes(tbs_bits)
                .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons()
                .getContentsUnlocked();
    }

    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                          auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) tbs_bits,
                                          RandomNumberGenerator rng)
    {
        return makeSigned(signer, *tbs_bits, rng);
    }

protected:
    ECDSAPublicKey m_pk;
    ASN1Chr m_chr;
    bool m_self_signed;
    abstract void forceDecode();
package:
    static void decodeInfo(ALLOC)(DataSource source,
                                      ref Vector!(ubyte, ALLOC) res_tbs_bits,
                                      ECDSASignature res_sig)
    {
        Vector!ubyte concat_sig;
        BERDecoder(source)
                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                .startCons((cast(ASN1Tag)78), ASN1Tag.APPLICATION)
                .rawBytes(res_tbs_bits)
                .endCons()
                .decode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons();
        res_sig = decodeConcatenation(concat_sig);
    }

    static void decodeInfo(ALLOC)(DataSource source,
                                  ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) res_tbs_bits,
                                  ECDSASignature res_sig)
    {
        return decodeInfo(source, *res_tbs_bits, res_sig);
    }
}