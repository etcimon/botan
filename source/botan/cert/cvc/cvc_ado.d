/**
* EAC11 CVC ADO
* 
* Copyright:
* (C) 2008 Falko Strenzke
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.cvc_ado;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.cert.cvc.eac_obj;
import botan.cert.cvc.signed_obj;
import botan.cert.cvc.eac_asn_obj;
import botan.cert.cvc.cvc_req;
import botan.cert.cvc.ecdsa_sig;
import botan.rng.rng;
import botan.pubkey.pubkey;
import botan.filters.data_src;
import botan.filters.pipe;
import botan.pubkey.x509_key;
import botan.asn1.asn1_obj;
import botan.utils.types;
import std.typecons : scoped;

alias EAC11ADO = RefCounted!EAC11ADOImpl;
/**
* This class represents a TR03110 (EAC) v1.1 CVC ADO request
*/

 // CRTP continuation from EAC11obj
final class EAC11ADOImpl : EAC11obj!EAC11ADOImpl, SignedObject
{
public:
    override const(Vector!ubyte) getConcatSig() const { return super.getConcatSig(); }
    /**
    * Construct a CVC ADO request from a DER encoded CVC ADO request file.
    *
    * Params:
    *  str = the path to the DER encoded file
    */
    this(in string input)
    {
        auto stream = DataSourceStream(input, true);
        init(cast(DataSource)stream);
        doDecode();
    }

    /**
    * Construct a CVC ADO request from a data source
    * Params:
    *  source = the data source
    */
    this(DataSource input)
    {
        init(input);
        doDecode();
    }

    /**
    * Create a signed CVC ADO request from to be signed (TBS) data
    * Params:
    *  signer = the signer used to sign the CVC ADO request
    *  tbs_bits = the TBS data to sign
    *  rng = a random number generator
    */
    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                                auto const ref Vector!(ubyte, ALLOC) tbs_bits,
                                                RandomNumberGenerator rng)
    {
        const Vector!ubyte concat_sig = signer.signMessage(tbs_bits, rng);
        
        return DEREncoder()
                .startCons((cast(ASN1Tag)7), ASN1Tag.APPLICATION)
                .rawBytes(tbs_bits)
                .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons()
                .getContentsUnlocked();
    }

    static Vector!ubyte makeSigned(ALLOC)(ref PKSigner signer,
                                          auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) tbs_bits,
                                          RandomNumberGenerator rng)
    {
        return makeSigned(signer, **tbs_bits, rng);
    }

    /**
    * Get the CAR of this CVC ADO request
    * Returns: the CAR of this CVC ADO request
    */
    const(ASN1Car) getCar() const
    {
        return m_car;
    }

    /**
    * Get the CVC request contained in this object.
    * Returns: the CVC request inside this CVC ADO request
    */    
    const(EAC11Req) getRequest() const
    {
        return m_req;
    }

    /**
    * Encode this object into a pipe. Only DER is supported.
    *
    * Params:
    *  output = the pipe to encode this object into
    *  encoding = the encoding type to use, must be DER
    */
    override void encode(Pipe output, X509Encoding encoding) const
    {
        if (encoding == PEM_)
            throw new InvalidArgument("encode() cannot PEM encode an EAC object");
        
        auto concat_sig = m_sig.getConcatenation();
        
        output.write(DEREncoder()
                     .startCons((cast(ASN1Tag)7), ASN1Tag.APPLICATION)
                     .rawBytes(m_tbs_bits)
                     .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                     .endCons()
                     .getContents());
    }

    bool opEquals(in EAC11ADO rhs) const
    {
        return (getConcatSig() == rhs.getConcatSig()
                && tbsData() == rhs.tbsData()
                && getCar() ==  rhs.getCar());
    }

    /**
    * Get the TBS data of this CVC ADO request.
    * Returns: the TBS data
    */
    override const(Vector!ubyte) tbsData() const
    {
        return m_tbs_bits.dup;
    }


    int opCmp(in EAC11ADOImpl rhs) const
    {
        if (this == rhs)
            return 0;
        else return -1; // no comparison support
    }

    /**
    * Construct a CVC ADO request from a copy of another ADO object
    * Params:
    *  other = the other object
    */
    this(ref EAC11ADO other)
    {
        m_sig = other.m_sig.dup;
        m_sig_algo = AlgorithmIdentifier(other.m_sig_algo);
        m_tbs_bits = other.m_tbs_bits.dup;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed;

        m_car = ASN1Car(other.m_car);
        m_req = EAC11Req(other.m_req);
    }

    /**
    * Replace this ADO request with references to another one
    * Params:
    *  other = the other object
    */
    void opAssign(ref EAC11ADO other)
    {
        m_sig = other.m_sig;
        m_sig_algo = other.m_sig_algo;
        m_tbs_bits = other.m_tbs_bits.dup;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed;

        m_car = other.m_car;
        m_req = other.m_req;
    }

protected:
    ASN1Car m_car;
    EAC11Req m_req;

    override void forceDecode()
    {
        Vector!ubyte inner_cert;
        BERDecoder(m_tbs_bits)
                    .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                    .rawBytes(inner_cert)
                    .endCons()
                    .decode(m_car)
                    .verifyEnd();
        
        Vector!ubyte req_bits = DEREncoder()
                                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                                .rawBytes(inner_cert)
                                .endCons()
                                .getContentsUnlocked();
        
        auto req_source = DataSourceMemory(&req_bits);
        m_req = EAC11Req(cast(DataSource)req_source);
        m_sig_algo = cast(AlgorithmIdentifier) m_req.signatureAlgorithm();
    }


package:
    static void decodeInfo(ALLOC)(DataSource source,
                                  auto ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) res_tbs_bits,
                                  ref ECDSASignature res_sig)
    {
        return decodeInfo(source, **res_tbs_bits, res_sig);
    }

    static void decodeInfo(ALLOC)(DataSource source,
                                     auto ref Vector!(ubyte, ALLOC) res_tbs_bits,
                                     ref ECDSASignature res_sig)
    {
        Vector!ubyte concat_sig;
        Vector!ubyte cert_inner_bits;
        ASN1Car car;
        
        BERDecoder(source)
            .startCons((cast(ASN1Tag)7), ASN1Tag.APPLICATION)
                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                .rawBytes(cert_inner_bits)
                .endCons()
                .decode(car)
                .decode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons();
        
        Vector!ubyte enc_cert = DEREncoder()
                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                .rawBytes(cert_inner_bits)
                .endCons()
                .getContentsUnlocked();
        
        res_tbs_bits = enc_cert.move();
        res_tbs_bits ~= DEREncoder().encode(car).getContentsUnlocked();
        res_sig = decodeConcatenation(concat_sig);
    }
}
