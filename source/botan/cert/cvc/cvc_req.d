/**
* EAC11 CVC Request
* 
* Copyright:
* (C) 2008 Falko Strenzke
*     2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.cvc_req;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.cert.cvc.cvc_gen_cert;
import botan.asn1.oids;
import botan.asn1.ber_dec;
import botan.utils.types;
import botan.cert.cvc.cvc_cert;
import botan.cert.cvc.ecdsa_sig;
import botan.cert.cvc.signed_obj;
import botan.filters.pipe;
import botan.pubkey.x509_key;
import botan.pubkey.algo.ecdsa;

alias EAC11Req = RefCounted!EAC11ReqImpl;
/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
final class EAC11ReqImpl : EAC11genCVC!EAC11ReqImpl, SignedObject
{
public:

    /**
    * Compare for equality with other
    * Params:
    *  other = compare for equality with this object
    */
    bool opEquals(in EAC11Req rhs) const
    {
        return (this.tbsData() == rhs.tbsData() &&
                this.getConcatSig() == rhs.getConcatSig());
    }

    int opCmp(in EAC11ReqImpl rhs) const
    {
        if (this == rhs)
            return 0;
        else return -1;

    }
    /**
    * Construct a CVC request from a data source.
    *
    * Params:
    *  source = the data source
    */
    this(DataSource source)
    {
        init(source);
        m_self_signed = true;
        doDecode();
    }

    /**
    * Construct a CVC request from a DER encoded CVC request file.
    *
    * Params:
    *  str = the path to the DER encoded file
    */
    this(in string str)
    {
        auto stream = DataSourceStream(str, true);
        init(cast(DataSource)stream);
        m_self_signed = true;
        doDecode();
    }

    // copy
    this(const ref EAC11Req other)
    {
        m_sig = other.m_sig.dup;
        m_sig_algo = AlgorithmIdentifier(other.m_sig_algo);
        m_tbs_bits = other.m_tbs_bits.dup;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed.dup;
    
        m_pk = cast(ECDSAPublicKey)other.m_pk; // no copy of this...
        m_chr = ASN1Chr(other.m_chr);
        m_self_signed = other.m_self_signed;
    }

    // assign
    void opAssign(ref EAC11Req other) {
        m_sig = other.m_sig;
        m_sig_algo = other.m_sig_algo;
        m_tbs_bits = other.m_tbs_bits.dup; // move?
        m_PEM_labels_allowed = other.m_PEM_labels_allowed;
        m_pk = other.m_pk;
        m_chr = other.m_chr;
        m_self_signed = other.m_self_signed;
    }

    // Interface fall-through
    override const(Vector!ubyte) getConcatSig() const { return super.getConcatSig(); }
    override void encode(Pipe pipe, X509Encoding encoding = PEM_) const { return super.encode(pipe, encoding); }
    override const(Vector!ubyte) tbsData() const { return super.tbsData(); }

protected:
    override void forceDecode()
    {
        Vector!ubyte enc_pk;
        BERDecoder tbs_cert = BERDecoder(m_tbs_bits);
        size_t cpi;
        tbs_cert.decode(cpi, (cast(ASN1Tag)41), ASN1Tag.APPLICATION)
                .startCons((cast(ASN1Tag)73), ASN1Tag.APPLICATION)
                .rawBytes(enc_pk)
                .endCons()
                .decode(m_chr)
                .verifyEnd();
        
        if (cpi != 0)
            throw new DecodingError("EAC1_1 requests cpi was not 0");
        
        m_pk = decodeEac11Key(enc_pk, m_sig_algo);
    }
}