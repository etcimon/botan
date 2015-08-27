/**
* OCSP subtypes
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.ocsp_types;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509cert;
import botan.asn1.asn1_time;
import botan.math.bigint.bigint;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.cert.x509.x509_ext;
import botan.libstate.lookup;
import botan.hash.hash;
import botan.asn1.oids;
import botan.utils.types;
import botan.utils.mem_ops;

alias CertID = RefCounted!CertIDImpl;

final class CertIDImpl : ASN1Object
{
public:
    this() {}

    this(in X509Certificate issuer,
         in X509Certificate subject)
    {
        /*
        In practice it seems some responders, including, notably,
        ocsp.verisign.com, will reject anything but SHA-1 here
        */
        Unique!HashFunction hash = retrieveHash("SHA-160").clone();
        
        m_hash_id = AlgorithmIdentifier(hash.name, AlgorithmIdentifierImpl.USE_NULL_PARAM);
        m_issuer_key_hash = unlock(hash.process(extractKeyBitstr(issuer)));
        m_issuer_dn_hash = unlock(hash.process(subject.rawIssuerDn()));
        m_subject_serial = BigInt.decode(subject.serialNumber());
    }

    bool isIdFor(in X509Certificate issuer,
                   const X509Certificate subject) const
    {
        try
        {
            if (BigInt.decode(subject.serialNumber()) != m_subject_serial)
                return false;
            
            Unique!HashFunction hash = retrieveHash(OIDS.lookup(m_hash_id.oid)).clone();
            
            if (m_issuer_dn_hash != unlock(hash.process(subject.rawIssuerDn())))
                return false;
            
            if (m_issuer_key_hash != unlock(hash.process(extractKeyBitstr(issuer))))
                return false;
        }
        catch (Throwable)
        {
            return false;
        }
        
        return true;
    }

    override void encodeInto(ref DEREncoder to) const
    {
        to.startCons(ASN1Tag.SEQUENCE)
                .encode(m_hash_id)
                .encode(m_issuer_dn_hash, ASN1Tag.OCTET_STRING)
                .encode(m_issuer_key_hash, ASN1Tag.OCTET_STRING)
                .encode(m_subject_serial)
                .endCons();
    }


    override void decodeFrom(ref BERDecoder from)
    {
        from.startCons(ASN1Tag.SEQUENCE)
                .decode(m_hash_id)
                .decode(m_issuer_dn_hash, ASN1Tag.OCTET_STRING)
                .decode(m_issuer_key_hash, ASN1Tag.OCTET_STRING)
                .decode(m_subject_serial)
                .endCons();
        
    }

package:
    Vector!ubyte extractKeyBitstr(in X509Certificate cert) const
    {
        const auto key_bits = cert.subjectPublicKeyBits();
        
        auto public_key_algid = AlgorithmIdentifier();
        Vector!ubyte public_key_bitstr;
        
        BERDecoder(key_bits)
                .decode(public_key_algid)
                .decode(public_key_bitstr, ASN1Tag.BIT_STRING);
        
        return public_key_bitstr;
    }

    AlgorithmIdentifier m_hash_id;
    Vector!ubyte m_issuer_dn_hash;
    Vector!ubyte m_issuer_key_hash;
    BigInt m_subject_serial;
}

alias SingleResponse = RefCounted!SingleResponseImpl;

final class SingleResponseImpl : ASN1Object
{
public:
    const(CertID) certid() const { return m_certid; }

    size_t certStatus() const { return m_cert_status; }

    const(X509Time) thisUpdate() const { return m_thisupdate; }

    const(X509Time) nextUpdate() const { return m_nextupdate; }

    override void encodeInto(ref DEREncoder) const
    {
        throw new Exception("Not implemented (SingleResponse::encodeInto)");
    }

    override void decodeFrom(ref BERDecoder from)
    {
        BERObject cert_status;
        X509Extensions extensions;
        
        from.startCons(ASN1Tag.SEQUENCE)
                .decode(m_certid)
                .getNext(cert_status)
                .decode(m_thisupdate)
                .decodeOptional(*m_nextupdate, (cast(ASN1Tag) 0),
                                 ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED)
                .decodeOptional(extensions, (cast(ASN1Tag)1),
                                 ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED)
                .endCons();
        
        m_cert_status = cert_status.type_tag;
    }

private:
    CertID m_certid;
    size_t m_cert_status = 2; // unknown
    X509Time m_thisupdate;
    X509Time m_nextupdate;
}