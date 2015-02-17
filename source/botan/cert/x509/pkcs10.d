/**
* PKCS #10
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.pkcs10;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.cert.x509.x509_obj;
import botan.asn1.x509_dn;
import botan.pubkey.pkcs8;
import botan.utils.datastor.datastor;
import botan.cert.x509.key_constraint;
import botan.asn1.asn1_attribute;
import botan.asn1.asn1_alt_name;
import botan.cert.x509.pkcs10;
import botan.cert.x509.x509_ext;
import botan.cert.x509.x509cert;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.asn1.oids;
import botan.codec.pem;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;

alias PKCS10Request = RefCounted!PKCS10RequestImpl;

/**
* PKCS #10 Certificate Request.
*/
final class PKCS10RequestImpl : X509Object
{
public:
    /**
    * Get the subject public key.
    * Returns: subject public key
    */
    PublicKey subjectPublicKey() const
    {
        auto source = DataSourceMemory(m_info.get1("X509.Certificate.public_key"));
        return x509_key.loadKey(cast(DataSource)source);
    }


    /**
    * Get the raw DER encoded public key.
    * Returns: the public key of the requestor
    */
    Vector!ubyte rawPublicKey() const
    {
        auto source = DataSourceMemory(m_info.get1("X509.Certificate.public_key"));
        return unlock(PEM.decodeCheckLabel(cast(DataSource)source, "PUBLIC KEY"));
    }

    /**
    * Get the subject DN.
    * Returns: the name of the requestor
    */
    X509DN subjectDn() const
    {
        return createDn(m_info);
    }

    /**
    * Get the subject alternative name.
    * Returns: the alternative names of the requestor
    */
    AlternativeName subjectAltName() const
    {
        return createAltName(m_info);
    }

    /**
    * Get the key constraints for the key associated with this
    * PKCS#10 object.
    * Returns: the key constraints (if any)
    */
    KeyConstraints constraints() const
    {
        return cast(KeyConstraints)m_info.get1Uint("X509v3.KeyUsage", KeyConstraints.NO_CONSTRAINTS);
    }

    /**
    * Get the extendend key constraints (if any).
    * Returns: the extendend key constraints (if any)
    */
    Vector!OID exConstraints() const
    {
        Vector!string oids = m_info.get("X509v3.ExtendedKeyUsage");
        
        Vector!OID result;
        foreach (oid; oids[])
            result.pushBack(OID(oid));
        return result;
    }

    /**
    * Find out whether this is a CA request.
    * Returns: true if it is a CA request, false otherwise.
    */
    bool isCA() const
    {
        return (m_info.get1Uint("X509v3.BasicConstraints.is_ca") > 0);
    }


    /**
    * Return the constraint on the path length defined
    * in the BasicConstraints extension.
    * Returns: the desired path limit (if any)
    */
    uint pathLimit() const
    {
        return m_info.get1Uint("X509v3.BasicConstraints.path_constraint", 0);
    }

    /**
    * Get the challenge password for this request
    * Returns: challenge password for this request
    */
    string challengePassword() const
    {
        return m_info.get1("PKCS9.ChallengePassword");
    }

    /**
    * Create a PKCS#10 Request from a data source.
    *
    * Params:
    *  source = the data source providing the DER encoded request
    */
    this(DataSource source)
    {
        super(source, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
        doDecode();
    }

    /**
    * Create a PKCS#10 Request from a file.
    *
    * Params:
    *  filename = the name of the file containing the DER or PEM
    * encoded request file
    */
    this(in string input)
    {
        super(input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
        doDecode();
    }

    /**
    * Create a PKCS#10 Request from binary data.
    *
    * Params:
    *  vec = a std::vector containing the DER value
    */
    this(ALLOC)(in Vector!(ubyte, ALLOC)* input)
    {
        super(*input, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST");
        doDecode();
    }
protected:
    /*
    * Deocde the CertificateRequestInfo
    */
    override void forceDecode()
    {
        //logTrace("ForceDecode PKCS10Request");
        BERDecoder cert_req_info = BERDecoder(m_tbs_bits);
        
        size_t _version;
        cert_req_info.decode(_version);
        if (_version != 0)
            throw new DecodingError("Unknown version code in PKCS #10 request: " ~ to!string(_version));
        
        X509DN dn_subject = X509DN();
        cert_req_info.decode(dn_subject);
        
        m_info.add(dn_subject.contents());
        
        BERObject public_key = cert_req_info.getNextObject();
        if (public_key.type_tag != ASN1Tag.SEQUENCE || public_key.class_tag != ASN1Tag.CONSTRUCTED)
            throw new BERBadTag("PKCS10Request: Unexpected tag for public key",
                                  public_key.type_tag, public_key.class_tag);
        
        m_info.add("X509.Certificate.public_key", 
                   PEM.encode(putInSequence(unlock(public_key.value)), "PUBLIC KEY"));
        
        BERObject attr_bits = cert_req_info.getNextObject();
        
        if (attr_bits.type_tag == 0 &&
            attr_bits.class_tag == (ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
        {
            auto attributes = BERDecoder(attr_bits.value);
            while (attributes.moreItems())
            {
                auto attr = Attribute();
                attributes.decode(attr);
                handleAttribute(attr);
            }
            attributes.verifyEnd();
        }
        else if (attr_bits.type_tag != ASN1Tag.NO_OBJECT)
            throw new BERBadTag("PKCS10Request: Unexpected tag for attributes",
                                  attr_bits.type_tag, attr_bits.class_tag);
        
        cert_req_info.verifyEnd();
        
        if (!this.checkSignature(subjectPublicKey()))
            throw new DecodingError("PKCS #10 request: Bad signature detected");
    }

    /*
    * Handle attributes in a PKCS #10 request
    */
    void handleAttribute(in Attribute attr)
    {
        auto value = BERDecoder(attr.parameters);
        
        if (attr.oid == OIDS.lookup("PKCS9.EmailAddress"))
        {
            ASN1String email;
            value.decode(email);
            m_info.add("RFC822", email.value());
        }
        else if (attr.oid == OIDS.lookup("PKCS9.ChallengePassword"))
        {
            ASN1String challenge_password;
            value.decode(challenge_password);
            m_info.add("PKCS9.ChallengePassword", challenge_password.value());
        }
        else if (attr.oid == OIDS.lookup("PKCS9.ExtensionRequest"))
        {
            X509Extensions extensions;
            value.decode(extensions).verifyEnd();
            
            DataStore issuer_info;
            extensions.contentsTo(m_info, issuer_info);
        }
    }


    DataStore m_info;
}
