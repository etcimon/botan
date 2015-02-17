/**
* X.509 Certificates
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.x509cert;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

public import botan.utils.datastor.datastor;
public import botan.pubkey.x509_key;
public import botan.cert.x509.x509_obj;
public import botan.asn1.x509_dn;
public import botan.cert.x509.certstor;
import botan.cert.x509.key_constraint : KeyConstraints;
import botan.cert.x509.x509_ext;
import botan.codec.pem;
import botan.codec.hex;
import botan.asn1.asn1_alt_name;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import botan.asn1.asn1_time;
import botan.libstate.lookup;
import botan.math.bigint.bigint;
import botan.utils.types;
import memutils.refcounted;
import memutils.dictionarylist;
import memutils.hashmap;
import botan.utils.parsing;
import botan.utils.types : Vector, RefCounted;
import std.algorithm;
import std.array : Appender;

alias X509Certificate = RefCounted!X509CertificateImpl;

/**
* This class represents X.509 Certificate
*/
final class X509CertificateImpl : X509Object
{
public:
    /**
    * Get the public key associated with this certificate.
    * Returns: subject public key of this certificate
    */
    PublicKey subjectPublicKey() const
    {
        Vector!ubyte keybits = subjectPublicKeyBits().dup;
        return x509_key.loadKey(putInSequence(keybits));
    }

    /**
    * Get the public key associated with this certificate.
    * Returns: subject public key of this certificate
    */
    const(Vector!ubyte) subjectPublicKeyBits() const
    {
        return hexDecode(m_subject.get1("X509.Certificate.public_key"));
    }

    /**
    * Get the issuer certificate DN.
    * Returns: issuer DN of this certificate
    */
    const(X509DN) issuerDn() const
    {
        return createDn(m_issuer);
    }

    /**
    * Get the subject certificate DN.
    * Returns: subject DN of this certificate
    */
    const(X509DN) subjectDn() const
    {
        return createDn(m_subject);
    }

    /**
    * Get a value for a specific subject_info parameter name.
    *
    * Params:
    *  name = the name of the paramter to look up. Possible names are
    * "X509.Certificate.version", "X509.Certificate.serial",
    * "X509.Certificate.start", "X509.Certificate.end",
    * "X509.Certificate.v2.key_id", "X509.Certificate.public_key",
    * "X509v3.BasicConstraints.path_constraint",
    * "X509v3.BasicConstraints.is_ca", "X509v3.ExtendedKeyUsage",
    * "X509v3.CertificatePolicies", "X509v3.SubjectKeyIdentifier" or
    * "X509.Certificate.serial".
    * Returns: value(s) of the specified parameter
    */
    const(Vector!string) subjectInfo(in string what) const
    {
        return m_subject.get(X509DNImpl.derefInfoField(what));
    }

    /**
    * Get a value for a specific subject_info parameter name.
    *
    * Params:
    *  name = the name of the paramter to look up. Possible names are
    * "X509.Certificate.v2.key_id" or "X509v3.AuthorityKeyIdentifier".
    * Returns: value(s) of the specified parameter
    */
    const(Vector!string) issuerInfo(in string what) const
    {
        return m_issuer.get(X509DNImpl.derefInfoField(what));
    }

    /**
    * Raw subject DN
    */
    const(Vector!ubyte) rawIssuerDn() const
    {
        return m_issuer.get1Memvec("X509.Certificate.dn_bits");
    }


    /**
    * Raw issuer DN
    */
    const(Vector!ubyte) rawSubjectDn() const
    {
        return m_subject.get1Memvec("X509.Certificate.dn_bits");
    }

    /**
    * Get the notBefore of the certificate.
    * Returns: notBefore of the certificate
    */
    string startTime() const
    {
        return m_subject.get1("X509.Certificate.start");
    }

    /**
    * Get the notAfter of the certificate.
    * Returns: notAfter of the certificate
    */
    string endTime() const
    {
        return m_subject.get1("X509.Certificate.end");
    }

    /**
    * Get the X509 version of this certificate object.
    * Returns: X509 version
    */
    uint x509Version() const
    {
        return (m_subject.get1Uint("X509.Certificate.version") + 1);
    }

    /**
    * Get the serial number of this certificate.
    * Returns: certificates serial number
    */
    const(Vector!ubyte) serialNumber() const
    {
        return m_subject.get1Memvec("X509.Certificate.serial");
    }

    /**
    * Get the DER encoded AuthorityKeyIdentifier of this certificate.
    * Returns: DER encoded AuthorityKeyIdentifier
    */
    const(Vector!ubyte) authorityKeyId() const
    {
        return m_issuer.get1Memvec("X509v3.AuthorityKeyIdentifier");
    }

    /**
    * Get the DER encoded SubjectKeyIdentifier of this certificate.
    * Returns: DER encoded SubjectKeyIdentifier
    */
    const(Vector!ubyte) subjectKeyId() const
    {
        return m_subject.get1Memvec("X509v3.SubjectKeyIdentifier");
    }

    /**
    * Check whether this certificate is self signed.
    * Returns: true if this certificate is self signed
    */
    bool isSelfSigned() const { return m_self_signed; }

    /**
    * Check whether this certificate is a CA certificate.
    * Returns: true if this certificate is a CA certificate
    */
    bool isCACert() const
    {
        if (!m_subject.get1Uint("X509v3.BasicConstraints.is_ca"))
            return false;
        
        return allowedUsage(KeyConstraints.KEY_CERT_SIGN);
    }


    bool allowedUsage(KeyConstraints usage) const
    {
        if (constraints() == KeyConstraints.NO_CONSTRAINTS)
            return true;
        return cast(bool) (constraints() & usage);
    }

    /**
    * Returns true if and only if name (referring to an extended key
    * constraint, eg "PKIX.ServerAuth") is included in the extended
    * key extension.
    */
    bool allowedUsage(in string usage) const
    {
        auto constraints = exConstraints();
        foreach (constraint; constraints[])
            if (constraint == usage)
                return true;
        
        return false;
    }

    /**
    * Get the path limit as defined in the BasicConstraints extension of
    * this certificate.
    * Returns: path limit
    */
    uint pathLimit() const
    {
        return m_subject.get1Uint("X509v3.BasicConstraints.path_constraint", 0);
    }

    /**
    * Get the key constraints as defined in the KeyUsage extension of this
    * certificate.
    * Returns: key constraints
    */
    const(KeyConstraints) constraints() const
    {
        return cast(KeyConstraints) m_subject.get1Uint("X509v3.KeyUsage", KeyConstraints.NO_CONSTRAINTS);
    }

    /**
    * Get the key constraints as defined in the ExtendedKeyUsage
    * extension of this
    * certificate.
    * Returns: key constraints
    */
    const(Vector!string) exConstraints() const
    {
        return lookupOids(m_subject.get("X509v3.ExtendedKeyUsage"));
    }

    /**
    * Get the policies as defined in the CertificatePolicies extension
    * of this certificate.
    * Returns: certificate policies
    */
    const(Vector!string) policies() const
    {
        return lookupOids(m_subject.get("X509v3.CertificatePolicies"));
    }

    /**
    * Return the listed address of an OCSP responder, or empty if not set
    */
    string ocspResponder() const
    {
        //logTrace("Find OSCP responder in DataStore: ", m_subject.toString());
        return m_subject.get1("OCSP.responder", "");
    }

    /**
    * Return the CRL distribution point, or empty if not set
    */
    string crlDistributionPoint() const
    {
        return m_subject.get1("CRL.DistributionPoint", "");
    }

    /**
    * Returns: a string describing the certificate
    */

    override string toString() const
    {
        import std.array : Appender;
        __gshared immutable string[] dn_fields = [ "Name",
            "Email",
            "Organization",
            "Organizational Unit",
            "Locality",
            "State",
            "Country",
            "IP",
            "DNS",
            "URI",
            "PKIX.XMPPAddr" ];
        
        Appender!string output;
        
        foreach (const dn_field; dn_fields)
        {
            const Vector!string vals = subjectInfo(dn_field);
            
            if (vals.empty)
                continue;
            
            output ~= "Subject " ~ dn_field ~ ":";
            for (size_t j = 0; j != vals.length; ++j)
                output ~= " " ~ vals[j];
            output ~= "\n";
        }
        
        foreach (const dn_field; dn_fields)
        {
            const Vector!string vals = issuerInfo(dn_field);
            
            if (vals.empty)
                continue;
            
            output ~= "Issuer " ~ dn_field ~ ":";
            for (size_t j = 0; j != vals.length; ++j)
                output ~= " " ~ vals[j];
            output ~= "\n";
        }
        
        output ~= "\nVersion: " ~ x509Version().to!string;
        
        output ~= "\nNot valid before: " ~ startTime();
        output ~= "\nNot valid after: " ~ endTime();
        
        output ~= "\nConstraints:";
        KeyConstraints constraints = constraints();
        if (constraints == KeyConstraints.NO_CONSTRAINTS)
            output ~= " None";
        else
        {
            if (constraints & KeyConstraints.DIGITAL_SIGNATURE)
                output ~= "\n    Digital Signature";
            if (constraints & KeyConstraints.NON_REPUDIATION)
                output ~= "\n    Non-Repuidation";
            if (constraints & KeyConstraints.KEY_ENCIPHERMENT)
                output ~= "\n    Key Encipherment";
            if (constraints & KeyConstraints.DATA_ENCIPHERMENT)
                output ~= "\n    Data Encipherment";
            if (constraints & KeyConstraints.KEY_AGREEMENT)
                output ~= "\n    Key Agreement";
            if (constraints & KeyConstraints.KEY_CERT_SIGN)
                output ~= "\n    Cert Sign";
            if (constraints & KeyConstraints.CRL_SIGN)
                output ~= "\n    CRL Sign";
        }
        
        const Vector!string policies = policies();
        if (!policies.empty)
        {
            output ~= "\nPolicies: ";
            foreach (const policy; policies[])
                output ~= "    " ~ policy;
        }
        
        const Vector!string ex_constraints = exConstraints();
        if (!ex_constraints.empty)
        {
            output ~= "\nExtended Constraints:";
            foreach (const ex_constraint; ex_constraints[])
                output ~= "    " ~ ex_constraint;
        }
        
        if (ocspResponder() != "")
            output ~= "\nOCSP responder " ~ ocspResponder();
        if (crlDistributionPoint() != "")
            output ~= "\nCRL " ~ crlDistributionPoint();
        
        output ~= "\nSignature algorithm: " ~ OIDS.lookup(signatureAlgorithm().oid);
        
        output ~= "\nSerial number: " ~ hexEncode(serialNumber());
        
        if (authorityKeyId().length)
            output ~= "\nAuthority keyid: " ~ hexEncode(authorityKeyId());
        
        if (subjectKeyId().length)
            output ~= "\nSubject keyid: " ~ hexEncode(subjectKeyId());
        
        const X509PublicKey pubkey = subjectPublicKey();
        output ~= "\nPublic Key:\n\n" ~ x509_key.PEM_encode(pubkey) ~ "\n";
        
        return output.data;
    }


    /**
    * Return a fingerprint of the certificate
    */
    string fingerprint(in string hash_name) const
    {
        Unique!HashFunction hash = retrieveHash(hash_name).clone();
        hash.update(BER_encode());
        const auto hex_print = hexEncode(hash.finished());
        
        Vector!ubyte formatted_print;
        
        for (size_t i = 0; i != hex_print.length; i += 2)
        {
            formatted_print.pushBack(hex_print[i]);
            formatted_print.pushBack(hex_print[i+1]);
            
            if (i != hex_print.length - 2)
                formatted_print.pushBack(':');
        }
        
        return formatted_print[].idup;
    }

    /**
    * Check if a certain DNS name matches up with the information in
    * the cert
    */
    bool matchesDnsName(in string name) const
    {
        if (name == "")
            return false;
        
        if (certSubjectDnsMatch(name, subjectInfo("DNS")))
            return true;
        
        if (certSubjectDnsMatch(name, subjectInfo("Name")))
            return true;
        
        return false;
    }

    /**
    * Check to certificates for equality.
    * Returns: true both certificates are (binary) equal
    */
    bool opEquals(in X509Certificate other) const
    {
        return (m_sig == other.m_sig &&
                m_sig_algo == other.m_sig_algo &&
                m_self_signed == other.m_self_signed &&
                m_issuer == other.m_issuer &&
                m_subject == other.m_subject);
    }

    /**
    * Impose an arbitrary (but consistent) ordering
    * Returns: true if this is less than other by some unspecified criteria
    */
    bool opBinary(string op)(in X509Certificate other) const
        if (op == "<")
    {
        /* If signature values are not equal, sort by lexicographic ordering of that */
        if (sig != other.sig)
        {
            if (sig < other.sig)
                return true;
            return false;
        }
        
        // Then compare the signed contents
        return tbs_bits < other.tbs_bits;
    }

    /**
    * Check two certificates for ineah jsais sadfadfasfaquality
    * Returns: true if the arguments represent different certificates,
    * false if they are binary identical
    */
    int opCmp(in X509Certificate cert2)
    {
        if (this == cert2) return 0;
        else return -1;
    }


    /**
    * Create a certificate from a data source providing the DER or
    * PEM encoded certificate.
    *
    * Params:
    *  source = the data source
    */
    this(DataSource input)
    {
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    /**
    * Create a certificate from a file containing the DER or PEM
    * encoded certificate.
    *
    * Params:
    *  filename = the name of the certificate file
    */
    this(in string filename)
    {
        super(filename, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    this(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input)
    {
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    this(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input)
    {
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

protected:
    /*
    * Decode the TBSCertificate data
    */
    override void forceDecode()
    {
        size_t _version;
        BigInt serial_bn;
        auto sig_algo_inner = AlgorithmIdentifier();
        X509DN dn_issuer, dn_subject;
        X509Time start, end;
        
        BERDecoder tbsCert = BERDecoder(m_tbs_bits);
        tbsCert.decodeOptional(_version, (cast(ASN1Tag) 0),
                              (ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
                .decode(serial_bn)
                .decode(sig_algo_inner)
                .decode(dn_issuer)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(start)
                .decode(end)
                .verifyEnd()
                .endCons()
                .decode(dn_subject);
        
        if (_version > 2)
            throw new DecodingError("Unknown X.509 cert version " ~ to!string(_version));
        if (m_sig_algo != sig_algo_inner)
            throw new DecodingError("Algorithm identifier mismatch");
        
        m_self_signed = (dn_subject == dn_issuer);
        //logTrace("Is self signed: ", m_self_signed);
        m_subject.add(dn_subject.contents());
        m_issuer.add(dn_issuer.contents());
        
        m_subject.add("X509.Certificate.dn_bits", putInSequence(dn_subject.getBits()));
        m_issuer.add("X509.Certificate.dn_bits", putInSequence(dn_issuer.getBits()));
        
        BERObject public_key = tbsCert.getNextObject();

        if (public_key.type_tag != ASN1Tag.SEQUENCE || public_key.class_tag != ASN1Tag.CONSTRUCTED)
            throw new BERBadTag("X509Certificate: Unexpected tag for public key",
                                  public_key.type_tag, public_key.class_tag);
        
        Vector!ubyte v2_issuer_key_id, v2_subject_key_id;
        
        tbsCert.decodeOptionalString(v2_issuer_key_id, ASN1Tag.BIT_STRING, 1);
        tbsCert.decodeOptionalString(v2_subject_key_id, ASN1Tag.BIT_STRING, 2);
        
        BERObject v3_exts_data = tbsCert.getNextObject();
        if (v3_exts_data.type_tag == 3 &&
            v3_exts_data.class_tag == (ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC))
        {
            X509Extensions extensions;
            
            BERDecoder(v3_exts_data.value).decode(extensions).verifyEnd();
            
            extensions.contentsTo(m_subject, m_issuer);
        }
        else if (v3_exts_data.type_tag != ASN1Tag.NO_OBJECT)
            throw new BERBadTag("Unknown tag in X.509 cert", v3_exts_data.type_tag, v3_exts_data.class_tag);
        
        if (tbsCert.moreItems())
            throw new DecodingError("TBSCertificate has more items that expected");
        
        m_subject.add("X509.Certificate.version", _version);
        m_subject.add("X509.Certificate.serial", BigInt.encode(serial_bn));
        m_subject.add("X509.Certificate.start", start.readableString());
        m_subject.add("X509.Certificate.end", end.readableString());
        
        m_issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
        m_subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);
        
        m_subject.add("X509.Certificate.public_key",
        hexEncode(public_key.value));
        
        if (m_self_signed && _version == 0)
        {
            m_subject.add("X509v3.BasicConstraints.is_ca", 1);
            m_subject.add("X509v3.BasicConstraints.path_constraint", NO_CERT_PATH_LIMIT);
        }
        
        if (isCACert() &&
            !m_subject.hasValue("X509v3.BasicConstraints.path_constraint"))
        {
            const size_t limit = (x509Version() < 3) ? NO_CERT_PATH_LIMIT : 0;
            
            m_subject.add("X509v3.BasicConstraints.path_constraint", limit);
        }
    }


    this() {}

    DataStore m_subject, m_issuer;
    bool m_self_signed;
}


/*
* Data Store Extraction Operations
*/
/*
* Create and populate a X509DN
*/
X509DN createDn(in DataStore info)
{
    bool search_for(string key, string val)
    {
        return (key.canFind("X520."));
    }
    auto names = info.searchFor(&search_for);
    
    X509DN dn = X509DN();
    
    foreach (const ref string key, const ref string value; names)
        dn.addAttribute(key, value);
    
    return dn;
}


/*
* Create and populate an AlternativeName
*/
AlternativeName createAltName(in DataStore info)
{
    auto names = info.searchFor((string key, string)
                                 { return (key == "RFC822" || key == "DNS" || key == "URI" || key == "IP"); });
    
    AlternativeName alt_name = AlternativeName();
    
    foreach (const ref string key, const ref string value; names)
        alt_name.addAttribute(key, value);
    
    return alt_name;
}



/*
* Lookup each OID in the vector
*/
Vector!string lookupOids(ALLOC)(auto const ref Vector!(string, ALLOC) input)
{
    Vector!string output = Vector!string();
    
    foreach (oid_name; input[])
        output.pushBack(OIDS.lookup(OID(oid_name)));
    return output;
}


bool certSubjectDnsMatch(ALLOC)(in string name,
                                     auto const ref Vector!(string, ALLOC) cert_names)
{
    foreach (const cn; cert_names[])
    {
        if (cn == name)
            return true;
        
        /*
        * Possible wildcard match. We only support the most basic form of
        * cert wildcarding ala RFC 2595
        */
        if (cn.length > 2 && cn[0] == '*' && cn[1] == '.' && name.length > cn.length)
        {
            const string base = cn[1 .. $];
            size_t start = name.length - base.length;
            if (name[start .. start + base.length] == base)
                return true;
        }
    }
    
    return false;
}