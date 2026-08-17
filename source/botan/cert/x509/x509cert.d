/**
* X.509 Certificates
* 
* Copyright:
* (C) 1999-2010,2015,2017,2026 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
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
import botan.cert.x509.key_constraint : KeyConstraints, UsageType;
import std.string : indexOf;
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
        Vector!ubyte keybits = subjectPublicKeyBits().clone;
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
    *  what = the name of the paramter to look up. Possible names are
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
    *  what = the name of the paramter to look up. Possible names are
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

    /// C++ `allowed_extended_usage`: empty EKU allows any usage.
    bool allowedExtendedUsage(in string usage) const
    {
        auto constraints = exConstraints();
        if (!constraints.length)
            return true;
        foreach (constraint; constraints[])
        {
            if (constraint == usage || constraint == "X509v3.AnyExtendedKeyUsage")
                return true;
        }
        return false;
    }

    /// C++ `allowed_usage(Usage_Type)` RFC 5280 4.2.1.12.
    bool allowedUsageType(UsageType usage) const
    {
        if (usage == UsageType.UNSPECIFIED)
            return true;
        if (usage == UsageType.TLS_SERVER_AUTH)
            return (allowedUsage(KeyConstraints.KEY_AGREEMENT)
                    || allowedUsage(KeyConstraints.KEY_ENCIPHERMENT)
                    || allowedUsage(KeyConstraints.DIGITAL_SIGNATURE))
                && allowedExtendedUsage("PKIX.ServerAuth");
        if (usage == UsageType.TLS_CLIENT_AUTH)
            return (allowedUsage(KeyConstraints.DIGITAL_SIGNATURE)
                    || allowedUsage(KeyConstraints.KEY_AGREEMENT))
                && allowedExtendedUsage("PKIX.ClientAuth");
        if (usage == UsageType.OCSP_RESPONDER)
            return (allowedUsage(KeyConstraints.DIGITAL_SIGNATURE)
                    || allowedUsage(KeyConstraints.NON_REPUDIATION))
                && allowedUsage("PKIX.OCSPSigning");
        if (usage == UsageType.CERTIFICATE_AUTHORITY)
            return isCACert();
        if (usage == UsageType.ENCRYPTION)
            return allowedUsage(KeyConstraints.KEY_ENCIPHERMENT)
                || allowedUsage(KeyConstraints.DATA_ENCIPHERMENT);
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
        //logTrace("Find OCSP responder in DataStore: ", m_subject.toString());
        return m_subject.get1("OCSP.responder", "");
    }

    /**
    * Return the CRL distribution point, or empty if not set
    */
    string crlDistributionPoint() const
    {
		import std.range : front;
		auto crl_dist = m_subject.get("CRL.DistributionPoint");
		if (crl_dist.length)
			return crl_dist.front;
		return "";
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
        
        Unique!X509PublicKey pubkey = subjectPublicKey();
        output ~= "\nPublic Key:\n\n" ~ x509_key.PEM_encode(*pubkey) ~ "\n";
        
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
        
        Vector!char formatted_print;
        
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
        auto sans = subjectInfo("DNS");
        if (sans.length)
            return certSubjectDnsMatch(name, sans);
        return certSubjectDnsMatch(name, subjectInfo("Name"));
    }

    /**
    * Check to certificates for equality.
    * Returns: true both certificates are (binary) equal
    */
    bool opEquals(in X509Certificate other) const
    {
		if (*other is null)
			return false;
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
    * Check two certificates for quality
    * Returns: true if the arguments represent different certificates,
    * false if they are binary identical
    */
    int opCmp(in X509Certificate cert2)
    {
        if (this == cert2) return 0;
        else return -1;
    }

    bool isValid() {
        return !m_subject.get("X509.Certificate.start").empty;
    }

    /**
    * Create a certificate from a data source providing the DER or
    * PEM encoded certificate.
    *
    * Params:
    *  input = the data source
    */
    this(DataSource input, bool throw_on_unknown_critical_ = true)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
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
    this(in string filename, bool throw_on_unknown_critical_ = true)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
        super(filename, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    this(ALLOC)(const auto ref Vector!(ubyte, ALLOC) input, bool throw_on_unknown_critical_ = true)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
        super(input, "CERTIFICATE/X509 CERTIFICATE");
        m_self_signed = false;
        doDecode();
    }

    this(ALLOC)(const auto ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) input, bool throw_on_unknown_critical_ = true)
    {
        m_throw_on_unknown_critical = throw_on_unknown_critical_;
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
        import std.datetime : Clock, UTC;
        X509Time start = X509Time(Clock.currTime(UTC()));
        X509Time end = X509Time(Clock.currTime(UTC()));
        
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
            X509Extensions extensions = X509Extensions(m_throw_on_unknown_critical);
            
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
    bool m_throw_on_unknown_critical;
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
Vector!string lookupOids(ALLOC)(const auto ref Vector!(string, ALLOC) input)
{
    Vector!string output = Vector!string();
    
    foreach (oid_name; input[])
        output.pushBack(OIDS.lookup(OID(oid_name)));
    return output;
}


bool certSubjectDnsMatch(ALLOC)(in string name,
                                     const auto ref Vector!(string, ALLOC) cert_names)
{
    foreach (const cn; cert_names[])
    {
        if (hostWildcardMatch(cn, name))
            return true;
    }
    return false;
}

private bool dnsCharEq(char a, char b)
{
    if (a == b)
        return true;
    auto la = cast(ubyte)(a | 0x20);
    auto lb = cast(ubyte)(b | 0x20);
    return la == lb && la >= 'a' && la <= 'z';
}

public import botan.asn1.asn1_alt_name : dnsNameFromSan;

/// C++ `DNSName::host_wildcard_match` (RFC 6125 6.4.3).
bool hostWildcardMatch(string issued, string host)
{
    while (issued.length && issued[$ - 1] == 0)
        issued = issued[0 .. $ - 1];
    while (host.length && host[$ - 1] == 0)
        host = host[0 .. $ - 1];
    if (!issued.length || !host.length || host.length > 253)
        return false;
    if (issued.length > host.length + 1)
        return false;
    if (issued.canFind('\0') || host.canFind('\0') || host.canFind('*'))
        return false;
    if (host[0] == '.' || host[$ - 1] == '.' || host.canFind(".."))
        return false;
    bool eqRange(string a, string b)
    {
        if (a.length != b.length)
            return false;
        foreach (i; 0 .. a.length)
            if (!dnsCharEq(a[i], b[i]))
                return false;
        return true;
    }
    if (eqRange(issued, host))
        return true;
    auto first_star = issued.indexOf('*');
    if (first_star < 0)
        return false;
    if (issued.indexOf('*', first_star + 1) >= 0)
        return false;
    auto issued_label = issued[0 .. (issued.indexOf('.') >= 0 ? issued.indexOf('.') : issued.length)];
    bool idna(string label)
    {
        return label.length >= 4 && eqRange(label[0 .. 4], "xn--");
    }
    if (idna(issued_label))
        return false;
    auto host_dot = host.indexOf('.');
    if (issued_label != "*" && idna(host[0 .. (host_dot >= 0 ? host_dot : host.length)]))
        return false;
    size_t dots_seen;
    size_t host_idx;
    foreach (i; 0 .. issued.length)
    {
        if (issued[i] == '.')
            ++dots_seen;
        if (issued[i] == '*')
        {
            if (dots_seen)
                return false;
            const size_t advance = host.length - issued.length + 1;
            if (host_idx + advance > host.length)
                return false;
            foreach (k; host_idx .. host_idx + advance)
                if (host[k] == '.')
                    return false;
            host_idx += advance;
        }
        else
        {
            if (host_idx >= host.length || !dnsCharEq(issued[i], host[host_idx]))
                return false;
            ++host_idx;
        }
    }
    return dots_seen >= 2 && host_idx == host.length;
}