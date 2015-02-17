/**
* X.509 Certificate Extensions
* 
* Copyright:
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.x509_ext;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.asn1_str;
import botan.utils.datastor.datastor;
import botan.cert.x509.crl_ent;
import botan.cert.x509.key_constraint;
import botan.hash.sha160;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oids;
import botan.asn1.asn1_alt_name;
import botan.utils.charset;
import botan.utils.bit_ops;
import std.algorithm;
import botan.utils.types;
import botan.utils.mem_ops;
import memutils.dictionarylist;

/**
* X.509 Certificate Extension
*/
interface CertificateExtension
{
public:
    /**
    * Returns: OID representing this extension
    */
    final OID oidOf() const
    {
        return OIDS.lookup(oidName());
    }

    /**
    * Make a copy of this extension
    * Returns: copy of this
    */
    abstract CertificateExtension copy() const;

    /*
    * Add the contents of this extension into the information
    * for the subject and/or issuer, as necessary.
    *
    * Params:
    *  subject = the subject info
    *  issuer = the issuer info
    */
    abstract void contentsTo(ref DataStore subject,
                             ref DataStore issuer) const;

    /*
    * Returns: specific OID name
    */
    abstract string oidName() const;

protected:
    abstract bool shouldEncode() const;
    abstract Vector!ubyte encodeInner() const;
    abstract void decodeInner(const ref Vector!ubyte);
}

alias X509Extensions = RefCounted!X509ExtensionsImpl;

/**
* X.509 Certificate Extension List
*/
final class X509ExtensionsImpl : ASN1Object
{
public:

    override void encodeInto(ref DEREncoder to_object) const
    {
        foreach (const extension; m_extensions[])
        {
            const CertificateExtension ext = extension.first;
            const bool is_critical = extension.second;
            
            const bool should_encode = ext.shouldEncode();
            
            if (should_encode)
            {
                to_object.startCons(ASN1Tag.SEQUENCE)
                           .encode(ext.oidOf())
                           .encodeOptional(is_critical, false)
                           .encode(ext.encodeInner(), ASN1Tag.OCTET_STRING)
                           .endCons();
            }
        }
    }

    override void decodeFrom(ref BERDecoder from_source)
    {
        CertificateExtension cext;
        foreach (Pair!(CertificateExtension, bool) extension; m_extensions[]) {
            cext = extension.first;
            destroy(cext);
        }
        m_extensions.clear();
        
        BERDecoder sequence = from_source.startCons(ASN1Tag.SEQUENCE);
        
        while (sequence.moreItems())
        {
            OID oid = OID();
            Vector!ubyte value;
            bool critical;
            
            sequence.startCons(ASN1Tag.SEQUENCE)
                    .decode(oid)
                    .decodeOptional(critical, ASN1Tag.BOOLEAN, ASN1Tag.UNIVERSAL, false)
                    .decode(value, ASN1Tag.OCTET_STRING)
                    .verifyEnd()
                    .endCons();
            
            CertificateExtension ext = getExtension(oid);
            
            if (!ext && critical && m_throw_on_unknown_critical)
                throw new DecodingError("Encountered unknown X.509 extension marked "
                                         ~ "as critical; OID = " ~ oid.toString());
            
            if (ext)
            {
                try
                {
                    ext.decodeInner(value);
                }
                catch(Exception e)
                {
                    throw new DecodingError("Exception while decoding extension " ~
                                             oid.toString() ~ ": " ~ e.msg);
                }
                
                m_extensions.pushBack(makePair(ext, critical));
            }
        }
        
        sequence.verifyEnd();
    }

    void contentsTo(ref DataStore subject_info,
                    ref DataStore issuer_info) const
    {
        foreach (extension; m_extensions[])
            extension.first.contentsTo(subject_info, issuer_info);
    }

    void add(CertificateExtension extn, bool critical = false)
    {
        m_extensions.pushBack(makePair(extn, critical));
    }

    X509ExtensionsImpl opAssign(in X509Extensions other)
    {
        CertificateExtension cext;
        foreach (extension; m_extensions[]) {
            cext = extension.first;
            destroy(cext);
        }
        m_extensions.clear();
        
        foreach (extension; other.m_extensions[])
            m_extensions.pushBack(makePair(extension.first.copy(), extension.second));
        
        return this;
    }

    this(in X509Extensions ext) {
        this = ext;
    }

    this(bool st = true) { m_throw_on_unknown_critical = st; }

    ~this()
    {
        CertificateExtension cext;
        foreach (extension; m_extensions[]) {
            cext = extension.first;
            destroy(cext);
        }
    }

    override string toString() const {
        import std.array :Appender;
        Appender!string ret;
        foreach (ext; m_extensions[])
            ret ~= ext.first.oidName() ~ "\n";
        return ret.data;
    }

private:

    /*
    * List of X.509 Certificate Extensions
    */
    CertificateExtension getExtension(in OID oid)
    {
        string X509_EXTENSION(string NAME, string TYPE)() {
            return `if (OIDS.nameOf(oid, "` ~ NAME ~ `")) return new ` ~ TYPE ~ `();`;
        }
        
        mixin( X509_EXTENSION!("X509v3.KeyUsage", "KeyUsage")() );
        mixin( X509_EXTENSION!("X509v3.BasicConstraints", "BasicConstraints")() );
        mixin( X509_EXTENSION!("X509v3.SubjectKeyIdentifier", "SubjectKeyID")() );
        mixin( X509_EXTENSION!("X509v3.AuthorityKeyIdentifier", "AuthorityKeyID")() );
        mixin( X509_EXTENSION!("X509v3.ExtendedKeyUsage", "ExtendedKeyUsage")() );
        mixin( X509_EXTENSION!("X509v3.IssuerAlternativeName", "IssuerAlternativeName")() );
        mixin( X509_EXTENSION!("X509v3.SubjectAlternativeName", "SubjectAlternativeName")() );
        mixin( X509_EXTENSION!("X509v3.CertificatePolicies", "CertificatePolicies")() );
        mixin( X509_EXTENSION!("X509v3.CRLDistributionPoints", "CRLDistributionPoints")() );
        mixin( X509_EXTENSION!("PKIX.AuthorityInformationAccess", "AuthorityInformationAccess")() );
        mixin( X509_EXTENSION!("X509v3.CRLNumber", "CRLNumber")() );
        mixin( X509_EXTENSION!("X509v3.ReasonCode", "CRLReasonCode")() );
        
        return null;
    }


    Vector!( Pair!(CertificateExtension, bool)  ) m_extensions;
    bool m_throw_on_unknown_critical;
}

__gshared immutable size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
final class BasicConstraints : CertificateExtension
{
public:
    override BasicConstraints copy() const
    { return new BasicConstraints(m_is_ca, m_path_limit); }

    this(bool ca = false, size_t limit = 0)
    {
        m_is_ca = ca;
        m_path_limit = limit; 
    }

    bool getIsCa() const { return m_is_ca; }
    /*
    * Checked accessor for the path_limit member
    */
    size_t getPathLimit() const
    {
        if (!m_is_ca)
            throw new InvalidState("Basic_Constraints::get_path_limit: Not a CA");
        return m_path_limit;
    }

protected:
    override bool shouldEncode() const { return true; }

    string oidName() const { return "X509v3.BasicConstraints"; }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encodeIf (m_is_ca,
                            DEREncoder()
                                .encode(m_is_ca)
                                .encodeOptional(m_path_limit, NO_CERT_PATH_LIMIT)
                            )
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeOptional(m_is_ca, ASN1Tag.BOOLEAN, ASN1Tag.UNIVERSAL, false)
                .decodeOptional(m_path_limit, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL, NO_CERT_PATH_LIMIT)
                .verifyEnd()
                .endCons();
        
        if (m_is_ca == false)
            m_path_limit = 0;
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.BasicConstraints.is_ca", (m_is_ca ? 1 : 0));
        subject.add("X509v3.BasicConstraints.path_constraint", m_path_limit);
    }

    bool m_is_ca;
    size_t m_path_limit;
}

/**
* Key Usage Constraints Extension
*/
final class KeyUsage : CertificateExtension
{
public:
    override KeyUsage copy() const { return new KeyUsage(m_constraints); }

    this(KeyConstraints c = KeyConstraints.NO_CONSTRAINTS) { m_constraints = c; }

    KeyConstraints getConstraints() const { return m_constraints; }
protected:
    string oidName() const { return "X509v3.KeyUsage"; }

    bool shouldEncode() const { return (m_constraints != KeyConstraints.NO_CONSTRAINTS); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        if (m_constraints == KeyConstraints.NO_CONSTRAINTS)
            throw new EncodingError("Cannot encode zero usage constraints");
        
        const size_t unused_bits = lowBit(m_constraints) - 1;
        
        Vector!ubyte der;
        der.pushBack(ASN1Tag.BIT_STRING);
        der.pushBack(2 + ((unused_bits < 8) ? 1 : 0));
        der.pushBack(unused_bits % 8);
        der.pushBack((m_constraints >> 8) & 0xFF);
        if (m_constraints & 0xFF)
            der.pushBack(m_constraints & 0xFF);
        
        return der;
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder ber = BERDecoder(input);
        
        BERObject obj = ber.getNextObject();
        
        if (obj.type_tag != ASN1Tag.BIT_STRING || obj.class_tag != ASN1Tag.UNIVERSAL)
            throw new BERBadTag("Bad tag for usage constraint",
                                  obj.type_tag, obj.class_tag);
        
        if (obj.value.length != 2 && obj.value.length != 3)
            throw new BERDecodingError("Bad size for BITSTRING in usage constraint");
        
        if (obj.value[0] >= 8)
            throw new BERDecodingError("Invalid unused bits in usage constraint");
        
        obj.value[obj.value.length-1] &= (0xFF << obj.value[0]);
        
        KeyConstraints usage;
        foreach (size_t i; 1 .. obj.value.length)
            usage |= cast(KeyConstraints) (obj.value[i] << 8);
        
        m_constraints = usage;
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.KeyUsage", m_constraints);
    }

    KeyConstraints m_constraints;
}

/**
* Subject Key Identifier Extension
*/
final class SubjectKeyID : CertificateExtension
{
public:
    override SubjectKeyID copy() const { return new SubjectKeyID(m_key_id); }

    this() {}
    this()(auto const ref Vector!ubyte pub_key)
    {
        auto hash = scoped!SHA160();
        m_key_id = unlock(hash.process(pub_key));
    }


    ref const(Vector!ubyte) getKeyId() const { return m_key_id; }
protected:
    string oidName() const { return "X509v3.SubjectKeyIdentifier"; }

    bool shouldEncode() const { return (m_key_id.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_key_id, ASN1Tag.OCTET_STRING).getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input).decode(m_key_id, ASN1Tag.OCTET_STRING).verifyEnd();
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        subject.add("X509v3.SubjectKeyIdentifier", m_key_id);
    }

    Vector!ubyte m_key_id;
}

/**
* Authority Key Identifier Extension
*/
class AuthorityKeyID : CertificateExtension
{
public:
    override AuthorityKeyID copy() const { return new AuthorityKeyID(m_key_id); }

    this() {}
    this()(auto const ref Vector!ubyte k) { m_key_id = k.dup(); }

    ref const(Vector!ubyte) getKeyId() const { return m_key_id; }
protected:
    string oidName() const { return "X509v3.AuthorityKeyIdentifier"; }

    bool shouldEncode() const { return (m_key_id.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(m_key_id, ASN1Tag.OCTET_STRING, (cast(ASN1Tag) 0), ASN1Tag.CONTEXT_SPECIFIC)
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeOptionalString(m_key_id, ASN1Tag.OCTET_STRING, 0);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore, ref DataStore issuer) const
    {
        if (m_key_id.length)
            issuer.add("X509v3.AuthorityKeyIdentifier", m_key_id);
    }


    Vector!ubyte m_key_id;
}

/**
* Alternative Name Extension Base Class
*/
abstract class AlternativeNameExt : CertificateExtension
{
public:
    const(AlternativeName) getAltName() const { return m_alt_name; }

protected:

    this(AlternativeName alt_name = AlternativeName.init, string oid_name_str = null)
    {
        m_alt_name = alt_name;
        m_oid_name_str = oid_name_str;
    }

    string oidName() const { return m_oid_name_str; }

    bool shouldEncode() const { return m_alt_name.hasItems(); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_alt_name).getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input).decode(m_alt_name);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject_info,
                    ref DataStore issuer_info) const
    {
        DictionaryListRef!(string, string) contents = getAltName().contents();
        
        if (m_oid_name_str == "X509v3.SubjectAlternativeName")
            subject_info.add(contents);
        else if (m_oid_name_str == "X509v3.IssuerAlternativeName")
            issuer_info.add(contents);
        else
            throw new InternalError("In AlternativeName, unknown type " ~ m_oid_name_str);
    }

    string m_oid_name_str;
    AlternativeName m_alt_name;
}




/**
* Subject Alternative Name Extension
*/
final class SubjectAlternativeName : AlternativeNameExt, CertificateExtension
{
public:

    override void contentsTo(ref DataStore subject, ref DataStore issuer) const {
        super.contentsTo(subject, issuer);
    }

    override string oidName() const {
        return super.oidName();
    }

    override bool shouldEncode() const {
        return super.shouldEncode();
    }

    override Vector!ubyte encodeInner() const
    {
        return super.encodeInner();
    }

    override void decodeInner(const ref Vector!ubyte input) {
        super.decodeInner(input);
    }

    override SubjectAlternativeName copy() const
    { return new SubjectAlternativeName(cast(AlternativeName) getAltName()); }

    this(AlternativeName name = AlternativeName()) {
        super(name, "X509v3.SubjectAlternativeName");
    }
}

/**
* Issuer Alternative Name Extension
*/
final class IssuerAlternativeName : AlternativeNameExt, CertificateExtension
{
public:
    override void contentsTo(ref DataStore subject, ref DataStore issuer) const {
        super.contentsTo(subject, issuer);
    }
    
    override string oidName() const {
        return super.oidName();
    }
    
    override bool shouldEncode() const {
        return super.shouldEncode();
    }
    
    override Vector!ubyte encodeInner() const
    {
        return super.encodeInner();
    }
    
    override void decodeInner(const ref Vector!ubyte input) {
        super.decodeInner(input);
    }

    override IssuerAlternativeName copy() const
    { return new IssuerAlternativeName(cast(AlternativeName)getAltName()); }

    this(AlternativeName name = AlternativeName()) {
        super(name, "X509v3.IssuerAlternativeName");
    }
}

/**
* Extended Key Usage Extension
*/
final class ExtendedKeyUsage : CertificateExtension
{
public:
    override ExtendedKeyUsage copy() const { return new ExtendedKeyUsage(m_oids.dup); }

    this() {}

    this()(auto const ref Vector!OID o) 
    {
        m_oids = o.dup;
    }

    ref const(Vector!OID) getOids() const { return m_oids; }
protected:
    string oidName() const { return "X509v3.ExtendedKeyUsage"; }

    bool shouldEncode() const { return (m_oids.length > 0); }
    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encodeList(m_oids)
                .endCons()
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input).decodeList(m_oids);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        foreach (oid; m_oids[])
            subject.add("X509v3.ExtendedKeyUsage", oid.toString());
    }

    Vector!OID m_oids;
}

/**
* Certificate Policies Extension
*/
final class CertificatePolicies : CertificateExtension
{
public:
    override CertificatePolicies copy() const
    { return new CertificatePolicies(m_oids); }

    this() {}
    this()(auto const ref Vector!OID o) { m_oids = o.dup(); }

    ref const(Vector!OID) getOids() const { return m_oids; }
protected:
    string oidName() const { return "X509v3.CertificatePolicies"; }

    bool shouldEncode() const { return (m_oids.length > 0); }

    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        Vector!( PolicyInformation ) policies;

        foreach (oid; m_oids[])
            policies.pushBack(PolicyInformation(oid));
        
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encodeList(policies)
                .endCons()
                .getContentsUnlocked();
    }
    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        Vector!( PolicyInformation ) policies;
        //logTrace("Decode list of policies");
        BERDecoder(input).decodeList(policies);
        
        m_oids.clear();
        foreach (policy; policies[])
            m_oids.pushBack(policy.oid);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore info, ref DataStore) const
    {
        foreach (oid; m_oids[])
            info.add("X509v3.CertificatePolicies", oid.toString());
    }

    Vector!OID m_oids;
}

final class AuthorityInformationAccess : CertificateExtension
{
public:
    override AuthorityInformationAccess copy() const
    { return new AuthorityInformationAccess(m_ocsp_responder); }

    this() {}

    this(in string ocsp) { m_ocsp_responder = ocsp; }

protected:
    string oidName() const { return "PKIX.AuthorityInformationAccess"; }

    bool shouldEncode() const { return (m_ocsp_responder != ""); }

    Vector!ubyte encodeInner() const
    {
        ASN1String url = ASN1String(m_ocsp_responder, ASN1Tag.IA5_STRING);

        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(OIDS.lookup("PKIX.OCSP"))
                .addObject((cast(ASN1Tag)6), ASN1Tag.CONTEXT_SPECIFIC, url.iso8859())
                .endCons()
                .endCons().getContentsUnlocked();
    }

    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder ber = BERDecoder(input).startCons(ASN1Tag.SEQUENCE);
        
        while (ber.moreItems())
        {
            OID oid = OID();
            
            BERDecoder info = ber.startCons(ASN1Tag.SEQUENCE);
            
            info.decode(oid);
            
            if (oid == OIDS.lookup("PKIX.OCSP"))
            {
                BERObject name = info.getNextObject();
                
                if (name.type_tag == 6 && name.class_tag == ASN1Tag.CONTEXT_SPECIFIC)
                {
                    m_ocsp_responder = transcode(name.toString(),
                                                 LATIN1_CHARSET,
                                                 LOCAL_CHARSET);
                }
                
            }
        }
    }



    void contentsTo(ref DataStore subject, ref DataStore) const
    {
        if (m_ocsp_responder != "")
            subject.add("OCSP.responder", m_ocsp_responder);
    }

    string m_ocsp_responder;
}


/**
* CRL Number Extension
*/
final class CRLNumber : CertificateExtension
{
public:
    /*
    * Copy a CRL_Number extension
    */
    override CRLNumber copy() const
    {
        if (!m_has_value)
            throw new InvalidState("CRL_Number::copy: Not set");
        return new CRLNumber(m_crl_number);
    }


    this() { m_has_value = false; m_crl_number = 0; }
    this(size_t n) { m_has_value = true; m_crl_number = n; }

    /*
    * Checked accessor for the crl_number member
    */
    size_t getCrlNumber() const
    {
        if (!m_has_value)
            throw new InvalidState("CRL_Number::get_crl_number: Not set");
        return m_crl_number;
    }

protected:
    string oidName() const { return "X509v3.CRLNumber"; }

    bool shouldEncode() const { return m_has_value; }
    /*
    * Encode the extension
    */
    Vector!ubyte encodeInner() const
    {
        return DEREncoder().encode(m_crl_number).getContentsUnlocked();
    }
    /*
    * Decode the extension
    */
    void decodeInner(const ref Vector!ubyte input)
    {
        BERDecoder(input).decode(m_crl_number);
    }

    /*
    * Return a textual representation
    */
    void contentsTo(ref DataStore info, ref DataStore) const
    {
        info.add("X509v3.CRLNumber", m_crl_number);
    }

    bool m_has_value;
    size_t m_crl_number;
}

/**
* CRL Entry Reason Code Extension
*/
final class CRLReasonCode : CertificateExtension
{
public:
    override CRLReasonCode copy() const { return new CRLReasonCode(m_reason); }

    this(CRLCode r = UNSPECIFIED) { m_reason = r; }

    CRLCode getReason() const { return m_reason; }

protected:
    override string oidName() const { return "X509v3.ReasonCode"; }

    override bool shouldEncode() const { return (m_reason != UNSPECIFIED); }
    /*
    * Encode the extension
    */
    override Vector!ubyte encodeInner() const
    {
        return DEREncoder()
                .encode(cast(size_t)(m_reason), ASN1Tag.ENUMERATED, ASN1Tag.UNIVERSAL)
                .getContentsUnlocked();
    }

    /*
    * Decode the extension
    */
    override void decodeInner(const ref Vector!ubyte input)
    {
        size_t reason_code = 0;
        BERDecoder(input).decode(reason_code, ASN1Tag.ENUMERATED, ASN1Tag.UNIVERSAL);
        m_reason = cast(CRLCode)(reason_code);
    }

    /*
    * Return a textual representation
    */
    override void contentsTo(ref DataStore info, ref DataStore) const
    {
        info.add("X509v3.CRLReasonCode", m_reason);
    }

    CRLCode m_reason;
}


/**
* CRL Distribution Points Extension
*/
final class CRLDistributionPoints : CertificateExtension
{
public:
    alias DistributionPoint = RefCounted!DistributionPointImpl;
    final class DistributionPointImpl : ASN1Object
    {
    public:
        override void encodeInto(ref DEREncoder) const
        {
            throw new Exception("CRLDistributionPoints encoding not implemented");
        }

        override void decodeFrom(ref BERDecoder ber)
        {
            ber.startCons(ASN1Tag.SEQUENCE)
                    .startCons((cast(ASN1Tag) 0), ASN1Tag.CONTEXT_SPECIFIC)
                    .decodeOptionalImplicit(m_point, (cast(ASN1Tag) 0),
                                              (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED),
                                              ASN1Tag.SEQUENCE, ASN1Tag.CONSTRUCTED)
                    .endCons().endCons();
        }


        const(AlternativeName) point() const { return m_point; }
    private:
        AlternativeName m_point;
    }

    override CRLDistributionPoints copy() const
    { return new CRLDistributionPoints(m_distribution_points); }

    this() {}

    this()(auto const ref Vector!( DistributionPoint ) points) { m_distribution_points = points.dup; }

    ref const(Vector!( DistributionPoint )) distributionPoints() const
    { return m_distribution_points; }

protected:
    string oidName() const { return "X509v3.CRLDistributionPoints"; }

    bool shouldEncode() const { return !m_distribution_points.empty; }

    Vector!ubyte encodeInner() const
    {
        throw new Exception("CRLDistributionPoints encoding not implemented");
    }

    void decodeInner(const ref Vector!ubyte buf)
    {
        BERDecoder(buf).decodeList(m_distribution_points).verifyEnd();
    }


    void contentsTo(ref DataStore info, ref DataStore) const
    {
        foreach (distribution_point; m_distribution_points[])
        {
            auto point = distribution_point.point().contents();
            
            point.getValuesAt("URI", (in string val) {
                info.add("CRL.DistributionPoint", val);
            });
        }
    }

    Vector!( DistributionPoint ) m_distribution_points;
}


alias PolicyInformation = RefCounted!PolicyInformationImpl;

/*
* A policy specifier
*/
final class PolicyInformationImpl : ASN1Object
{
public:
    OID oid;
    
    this() {}
    this(OID oid_) { oid = oid_; }
    
    override void encodeInto(ref DEREncoder codec) const
    {
        codec.startCons(ASN1Tag.SEQUENCE)
                .encode(oid)
                .endCons();
    }
    
    override void decodeFrom(ref BERDecoder codec)
    {
        oid = OID();
        codec.startCons(ASN1Tag.SEQUENCE)
                .decode(oid)
                .discardRemaining()
                .endCons();
    }
}
