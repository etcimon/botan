/**
* Certificate Store
* 
* Copyright:
* (C) 1999-2010,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.certstor;

import botan.constants;

import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.utils.types;
import std.file;

version(X509):

/**
* Certificate Store Interface
*/
interface CertificateStore
{
public:
    /**
    * Subject DN and (optionally) key identifier
    */
    X509Certificate findCertRef(in X509DN subject_dn, const ref Vector!ubyte key_id) const;

    final X509Certificate findCert()(in X509DN subject_dn, auto const ref Vector!ubyte key_id) const {
        return findCertRef(subject_dn, key_id);
    }

    X509CRL findCrlFor(in X509Certificate subject) const;


    final bool certificateKnown(in X509Certificate cert) const
    {
        if (!*cert) return false;
		auto cert_ = findCert(cert.subjectDn(), cert.subjectKeyId());
		if (!*cert_) return false;
        return cert_ != X509Certificate.init;
    }

    // remove this (used by TLSServer)
    Vector!X509DN allSubjects() const;
}

/**
* In Memory Certificate Store
*/
final class CertificateStoreInMemory : CertificateStore
{
public:
    /**
    * Attempt to parse all files in dir (including subdirectories)
    * as certificates. Ignores errors.
    */
    this(in string dir)
    {
        if (dir == "")
            return;
        foreach(string name; dirEntries(dir, SpanMode.breadth)) {
            if (isFile(name))
                m_certs.pushBack(X509Certificate(name));
        }
    }

    this() {}

    void addCertificate(X509Certificate cert)
    {
        foreach (const cert_stored; m_certs[])
        {
            if (cert_stored == cert)
                return;
        }
        
        m_certs.pushBack(cert);
    }

    override Vector!X509DN allSubjects() const
    {
        Vector!X509DN subjects;
        foreach (ref cert; m_certs[]) {
			auto subj_dn = cert.subjectDn();
            subjects.pushBack(subj_dn.dup);
		}
        return subjects;
    }

    override X509Certificate findCertRef(in X509DN subject_dn, const ref Vector!ubyte key_id) const
    {
        return certSearch(subject_dn, key_id, m_certs);
    }

    void addCrl(X509CRL crl)
    {
        X509DN crl_issuer = crl.issuerDn();
        
        foreach (ref crl_stored; m_crls[])
        {
            // Found an update of a previously existing one; replace it
            if (crl_stored.issuerDn() == crl_issuer)
            {
                if (crl_stored.thisUpdate() <= crl.thisUpdate())
                    crl_stored = crl;
                return;
            }
        }
        
        // Totally new CRL, add to the list
        m_crls.pushBack(crl);
    }

    override X509CRL findCrlFor(in X509Certificate subject) const
    {
        const Vector!ubyte key_id = subject.authorityKeyId();
        
        foreach (crl; m_crls[])
        {
            // Only compare key ids if set in both call and in the CRL
            if (key_id.length)
            {
                Vector!ubyte akid = crl.authorityKeyId();
                
                if (akid.length && akid != key_id) // no match
                    continue;
            }

            if (crl.issuerDn() == subject.issuerDn())
                return crl;
        }
        
        return X509CRL.init;
    }

private:
    // TODO: Add indexing on the DN and key id to avoid linear search
    Vector!X509Certificate m_certs;
    Vector!X509CRL m_crls;
}

final class CertificateStoreOverlay : CertificateStore
{
public:
    this(const ref Vector!X509Certificate certs)
    {
        foreach (ref cert; certs[]) {
            m_certs ~= cert;
        }
    }

    override X509CRL findCrlFor(in X509Certificate subject) const { return X509CRL.init; }

    override Vector!X509DN allSubjects() const
    {
        Vector!X509DN subjects;
        foreach (cert; m_certs[])
            subjects.pushBack(cert.subjectDn().dup);
        return subjects.move;
    }

    override X509Certificate findCertRef(in X509DN subject_dn, const ref Vector!ubyte key_id) const
    {
        return certSearch(subject_dn, key_id, m_certs);
    }
private:
    Vector!X509Certificate m_certs;
}

X509Certificate certSearch(in X509DN subject_dn, 
                           const ref Vector!ubyte key_id, 
                           const ref Vector!X509Certificate certs)
{
    foreach (cert; certs[])
    {
        // Only compare key ids if set in both call and in the cert
        if (key_id.length)
        {
            const Vector!ubyte skid = cert.subjectKeyId();
            if (skid.length && skid != key_id) // no match
                continue;
        }
        
        if (cert.subjectDn() == subject_dn) {
            return cert;
        }
    }
    
    return X509Certificate.init;
}