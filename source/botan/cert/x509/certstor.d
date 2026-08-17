/**
* Certificate Store
*
* Copyright:
* (C) 1999-2010,2013 Jack Lloyd
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.certstor;

import botan.constants;

import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.codec.pem;
import botan.filters.data_src;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import std.file;

static if (BOTAN_HAS_X509_CERTIFICATES):

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

    final X509Certificate findCert()(in X509DN subject_dn, const auto ref Vector!ubyte key_id) const {
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
            {
                try
                    addFromFile(name);
                catch (Exception)
                {}
            }
        }
    }

    this() {}

    /**
    * Load every CERTIFICATE / X509 CERTIFICATE / TRUSTED CERTIFICATE
    * block from a PEM bundle, or a single DER certificate. Duplicates
    * are ignored (same as addCertificate).
    */
    void addFromFile(in string path)
    {
        auto loaded = loadCertificatesFromFile(path);
        foreach (cert; loaded[])
            addCertificate(cert);
    }

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
            subjects.pushBack(subj_dn.clone);
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
            subjects.pushBack(cert.subjectDn().clone);
        return subjects.move;
    }

    override X509Certificate findCertRef(in X509DN subject_dn, const ref Vector!ubyte key_id) const
    {
        return certSearch(subject_dn, key_id, m_certs);
    }
private:
    Vector!X509Certificate m_certs;
}

/**
* Decode every PEM certificate object in `source`. Non-certificate
* labels are skipped. A trailing DecodingError (no further PEM header)
* ends the scan, matching C++ Flatfile_Certificate_Store.
*/
Vector!X509Certificate decodeAllPemCertificates(DataSource source)
{
    Vector!X509Certificate certs;
    while (!source.endOfData())
    {
        try
        {
            string label;
            auto der = unlock(PEM.decode(source, label));
            if (label == "CERTIFICATE" || label == "X509 CERTIFICATE" || label == "TRUSTED CERTIFICATE")
                certs.pushBack(X509Certificate(der));
        }
        catch (DecodingError)
        {
            break;
        }
    }
    return certs.move;
}

/**
* Load certificates from a regular file.
* PEM: every certificate block. DER: the single certificate.
*/
Vector!X509Certificate loadCertificatesFromFile(in string path)
{
    if (path.length == 0)
        throw new InvalidArgument("loadCertificatesFromFile: empty path");
    if (!exists(path) || !isFile(path))
        throw new InvalidArgument("loadCertificatesFromFile: not a file: " ~ path);

    auto raw = cast(const(ubyte)[]) read(path);
    if (raw.length == 0)
        return Vector!X509Certificate();

    auto src = DataSourceMemory(raw.ptr, raw.length);
    if (PEM.matches(cast(DataSource) src))
        return decodeAllPemCertificates(cast(DataSource) src);

    Vector!ubyte der;
    der.insert(raw);
    Vector!X509Certificate certs;
    certs.pushBack(X509Certificate(der));
    return certs.move;
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