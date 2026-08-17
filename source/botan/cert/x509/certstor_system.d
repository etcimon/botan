/**
* System Certificate Store (OS trust anchors)
*
* Copyright:
* (C) 2019 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.certstor_system;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES && BOTAN_HAS_CERTSTORE_SYSTEM):

import botan.cert.x509.certstor;
import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.utils.exceptn;
import botan.utils.types;

/**
* Certificate store backed by the operating system's trust store.
*
* Windows: CryptoAPI `Root` and `CA` system stores.
* POSIX: first existing well-known CA bundle path (Debian/RHEL/macOS).
*
* Not added to TLS credentials unless the application constructs one
* (tests stay deterministic).
*/
final class CertificateStoreSystem : CertificateStore
{
public:
    this()
    {
        version (Windows)
            loadWindowsStores();
        else
            loadPosixBundle();

        if (m_certs.empty)
            throw new InvalidState("CertificateStoreSystem: no certificates in the OS trust store");
    }

    override Vector!X509DN allSubjects() const
    {
        Vector!X509DN subjects;
        foreach (ref cert; m_certs[])
            subjects.pushBack(cert.subjectDn().clone);
        return subjects;
    }

    override X509Certificate findCertRef(in X509DN subject_dn, const ref Vector!ubyte key_id) const
    {
        return certSearch(subject_dn, key_id, m_certs);
    }

    override X509CRL findCrlFor(in X509Certificate) const
    {
        return X509CRL.init;
    }

private:
    void addParsed(X509Certificate cert)
    {
        if (!*cert)
            return;
        foreach (stored; m_certs[])
        {
            if (stored == cert)
                return;
        }
        m_certs.pushBack(cert);
    }

    version (Windows)
    {
        void loadWindowsStores()
        {
            foreach (name; ["Root", "CA"])
            {
                auto store = CertOpenSystemStoreA(null, name.ptr);
                if (store is null)
                    continue;
                scope (exit)
                    CertCloseStore(store, 0);

                CERT_CONTEXT* prev = null;
                while (true)
                {
                    auto ctx = CertEnumCertificatesInStore(store, prev);
                    prev = ctx;
                    if (ctx is null)
                        break;
                    try
                    {
                        Vector!ubyte der;
                        der.insert(ctx.pbCertEncoded[0 .. ctx.cbCertEncoded]);
                        addParsed(X509Certificate(der, false));
                    }
                    catch (Exception)
                    {}
                }
            }
        }
    }
    else
    {
        void loadPosixBundle()
        {
            import std.file : exists, isFile;
            foreach (path; posixSystemBundlePaths())
            {
                if (!exists(path) || !isFile(path))
                    continue;
                try
                {
                    auto loaded = loadCertificatesFromFile(path);
                    foreach (cert; loaded[])
                        addParsed(cert);
                    if (!m_certs.empty)
                        return;
                }
                catch (Exception)
                {}
            }
        }
    }

    Vector!X509Certificate m_certs;
}

/// Well-known CA bundle locations (Debian, RHEL, generic OpenSSL, Homebrew).
string[] posixSystemBundlePaths()
{
    return [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/opt/homebrew/etc/openssl@3/cert.pem",
    ];
}

version (Windows)
{
    private:
    alias HCERTSTORE = void*;
    struct CERT_CONTEXT
    {
        uint dwCertEncodingType;
        ubyte* pbCertEncoded;
        uint cbCertEncoded;
        void* pCertInfo;
        HCERTSTORE hCertStore;
    }

    extern (Windows)
    {
        HCERTSTORE CertOpenSystemStoreA(void* hprov, const(char)* szSubsystemProtocol);
        int CertCloseStore(HCERTSTORE hCertStore, uint dwFlags);
        CERT_CONTEXT* CertEnumCertificatesInStore(HCERTSTORE hCertStore, CERT_CONTEXT* pPrevCertContext);
    }
}
