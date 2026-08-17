/**
* Flatfile Certificate Store (PEM bundle of trusted CAs)
*
* Copyright:
* (C) 1999-2019 Jack Lloyd
* (C) 2019      Patrick Schmidt
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.certstor_flatfile;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES && BOTAN_HAS_CERTSTORE_FLATFILE):

import botan.cert.x509.certstor;
import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.utils.exceptn;
import botan.utils.types;

/**
* Certificate store backed by one PEM/DER file of trusted CAs.
*
* Matches C++ Flatfile_Certificate_Store: only self-signed CA
* certificates are kept. Set ignore_non_ca to skip other objects
* instead of throwing (system roots sometimes contain intermediates).
*/
final class CertificateStoreFlatfile : CertificateStore
{
public:
    /**
    * Params:
    *  file = path to a PEM bundle or a single DER certificate
    *  ignore_non_ca = if true, skip certs that are not self-signed CAs;
    *                  if false (default), throw InvalidArgument
    */
    this(in string file, bool ignore_non_ca = false)
    {
        if (file.length == 0)
            throw new InvalidArgument("CertificateStoreFlatfile: invalid file path");

        auto loaded = loadCertificatesFromFile(file);
        foreach (cert; loaded[])
        {
            if (cert.isSelfSigned() && cert.isCACert())
            {
                bool seen = false;
                foreach (stored; m_certs[])
                {
                    if (stored == cert)
                    {
                        seen = true;
                        break;
                    }
                }
                if (!seen)
                    m_certs.pushBack(cert);
            }
            else if (!ignore_non_ca)
            {
                throw new InvalidArgument("CertificateStoreFlatfile received non CA cert "
                    ~ cert.subjectDn().toString());
            }
        }

        if (m_certs.empty)
            throw new InvalidArgument("CertificateStoreFlatfile: cert file is empty");
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
    Vector!X509Certificate m_certs;
}
