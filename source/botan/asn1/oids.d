/**
* OID Registry
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.asn1.oids;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.asn1_oid;
import memutils.hashmap;
import botan.utils.types;
import core.sys.posix.signal;
import core.sys.posix.unistd;

struct OIDS {

private static:
    void addOidstr(string oidstr, string name)
    {
        addOid(OID(oidstr), name);
    }    
    
    void addOid(in OID oid, in string name)
    {
        globalOidMap().addOid(oid, name);
    }

    /**
    * Register an OID to string mapping.
    * 
    * Params:
    *  oid = the oid to register
    *  name = the name to be associated with the oid
    */
    void addOid2str(in OID oid, in string name)
    {
        globalOidMap().addOid2str(oid, name);
    }


    /// ditto
    void addStr2oid(in OID oid, in string name)
    {
        globalOidMap().addStr2oid(oid, name);
    }

public:
    /**
    * See if an OID exists in the internal table.
    * 
    * Params:
    *  oid = the oid to check for
    * 
    * Returns: true if the oid is registered
    */
    bool haveOid(in string name)
    {
        return globalOidMap().haveOid(name);
    }

    /**
    * Resolve an OID
    * 
    * Params:
    *  oid = the OID to look up
    * 
    * Returns: name associated with this OID
    */
    string lookup(in OID oid)
    {
        return globalOidMap().lookup(oid);
    }

    /**
    * Find the OID to a name. The lookup will be performed in the
    * general OID section of the configuration.
    * 
    * Params:
    *  name = the name to resolve
    * 
    * Returns: OID associated with the specified name
    */
    OID lookup(in string name)
    {
        return globalOidMap().lookup(name);
    }

    /**
    * Tests whether the specified OID stands for the specified name.
    * 
    * Params:
    *  oid = the OID to check
    *  name = the name to check
    * 
    * Returns: true if the specified OID stands for the specified name
    */
    bool nameOf(in OID oid, in string name)
    {
        return (oid == lookup(name));
    }

    /*
    * Load all of the default OIDs
    */
    static void setDefaults()
    {
        /* Public key types */
        addOidstr("1.2.840.113549.1.1.1", "RSA");
        assert(lookup(OID("1.2.840.113549.1.1.1")) == "RSA");
        addOidstr("2.5.8.1.1", "RSA"); // RSA alternate
        addOidstr("1.2.840.10040.4.1", "DSA");
        assert(lookup(OID("1.2.840.10040.4.1")) == "DSA");
        addOidstr("1.2.840.10046.2.1", "DH");
        addOidstr("1.3.6.1.4.1.3029.1.2.1", "ElGamal");
        addOidstr("1.3.6.1.4.1.25258.1.1", "RW");
        addOidstr("1.3.6.1.4.1.25258.1.2", "NR");
        
        // X9.62 ecPublicKey, valid for ECDSA and ECDH (RFC 3279 sec 2.3.5)
        addOidstr("1.2.840.10045.2.1", "ECDSA");
        
        /*
        * This is an OID defined for ECDH keys though rarely used for such.
        * In this configuration it is accepted on decoding, but not used for
        * encoding. You can enable it for encoding by calling
        * OIDS.addStr2oid("ECDH", "1.3.132.1.12")
        * from your application code.
        */
        addOid2str(OID("1.3.132.1.12"), "ECDH");
        
        addOidstr("1.2.643.2.2.19", "GOST-34.10"); // RFC 4491
        
        /* Ciphers */
        addOidstr("1.3.14.3.2.7", "DES/CBC");
        addOidstr("1.2.840.113549.3.7", "TripleDES/CBC");
        addOidstr("1.2.840.113549.3.2", "RC2/CBC");
        addOidstr("1.2.840.113533.7.66.10", "CAST-128/CBC");
        addOidstr("2.16.840.1.101.3.4.1.2", "AES-128/CBC");
        addOidstr("2.16.840.1.101.3.4.1.22", "AES-192/CBC");
        addOidstr("2.16.840.1.101.3.4.1.42", "AES-256/CBC");
        addOidstr("1.2.410.200004.1.4", "SEED/CBC"); // RFC 4010
        addOidstr("1.3.6.1.4.1.25258.3.1", "Serpent/CBC");
        
        /* Hash Functions */
        addOidstr("1.2.840.113549.2.5", "MD5");
        addOidstr("1.3.6.1.4.1.11591.12.2", "Tiger(24,3)");
        
        addOidstr("1.3.14.3.2.26", "SHA-160");
        addOidstr("2.16.840.1.101.3.4.2.4", "SHA-224");
        addOidstr("2.16.840.1.101.3.4.2.1", "SHA-256");
        addOidstr("2.16.840.1.101.3.4.2.2", "SHA-384");
        addOidstr("2.16.840.1.101.3.4.2.3", "SHA-512");
        
        /* MACs */
        addOidstr("1.2.840.113549.2.7", "HMAC(SHA-160)");
        addOidstr("1.2.840.113549.2.8", "HMAC(SHA-224)");
        addOidstr("1.2.840.113549.2.9", "HMAC(SHA-256)");
        addOidstr("1.2.840.113549.2.10", "HMAC(SHA-384)");
        addOidstr("1.2.840.113549.2.11", "HMAC(SHA-512)");
        
        /* Key Wrap */
        addOidstr("1.2.840.113549.1.9.16.3.6", "KeyWrap.TripleDES");
        addOidstr("1.2.840.113549.1.9.16.3.7", "KeyWrap.RC2");
        addOidstr("1.2.840.113533.7.66.15", "KeyWrap.CAST-128");
        addOidstr("2.16.840.1.101.3.4.1.5", "KeyWrap.AES-128");
        addOidstr("2.16.840.1.101.3.4.1.25", "KeyWrap.AES-192");
        addOidstr("2.16.840.1.101.3.4.1.45", "KeyWrap.AES-256");
        
        /* Compression */
        addOidstr("1.2.840.113549.1.9.16.3.8", "Compression.Zlib");
        
        /* Public key signature schemes */
        addOidstr("1.2.840.113549.1.1.1", "RSA/EME-PKCS1-v1_5");
        addOidstr("1.2.840.113549.1.1.2", "RSA/EMSA3(MD2)");
        addOidstr("1.2.840.113549.1.1.4", "RSA/EMSA3(MD5)");
        addOidstr("1.2.840.113549.1.1.5", "RSA/EMSA3(SHA-160)");
        addOidstr("1.2.840.113549.1.1.11", "RSA/EMSA3(SHA-256)");
        addOidstr("1.2.840.113549.1.1.12", "RSA/EMSA3(SHA-384)");
        addOidstr("1.2.840.113549.1.1.13", "RSA/EMSA3(SHA-512)");
        addOidstr("1.3.36.3.3.1.2", "RSA/EMSA3(RIPEMD-160)");
        
        addOidstr("1.2.840.10040.4.3", "DSA/EMSA1(SHA-160)");
        addOidstr("2.16.840.1.101.3.4.3.1", "DSA/EMSA1(SHA-224)");
        addOidstr("2.16.840.1.101.3.4.3.2", "DSA/EMSA1(SHA-256)");
        
        addOidstr("0.4.0.127.0.7.1.1.4.1.1", "ECDSA/EMSA1_BSI(SHA-160)");
        addOidstr("0.4.0.127.0.7.1.1.4.1.2", "ECDSA/EMSA1_BSI(SHA-224)");
        addOidstr("0.4.0.127.0.7.1.1.4.1.3", "ECDSA/EMSA1_BSI(SHA-256)");
        addOidstr("0.4.0.127.0.7.1.1.4.1.4", "ECDSA/EMSA1_BSI(SHA-384)");
        addOidstr("0.4.0.127.0.7.1.1.4.1.5", "ECDSA/EMSA1_BSI(SHA-512)");
        addOidstr("0.4.0.127.0.7.1.1.4.1.6", "ECDSA/EMSA1_BSI(RIPEMD-160)");
        
        addOidstr("1.2.840.10045.4.1", "ECDSA/EMSA1(SHA-160)");
        addOidstr("1.2.840.10045.4.3.1", "ECDSA/EMSA1(SHA-224)");
        addOidstr("1.2.840.10045.4.3.2", "ECDSA/EMSA1(SHA-256)");
        addOidstr("1.2.840.10045.4.3.3", "ECDSA/EMSA1(SHA-384)");
        addOidstr("1.2.840.10045.4.3.4", "ECDSA/EMSA1(SHA-512)");
        
        addOidstr("1.2.643.2.2.3", "GOST-34.10/EMSA1(GOST-R-34.11-94)");
        
        addOidstr("1.3.6.1.4.1.25258.2.1.1.1", "RW/EMSA2(RIPEMD-160)");
        addOidstr("1.3.6.1.4.1.25258.2.1.1.2", "RW/EMSA2(SHA-160)");
        addOidstr("1.3.6.1.4.1.25258.2.1.1.3", "RW/EMSA2(SHA-224)");
        addOidstr("1.3.6.1.4.1.25258.2.1.1.4", "RW/EMSA2(SHA-256)");
        addOidstr("1.3.6.1.4.1.25258.2.1.1.5", "RW/EMSA2(SHA-384)");
        addOidstr("1.3.6.1.4.1.25258.2.1.1.6", "RW/EMSA2(SHA-512)");
        
        addOidstr("1.3.6.1.4.1.25258.2.1.2.1", "RW/EMSA4(RIPEMD-160)");
        addOidstr("1.3.6.1.4.1.25258.2.1.2.2", "RW/EMSA4(SHA-160)");
        addOidstr("1.3.6.1.4.1.25258.2.1.2.3", "RW/EMSA4(SHA-224)");
        addOidstr("1.3.6.1.4.1.25258.2.1.2.4", "RW/EMSA4(SHA-256)");
        addOidstr("1.3.6.1.4.1.25258.2.1.2.5", "RW/EMSA4(SHA-384)");
        addOidstr("1.3.6.1.4.1.25258.2.1.2.6", "RW/EMSA4(SHA-512)");
        
        addOidstr("1.3.6.1.4.1.25258.2.2.1.1", "NR/EMSA2(RIPEMD-160)");
        addOidstr("1.3.6.1.4.1.25258.2.2.1.2", "NR/EMSA2(SHA-160)");
        addOidstr("1.3.6.1.4.1.25258.2.2.1.3", "NR/EMSA2(SHA-224)");
        addOidstr("1.3.6.1.4.1.25258.2.2.1.4", "NR/EMSA2(SHA-256)");
        addOidstr("1.3.6.1.4.1.25258.2.2.1.5", "NR/EMSA2(SHA-384)");
        addOidstr("1.3.6.1.4.1.25258.2.2.1.6", "NR/EMSA2(SHA-512)");
        
        addOidstr("2.5.4.3",  "X520.CommonName");
        addOidstr("2.5.4.4",  "X520.Surname");
        addOidstr("2.5.4.5",  "X520.SerialNumber");
        addOidstr("2.5.4.6",  "X520.Country");
        addOidstr("2.5.4.7",  "X520.Locality");
        addOidstr("2.5.4.8",  "X520.State");
        addOidstr("2.5.4.10", "X520.Organization");
        addOidstr("2.5.4.11", "X520.OrganizationalUnit");
        addOidstr("2.5.4.12", "X520.Title");
        addOidstr("2.5.4.42", "X520.GivenName");
        addOidstr("2.5.4.43", "X520.Initials");
        addOidstr("2.5.4.44", "X520.GenerationalQualifier");
        addOidstr("2.5.4.46", "X520.DNQualifier");
        addOidstr("2.5.4.65", "X520.Pseudonym");
        
        addOidstr("1.2.840.113549.1.5.12", "PKCS5.PBKDF2");
        addOidstr("1.2.840.113549.1.5.13", "PBE-PKCS5v20");
        
        addOidstr("1.2.840.113549.1.9.1", "PKCS9.EmailAddress");
        addOidstr("1.2.840.113549.1.9.2", "PKCS9.UnstructuredName");
        addOidstr("1.2.840.113549.1.9.3", "PKCS9.ContentType");
        addOidstr("1.2.840.113549.1.9.4", "PKCS9.MessageDigest");
        addOidstr("1.2.840.113549.1.9.7", "PKCS9.ChallengePassword");
        addOidstr("1.2.840.113549.1.9.14", "PKCS9.ExtensionRequest");
        
        addOidstr("1.2.840.113549.1.7.1",        "CMS.DataContent");
        addOidstr("1.2.840.113549.1.7.2",        "CMS.SignedData");
        addOidstr("1.2.840.113549.1.7.3",        "CMS.EnvelopedData");
        addOidstr("1.2.840.113549.1.7.5",        "CMS.DigestedData");
        addOidstr("1.2.840.113549.1.7.6",        "CMS.EncryptedData");
        addOidstr("1.2.840.113549.1.9.16.1.2", "CMS.AuthenticatedData");
        addOidstr("1.2.840.113549.1.9.16.1.9", "CMS.CompressedData");
        
        addOidstr("2.5.29.14", "X509v3.SubjectKeyIdentifier");
        addOidstr("2.5.29.15", "X509v3.KeyUsage");
        addOidstr("2.5.29.17", "X509v3.SubjectAlternativeName");
        addOidstr("2.5.29.18", "X509v3.IssuerAlternativeName");
        addOidstr("2.5.29.19", "X509v3.BasicConstraints");
        addOidstr("2.5.29.20", "X509v3.CRLNumber");
        addOidstr("2.5.29.21", "X509v3.ReasonCode");
        addOidstr("2.5.29.23", "X509v3.HoldInstructionCode");
        addOidstr("2.5.29.24", "X509v3.InvalidityDate");
        addOidstr("2.5.29.31", "X509v3.CRLDistributionPoints");
        addOidstr("2.5.29.32", "X509v3.CertificatePolicies");
        addOidstr("2.5.29.35", "X509v3.AuthorityKeyIdentifier");
        addOidstr("2.5.29.36", "X509v3.PolicyConstraints");
        addOidstr("2.5.29.37", "X509v3.ExtendedKeyUsage");
        addOidstr("1.3.6.1.5.5.7.1.1", "PKIX.AuthorityInformationAccess");
        
        addOidstr("2.5.29.32.0", "X509v3.AnyPolicy");
        
        addOidstr("1.3.6.1.5.5.7.3.1", "PKIX.ServerAuth");
        addOidstr("1.3.6.1.5.5.7.3.2", "PKIX.ClientAuth");
        addOidstr("1.3.6.1.5.5.7.3.3", "PKIX.CodeSigning");
        addOidstr("1.3.6.1.5.5.7.3.4", "PKIX.EmailProtection");
        addOidstr("1.3.6.1.5.5.7.3.5", "PKIX.IPsecEndSystem");
        addOidstr("1.3.6.1.5.5.7.3.6", "PKIX.IPsecTunnel");
        addOidstr("1.3.6.1.5.5.7.3.7", "PKIX.IPsecUser");
        addOidstr("1.3.6.1.5.5.7.3.8", "PKIX.TimeStamping");
        addOidstr("1.3.6.1.5.5.7.3.9", "PKIX.OCSPSigning");
        
        addOidstr("1.3.6.1.5.5.7.8.5", "PKIX.XMPPAddr");
        
        addOidstr("1.3.6.1.5.5.7.48.1", "PKIX.OCSP");
        addOidstr("1.3.6.1.5.5.7.48.1.1", "PKIX.OCSP.BasicResponse");
        
        /* ECC domain parameters */
        addOidstr("1.3.132.0.6",  "secp112r1");
        addOidstr("1.3.132.0.7",  "secp112r2");
        addOidstr("1.3.132.0.8",  "secp160r1");
        addOidstr("1.3.132.0.9",  "secp160k1");
        addOidstr("1.3.132.0.10", "secp256k1");
        addOidstr("1.3.132.0.28", "secp128r1");
        addOidstr("1.3.132.0.29", "secp128r2");
        addOidstr("1.3.132.0.30", "secp160r2");
        addOidstr("1.3.132.0.31", "secp192k1");
        addOidstr("1.3.132.0.32", "secp224k1");
        addOidstr("1.3.132.0.33", "secp224r1");
        addOidstr("1.3.132.0.34", "secp384r1");
        addOidstr("1.3.132.0.35", "secp521r1");
        
        addOidstr("1.2.840.10045.3.1.1", "secp192r1");
        addOidstr("1.2.840.10045.3.1.2", "x962_p192v2");
        addOidstr("1.2.840.10045.3.1.3", "x962_p192v3");
        addOidstr("1.2.840.10045.3.1.4", "x962_p239v1");
        addOidstr("1.2.840.10045.3.1.5", "x962_p239v2");
        addOidstr("1.2.840.10045.3.1.6", "x962_p239v3");
        addOidstr("1.2.840.10045.3.1.7", "secp256r1");
        
        addOidstr("1.3.36.3.3.2.8.1.1.1",  "brainpool160r1");
        addOidstr("1.3.36.3.3.2.8.1.1.3",  "brainpool192r1");
        addOidstr("1.3.36.3.3.2.8.1.1.5",  "brainpool224r1");
        addOidstr("1.3.36.3.3.2.8.1.1.7",  "brainpool256r1");
        addOidstr("1.3.36.3.3.2.8.1.1.9",  "brainpool320r1");
        addOidstr("1.3.36.3.3.2.8.1.1.11", "brainpool384r1");
        addOidstr("1.3.36.3.3.2.8.1.1.13", "brainpool512r1");
        
        addOidstr("1.2.643.2.2.35.1", "gost_256A");
        addOidstr("1.2.643.2.2.36.0", "gost_256A");
        
        /* CVC */
        addOidstr("0.4.0.127.0.7.3.1.2.1", "CertificateHolderAuthorizationTemplate");
    }
}

struct OIDMap
{
public:
    void addOid(in OID oid, in string str)
    {
        //logTrace("addOid: ", str);
        addStr2oid(oid, str);
        addOid2str(oid, str);
    }
    
    void addStr2oid(in OID oid, in string str)
    {
        if (!haveOid(str))
            m_str2oid[str] = oid;
    }
    
    void addOid2str(in OID oid, in string str)
    {
        if (m_oid2str.get(oid) == string.init) 
            m_oid2str[oid] = str;
    }

    string lookup(in OID oid)
    {
        auto str = m_oid2str.get(oid, string.init);
        //scope(exit) logTrace("OID lookup found: ", str);
        if (str)
            return str;
        
        return string.init;
    }
    
    OID lookup(in string str)
    {

        if (str in m_str2oid)
            return m_str2oid[str];
        
        // Try to parse as plain OID
        try
        {
            return OID(str);
        }
        catch {}
        
        throw new LookupError("No object identifier found for " ~ str);
    }
    
    bool haveOid(in string str)
    {
        return (str in m_str2oid) !is null;
    }
    
private:
    HashMap!(string, OID) m_str2oid;
    HashMap!(OID, string) m_oid2str;
}

ref OIDMap globalOidMap()
{
    static OIDMap map;

    return map;
}
