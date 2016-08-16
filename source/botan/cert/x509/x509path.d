/**
* X.509 Cert Path Validation
* 
* Copyright:
* (C) 2010-2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.x509path;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

public import botan.cert.x509.ocsp;
public import botan.cert.x509.x509_crl;
import botan.cert.x509.key_constraint;
import botan.utils.http_util.http_util;
import botan.utils.parsing;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.asn1.asn1_time;
import std.algorithm;
import std.datetime;
import botan.utils.types;
import memutils.rbtree : RBTreeRef, RBTree;
//version(Have_vibe_d) {
//    import vibe.core.concurrency;
//}
//else {
    import core.thread;
//}
import botan.cert.x509.cert_status;
import botan.cert.x509.x509cert;
import core.sync.mutex;

/**
* Specifies restrictions on the PKIX path validation
*/
struct PathValidationRestrictions
{
public:
    /**
    * Params:
    *  require_rev = if true, revocation information is required
    *  key_strength = is the minimum strength (in terms of
    *          operations, eg 80 means 2^80) of a signature. Signatures
    *          weaker than this are rejected. If more than 80, SHA-1
    *          signatures are also rejected.
    *  ocsp_all = where to use all intermediates
    */
    this(bool require_rev, size_t key_strength = 80, bool ocsp_all = false, int max_cert_chain_length = 9) 
    {
        m_require_revocation_information = require_rev;
        m_ocsp_all_intermediates = ocsp_all;
        m_minimum_key_strength = key_strength;
        if (key_strength <= 80)
            m_trusted_hashes.insert("SHA-160");
        
        m_trusted_hashes.insert("SHA-224");
        m_trusted_hashes.insert("SHA-256");
        m_trusted_hashes.insert("SHA-384");
        m_trusted_hashes.insert("SHA-512");
    }

    /**
    * Params:
    *  require_rev = if true, revocation information is required
    *  minimum_key_strength = is the minimum strength (in terms of
    *          operations, eg 80 means 2^80) of a signature. Signatures
    *          weaker than this are rejected.
    *  ocsp_all_intermediates = where to use all intermediates
    *  trusted_hashes = a set of trusted hashes. Any signatures
    *          created using a hash other than one of these will be
    *          rejected.
    */
    this(bool require_rev, 
         size_t minimum_key_strength, 
         bool ocsp_all_intermediates, 
		 RBTreeRef!string trusted_hashes, 
		 int max_cert_chain_length = 9) 
    {
        m_require_revocation_information = require_rev;
        m_ocsp_all_intermediates = ocsp_all_intermediates;
        m_trusted_hashes.insert((*trusted_hashes)[]);
        m_minimum_key_strength = minimum_key_strength;
    }

	@property int maxCertChainLength() const { return m_max_cert_chain_length; }
	@property void maxCertChainLength(int sz) { m_max_cert_chain_length = sz; }

    bool requireRevocationInformation() const
    { return m_require_revocation_information; }

    bool ocspAllIntermediates() const
    { return m_ocsp_all_intermediates; }

    ref const(RBTree!string) trustedHashes() const
    { 
		if (m_trusted_hashes.length > 0)
			return m_trusted_hashes;
		return m_def_trusted_hashes;
	}

    size_t minimumKeyStrength() const
    { return m_minimum_key_strength; }

private:
    bool m_require_revocation_information = false;
    bool m_ocsp_all_intermediates = false;
	int m_max_cert_chain_length = 9;
	RBTree!string m_trusted_hashes;
    size_t m_minimum_key_strength = 80;

	static this() {
		m_def_trusted_hashes.insert("SHA-160");		
		m_def_trusted_hashes.insert("SHA-224");
		m_def_trusted_hashes.insert("SHA-256");
		m_def_trusted_hashes.insert("SHA-384");
		m_def_trusted_hashes.insert("SHA-512");
	}
	static ~this() {
		m_def_trusted_hashes.clear();
		m_def_trusted_hashes.destroy();
	}
	static RBTree!string m_def_trusted_hashes;
}

/**
* Represents the result of a PKIX path validation
*/
struct PathValidationResult
{
public:
    alias Code = CertificateStatusCode;

    /**
    * Returns: the set of hash functions you are implicitly
    * trusting by trusting this result.
    */
    RBTreeRef!string trustedHashes() const
    {
        RBTreeRef!string hashes;
        foreach (cert_path; m_cert_path[])
            hashes.insert(cert_path.hashUsedForSignature());
        return hashes;
    }

    /**
    * Returns: the trust root of the validation
    */
    X509Certificate trustRoot() const
    {
        import std.range : back;
        if (m_cert_path.length == 0) return X509Certificate.init;
        return m_cert_path[].back;
    }

    /**
    * Returns: the full path from subject to trust root
    */
    ref const(Vector!X509Certificate) certPath() const { return m_cert_path; }

    /**
    * Returns: true iff the validation was succesful
    */
    bool successfulValidation() const
    {
        if (result() == CertificateStatusCode.VERIFIED ||
            result() == CertificateStatusCode.OCSP_RESPONSE_GOOD)
            return true;
        return false;
    }

    /**
    * Returns: overall validation result code
    */
    CertificateStatusCode result() const { return m_overall; }

    /**
    * Return a set of status codes for each certificate in the chain
    */
    ref const(Vector!(RBTreeRef!CertificateStatusCode)) allStatuses() const
    { return m_all_status; }

    /**
    * Returns: string representation of the validation result
    */
    string resultString() const
    {
        return statusString(result());
    }


    static string statusString(CertificateStatusCode code)
    {
        switch(code)
        {
            case CertificateStatusCode.VERIFIED:
                return "Verified";
            case CertificateStatusCode.OCSP_RESPONSE_GOOD:
                return "OCSP response good";
            case CertificateStatusCode.NO_REVOCATION_DATA:
                return "No revocation data";
            case CertificateStatusCode.SIGNATURE_METHOD_TOO_WEAK:
                return "Signature method too weak";
            case CertificateStatusCode.UNTRUSTED_HASH:
                return "Untrusted hash";
                
            case CertificateStatusCode.CERT_NOT_YET_VALID:
                return "Certificate is not yet valid";
            case CertificateStatusCode.CERT_HAS_EXPIRED:
                return "Certificate has expired";
            case CertificateStatusCode.OCSP_NOT_YET_VALID:
                return "OCSP is not yet valid";
            case CertificateStatusCode.OCSP_HAS_EXPIRED:
                return "OCSP has expired";
            case CertificateStatusCode.CRL_NOT_YET_VALID:
                return "CRL is not yet valid";
            case CertificateStatusCode.CRL_HAS_EXPIRED:
                return "CRL has expired";
                
            case CertificateStatusCode.CERT_ISSUER_NOT_FOUND:
                return "Certificate issuer not found";
            case CertificateStatusCode.CANNOT_ESTABLISH_TRUST:
                return "Cannot establish trust";
                
            case CertificateStatusCode.POLICY_ERROR:
                return "TLSPolicy error";
            case CertificateStatusCode.INVALID_USAGE:
                return "Invalid usage";
            case CertificateStatusCode.CERT_CHAIN_TOO_LONG:
                return "Certificate chain too long";
            case CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER:
                return "CA certificate not allowed to issue certs";
            case CertificateStatusCode.CA_CERT_NOT_FOR_CRL_ISSUER:
                return "CA certificate not allowed to issue CRLs";
            case CertificateStatusCode.OCSP_CERT_NOT_LISTED:
                return "OCSP cert not listed";
            case CertificateStatusCode.OCSP_BAD_STATUS:
                return "OCSP bad status";
                
            case CertificateStatusCode.CERT_IS_REVOKED:
                return "Certificate is revoked";
            case CertificateStatusCode.CRL_BAD_SIGNATURE:
                return "CRL bad signature";
            case CertificateStatusCode.SIGNATURE_ERROR:
                return "Signature error";
            default:
                return "Unknown error";
        }
    }

    this()(auto ref Vector!(RBTreeRef!CertificateStatusCode ) status,
           auto ref Vector!X509Certificate cert_chain)
    {
        int i = 1;
        m_overall = CertificateStatusCode.VERIFIED;
        // take the "worst" error as overall
        foreach (ref s; status[])
        {
            if (!s.empty)
            {
                auto worst = s.back;
                // Leave OCSP confirmations on cert-level status only
                if (worst != CertificateStatusCode.OCSP_RESPONSE_GOOD)
                    m_overall = worst;
            }
        }
        m_all_status = status.move();
        m_cert_path = cert_chain.move();
    }


    this(CertificateStatusCode status)  { m_overall = status; }

private:
    CertificateStatusCode m_overall;
    Vector!( RBTreeRef!CertificateStatusCode ) m_all_status;
    Vector!X509Certificate m_cert_path;
}

/**
* PKIX Path Validation
*/
PathValidationResult 
    x509PathValidate()(const ref Vector!X509Certificate end_certs,
                       auto const ref PathValidationRestrictions restrictions,
                       const ref Vector!CertificateStore certstores)
{
	const size_t max_iterations = restrictions.maxCertChainLength();
    if (end_certs.empty) 
        throw new InvalidArgument("x509PathValidate called with no subjects");
    Vector!X509Certificate cert_path = Vector!X509Certificate();
    cert_path.pushBack(end_certs[0]);

    Unique!CertificateStoreOverlay extra = new CertificateStoreOverlay(end_certs);
    CertificateStore cert_store = cast(CertificateStore)*extra;
	size_t i;
    // iterate until we reach a root or cannot find the issuer
    while (!cert_path.back().isSelfSigned() && ++i < max_iterations)
    {
        X509Certificate cert = findIssuingCert(cert_path.back(), cert_store, certstores);
        if (!cert) {
            return PathValidationResult(CertificateStatusCode.CERT_ISSUER_NOT_FOUND);
        }
        cert_path.pushBack(cert);
    }
	if (i >= max_iterations)
		throw new PKCS8Exception("Max iterations reached when attempting to find root certificate");
    auto chain = checkChain(cert_path, restrictions, certstores);

    return PathValidationResult(chain, cert_path);
}


/**
* PKIX Path Validation
*/
PathValidationResult x509PathValidate()(in X509Certificate end_cert,
                                        auto const ref PathValidationRestrictions restrictions,
                                        const ref Vector!CertificateStore certstores)
{
    Vector!X509Certificate certs;
    certs.pushBack(cast(X509Certificate)end_cert);
    return x509PathValidate(certs, restrictions, certstores);
}

/**
* PKIX Path Validation
*/
PathValidationResult x509PathValidate()(in X509Certificate end_cert,
                                        auto const ref PathValidationRestrictions restrictions,
                                        in CertificateStore store)
{
    Vector!X509Certificate certs;
    certs.pushBack(cast(X509Certificate)end_cert);
    
    Vector!CertificateStore certstores;
    certstores.pushBack(cast(CertificateStore) store);
    
    return x509PathValidate(certs, restrictions, certstores);
}

/**
* PKIX Path Validation
*/
PathValidationResult x509PathValidate()(const ref Vector!X509Certificate end_certs,
                                        auto const ref PathValidationRestrictions restrictions,
                                        in CertificateStore store)
{
    Vector!CertificateStore certstores;
    certstores.pushBack(cast(CertificateStore)store);
    
    return x509PathValidate(end_certs, restrictions, certstores);
}

X509Certificate findIssuingCert(in X509Certificate cert_,
                                ref CertificateStore end_certs, 
                                const ref Vector!CertificateStore certstores)
{

    const X509DN issuer_dn = cert_.issuerDn();

    const Vector!ubyte auth_key_id = cert_.authorityKeyId();
    
    if (X509Certificate cert = end_certs.findCert(issuer_dn, auth_key_id)) {
        //logTrace("Found certificate: ", cert.toString());
        return cert;
    } 

    foreach (certstore; certstores[])
    {

        if (X509Certificate cert = certstore.findCert(issuer_dn, auth_key_id))
            return cert;
    }
    
    return X509Certificate.init;
}

const(X509CRL) findCrlsFor(in X509Certificate cert,
                           const ref Vector!CertificateStore certstores)
{
    foreach (certstore; certstores[])
    {
        if (const X509CRL crl = certstore.findCrlFor(cert))
            return crl;
    }

    /// todo: use crl distribution point and download the CRL
    version(none) {
        /*
        const string crl_url = cert.crlDistributionPoint();
        if (crl_url != "")
        {
        std::cout << "Downloading CRL " << crl_url << "";
            auto http = HTTP::GET_sync(crl_url);
            
        std::cout << http.status_message() << "";
            
            http.throw_unless_ok();
            // check the mime type
            
            auto crl = X509CRL(http.body());
            
            return crl;
        }*/
    }
    
    return X509CRL.init;
}

Vector!( RBTreeRef!CertificateStatusCode )
    checkChain(const ref Vector!X509Certificate cert_path,
               const ref PathValidationRestrictions restrictions,
               const ref Vector!CertificateStore certstores)
{
	//import core.memory : GC; GC.disable(); scope(exit) GC.enable();
	const RBTree!string* trusted_hashes = &restrictions.trustedHashes();
    
    const bool self_signed_ee_cert = (cert_path.length == 1);
    
    X509Time current_time = X509Time(Clock.currTime(UTC()));
    
    Vector!( Thread ) ocsp_responses;

	scope(exit) foreach (Thread thr; ocsp_responses[]) {
		ThreadMem.free(thr);
	}

    Vector!(OCSPResponse) ocsp_data = Vector!OCSPResponse(8);
    
    Vector!( RBTreeRef!CertificateStatusCode ) cert_status = Vector!( RBTreeRef!CertificateStatusCode )( cert_path.length );
    
    foreach (ref e; cert_status) {
        e.clear(); // touch
    }

    //logTrace("Cert path size: ", cert_path.length);

    foreach (size_t i; 0 .. cert_path.length)
    {
        auto status = &*(cert_status[i]);
        
        const bool at_self_signed_root = (i == cert_path.length - 1);
        
        const X509Certificate subject = cert_path[i];
        
        const X509Certificate issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];
        
        const CertificateStore* trusted = certstores.ptr;
        
		Mutex mtx = new Mutex;

        if (i == 0 || restrictions.ocspAllIntermediates()) {

			if (certstores.length > 1) {

	            //version(Have_vibe_d)
	            //    Tid id_ = runTask(&onlineCheck, cast(shared)Tid.getThis(), cast(shared)i, cast(shared)&ocsp_data[i], cast(shared)&issuer, cast(shared)&subject, cast(shared)trusted);
	            //else
				synchronized(mtx) {
					ocsp_data.length = i + 1;
		            OnlineCheck oc = OnlineCheck( cast(shared)mtx, cast(shared)i,  cast(shared)&ocsp_data[i], cast(shared)&issuer, cast(shared)&subject, cast(shared)trusted );
					Thread thr = ThreadMem.alloc!Thread(&oc.run);
					thr.start();
					ocsp_responses ~= thr;
				}
			}
        }
        // Check all certs for valid time range
        if (current_time < X509Time(subject.startTime()))
            status.insert(CertificateStatusCode.CERT_NOT_YET_VALID);
        
        if (current_time > X509Time(subject.endTime()))
            status.insert(CertificateStatusCode.CERT_HAS_EXPIRED);
        
        // Check issuer constraints
        logTrace("Check issuer constraints");
        // Don't require CA bit set on self-signed end entity cert
        if (!issuer.isCACert() && !self_signed_ee_cert)
            status.insert(CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER);
        
        if (issuer.pathLimit() < i)
            status.insert(CertificateStatusCode.CERT_CHAIN_TOO_LONG);
        const PublicKey issuer_key = issuer.subjectPublicKey();
        logTrace("Got issuer key");
        if (subject.checkSignature(issuer_key) == false)
            status.insert(CertificateStatusCode.SIGNATURE_ERROR);
        logTrace("Get estimated strength");
        if (issuer_key.estimatedStrength() < restrictions.minimumKeyStrength())
            status.insert(CertificateStatusCode.SIGNATURE_METHOD_TOO_WEAK);
        
        logTrace("Scan untrusted hashes");
        // Allow untrusted hashes on self-signed roots
        if (!trusted_hashes.empty && !at_self_signed_root)
        {
            if (subject.hashUsedForSignature() !in *trusted_hashes)
                status.insert(CertificateStatusCode.UNTRUSTED_HASH);
        }
    }
    logTrace("Certificates to check: ", cert_path.length);
    foreach (size_t i; 0 .. cert_path.length - 1)
    {
        logTrace("Checking status ", i);

        auto status = &*(cert_status[i]);
        
        const X509Certificate subject = cert_path[i];
        const X509Certificate ca = cert_path[i+1];
        
        logTrace("Checking response ", i+1, " of ", ocsp_responses.length);
        if (i < ocsp_responses.length)
        {
            try
            {
				ocsp_responses[i].join();
				if (ocsp_data.length <= i) continue;
				OCSPResponse ocsp = ocsp_data[i];
                logTrace("Got response for ID#", i.to!string);
                if (!ocsp || ocsp.empty)
                    throw new Exception("OSCP.responder is undefined");
                auto ocsp_status = ocsp.statusFor(ca, subject);
                
                status.insert(ocsp_status);
                
                logTrace("OCSP status: ", ocsp_status.to!string);
                //std::cout << "OCSP status: " << statusString(ocsp_status) << "\n";
                
                // Either way we have a definitive answer, no need to check CRLs
                if (ocsp_status == CertificateStatusCode.CERT_IS_REVOKED)
                    return cert_status.move();
                else if (ocsp_status == CertificateStatusCode.OCSP_RESPONSE_GOOD)
                    continue;
            }
            catch(Exception e)
            {
                logTrace("OCSP error: " ~ e.msg ~ "");
            }
        }
        
        const X509CRL crl = findCrlsFor(subject, certstores);
        
        if (!crl)
        {
            if (restrictions.requireRevocationInformation())
                status.insert(CertificateStatusCode.NO_REVOCATION_DATA);
            continue;
        }

        if (!ca.allowedUsage(KeyConstraints.CRL_SIGN))
            status.insert(CertificateStatusCode.CA_CERT_NOT_FOR_CRL_ISSUER);
        
        if (current_time < crl.thisUpdate())
            status.insert(CertificateStatusCode.CRL_NOT_YET_VALID);
        
        if (current_time > crl.nextUpdate())
            status.insert(CertificateStatusCode.CRL_HAS_EXPIRED);
		Unique!PublicKey pubkey = ca.subjectPublicKey();
		if (crl.checkSignature(*pubkey) == false)
            status.insert(CertificateStatusCode.CRL_BAD_SIGNATURE);
        
        if (crl.isRevoked(subject))
            status.insert(CertificateStatusCode.CERT_IS_REVOKED);
    }

    if (self_signed_ee_cert)
        cert_status.back().insert(CertificateStatusCode.CANNOT_ESTABLISH_TRUST);
    
    return cert_status.move();
}