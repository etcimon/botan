/**
* OCSP
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.ocsp;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

public import botan.cert.x509.cert_status;
public import botan.cert.x509.certstor;
public import botan.cert.x509.x509cert;
import botan.cert.x509.ocsp_types;
import botan.asn1.asn1_time;
import botan.asn1.x509_dn;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.asn1_obj;
import botan.cert.x509.x509_ext;
import botan.asn1.oids;
import botan.codec.base64;
import botan.pubkey.pubkey;
import botan.cert.x509.x509path;
import botan.utils.http_util.http_util;
import botan.utils.types;
import std.datetime;
import std.algorithm : splitter;
import core.sync.mutex;
import botan.utils.mem_ops;

struct OCSPRequest
{
public:
    @disable this();

    this(X509Certificate issuer_cert,
         X509Certificate subject_cert) 
        
    {
        logTrace("OCSPRequest: Issuer Cert: ", issuer_cert.toString());
        logTrace("OCSPRequest: Subject Cert: ", subject_cert.toString());
        m_issuer = issuer_cert;
        m_subject = subject_cert;
    }

    Vector!ubyte BER_encode() const
    {
        CertID certid = CertID(m_issuer, m_subject);
        
        return DEREncoder().startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .startExplicit(0)
                .encode(cast(size_t)(0)) // version #
                .endExplicit()
                .startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(certid)
                .endCons()
                .endCons()
                .endCons()
                .endCons().getContentsUnlocked();
    }

    string base64Encode() const
    {
        return .base64Encode(BER_encode());
    }

    const(X509Certificate) issuer() const { return m_issuer; }

    const(X509Certificate) subject() const { return m_subject; }
private:
    X509Certificate m_issuer, m_subject;
}

struct OCSPResponse
{
public:
    this(in CertificateStore trusted_roots,
         in string response_bits)
    {
        Vector!ubyte response_vec = Vector!ubyte(response_bits);
        BERDecoder response_outer = BERDecoder(response_vec).startCons(ASN1Tag.SEQUENCE);
        
        size_t resp_status = 0;
        
        response_outer.decode(resp_status, ASN1Tag.ENUMERATED, ASN1Tag.UNIVERSAL);
        
        if (resp_status != 0)
            throw new Exception("OCSP response status " ~ to!string(resp_status));
        
        if (response_outer.moreItems())
        {
            BERDecoder response_bytes = response_outer.startCons((cast(ASN1Tag) 0), ASN1Tag.CONTEXT_SPECIFIC).startCons(ASN1Tag.SEQUENCE);
            
            response_bytes.decodeAndCheck(OID("1.3.6.1.5.5.7.48.1.1"), "Unknown response type in OCSP response");
            
            BERDecoder basicresponse = BERDecoder(response_bytes.getNextOctetString()).startCons(ASN1Tag.SEQUENCE);
            
            Vector!ubyte tbs_bits;
            auto sig_algo = AlgorithmIdentifier();
            Vector!ubyte signature;
            Vector!X509Certificate certs;
            
            basicresponse.startCons(ASN1Tag.SEQUENCE)
                    .rawBytes(tbs_bits)
                    .endCons()
                    .decode(sig_algo)
                    .decode(signature, ASN1Tag.BIT_STRING);

            decodeOptionalList(basicresponse, (cast(ASN1Tag) 0), certs);
            
            size_t responsedata_version;
            X509DN name = X509DN();
            Vector!ubyte key_hash;
            X509Time produced_at;
            X509Extensions extensions;
            
            BERDecoder(tbs_bits)
                    .decodeOptional(responsedata_version, (cast(ASN1Tag) 0), ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC)
                    .decodeOptional(name, (cast(ASN1Tag)1), ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC)                    
                    .decodeOptionalString(key_hash, ASN1Tag.OCTET_STRING, 2, ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC)
                    .decode(produced_at)
                    .decodeList(m_responses)
                    .decodeOptional(extensions, (cast(ASN1Tag)1), ASN1Tag.CONSTRUCTED | ASN1Tag.CONTEXT_SPECIFIC);
            
            if (certs.empty)
            {
                if (auto cert = trusted_roots.findCert(name, Vector!ubyte()))
                    certs.pushBack(cert);
                else
                    throw new Exception("Could not find certificate that signed OCSP response");
            }
            
            checkSignature(tbs_bits, sig_algo, signature, trusted_roots, certs);
        }
        
        response_outer.endCons();
    }

    CertificateStatusCode statusFor(in X509Certificate issuer,
                                    in X509Certificate subject) const
    {
        //logTrace("Responses: ", m_responses.length);
        foreach (response; m_responses[])
        {
            if (response.certid().isIdFor(issuer, subject))
            {
                X509Time current_time = X509Time(Clock.currTime());
                
                if (response.certStatus() == 1)
                    return CertificateStatusCode.CERT_IS_REVOKED;
                
                if (response.thisUpdate() > current_time)
                    return CertificateStatusCode.OCSP_NOT_YET_VALID;
                
                if (response.nextUpdate().timeIsSet() && current_time > response.nextUpdate())
                    return CertificateStatusCode.OCSP_HAS_EXPIRED;
                
                if (response.certStatus() == 0)
                    return CertificateStatusCode.OCSP_RESPONSE_GOOD;
                else
                    return CertificateStatusCode.OCSP_BAD_STATUS;
            }
        }
        
        return CertificateStatusCode.OCSP_CERT_NOT_LISTED;
    }

    @property bool empty() {
        return m_responses.length == 0;
    }
private:
    Array!( SingleResponse ) m_responses;
}


void decodeOptionalList(ref BERDecoder ber,
                        ASN1Tag tag,
                        ref Vector!X509Certificate output)
{
    BERObject obj = ber.getNextObject();
    
    if (obj.type_tag != tag || obj.class_tag != (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED))
    {
        ber.pushBack(obj);
        return;
    }
    
    BERDecoder list = BERDecoder(obj.value);
    
    while (list.moreItems())
    {
        BERObject certbits = list.getNextObject();
        X509Certificate cert = X509Certificate(unlock(certbits.value));
        output.pushBack(cert);
    }
}

/// Does not use trusted roots
/// Throws if not trusted
void checkSignature(ALLOC)(auto const ref Vector!(ubyte, ALLOC) tbs_response,
                               const AlgorithmIdentifier sig_algo,
                               const ref Vector!ubyte signature,
                               const X509Certificate cert)
{
    const PublicKey pub_key = cert.subjectPublicKey();
    
    const Vector!string sig_info = splitter(OIDS.lookup(sig_algo.oid), '/');
    
    if (sig_info.length != 2 || sig_info[0] != pub_key.algoName)
        throw new Exception("Information in OCSP response does not match cert");

    string padding = sig_info[1];
    SignatureFormat format = (pub_key.messageParts() >= 2) ? DER_SEQUENCE : IEEE_1363;
    
    PKVerifier verifier = PKVerifier(pub_key, padding, format);
    if (!verifier.verifyMessage(putInSequence(tbs_response), signature))
        throw new Exception("Signature on OCSP response does not verify");
}

/// Iterates over trusted roots certificate store
/// throws if not trusted
void checkSignature(ALLOC)(auto const ref Vector!(ubyte, ALLOC) tbs_response,
                                 const AlgorithmIdentifier sig_algo,
                                 const ref Vector!ubyte signature,
                                 const CertificateStore trusted_roots,
                                 const ref Vector!X509Certificate certs)
{
    if (certs.length < 1)
        throw new InvalidArgument("Short cert chain for checkSignature");
    
    if (trusted_roots.certificateKnown(certs[0]))
        return checkSignature(tbs_response, sig_algo, signature, certs[0]);
    
    // Otherwise attempt to chain the signing cert to a trust root
    
    if (!certs[0].allowedUsage("PKIX.OCSPSigning"))
        throw new Exception("OCSP response cert does not allow OCSP signing");
    
    auto result = x509PathValidate(certs, PathValidationRestrictions(), trusted_roots);
    
    if (!result.successfulValidation())
        throw new Exception("Certificate validation failure: " ~ result.resultString());
    
    if (!trusted_roots.certificateKnown(result.trustRoot())) // not needed anymore?
        throw new Exception("Certificate chain roots in unknown/untrusted CA");
        
    checkSignature(tbs_response, sig_algo, signature, result.certPath()[0]);
}

version(Have_vibe_d) import vibe.core.concurrency : Tid, send;
else import std.concurrency : Tid, send;
/// Checks the certificate online
void onlineCheck(shared(Tid) sender,
                 shared(size_t) id,
                 shared(OCSPResponse*) resp,
                 shared(const(X509Certificate)*) issuer,
                 shared(const(X509Certificate)*) subject,
                 shared(const(CertificateStore)*) trusted_roots)
{
    /// TODO: Test OCSP with correct BER Decoding
    logTrace("Checking OCSP online");
    const string responder_url = (*cast(X509Certificate*)issuer).ocspResponder();
    logTrace("Responder url: ", responder_url.length);

    if (responder_url.length == 0) {
        logTrace("Aborting OCSP for ID#", id.to!string);
        *cast(OCSPResponse*)resp = OCSPResponse.init;
        send(cast(Tid)sender, cast(size_t)id);
        return;
    }

    OCSPRequest req = OCSPRequest(*cast(X509Certificate*)issuer, *cast(X509Certificate*)subject);
    
    logTrace("POST_sync");
    HTTPResponse res = POST_sync(responder_url, "application/ocsp-request", req.BER_encode());
    
    res.throwUnlessOk();
    
    // Check the MIME type?
    *cast(OCSPResponse*)resp = OCSPResponse(*(cast(CertificateStore*)trusted_roots), res._body());
    
    send(cast(Tid)sender, cast(size_t)id);
}