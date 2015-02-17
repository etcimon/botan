/**
* Unit test helper
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.test;

/*
  Code to run the X.509v3 processing tests described in "Conformance
  Testing of Relying Party Client Certificate Path Proccessing Logic",
  which is available on NIST's web site.

Known Failures/Problems

TLSPolicy extensions are not implemented, so we skip tests #34-#53.

Tests #75 and #76 are skipped as they make use of relatively obscure CRL
extensions which are not supported.
*/
import botan.constants;
static if (BOTAN_TEST && BOTAN_HAS_X509_CERTIFICATES):

import botan.test;
import botan.cert.x509.x509path;
import botan.utils.types;
import std.file;
import std.array;

string[] dirListing(string dir_path)
{
    auto dirfiles = dirEntries(dir_path, "*", SpanMode.shallow);
    string[] files;
    foreach(file; dirfiles) {
        files ~= file.name;
    }
    files.sort();
    return files;
}

/*
  The expected results are essentially the error codes that best coorespond
  to the problem described in the testing documentation.

  There are a few cases where the tests say there should or should not be an
  error, and I disagree. A few of the tests have test results different from
  what they "should" be: these changes are marked as such, and have comments
  explaining the problem at hand.
*/
CertificateStatusCode[] getExpected()
{
    CertificateStatusCode[] expected_results;
    expected_results.length = 75;
    
    /* OK, not a super great way of doing this... */
    expected_results[1] = CertificateStatusCode.VERIFIED;
    expected_results[2] = CertificateStatusCode.SIGNATURE_ERROR;
    expected_results[3] = CertificateStatusCode.SIGNATURE_ERROR;
    expected_results[4] = CertificateStatusCode.VERIFIED;
    expected_results[5] = CertificateStatusCode.CERT_NOT_YET_VALID;
    expected_results[6] = CertificateStatusCode.CERT_NOT_YET_VALID;
    expected_results[7] = CertificateStatusCode.VERIFIED;
    expected_results[8] = CertificateStatusCode.CERT_NOT_YET_VALID;
    expected_results[9] = CertificateStatusCode.CERT_HAS_EXPIRED;
    expected_results[10] = CertificateStatusCode.CERT_HAS_EXPIRED;
    expected_results[11] = CertificateStatusCode.CERT_HAS_EXPIRED;
    expected_results[12] = CertificateStatusCode.VERIFIED;
    expected_results[13] = CertificateStatusCode.CERT_ISSUER_NOT_FOUND;
    
    expected_results[14] = CertificateStatusCode.CERT_ISSUER_NOT_FOUND;
    expected_results[15] = CertificateStatusCode.VERIFIED;
    expected_results[16] = CertificateStatusCode.VERIFIED;
    expected_results[17] = CertificateStatusCode.VERIFIED;
    expected_results[18] = CertificateStatusCode.VERIFIED;
    
    expected_results[19] = CertificateStatusCode.NO_REVOCATION_DATA;
    expected_results[20] = CertificateStatusCode.CERT_IS_REVOKED;
    expected_results[21] = CertificateStatusCode.CERT_IS_REVOKED;
    
    expected_results[22] = CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER;
    expected_results[23] = CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER;
    expected_results[24] = CertificateStatusCode.VERIFIED;
    expected_results[25] = CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER;
    expected_results[26] = CertificateStatusCode.VERIFIED;
    expected_results[27] = CertificateStatusCode.VERIFIED;
    expected_results[28] = CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER;
    expected_results[29] = CertificateStatusCode.CA_CERT_NOT_FOR_CERT_ISSUER;
    expected_results[30] = CertificateStatusCode.VERIFIED;
    
    expected_results[31] = CertificateStatusCode.CA_CERT_NOT_FOR_CRL_ISSUER;
    expected_results[32] = CertificateStatusCode.CA_CERT_NOT_FOR_CRL_ISSUER;
    expected_results[33] = CertificateStatusCode.VERIFIED;
    
    /*
     TLSPolicy tests: a little trickier because there are other inputs
     which affect the result.

     In the case of the tests currently in the suite, the default
     method (with acceptable policy being "any-policy" and with no
     explict policy required), will almost always result in a verified
     status. This is not particularly helpful. So, we should do several
     different tests for each test set:

         1) With the user policy as any-policy and no explicit policy
         2) With the user policy as any-policy and an explicit policy required
         3) With the user policy as test-policy-1 (2.16.840.1.101.3.1.48.1) and
             an explict policy required
         4) With the user policy as either test-policy-1 or test-policy-2 and an
             explicit policy required

      This provides reasonably good coverage of the possible outcomes.
    */
    
    expected_results[34] = CertificateStatusCode.VERIFIED;
    expected_results[35] = CertificateStatusCode.VERIFIED;
    expected_results[36] = CertificateStatusCode.VERIFIED;
    expected_results[37] = CertificateStatusCode.VERIFIED;
    expected_results[38] = CertificateStatusCode.VERIFIED;
    expected_results[39] = CertificateStatusCode.VERIFIED;
    expected_results[40] = CertificateStatusCode.VERIFIED;
    expected_results[41] = CertificateStatusCode.VERIFIED;
    expected_results[42] = CertificateStatusCode.VERIFIED;
    expected_results[43] = CertificateStatusCode.VERIFIED;
    expected_results[44] = CertificateStatusCode.VERIFIED;
    
    //expected_results[45] = CertificateStatusCode.EXPLICT_POLICY_REQUIRED;
    //expected_results[46] = CertificateStatusCode.ACCEPT;
    //expected_results[47] = CertificateStatusCode.EXPLICT_POLICY_REQUIRED;
    
    expected_results[48] = CertificateStatusCode.VERIFIED;
    expected_results[49] = CertificateStatusCode.VERIFIED;
    expected_results[50] = CertificateStatusCode.VERIFIED;
    expected_results[51] = CertificateStatusCode.VERIFIED;
    expected_results[52] = CertificateStatusCode.VERIFIED;
    expected_results[53] = CertificateStatusCode.VERIFIED;
    
    expected_results[54] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[55] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[56] = CertificateStatusCode.VERIFIED;
    expected_results[57] = CertificateStatusCode.VERIFIED;
    expected_results[58] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[59] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[60] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[61] = CertificateStatusCode.CERT_CHAIN_TOO_LONG;
    expected_results[62] = CertificateStatusCode.VERIFIED;
    expected_results[63] = CertificateStatusCode.VERIFIED;
    
    expected_results[64] = CertificateStatusCode.CRL_BAD_SIGNATURE;
    
    expected_results[65] = CertificateStatusCode.NO_REVOCATION_DATA;
    expected_results[66] = CertificateStatusCode.NO_REVOCATION_DATA;
    
    expected_results[67] = CertificateStatusCode.VERIFIED;
    
    expected_results[68] = CertificateStatusCode.CERT_IS_REVOKED;
    expected_results[69] = CertificateStatusCode.CERT_IS_REVOKED;
    expected_results[70] = CertificateStatusCode.CERT_IS_REVOKED;
    expected_results[71] = CertificateStatusCode.CERT_IS_REVOKED;
    expected_results[72] = CertificateStatusCode.CRL_HAS_EXPIRED;
    expected_results[73] = CertificateStatusCode.CRL_HAS_EXPIRED;
    expected_results[74] = CertificateStatusCode.VERIFIED;
    
    /* These tests use weird CRL extensions which aren't supported yet */
    //expected_results[75] = ;
    //expected_results[76] = ;
    
    return expected_results;
}

static if (!SKIP_X509_TEST) unittest
{
    import botan.libstate.global_state;
    auto state = globalState(); // ensure initialized

    logDebug("Testing x509/test.d ...");
    const string root_test_dir = "../test_data/nist_x509/";
    
    size_t unexp_failure = 0;
    size_t unexp_success = 0;
    size_t wrong_error = 0;
    size_t skipped = 0;
    size_t ran = 0;
    
    CertificateStatusCode[] expected_results = getExpected();
    
    try {
        
        const string[] test_dirs = dirListing(root_test_dir);
        
        for(size_t i = 0; i != 74; i++)
        {
            const size_t test_no = i+1;
            logDebug("NIST X.509 test #", test_no);
            
            const string test_dir = test_dirs[i];
            const string[] all_files = dirListing(test_dir);
            
            Vector!string certs, crls;
            string root_cert, to_verify;
            
            for(size_t k = 0; k != all_files.length; k++)
            {
                const string current = all_files[k];
                
                if (current.canFind("int") && current.canFind(".crt"))
                    certs.pushBack(current);
                else if (current.canFind("root.crt"))
                    root_cert = current;
                else if (current.canFind("end.crt"))
                    to_verify = current;
                else if (current.canFind(".crl"))
                    crls.pushBack(current);
            }
            
            if (expected_results.canFind(i+1) == -1)
            {
                skipped++;
                continue;
            }
            
            ++ran;
            
            auto store = scoped!CertificateStoreInMemory();
            
            //logTrace(root_cert);
            store.addCertificate(X509Certificate(root_cert));
            
            X509Certificate end_user = X509Certificate(to_verify);
            foreach(cert; certs[])
                store.addCertificate(X509Certificate(cert));
            
            foreach(crl; crls[])
            {
                DataSourceStream input = DataSourceStream(crl);
                X509CRL crl_ = X509CRL(cast(DataSource)input);
                store.addCrl(crl_);
            }
            
            auto restrictions = PathValidationRestrictions(true);
            
            PathValidationResult validation_result = x509PathValidate(end_user, restrictions, store);
            auto expected = expected_results[test_no];
            CertificateStatusCode result = validation_result.result();
            if (result != expected) {
                logError("NIST X.509 test #", test_no, " : ");
                const string result_str = PathValidationResult.statusString(result);
                const string exp_str = PathValidationResult.statusString(expected);
                if (expected == CertificateStatusCode.VERIFIED) {
                    logError("unexpected failure: " ~ result_str);
                    unexp_failure++;
                }
                else if (result == CertificateStatusCode.VERIFIED) {
                    logError("unexpected success, expected " ~ exp_str);
                    unexp_success++;
                } 
                else {
                    logError("wrong error, got '" ~ result_str ~ "' expected '" ~ exp_str ~ "'");
                    wrong_error++;
                    assert(false);
                }
            }
        }
    }
    catch(Throwable e)
    {
        logError(e.toString());
        logTrace(e.msg);
    }
    
    const size_t all_failures = unexp_failure + unexp_success + wrong_error;
    
    testReport("NIST X.509 path validation", ran, all_failures);
}