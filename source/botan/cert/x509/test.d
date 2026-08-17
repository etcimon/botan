/**
* Unit test helper
*
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.test;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

/*
  Code to run the X.509v3 processing tests described in "Conformance
  Testing of Relying Party Client Certificate Path Proccessing Logic",
  which is available on NIST's web site.

Known Failures/Problems

TLSPolicy extensions are not implemented, so we skip tests #34-#53.

Tests #75 and #76 are skipped as they make use of relatively obscure CRL
extensions which are not supported.
*/
static if (BOTAN_TEST && BOTAN_HAS_X509_CERTIFICATES):

import botan.test;
import botan.cert.x509.x509path;
import botan.utils.types;
import std.file;
import std.array;
import std.conv : to;

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

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
    import botan.libstate.global_state;
    auto state = globalState(); // ensure initialized

    logDebug("Testing x509/test.d ...");
    const string root_test_dir = "test_data/nist_x509/";
    
    size_t unexp_failure = 0;
    size_t unexp_success = 0;
    size_t wrong_error = 0;
    size_t skipped = 0;
    size_t ran = 0;

    {
        import botan.cert.x509.x509_ext;
        import botan.asn1.ber_dec;
        import botan.utils.exceptn;
        ubyte[13] empty_nc = [
            0x30, 0x0B,
              0x30, 0x09,
                0x06, 0x03, 0x55, 0x1D, 0x1E,
                0x04, 0x02, 0x30, 0x00
        ];
        bool threw;
        try
        {
            X509Extensions exts;
            BERDecoder dec = BERDecoder(empty_nc.ptr, empty_nc.length);
            exts.decodeFrom(dec);
        }
        catch (DecodingError)
            threw = true;
        if (!threw)
        {
            logError("S3 empty NameConstraints accepted");
            ++unexp_failure;
        }
        ubyte[23] ok_nc = [
            0x30, 0x15,
              0x30, 0x13,
                0x06, 0x03, 0x55, 0x1D, 0x1E,
                0x04, 0x0C,
                  0x30, 0x0A,
                    0xA0, 0x08,
                      0x30, 0x06,
                        0x30, 0x04,
                          0x82, 0x02, 0x61, 0x61
        ];
        try
        {
            X509Extensions exts;
            BERDecoder dec = BERDecoder(ok_nc.ptr, ok_nc.length);
            exts.decodeFrom(dec);
        }
        catch (Exception e)
        {
            logError("S3 valid NameConstraints rejected: ", e.msg);
            ++unexp_failure;
        }
    }
    
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

/// C++ `x509_path_x509test`: hostname + TLS server usage + fixed time.
static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
    import botan.libstate.global_state;
    import botan.cert.x509.certstor;
    import botan.cert.x509.key_constraint : UsageType;
    import botan.asn1.asn1_time;
    import std.file : exists;
    import std.datetime;

    auto state = globalState();
    logDebug("Testing x509/x509test path validation ...");
    if (!exists("test_data/x509/x509test/root.pem"))
        return;
    size_t fails;
    auto root = X509Certificate("test_data/x509/x509test/root.pem");
    auto store = scoped!CertificateStoreInMemory();
    store.addCertificate(root);
    auto restrictions = PathValidationRestrictions(false);
    auto when = X509Time(SysTime(DateTime(2016, 10, 21, 4, 20, 0), UTC()));
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/ValidCert.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Verified")
        {
            logError("x509test ValidCert got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidNotAfter.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate has expired")
        {
            logError("x509test InvalidNotAfter got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test path validation", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
    import botan.libstate.global_state;
    import botan.cert.x509.certstor;
    import botan.cert.x509.key_constraint : UsageType;
    import botan.asn1.asn1_time;
    import std.file : exists;
    import std.datetime;

    auto state = globalState();
    if (!exists("test_data/x509/x509test/root.pem"))
        return;
    size_t fails;
    auto root = X509Certificate("test_data/x509/x509test/root.pem");
    auto store = scoped!CertificateStoreInMemory();
    store.addCertificate(root);
    auto restrictions = PathValidationRestrictions(false);
    auto when = X509Time(SysTime(DateTime(2016, 10, 21, 4, 20, 0), UTC()));
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/ValidWildcard.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Verified")
        {
            logError("x509test ValidWildcard got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidName got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test name/wildcard", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
    import botan.libstate.global_state;
    import botan.cert.x509.certstor;
    static if (BOTAN_HAS_CERTSTORE_FLATFILE)
        import botan.cert.x509.certstor_flatfile;
    import botan.cert.x509.x509self;
    import botan.cert.x509.x509_ca;
    import botan.cert.x509.pkcs10;
    import botan.pubkey.algo.rsa;
    import botan.rng.auto_rng;
    import botan.asn1.asn1_time;
    import botan.utils.exceptn;
    import std.path : buildPath;
    import std.file : tempDir, write, remove, exists;
    import std.exception : collectException;
    import std.datetime;

    auto state = globalState();
    logDebug("Testing PEM-bundle CertificateStore (CS1) ...");

    size_t fails = 0;
    size_t ran = 0;

    Unique!AutoSeededRNG rng = new AutoSeededRNG;

    X509CertOptions opts1;
    opts1.common_name = "CS1 Test CA One";
    opts1.country = "US";
    opts1.CAKey(1);
    auto ca1_key = RSAPrivateKey(*rng, 2048);
    auto ca1 = x509self.createSelfSignedCert(opts1, *ca1_key, "SHA-256", *rng);

    X509CertOptions opts2;
    opts2.common_name = "CS1 Test CA Two";
    opts2.country = "US";
    opts2.CAKey(1);
    auto ca2_key = RSAPrivateKey(*rng, 2048);
    auto ca2 = x509self.createSelfSignedCert(opts2, *ca2_key, "SHA-256", *rng);

    X509CertOptions leaf_opts;
    leaf_opts.common_name = "cs1.example";
    leaf_opts.country = "US";
    auto leaf_key = RSAPrivateKey(*rng, 2048);
    auto req = x509self.createCertReq(leaf_opts, *leaf_key, "SHA-256", *rng);
    auto ca = X509CA(ca1, *ca1_key, "SHA-256");
    auto now = Clock.currTime(UTC());
    auto leaf = ca.signRequest(req, *rng, X509Time(now), X509Time(now + 365.days));

    const string bundle_path = buildPath(tempDir(), "botan_cs1_bundle.pem");
    const string mixed_path = buildPath(tempDir(), "botan_cs1_mixed.pem");
    const string empty_path = buildPath(tempDir(), "botan_cs1_empty.pem");
    write(bundle_path, ca1.PEM_encode() ~ ca2.PEM_encode());
    write(mixed_path, ca1.PEM_encode() ~ leaf.PEM_encode());
    write(empty_path, "");
    scope (exit)
    {
        foreach (p; [bundle_path, mixed_path, empty_path])
        {
            if (exists(p))
                collectException(remove(p));
        }
    }

    void fail(string what)
    {
        ++fails;
        logError("CS1: " ~ what);
    }

    // CS1b — InMemory.addFromFile loads every PEM block
    {
        ++ran;
        if (ca1.subjectDn() == ca2.subjectDn())
            fail("generated CAs share a subject DN");

        auto mem = new CertificateStoreInMemory;
        mem.addFromFile(bundle_path);
        ++ran;
        if (mem.allSubjects().length < 2)
            fail("InMemory allSubjects < 2 (decoded "
                ~ mem.allSubjects().length.to!string ~ ")");
        ++ran;
        if (!mem.certificateKnown(ca1))
            fail("InMemory bundle missing ca1");
        ++ran;
        if (!mem.certificateKnown(ca2))
            fail("InMemory bundle missing ca2");

        auto mem_mixed = new CertificateStoreInMemory;
        mem_mixed.addFromFile(mixed_path);
        ++ran;
        if (!mem_mixed.certificateKnown(leaf))
            fail("InMemory mixed missing leaf");
    }

    static if (BOTAN_HAS_CERTSTORE_FLATFILE)
    {
        auto store = new CertificateStoreFlatfile(bundle_path);
        ++ran;
        if (!store.certificateKnown(ca1))
            fail("Flatfile bundle missing ca1");
        ++ran;
        if (!store.certificateKnown(ca2))
            fail("Flatfile bundle missing ca2");
        ++ran;
        if (store.allSubjects().length < 2)
            fail("Flatfile allSubjects < 2");
        ++ran;
        if (*store.findCrlFor(leaf))
            fail("Flatfile unexpectedly returned a CRL");

        auto restrictions = PathValidationRestrictions(false);
        auto validation = x509PathValidate(leaf, restrictions, store);
        ++ran;
        if (validation.result() != CertificateStatusCode.VERIFIED)
            fail("path validate: " ~ PathValidationResult.statusString(validation.result()));

        bool threw_mixed = false;
        try
            auto ignored = new CertificateStoreFlatfile(mixed_path);
        catch (InvalidArgument)
            threw_mixed = true;
        ++ran;
        if (!threw_mixed)
            fail("Flatfile mixed bundle should throw");

        auto skipped = new CertificateStoreFlatfile(mixed_path, true);
        ++ran;
        if (!skipped.certificateKnown(ca1))
            fail("ignore_non_ca lost ca1");
        ++ran;
        if (skipped.certificateKnown(leaf))
            fail("ignore_non_ca kept leaf");

        bool threw_empty = false;
        try
            auto ignored_empty = new CertificateStoreFlatfile(empty_path);
        catch (InvalidArgument)
            threw_empty = true;
        ++ran;
        if (!threw_empty)
            fail("empty file should throw");

        bool threw_nopath = false;
        try
            auto ignored_nopath = new CertificateStoreFlatfile("");
        catch (InvalidArgument)
            threw_nopath = true;
        ++ran;
        if (!threw_nopath)
            fail("empty path should throw");
    }

    testReport("X.509 PEM-bundle store", ran, fails);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST && BOTAN_HAS_CERTSTORE_SYSTEM) unittest
{
    import botan.libstate.global_state;
    import botan.cert.x509.certstor_system;

    auto state = globalState();
    logDebug("Testing system CertificateStore (CS2) ...");

    size_t fails = 0;
    size_t ran = 0;

    void fail(string what)
    {
        ++fails;
        logError("CS2: " ~ what);
    }

    ++ran;
    CertificateStoreSystem store;
    try
        store = new CertificateStoreSystem;
    catch (Exception e)
    {
        version (Windows)
            fail("Windows system store ctor: " ~ e.msg);
        else
            logDebug("CS2: no OS bundle on this cell (" ~ e.msg ~ ")");
    }

    if (store !is null)
    {
        auto subjects = store.allSubjects();
        ++ran;
        if (subjects.empty)
            fail("system store opened but allSubjects is empty");
        else
        {
            auto none = Vector!ubyte();
            auto found = store.findCert(subjects[0], none);
            ++ran;
            if (!*found)
                fail("findCert missed the first allSubjects DN");
            ++ran;
            if (*found && !store.certificateKnown(found))
                fail("certificateKnown false for a cert from this store");
            ++ran;
            if (*store.findCrlFor(found))
                fail("system store unexpectedly returned a CRL");
        }
    }

    testReport("X.509 system store", ran, fails);
}