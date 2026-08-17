/**
* C++ `x509_path_x509test` leftovers (directed, 2 cases per unittest).
*
* Lives in its own module so `test.d` stays below the LDC unittest AV limit.
*
* Copyright:
* (C) 2006,2011,2012,2014,2015 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.x509.test_x509test;

import botan.constants;
static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST && BOTAN_HAS_X509_CERTIFICATES):

import botan.test;
import botan.cert.x509.x509path;
import botan.cert.x509.x509cert;
import botan.cert.x509.certstor;
import botan.cert.x509.key_constraint : UsageType;
import botan.asn1.asn1_time;
import botan.libstate.global_state;
import botan.utils.types;
import std.file : exists;
import std.datetime;

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/ValidAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Verified")
        {
            logError("x509test ValidAltName got '", got, "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidSelfSign.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Cannot establish trust")
        {
            logError("x509test InvalidSelfSign got '", got, "'");
            ++fails;
        }
    }
    testReport("x509test altname/selfsign", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidKeyUsage.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not allow the requested usage")
        {
            logError("x509test InvalidKeyUsage got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidExtendedKeyUsage.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not allow the requested usage")
        {
            logError("x509test InvalidExtendedKeyUsage got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test key usage", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidNameAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidNameAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidNameAltNameWithSubj.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidNameAltNameWithSubj got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test altname mismatch", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardAll.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidWildcardAll got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardLeft.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidWildcardLeft got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test wildcard CN", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardMid.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidWildcardMid got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardSingle.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidWildcardSingle got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test wildcard CN 2", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardAllAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate extension encoding error")
        {
            logError("x509test InvalidWildcardAllAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardLeftAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate extension encoding error")
        {
            logError("x509test InvalidWildcardLeftAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test wildcard SAN encode", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardMidAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate extension encoding error")
        {
            logError("x509test InvalidWildcardMidAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardSingleAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate extension encoding error")
        {
            logError("x509test InvalidWildcardSingleAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test wildcard SAN encode 2", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardMidMixed.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not match provided name")
        {
            logError("x509test InvalidWildcardMidMixed got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        Vector!X509Certificate certs;
        certs.pushBack(X509Certificate("test_data/x509/x509test/InvalidWildcardMidMixedAltName.pem"));
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate extension encoding error")
        {
            logError("x509test InvalidWildcardMidMixedAltName got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test wildcard mixed", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/ValidChained.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Verified")
        {
            logError("x509test ValidChained got '", got, "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidNotAfterChained.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate has expired")
        {
            logError("x509test InvalidNotAfterChained got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/ValidNameConstraint.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Verified")
        {
            logError("x509test ValidNameConstraint got '", got, "'");
            ++fails;
        }
        auto as_only = X509Certificate("test_data/x509/x509test/ASNumberOnly.pem");
        if (!as_only.subjectInfo("X509v3.ASIdentifiers.asnum").length)
        {
            logError("x509test ASNumberOnly missing asnum");
            ++fails;
        }
        auto as_inh = X509Certificate("test_data/x509/x509test/ASNumberInherit.pem");
        if (!as_inh.subjectInfo("X509v3.ASIdentifiers.asnum_inherit").length
            && !as_inh.subjectInfo("X509v3.ASIdentifiers.rdi").length)
        {
            logError("x509test ASNumberInherit missing asnum inherit / rdi");
            ++fails;
        }
        auto ip_all = X509Certificate("test_data/x509/x509test/IPAddrBlocksAll.pem");
        if (!ip_all.subjectInfo("X509v3.IPAddrBlocks.v4").length
            || !ip_all.subjectInfo("X509v3.IPAddrBlocks.v6").length)
        {
            logError("x509test IPAddrBlocksAll missing v4/v6");
            ++fails;
        }
    }
    testReport("x509test chained", 3, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/ValidIntCALen.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Verified")
        {
            logError("x509test ValidIntCALen got '", got, "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCALen.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate chain too long")
        {
            logError("x509test InvalidIntCALen got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidNameConstraintExclude.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Certificate does not pass name constraint")
        {
            logError("x509test InvalidNameConstraintExclude got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test CA pathlen", 3, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCAFlag.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test InvalidIntCAFlag got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCAKeyUsage.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test InvalidIntCAKeyUsage got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test CA flag/usage", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCALoop.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "Loop in certificate chain")
        {
            logError("x509test InvalidIntCALoop got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCASelfSign.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        auto got = result.resultString();
        if (result.successfulValidation() && result.trustRoot() != root)
            got = "Cannot establish trust";
        if (got != "Cannot establish trust")
        {
            logError("x509test InvalidIntCASelfSign got '", got, "'");
            ++fails;
        }
    }
    testReport("x509test CA loop/selfsign", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCAVersionOne.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test InvalidIntCAVersionOne got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/InvalidIntCAVersionTwo.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test InvalidIntCAVersionTwo got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test CA version", 2, fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS && !SKIP_X509_TEST) unittest
{
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
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/MissingIntCABasicConstraintWithCertSign.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test MissingIntCABasicConstraintWithCertSign got '", result.resultString(), "'");
            ++fails;
        }
    }
    {
        auto certs = loadCertificatesFromFile("test_data/x509/x509test/MissingIntCAExtensions.pem");
        auto result = x509PathValidate(certs, restrictions, store, "www.tls.test",
                                       UsageType.TLS_SERVER_AUTH, when);
        if (result.resultString() != "CA certificate not allowed to issue certs")
        {
            logError("x509test MissingIntCAExtensions got '", result.resultString(), "'");
            ++fails;
        }
    }
    testReport("x509test CA missing ext", 2, fails);
    assert(fails == 0);
}
