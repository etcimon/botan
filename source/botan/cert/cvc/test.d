/**
* CVC EAC1.1 tests
*
* Copyright:
* (C) 2008 Falko Strenzke (strenzke@flexsecure.de)
*     2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
* 
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.test;

import botan.constants;
static if(BOTAN_TEST && BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.test;
import botan.rng.auto_rng;
import botan.pubkey.algo.ecdsa;
import botan.pubkey.algo.rsa;

import botan.cert.x509.x509cert;
import botan.cert.x509.x509self;
import botan.asn1.oids;
import botan.cert.cvc.cvc_self;
import botan.cert.cvc.cvc_ado;
import botan.cert.cvc.cvc_cert;
import botan.cert.cvc.signed_obj;
import botan.utils.types;
import std.datetime;


// helper functions
void helperWriteFile(in EACSignedObject to_write, in string file_path)
{
    Array!ubyte sv = to_write.BER_encode();
    File cert_file = File(file_path, "wb+");
    cert_file.write(sv.ptr[0 .. sv.length]);
}


bool helperFilesEqual(in string file_path1, in string file_path2)
{
    File cert_1_in = File(file_path1, "r");
    File cert_2_in = File(file_path2, "r");
    Vector!ubyte sv1;
    Vector!ubyte sv2;
    if (!cert_1_in.ok || !cert_2_in.ok)
    {
        return false;
    }
    while (!cert_1_in.eof && !cert_1_in.error)
    {
        ubyte[16] now;
        auto data = cert_1_in.rawRead(now.ptr[0 .. now.length]);
        sv1.pushBack(data);
    }
    while (!cert_2_in.eof && !cert_2_in.error)
    {
        ubyte[16] now;
        auto data = cert_2_in.rawRead(now.ptr[0 .. now.length]);
        sv2.pushBack(data);
    }
    if (sv1.length == 0)
    {
        return false;
    }
    return sv1 == sv2;
}

void testEncGenSelfsigned(RandomNumberGenerator rng)
{

    size_t fails;
    size_t total_tests;
    scope(exit) testReport("testEncGenSelfSigned", total_tests, fails);

    EAC11CVCOptions opts;
    //opts.cpi = 0;
    opts.chr = ASN1Chr("my_opt_chr"); // not used
    opts.car = ASN1Car("my_opt_car");
    opts.cex = ASN1Cex("2010 08 13");
    opts.ced = ASN1Ced("2010 07 27");
    opts.holder_auth_templ = 0xC1;
    opts.hash_alg = "SHA-256";
    
    // creating a non sense selfsigned cert w/o dom pars
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.11"));
    ECDSAPrivateKey key = ECDSAPrivateKey(rng, dom_pars);
    key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    EAC11CVC cert = createSelfSignedCert(key, opts, rng);
    {
        Array!ubyte der = cert.BER_encode();
        File cert_file = File("../test_data/ecc/my_cv_cert.ber", "wb+");
        //cert_file << der; // this is bad !!!
        cert_file.write(cast(string) der.ptr[0 .. der.length]);
    }
    
    EAC11CVC cert_in = EAC11CVC("../test_data/ecc/my_cv_cert.ber");
    mixin( CHECK(` cert == cert_in `) );
    // encoding it again while it has no dp
    {
        Array!ubyte der2 = cert_in.BER_encode();
        File cert_file2 = File("../test_data/ecc/my_cv_cert2.ber", "wb+");
        cert_file2.write(der2.ptr[0 .. der2.length]);
    }
    // read both and compare them
    {
        File cert_1_in = File("../test_data/ecc/my_cv_cert.ber", "r");
        File cert_2_in = File("../test_data/ecc/my_cv_cert2.ber", "r");
        Vector!ubyte sv1;
        Vector!ubyte sv2;
        if (!cert_1_in.ok || !cert_2_in.ok)
        {
            mixin( CHECK_MESSAGE( `false`, "could not read certificate files" ) );
        }
        while (!cert_1_in.eof && !cert_1_in.error)
        {
            ubyte[16] now;
            auto data = cert_1_in.rawRead(now.ptr[0 .. now.length]);
            sv1.pushBack(data);
        }
        while (!cert_2_in.eof && !cert_2_in.error)
        {
            ubyte[16] now;
            auto data = cert_2_in.rawRead(now.ptr[0 .. now.length]);
            sv2.pushBack(data);
        }
        mixin( CHECK(` sv1.length > 10 `) );
        mixin( CHECK_MESSAGE( `sv1 == sv2`, "reencoded file of cert without domain parameters is different from original" ) );
    }
    //cout " ~reading cert again");
    mixin( CHECK(` cert_in.getCar().value() == "my_opt_car" `) );
    mixin( CHECK(` cert_in.getChr().value() == "my_opt_car" `) );
    mixin( CHECK(` cert_in.getCed().toString() == "20100727" `) );
    mixin( CHECK(` cert_in.getCed().readableString() == "2010/07/27 " `) );
    
    bool ill_date_exc = false;
    try
    {
        ASN1Ced("1999 01 01");
    }
    catch (Throwable)
    {
        ill_date_exc = true;
    }
    mixin( CHECK(` ill_date_exc `) );
    
    bool ill_date_exc2 = false;
    try
    {
        ASN1Ced("2100 01 01");
    }
    catch (Throwable)
    {
        ill_date_exc2 = true;
    }
    mixin( CHECK(` ill_date_exc2 `) );
    //cout " ~readable = '" ~ cert_in.getCed().readableString() " ~'");
    Unique!PublicKey p_pk = cert_in.subjectPublicKey();
    ECDSAPublicKey p_ecdsa_pk = cast(ECDSAPublicKey)(*p_pk);
    
    // let´s see if encoding is truely implicitca, because this is what the key should have
    // been set to when decoding (see above)(because it has no domain params):
    
    mixin( CHECK(` p_ecdsa_pk.domainFormat() == EC_DOMPAR_ENC_IMPLICITCA `) );
    bool exc = false;
    try
    {
        logTrace("order = ", p_ecdsa_pk.domain().getOrder().dup.toString());
    }
    catch (InvalidState)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    // set them and try again
    //cert_in -> setDomainParameters(dom_pars);
    Unique!PublicKey p_pk2 = cert_in.subjectPublicKey();
    ECDSAPublicKey p_ecdsa_pk2 = cast(ECDSAPublicKey)(*p_pk2);
    //p_ecdsa_pk2 -> setDomainParameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk2.domain().getOrder() == dom_pars.getOrder() `) );
    bool ver_ec = cert_in.checkSignature(*p_pk2);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct selfsigned cvc certificate" ) );

}

void testEncGenReq(RandomNumberGenerator rng)
{

    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testEncGenReq", total_tests, fails);

    EAC11CVCOptions opts;
    
    //opts.cpi = 0;
    opts.chr = ASN1Chr("my_opt_chr");
    opts.hash_alg = "SHA-160";
    
    // creating a non sense selfsigned cert w/o dom pars
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    auto key = ECDSAPrivateKey(rng, dom_pars);
    key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    EAC11Req req = createCvcReq(key, opts.chr, opts.hash_alg, rng);
    {
        Array!ubyte der = req.BER_encode();
        File req_file = File("../test_data/ecc/my_cv_req.ber", "wb+");
        req_file.write(der.ptr[0 .. der.length]);
    }
    
    // read and check signature...
    EAC11Req req_in = EAC11Req("../test_data/ecc/my_cv_req.ber");
    //req_in.setDomainParameters(dom_pars);
    Unique!PublicKey p_pk = req_in.subjectPublicKey();
    ECDSAPublicKey p_ecdsa_pk = cast(ECDSAPublicKey)(*p_pk);
    //p_ecdsa_pk.setDomainParameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk.domain().getOrder() == dom_pars.getOrder() `) );
    bool ver_ec = req_in.checkSignature(*p_pk);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct selfsigned (created by myself) cvc request" ) );
}

void testCvcReqExt(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCvcReqExt", total_tests, fails);
    EAC11Req req_in = EAC11Req("../test_data/ecc/DE1_flen_chars_cvcRequest_ECDSA.der");
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    //req_in.setDomainParameters(dom_pars);
    Unique!PublicKey p_pk = req_in.subjectPublicKey();
    ECDSAPublicKey p_ecdsa_pk = cast(ECDSAPublicKey)(*p_pk);
    //p_ecdsa_pk.setDomainParameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk.domain().getOrder() == dom_pars.getOrder() `) );
    bool ver_ec = req_in.checkSignature(*p_pk);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct selfsigned (external testdata) cvc request" ) );
}

void testCvcAdoExt(RandomNumberGenerator)
{    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCvcAdoExt", total_tests, fails);
    EAC11ADO req_in = EAC11ADO("../test_data/ecc/ado.cvcreq");
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    //cout " ~car = " ~ req_in.getCar().value());
    //req_in.setDomainParameters(dom_pars);
}

void testCvcAdoCreation(RandomNumberGenerator rng)
{    
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCvcAdoCreation", total_tests, fails);
    EAC11CVCOptions opts;
    //opts.cpi = 0;
    opts.chr = ASN1Chr("my_opt_chr");
    opts.hash_alg = "SHA-256";
    
    // creating a non sense selfsigned cert w/o dom pars
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.11"));
    //cout " ~mod = " ~ hex << dom_pars.getCurve().getP());
    auto req_key = ECDSAPrivateKey(rng, dom_pars);
    req_key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC11Req req = createCvcReq(req_key, opts);
    EAC11Req req = createCvcReq(req_key, opts.chr, opts.hash_alg, rng);
    {
        Array!ubyte der = req.BER_encode();
        File req_file = File("../test_data/ecc/my_cv_req.ber", "wb+");
        req_file.write(der.ptr[0 .. der.length]);
    }
    
    // create an ado with that req
    auto ado_key = ECDSAPrivateKey(rng, dom_pars);
    EAC11CVCOptions ado_opts;
    ado_opts.car = ASN1Car("my_ado_car");
    ado_opts.hash_alg = "SHA-256"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request
    
    //EAC11ADO ado = createAdoReq(ado_key, req, ado_opts);
    EAC11ADO ado = createAdoReq(ado_key, req, ado_opts.car, rng);
    mixin( CHECK_MESSAGE( `ado.checkSignature(ado_key)`, "failure of ado verification after creation" ) );
    
    {
        File ado_file = File("../test_data/ecc/ado", "wb+");
        Array!ubyte ado_der = ado.BER_encode();
        ado_file.write(ado_der.ptr[0 .. ado_der.length]);
    }
    // read it again and check the signature
    EAC11ADO ado2 = EAC11ADO("../test_data/ecc/ado");
    mixin( CHECK(` ado == ado2 `) );
    //ECDSAPublicKey p_ado_pk = cast(ECDSAPublicKey)(&ado_key);
    //bool ver = ado2.checkSignature(*p_ado_pk);
    bool ver = ado2.checkSignature(ado_key);
    mixin( CHECK_MESSAGE( `ver`, "failure of ado verification after reloading" ) );
}

void testCvcAdoComparison(RandomNumberGenerator rng)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCvcAdoComparison", total_tests, fails);
    EAC11CVCOptions opts;
    //opts.cpi = 0;
    opts.chr = ASN1Chr("my_opt_chr");
    opts.hash_alg = "SHA-224";
    
    // creating a non sense selfsigned cert w/o dom pars
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.11"));
    auto req_key = ECDSAPrivateKey(rng, dom_pars);
    req_key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC11Req req = createCvcReq(req_key, opts);
    EAC11Req req = createCvcReq(req_key, opts.chr, opts.hash_alg, rng);
    
    // create an ado with that req
    auto ado_key = ECDSAPrivateKey(rng, dom_pars);
    EAC11CVCOptions ado_opts;
    ado_opts.car = ASN1Car("my_ado_car1");
    ado_opts.hash_alg = "SHA-224"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
    //EAC11ADO ado = createAdoReq(ado_key, req, ado_opts);
    EAC11ADO ado = createAdoReq(ado_key, req, ado_opts.car, rng);
    mixin( CHECK_MESSAGE( `ado.checkSignature(ado_key)`, "failure of ado verification after creation" ) );
    // make a second one for comparison
    EAC11CVCOptions opts2;
    //opts2.cpi = 0;
    opts2.chr = ASN1Chr("my_opt_chr");
    opts2.hash_alg = "SHA-160"; // this is the only difference
    auto req_key2 = ECDSAPrivateKey(rng, dom_pars);
    req_key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC11Req req2 = createCvcReq(req_key2, opts2, rng);
    EAC11Req req2 = createCvcReq(req_key2, opts2.chr, opts2.hash_alg, rng);
    auto ado_key2 = ECDSAPrivateKey(rng, dom_pars);
    EAC11CVCOptions ado_opts2;
    ado_opts2.car = ASN1Car("my_ado_car1");
    ado_opts2.hash_alg = "SHA-160"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
    
    EAC11ADO ado2 = createAdoReq(ado_key2, req2, ado_opts2.car, rng);
    mixin( CHECK_MESSAGE( `ado2.checkSignature(ado_key2)`, "failure of ado verification after creation" ) );
    
    mixin( CHECK_MESSAGE( `ado != ado2`, "ado s found to be equal where they are not" ) );
    //      std::ofstream ado_file("../test_data/ecc/ado");
    //      Vector!ubyte ado_der(ado.BER_encode());
    //      ado_file.write((char*)ado_der.ptr, ado_der.length);
    //      ado_file.close();
    // read it again and check the signature
    
    //     EAC11ADO ado2("../test_data/ecc/ado");
    //     ECDSAPublicKey p_ado_pk = cast(ECDSAPublicKey)(&ado_key);
    //     //bool ver = ado2.checkSignature(p_ado_pk);
    //     bool ver = ado2.checkSignature(ado_key);
    //     mixin( CHECK_MESSAGE( ver, "failure of ado verification after reloading" ) );
}

void testEacTime(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testEacTime", total_tests, fails);
    EACTime time = EACTime(Clock.currTime(UTC()));
    //      logTrace("time as string = " ~ time.toString());
    EACTime sooner = EACTime("", (cast(ASN1Tag)99));
    //X509Time sooner("", (cast(ASN1Tag)99));
    sooner.setTo("2007 12 12");
    //      logTrace("sooner as string = " ~ sooner.toString());
    EACTime later = EACTime("2007 12 13");
    //X509Time later("2007 12 13");
    //      logTrace("later as string = " ~ later.toString());
    mixin( CHECK(` sooner <= later `) );
    mixin( CHECK(` sooner == sooner `) );
    
    ASN1Cex my_cex = ASN1Cex("2007 08 01");
    my_cex.addMonths(12);
    mixin( CHECK(` my_cex.getYear() == 2008 `) );
    mixin( CHECK_MESSAGE( ` my_cex.getMonth() == 8 `, "shoult be 8, was `, my_cex.getMonth(), `" ) );
    
    my_cex.addMonths(4);
    mixin( CHECK(` my_cex.getYear() == 2008 `) );
    mixin( CHECK(` my_cex.getMonth() == 12 `) );
    
    my_cex.addMonths(4);
    mixin( CHECK(` my_cex.getYear() == 2009 `) );
    mixin( CHECK(` my_cex.getMonth() == 4 `) );
    
    my_cex.addMonths(41);
    mixin( CHECK(` my_cex.getYear() == 2012 `) );
    mixin( CHECK(` my_cex.getMonth() == 9 `) );
    
    
    
}

void testVerCvca(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testVerCvca", total_tests, fails);
    EAC11CVC req_in = EAC11CVC("../test_data/ecc/cvca01.cv.crt");
    
    bool exc = false;
    
    Unique!PublicKey p_pk2 = req_in.subjectPublicKey();
    ECDSAPublicKey p_ecdsa_pk2 = cast(ECDSAPublicKey)(*p_pk2);
    bool ver_ec = req_in.checkSignature(*p_pk2);
    mixin( CHECK_MESSAGE( `ver_ec`, "could not positively verify correct selfsigned cvca certificate" ) );
    
    try
    {
        p_ecdsa_pk2.domain().getOrder();
    }
    catch (InvalidState)
    {
        exc = true;
    }
    mixin( CHECK(` !exc `) );
}

void testCopyAndAssignment(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCopyAndAssignment", total_tests, fails);
    EAC11CVC cert_in = EAC11CVC("../test_data/ecc/cvca01.cv.crt");
    EAC11CVC cert_cp = EAC11CVC(cert_in);
    EAC11CVC cert_ass = cert_in;
    mixin( CHECK(` cert_in == cert_cp `) );
    mixin( CHECK(` cert_in == cert_ass `) );
    
    EAC11ADO ado_in = EAC11ADO("../test_data/ecc/ado.cvcreq");
    //ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    EAC11ADO ado_cp = EAC11ADO(ado_in);
    EAC11ADO ado_ass = ado_in;
    mixin( CHECK(` ado_in == ado_cp `) );
    mixin( CHECK(` ado_in == ado_ass `) );
    
    EAC11Req req_in = EAC11Req("../test_data/ecc/DE1_flen_chars_cvcRequest_ECDSA.der");
    //ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    EAC11Req req_cp = EAC11Req(req_in);
    EAC11Req req_ass = req_in;
    mixin( CHECK(` req_in == req_cp `) );
    mixin( CHECK(` req_in == req_ass `) );
}

void testEacStrIllegalValues(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCopyAndAssignment", total_tests, fails);
    bool exc = false;
    try
    {
        EAC11CVC("../test_data/ecc/cvca_illegal_chars.cv.crt");
        
    }
    catch (DecodingError)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    
    bool exc2 = false;
    try
    {
        EAC11CVC("../test_data/ecc/cvca_illegal_chars2.cv.crt");
        
    }
    catch (DecodingError)
    {
        exc2 = true;
    }
    mixin( CHECK(` exc2 `) );
}

void testTmpEacStrEnc(RandomNumberGenerator)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testTmpEacStrEnc", total_tests, fails);
    bool exc = false;
    try
    {
        ASN1Car("abc!+-µ\n");
    }
    catch (InvalidArgument)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    //      string val = car.iso8859();
    //      logTrace("car 8859 = " ~ val);
    //      logTrace(hex <<(unsigned char)val[1]);
}

void testCvcChain(RandomNumberGenerator rng)
{
    size_t fails;
    size_t total_tests;
    scope(exit)testReport("testCvcChain", total_tests, fails);
    ECGroup dom_pars = ECGroup(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    auto cvca_privk = ECDSAPrivateKey(rng, dom_pars);
    string hash = "SHA-224";
    ASN1Car car = ASN1Car("DECVCA00001");
    EAC11CVC cvca_cert = cvc_self.createCvca(cvca_privk, hash, car, true, true, 12, rng);
    {
        File cvca_file = File("../test_data/ecc/cvc_chain_cvca.cer","wb+");
        Array!ubyte cvca_sv = cvca_cert.BER_encode();
        cvca_file.write(cast(string) cvca_sv.ptr[0 .. cvca_sv.length]);
    }
    
    auto cvca_privk2 = ECDSAPrivateKey(rng, dom_pars);
    ASN1Car car2 = ASN1Car("DECVCA00002");
    EAC11CVC cvca_cert2 = cvc_self.createCvca(cvca_privk2, hash, car2, true, true, 12, rng);
    EAC11CVC link12 = cvc_self.linkCvca(cvca_cert, cvca_privk, cvca_cert2, rng);
    {
        Array!ubyte link12_sv = link12.BER_encode();
        File link12_file = File("../test_data/ecc/cvc_chain_link12.cer", "wb+");
        link12_file.write(link12_sv.ptr[0 .. link12_sv.length]);
    }
    
    // verify the link
    mixin( CHECK(` link12.checkSignature(cvca_privk) `) );
    EAC11CVC link12_reloaded = EAC11CVC("../test_data/ecc/cvc_chain_link12.cer");
    EAC11CVC cvca1_reloaded = EAC11CVC("../test_data/ecc/cvc_chain_cvca.cer");
    Unique!PublicKey cvca1_rel_pk = cvca1_reloaded.subjectPublicKey();
    mixin( CHECK(` link12_reloaded.checkSignature(*cvca1_rel_pk) `) );
    
    // create first round dvca-req
    auto dvca_priv_key = ECDSAPrivateKey(rng, dom_pars);
    EAC11Req dvca_req = cvc_self.createCvcReq(dvca_priv_key, ASN1Chr("DEDVCAEPASS"), hash, rng);
    {
        File dvca_file = File("../test_data/ecc/cvc_chain_dvca_req.cer", "wb+");
        Array!ubyte dvca_sv = dvca_req.BER_encode();
        dvca_file.write(dvca_sv.ptr[0 .. dvca_sv.length]);
    }
    
    // sign the dvca_request
    EAC11CVC dvca_cert1 = cvc_self.signRequest(cvca_cert, cvca_privk, dvca_req, 1, 5, true, 3, 1, rng);
    mixin( CHECK(` dvca_cert1.getCar().iso8859() == "DECVCA00001" `) );
    mixin( CHECK(` dvca_cert1.getChr().iso8859() == "DEDVCAEPASS00001" `) );
    helperWriteFile(dvca_cert1, "../test_data/ecc/cvc_chain_dvca_cert1.cer");
    
    // make a second round dvca ado request
    auto dvca_priv_key2 = ECDSAPrivateKey(rng, dom_pars);
    EAC11Req dvca_req2 = cvc_self.createCvcReq(dvca_priv_key2, ASN1Chr("DEDVCAEPASS"), hash, rng);
    {
        File dvca_file2 = File("../test_data/ecc/cvc_chain_dvca_req2.cer", "wb+");
        Array!ubyte dvca_sv2 = dvca_req2.BER_encode();
        dvca_file2.write(dvca_sv2.ptr[0 .. dvca_sv2.length]);
    }
    
    EAC11ADO dvca_ado2 = createAdoReq(dvca_priv_key, dvca_req2, ASN1Car(dvca_cert1.getChr().iso8859()), rng);
    helperWriteFile(dvca_ado2, "../test_data/ecc/cvc_chain_dvca_ado2.cer");
    
    // verify the ado and sign the request too
    
    Unique!PublicKey ap_pk = dvca_cert1.subjectPublicKey();
    ECDSAPublicKey cert_pk = cast(ECDSAPublicKey)(*ap_pk);
    
    //cert_pk.setDomainParameters(dom_pars);
    //logTrace("dvca_cert.public_point.length = " ~ ec::EC2OSP(cert_pk.get_publicPoint(), ec::PointGFp.COMPRESSED).length);
    EAC11CVC dvca_cert1_reread = EAC11CVC("../test_data/ecc/cvc_chain_cvca.cer");
    mixin( CHECK(` dvca_ado2.checkSignature(cert_pk) `) );
    
    mixin( CHECK(` dvca_ado2.checkSignature(dvca_priv_key) `) ); // must also work
    
    EAC11Req dvca_req2b = EAC11Req(dvca_ado2.getRequest());
    helperWriteFile(dvca_req2b, "../test_data/ecc/cvc_chain_dvca_req2b.cer");
    mixin( CHECK(` helperFilesEqual("../test_data/ecc/cvc_chain_dvca_req2b.cer", "../test_data/ecc/cvc_chain_dvca_req2.cer") `) );
    EAC11CVC dvca_cert2 = cvc_self.signRequest(cvca_cert, cvca_privk, dvca_req2b, 2, 5, true, 3, 1, rng);
    mixin( CHECK(` dvca_cert2.getCar().iso8859() == "DECVCA00001" `) );
    CHECK_MESSAGE(`dvca_cert2.getChr().iso8859() == "DEDVCAEPASS00002"`, "chr = ` ~ dvca_cert2.getChr().iso8859() ~ `");
    
    // make a first round IS request
    auto is_priv_key = ECDSAPrivateKey(rng, dom_pars);
    EAC11Req is_req = cvc_self.createCvcReq(is_priv_key, ASN1Chr("DEIS"), hash, rng);
    helperWriteFile(is_req, "../test_data/ecc/cvc_chain_is_req.cer");
    
    // sign the IS request
    //dvca_cert1.setDomainParameters(dom_pars);
    EAC11CVC is_cert1 = cvc_self.signRequest(dvca_cert1, dvca_priv_key, is_req, 1, 5, true, 3, 1, rng);
    mixin( CHECK_MESSAGE( `is_cert1.getCar().iso8859() == "DEDVCAEPASS00001"`, "car = ` ~ is_cert1.getCar().iso8859() ~ `" ) );
    mixin( CHECK(` is_cert1.getChr().iso8859() == "DEIS00001" `) );
    helperWriteFile(is_cert1, "../test_data/ecc/cvc_chain_is_cert.cer");
    
    // verify the signature of the certificate
    mixin( CHECK(` is_cert1.checkSignature(dvca_priv_key) `) );
}

static if (!SKIP_CVC_TEST) unittest
{

    logDebug("Testing cvc/test.d ...");
    auto rng = AutoSeededRNG();
    
    logTrace("testEncGenSelfsigned");
    testEncGenSelfsigned(rng);
    logTrace("testEncGenReq");
    testEncGenReq(rng);
    logTrace("testCvcReqExt");
    testCvcReqExt(rng);
    logTrace("testCvcAdoExt");
    testCvcAdoExt(rng);
    logTrace("testCvcAdoCreation");
    testCvcAdoCreation(rng);
    logTrace("testCvcAdoComparison");
    testCvcAdoComparison(rng);
    logTrace("testEacTime");
    testEacTime(rng);
    logTrace("testVerCvca");
    testVerCvca(rng);
    logTrace("testCopyAndAssignment");
    testCopyAndAssignment(rng);
    logTrace("testEacStrIllegalValues");
    testEacStrIllegalValues(rng);
    logTrace("testTmpEacStrEnc");
    testTmpEacStrEnc(rng);
    logTrace("testCvcChain");
    testCvcChain(rng);
}