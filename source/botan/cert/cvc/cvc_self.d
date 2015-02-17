/**
* CVC Self-Signed Certificate
* 
* Copyright:
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.cert.cvc.cvc_self;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

static assert(BOTAN_HAS_ECDSA, "CVC requires ECDSA");

alias cvc_self = botan.cert.cvc.cvc_self;

public import botan.pubkey.algo.ecc_key;
import botan.pubkey.pkcs8;
import botan.asn1.oids;
import botan.asn1.asn1_obj;
import botan.cert.cvc.cvc_cert;
public import botan.cert.cvc.cvc_req;
import botan.cert.cvc.cvc_ado;
import botan.cert.cvc.cvc_gen_cert;
import botan.math.ec_gfp.curve_gfp;
import botan.pubkey.pubkey;
import botan.pubkey.algo.ecdsa;
import botan.cert.cvc.eac_asn_obj;
import botan.rng.rng;
import botan.utils.types;
import std.datetime;
import std.array : Appender;

/**
* This class represents a set of options used for the creation of CVC certificates
*/
struct EAC11CVCOptions
{
public:

    ASN1Car car;
    ASN1Chr chr;
    ubyte holder_auth_templ;
    ASN1Ced ced;
    ASN1Cex cex;
    string hash_alg;
}

/**
* Create a selfsigned CVCA
* Params:
*  rng = the rng to use
*  key = the ECDSA private key to be used to sign the certificate
*  opts = used to set several parameters. Necessary are:
* car, holder_auth_templ, hash_alg, ced, cex and hash_alg
* Returns: the self signed certificate
*/
EAC11CVC createSelfSignedCert(in PrivateKey key,
                              in EAC11CVCOptions opt,
                              RandomNumberGenerator rng)
{
    // NOTE: we ignore the value of opt.chr
    ECDSAPrivateKey priv_key = ECDSAPrivateKey(key);
    
    if (!priv_key)
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    
    ASN1Chr chr = ASN1Chr(opt.car.value());
    
    auto sig_algo = AlgorithmIdentifier();
    string padding_and_hash = "EMSA1_BSI(" ~ opt.hash_alg ~ ")";
    //logTrace(padding_and_hash);
    sig_algo.oid = OIDS.lookup(priv_key.algoName ~ "/" ~ padding_and_hash);
    sig_algo = AlgorithmIdentifier(cast(OID)sig_algo.oid, AlgorithmIdentifierImpl.USE_NULL_PARAM);
    
    PKSigner signer = PKSigner(key, padding_and_hash);
    
    Vector!ubyte enc_public_key = eac11Encoding(cast(ECPublicKey)key, sig_algo.oid);
    
    return makeCvcCert(signer,
                       enc_public_key,
                       opt.car, chr,
                       opt.holder_auth_templ,
                       opt.ced, opt.cex, rng);
}


/**
* Create a CVC request. The key encoding will be according to the provided private key.
* Params:
*  priv_key = the private key associated with the requesting entity
*  chr = the chr to appear in the certificate (to be provided without
* sequence number)
*  hash_alg = the string defining the hash algorithm to be used for the creation
* of the signature
*  rng = the rng to use
* Returns: the new request
*/
EAC11Req createCvcReq(in PrivateKey key,
                      in ASN1Chr chr,
                      in string hash_alg,
                      RandomNumberGenerator rng)
{
    
    const ECDSAPrivateKey priv_key = cast(const ECDSAPrivateKey) key;
    if (priv_key is null)
    {
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    }
    auto sig_algo = AlgorithmIdentifier();
    string padding_and_hash = "EMSA1_BSI(" ~ hash_alg ~ ")";
    sig_algo.oid = OIDS.lookup(priv_key.algoName ~ "/" ~ padding_and_hash);
    sig_algo = AlgorithmIdentifier(cast(OID)sig_algo.oid, AlgorithmIdentifierImpl.USE_NULL_PARAM);
    
    PKSigner signer = PKSigner(priv_key, padding_and_hash);
    
    Vector!ubyte enc_public_key = eac11Encoding(priv_key, sig_algo.oid);
    
    Vector!ubyte enc_cpi;
    enc_cpi.pushBack(0x00);
    Vector!ubyte tbs = DEREncoder()
            .encode(enc_cpi, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)41), ASN1Tag.APPLICATION)
            .rawBytes(enc_public_key)
            .encode(chr)
            .getContentsUnlocked();
    
    Vector!ubyte signed_cert = 
        EAC11genCVC!EAC11ReqImpl.makeSigned(signer,
                                            EAC11genCVC!EAC11ReqImpl.buildCertBody(tbs),
                                            rng);
    
    auto source = DataSourceMemory(&signed_cert);
    return EAC11Req(cast(DataSource)source);
}

/**
* Create an ADO from a request object.
* Params:
*  priv_key = the private key used to sign the ADO
*  req = the request forming the body of the ADO
*  car = the CAR forming the body of the ADO, i.e. the
* CHR of the entity associated with the provided private key
*  rng = the rng to use
*/
EAC11ADO createAdoReq(in PrivateKey key,
                      in EAC11Req req,
                      in ASN1Car car,
                      RandomNumberGenerator rng)
{
    
    const ECDSAPrivateKey priv_key = cast(const ECDSAPrivateKey) key;
    if (!priv_key)
    {
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    }
    
    string padding_and_hash = paddingAndHashFromOid(req.signatureAlgorithm().oid);
    PKSigner signer = PKSigner(priv_key, padding_and_hash);
    Vector!ubyte tbs_bits = req.BER_encode();
    tbs_bits ~= DEREncoder().encode(car).getContentsUnlocked();
    
    Vector!ubyte signed_cert = EAC11ADO.makeSigned(signer, tbs_bits, rng);
    
    auto source = DataSourceMemory(&signed_cert);
    return EAC11ADO(cast(DataSource)source);
}


/**
* Create a CVCA certificate.
* Params:
*  priv_key = the private key associated with the CVCA certificate
* to be created
*  hash = the string identifying the hash algorithm to be used
* for signing the certificate to be created
*  car = the CAR of the certificate to be created
*  iris = indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical iris image
*  fingerpr = indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical fingerprint image
*  cvca_validity_months = length of time in months this will be valid
*  rng = a random number generator
* Returns: the CVCA certificate created
*/
EAC11CVC createCvca(in PrivateKey key,
                    in string hash,
                    in ASN1Car car, bool iris, bool fingerpr,
                    uint cvca_validity_months,
                    RandomNumberGenerator rng)
{
    const ECDSAPrivateKey priv_key = cast(const ECDSAPrivateKey) key;
    if (!priv_key)
    {
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    }
    EAC11CVCOptions opts;
    opts.car = cast(ASN1Car)car;
    
    opts.ced = ASN1Ced(Clock.currTime());
    opts.cex = ASN1Cex(opts.ced);
    opts.cex.addMonths(cvca_validity_months);
    opts.holder_auth_templ = (CVCA | (iris * IRIS) | (fingerpr * FINGERPRINT));
    opts.hash_alg = hash;
    return createSelfSignedCert(priv_key, opts, rng);
}


/**
* Create a link certificate between two CVCA certificates. The key
* encoding will be implicitCA.
* Params:
*  signer = the cvca certificate associated with the signing
* entity
*  priv_key = the private key associated with the signer
*  to_be_signed = the certificate which whose CAR/CHR will be
* the holder of the link certificate
*  rng = a random number generator
*/
EAC11CVC linkCvca(in EAC11CVC signer,
                  in PrivateKey key,
                  in EAC11CVC signee,
                  RandomNumberGenerator rng)
{
    const ECDSAPrivateKey priv_key = cast(const ECDSAPrivateKey) key;
    
    if (!priv_key)
        throw new InvalidArgument("linkCvca(): unsupported key type");
    
    ASN1Ced ced = ASN1Ced(Clock.currTime());
    ASN1Cex cex = ASN1Cex(signee.getCex());
    if (cast(EACTimeImpl)(*ced) > cast(EACTimeImpl)(*cex))
    {
        Appender!string detail = "linkCvca(): validity periods of provided certificates don't overlap: currend time = ced = ";
        detail ~= ced.toString();
        detail ~= ", signee.cex = ";
        detail ~= cex.toString();
        throw new InvalidArgument(detail.data);
    }
    if (signer.signatureAlgorithm() != signee.signatureAlgorithm())
    {
        throw new InvalidArgument("linkCvca(): signature algorithms of signer and signee don't match");
    }
    AlgorithmIdentifier sig_algo = cast(AlgorithmIdentifier) signer.signatureAlgorithm();
    string padding_and_hash = paddingAndHashFromOid(sig_algo.oid);
    PKSigner pk_signer = PKSigner(priv_key, padding_and_hash);
    Unique!PublicKey pk = signee.subjectPublicKey();
    ECDSAPublicKey subj_pk = cast(ECDSAPublicKey)(*pk);
    subj_pk.setParameterEncoding(EC_DOMPAR_ENC_EXPLICIT);
    
    Vector!ubyte enc_public_key = eac11Encoding(priv_key, sig_algo.oid);
    
    return makeCvcCert(pk_signer, enc_public_key,
                         signer.getCar(),
                         signee.getChr(),
                         signer.getChatValue(),
                         ced, cex,
                         rng);
}

/**
* Create a CVC request. The key encoding will be implicitCA.
* Params:
*  priv_key = the private key associated with the requesting entity
*  chr = the chr to appear in the certificate (to be provided without
* sequence number)
*  hash_alg = the string defining the hash algorithm to be used for the creation
* of the signature
*  rng = a random number generator
* Returns: the new request
*/
EAC11Req createCVCReqImplicitca(PrivateKey prkey, in ASN1Chr chr,
                                in string hash_alg, RandomNumberGenerator rng)
{
    ECDSAPrivateKey priv_key = cast(ECDSAPrivateKey) prkey;
    if (!priv_key)
    {
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    }
    priv_key.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    return createCvcReq(priv_key, chr, hash_alg, rng);
}

/**
* Sign a CVC request.
* 
* Params:
*  signer_cert = the certificate of the signing entity
*  key = the private key of the signing entity
*  signee = the request to be signed
*  seqnr = the sequence number of the certificate to be created
*  seqnr_len = the number of digits the sequence number will be
* encoded in
*  domestic = indicates whether to sign a domestic or a foreign
* certificate: set to true for domestic
*  dvca_validity_months = validity period in months
*  ca_is_validity_months = validity period in months
*  rng = a random number generator
* Returns: the new certificate
*
**/

EAC11CVC signRequest(in EAC11CVC signer_cert,
                        in PrivateKey key,
                        in EAC11Req signee,
                        uint seqnr,
                        uint seqnr_len,
                        bool domestic,
                        uint dvca_validity_months,
                        uint ca_is_validity_months,
                        RandomNumberGenerator rng)
{
    const ECDSAPrivateKey  priv_key = cast(const ECDSAPrivateKey) key;
    if (!priv_key)
    {
        throw new InvalidArgument("CVC_EAC.createSelfSignedCert(): unsupported key type");
    }
    string chr_str = signee.getChr().value();
    
    string seqnr_string = to!string(seqnr);
    
    while (seqnr_string.length < seqnr_len)
        seqnr_string = '0' ~ seqnr_string;
    
    chr_str ~= seqnr_string;
    ASN1Chr chr = ASN1Chr(chr_str);
    string padding_and_hash = paddingAndHashFromOid(signee.signatureAlgorithm().oid);
    PKSigner pk_signer = PKSigner(priv_key, padding_and_hash);
    Unique!PublicKey pk = signee.subjectPublicKey();
    ECDSAPublicKey subj_pk = cast(ECDSAPublicKey) *pk;
    // Unique!PublicKey signer_pk = signer_cert.subjectPublicKey();
    
    // for the case that the domain parameters are not set...
    // (we use those from the signer because they must fit)
    //subj_pk.setDomainParameters(priv_key.domain_parameters());
    
    subj_pk.setParameterEncoding(EC_DOMPAR_ENC_IMPLICITCA);
    
    AlgorithmIdentifier sig_algo = cast(AlgorithmIdentifier) signer_cert.signatureAlgorithm();

    ASN1Ced ced = ASN1Ced(Clock.currTime());
    
    ubyte chat_val;
    ubyte chat_low = signer_cert.getChatValue() & 0x3; // take the chat rights from signer
    ASN1Cex cex = ASN1Cex(ced);
    if ((signer_cert.getChatValue() & CVCA) == CVCA)
    {
        // we sign a dvca
        cex.addMonths(dvca_validity_months);
        if (domestic)
            chat_val = DVCA_domestic | chat_low;
        else
            chat_val = DVCA_foreign | chat_low;
    }
    else if ((signer_cert.getChatValue() & DVCA_domestic) == DVCA_domestic ||
             (signer_cert.getChatValue() & DVCA_foreign) == DVCA_foreign)
    {
        cex.addMonths(ca_is_validity_months);
        chat_val = IS | chat_low;
    }
    else
    {
        throw new InvalidArgument("signRequest(): encountered illegal value for CHAT");
        // (IS cannot sign certificates)
    }
    
    Vector!ubyte enc_public_key = eac11Encoding(priv_key, sig_algo.oid);
    
    return makeCvcCert(pk_signer, enc_public_key,
                       ASN1Car(signer_cert.getChr().iso8859()),
                       chr,
                       chat_val,
                       ced,
                       cex,
                       rng);
}

/*
* cvc CHAT values
*/
alias CHATValues = ubyte;
enum : CHATValues {
    CVCA = 0xC0,
    DVCA_domestic = 0x80,
    DVCA_foreign =  0x40,
    IS    = 0x00,
    
    IRIS = 0x02,
    FINGERPRINT = 0x01
}

void encodeEacBigint()(ref DEREncoder der, auto const ref BigInt x, ASN1Tag tag)
{
    der.encode(BigInt.encode1363(x, x.bytes()), ASN1Tag.OCTET_STRING, tag);
}

Vector!ubyte eac11Encoding(const ECPublicKey key, in OID sig_algo)
{
    if (key.domainFormat() == EC_DOMPAR_ENC_OID)
        throw new EncodingError("CVC encoder: cannot encode parameters by OID");
    
    const ECGroup* domain = &key.domain();
    
    // This is why we can't have nice things
    
    DEREncoder enc;
    enc.startCons((cast(ASN1Tag)73), ASN1Tag.APPLICATION).encode(sig_algo);
    
    if (key.domainFormat() == EC_DOMPAR_ENC_EXPLICIT)
    {
        encodeEacBigint(enc, domain.getCurve().getP(), (cast(ASN1Tag)1));
        encodeEacBigint(enc, domain.getCurve().getA(), (cast(ASN1Tag)2));
        encodeEacBigint(enc, domain.getCurve().getB(), (cast(ASN1Tag)3));
        
        enc.encode(EC2OSP(domain.getBasePoint(), PointGFp.UNCOMPRESSED), 
                   ASN1Tag.OCTET_STRING, (cast(ASN1Tag)4));
        
        encodeEacBigint(enc, domain.getOrder(), (cast(ASN1Tag)4));
    }
    
    enc.encode(EC2OSP(key.publicPoint(), PointGFp.UNCOMPRESSED), 
               ASN1Tag.OCTET_STRING, (cast(ASN1Tag)6));
    
    if (key.domainFormat() == EC_DOMPAR_ENC_EXPLICIT)
        encodeEacBigint(enc, domain.getCofactor(), (cast(ASN1Tag)7));
    
    enc.endCons();
    
    return enc.getContentsUnlocked();
}

string paddingAndHashFromOid(in OID oid)
{
    import std.string : indexOf;
    string padding_and_hash = OIDS.lookup(oid); // use the hash
    
    if (padding_and_hash[0 .. 6] != "ECDSA/")
        throw new InvalidState("CVC: Can only use ECDSA, not " ~ padding_and_hash);
    
    padding_and_hash = padding_and_hash[padding_and_hash.indexOf("/") + 1 .. $];
    return padding_and_hash;
}