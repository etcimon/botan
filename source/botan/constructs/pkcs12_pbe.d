/**
* PKCS#12 PBE (RFC 7292 Appendix B)
*
* Copyright:
* (C) 2026 Damiano Mazzella
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.pkcs12_pbe;

import botan.constants;
static if (BOTAN_HAS_PKCS12):

import botan.asn1.alg_id;
import botan.asn1.asn1_oid;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.asn1.oids;
import botan.asn1.asn1_obj;
import botan.hash.hash;
import botan.pbkdf.pbkdf;
import botan.libstate.lookup;
import botan.modes.cbc;
import botan.modes.mode_pad;
import botan.pbkdf.pkcs12_kdf;
import botan.rng.rng;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.algo_base.symkey;
static if (BOTAN_HAS_PBE_PKCS_V20) import botan.constructs.pbes2;

enum size_t PKCS12_MAX_ITERATIONS = 100_000_000;

private struct Pkcs12PbeParams
{
    OID oid;
    string cipher_name;
    size_t key_len;
}

private Pkcs12PbeParams pbeParamsForOid(OID oid)
{
    if (oid == OIDS.lookup("PBE-SHA1-3DES"))
        return Pkcs12PbeParams(oid.clone, "TripleDES/CBC", 24);
    if (oid == OIDS.lookup("PBE-SHA1-2DES"))
        return Pkcs12PbeParams(oid.clone, "TripleDES/CBC", 16);
    throw new DecodingError("Unsupported PKCS#12 PBE algorithm: " ~ oid.toString());
}

private void deriveKeyIv(in string password, const ref Vector!ubyte salt,
                         size_t iterations, const ref Pkcs12PbeParams params,
                         bool openssl_empty, ref SecureVector!ubyte key, ref SecureVector!ubyte iv)
{
    enum size_t iv_len = 8;
    key.length = params.key_len;
    iv.length = iv_len;
    Unique!HashFunction hash = retrieveHash("SHA-160").clone();
    if (openssl_empty && password.length == 0)
    {
        pkcs12Kdf(key.ptr, params.key_len, null, 0, salt.ptr, salt.length, iterations, 1, *hash);
        pkcs12Kdf(iv.ptr, iv_len, null, 0, salt.ptr, salt.length, iterations, 2, *hash);
    }
    else
    {
        Unique!PBKDF kdf_key = getPbkdf("PKCS12-KDF(SHA-160,1)");
        Unique!PBKDF kdf_iv = getPbkdf("PKCS12-KDF(SHA-160,2)");
        auto k = kdf_key.deriveKey(params.key_len, password, salt.ptr, salt.length, iterations);
        auto v = kdf_iv.deriveKey(iv_len, password, salt.ptr, salt.length, iterations);
        key[] = k.bitsOf()[];
        iv[] = v.bitsOf()[];
    }
    if (params.key_len == 16)
    {
        key.length = 24;
        key[16 .. 24] = key[0 .. 8];
    }
}

/**
* Decrypt PKCS#12 PBE (SHA-1/3DES or 2DES) or PBES2.
* `openssl_empty` feeds a zero-length password to the PKCS#12 KDF.
*/
SecureVector!ubyte pkcs12PbeDecrypt(const(ubyte)* ciphertext, size_t ct_len,
                                    in string password,
                                    const ref AlgorithmIdentifier pbe_algo,
                                    bool openssl_empty = false)
{
    if (pbe_algo.oid == OIDS.lookup("PBE-PKCS5v20"))
    {
        static if (BOTAN_HAS_PBE_PKCS_V20)
        {
            auto bits = SecureVector!ubyte(ciphertext[0 .. ct_len]);
            auto params = pbe_algo.parameters;
            return pbes2Decrypt(bits, password, params);
        }
        else
            throw new DecodingError("Unsupported PKCS#12 PBE algorithm: PBES2");
    }

    Vector!ubyte salt;
    size_t iterations = 0;
    BERDecoder(pbe_algo.parameters)
        .startCons(ASN1Tag.SEQUENCE)
        .decode(salt, ASN1Tag.OCTET_STRING)
        .decode(iterations)
        .verifyEnd()
        .endCons();
    if (iterations == 0 || iterations > PKCS12_MAX_ITERATIONS)
        throw new DecodingError("PKCS#12 PBE has invalid iteration count");

    auto pbe_oid = pbe_algo.oid.clone;
    auto params = pbeParamsForOid(pbe_oid);
    SecureVector!ubyte key, iv;
    deriveKeyIv(password, salt, iterations, params, openssl_empty, key, iv);

    Unique!CBCDecryption dec = new CBCDecryption(
        retrieveBlockCipher("TripleDES").clone(), new PKCS7Padding);
    dec.setKey(key.ptr, key.length);
    dec.start(iv.ptr, iv.length);
    auto pt = SecureVector!ubyte(ciphertext[0 .. ct_len]);
    dec.finish(pt);
    return pt.move();
}

private Pkcs12PbeParams pbeParamsForAlgo(string algo)
{
    if (algo == "PBE-SHA1-3DES")
        return Pkcs12PbeParams(OIDS.lookup("PBE-SHA1-3DES").clone, "TripleDES/CBC", 24);
    if (algo == "PBE-SHA1-2DES")
        return Pkcs12PbeParams(OIDS.lookup("PBE-SHA1-2DES").clone, "TripleDES/CBC", 16);
    throw new InvalidArgument("Unsupported PKCS#12 PBE algorithm: " ~ algo);
}

/**
* Encrypt with PKCS#12 PBE (SHA-1/3DES or 2DES) or PBES2.
* Returns the AlgorithmIdentifier and ciphertext.
*/
Pair!(AlgorithmIdentifier, Array!ubyte) pkcs12PbeEncrypt(const(ubyte)* plaintext, size_t pt_len,
                                                         in string password,
                                                         in string algo,
                                                         size_t iterations,
                                                         RandomNumberGenerator rng)
{
    if (iterations == 0 || iterations > PKCS12_MAX_ITERATIONS)
        throw new InvalidArgument("PKCS#12 PBE: iteration count must be between 1 and 100000000");

    static if (BOTAN_HAS_PBE_PKCS_V20)
    {
        if (algo == "PBES2-SHA256-AES256" || algo == "PBES2-SHA256-AES128")
        {
            const string cipher = (algo == "PBES2-SHA256-AES256") ? "AES-256/CBC" : "AES-128/CBC";
            auto bits = SecureVector!ubyte(plaintext[0 .. pt_len]);
            return pbes2EncryptIter(bits, password, iterations, cipher, "SHA-256", rng);
        }
    }

    auto params = pbeParamsForAlgo(algo);
    Vector!ubyte salt;
    salt.length = 8;
    rng.randomize(salt.ptr, salt.length);

    SecureVector!ubyte key, iv;
    deriveKeyIv(password, salt, iterations, params, false, key, iv);

    Unique!CBCEncryption enc = new CBCEncryption(
        retrieveBlockCipher("TripleDES").clone(), new PKCS7Padding);
    enc.setKey(key.ptr, key.length);
    enc.start(iv.ptr, iv.length);
    auto ct = SecureVector!ubyte(plaintext[0 .. pt_len]);
    enc.finish(ct);

    Vector!ubyte enc_params = DEREncoder()
        .startCons(ASN1Tag.SEQUENCE)
        .encode(salt, ASN1Tag.OCTET_STRING)
        .encode(iterations)
        .endCons()
        .getContentsUnlocked();
    auto oid = params.oid.clone;
    return makePair(AlgorithmIdentifier(oid, enc_params), unlock(ct).cloneToRef);
}
