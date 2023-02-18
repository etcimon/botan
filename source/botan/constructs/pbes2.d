/**
* PKCS #5 v2.0 PBE
*
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.pbes2;

import botan.constants;
static if (BOTAN_HAS_PBE_PKCS_V20):

import botan.utils.types;
import botan.algo_base.transform;
import std.datetime;
import botan.pbkdf.pbkdf;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.rng.rng;
import botan.utils.parsing;
import botan.stream.stream_cipher;
import botan.modes.cipher_mode;
import botan.modes.cbc;
import botan.modes.aead.gcm;
import botan.utils.mem_ops;
import botan.libstate.libstate;


/**
* Encrypt with PBES2 from PKCS #5 v2.0
*  key_bits = the passphrase to use for encryption
*  msec = how many milliseconds to run PBKDF2
*  cipher = specifies the block cipher to use to encrypt
*  digest = specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
*  rng = a random number generator
*/
Pair!(AlgorithmIdentifier, Array!ubyte)
	pbes2Encrypt()(auto const ref SecureVector!ubyte key_bits,
                   const string passphrase,
                   Duration msec,
                   const string cipher,
                   const string digest,
                   RandomNumberGenerator rng,
                   AlgorithmFactory af = null)
{
	if (!af) af = globalState().algorithmFactory();
	const string prf = "HMAC(" ~ digest ~ ")";
	
	const Vector!string cipher_spec = splitter(cipher, '/');
	if(cipher_spec.length != 2)
		throw new DecodingError("PBE-PKCS5 v2.0: Invalid cipher spec " ~ cipher);
	
	const SecureVector!ubyte salt = rng.randomVec(12);
	
	if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
		throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);

	Unique!KeyedTransform enc;
	static if (BOTAN_HAS_AEAD_GCM) {
		if(cipher_spec[1] == "GCM")
			enc = new GCMEncryption(af.makeBlockCipher(cipher_spec[0]));
		else if(cipher_spec[1] == "CBC")
			enc = new CBCEncryption(af.makeBlockCipher(cipher_spec[0]), new PKCS7Padding);
		else
			throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
	} else {	
		if(cipher_spec[1] == "CBC")
			enc = new CBCEncryption(af.makeBlockCipher(cipher_spec[0]), new PKCS7Padding);
		else
			throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
	}
	if (enc.isEmpty())
		throw new DecodingError("PBE-PKCS5: Cannot decrypt, no cipher " ~ cipher);
	Unique!PBKDF pbkdf = getPbkdf("PBKDF2(" ~ prf ~ ")");
	
	const size_t key_length = enc.keySpec().maximumKeylength();
	size_t iterations = 0;
	
	SecureVector!ubyte iv = rng.randomVec(enc.defaultNonceLength());

	auto key = pbkdf.deriveKey(key_length, passphrase, salt.ptr, salt.length,
		msec, iterations).bitsOf();
	enc.setKey(key.ptr, key.length);
	
	enc.start(iv);
	SecureVector!ubyte buf = key_bits.ptr[0 .. key_bits.length];
	enc.finish(buf);
	
	AlgorithmIdentifier id = AlgorithmIdentifier(
		OIDS.lookup("PBE-PKCS5v20"),
		encodePbes2Params(cipher, prf, salt, iv, iterations, key_length));
	
	return makePair(id, unlock(buf).cloneToRef);
	
}
/*
* Encode PKCS#5 PBES2 parameters
*/
Vector!ubyte encodePbes2Params(const string cipher,
                               const string prf,
                               const ref SecureVector!ubyte salt,
                               const ref SecureVector!ubyte iv,
                               size_t iterations,
                               size_t key_length)
{
	return DEREncoder()
		.startCons(ASN1Tag.SEQUENCE)
			.encode(AlgorithmIdentifier("PKCS5.PBKDF2", 
					DEREncoder()
					.startCons(ASN1Tag.SEQUENCE)
					.encode(salt, ASN1Tag.OCTET_STRING)
					.encode(iterations)
					.encode(key_length)
					.encodeIf(prf != "HMAC(SHA-160)",
						AlgorithmIdentifier(prf, AlgorithmIdentifierImpl.USE_NULL_PARAM))
					.endCons()
					.getContentsUnlocked()
					)
				)
			.encode(
				AlgorithmIdentifier(cipher,
					DEREncoder().encode(iv, ASN1Tag.OCTET_STRING).getContentsUnlocked()
					)
				)
			.endCons()
			.getContentsUnlocked();
}


/**
* Decrypt a PKCS #5 v2.0 encrypted stream
*  key_bits = the input
*  passphrase = the passphrase to use for decryption
*  params = the PBES2 parameters
*/
SecureVector!ubyte
	pbes2Decrypt()(const ref SecureVector!ubyte key_bits,
				   const string passphrase,
				   auto const ref Vector!ubyte params,
                   AlgorithmFactory af = null)
{
	if (!af) af = globalState().algorithmFactory();
	AlgorithmIdentifier kdf_algo, enc_algo;
	
	BERDecoder(params)
		.startCons(ASN1Tag.SEQUENCE)
			.decode(kdf_algo)
			.decode(enc_algo)
			.verifyEnd()
			.endCons();
	
	AlgorithmIdentifier prf_algo;
	
	if(kdf_algo.oid != OIDS.lookup("PKCS5.PBKDF2"))
		throw new DecodingError("PBE-PKCS5 v2.0: Unknown KDF algorithm " ~ kdf_algo.oid.toString());
	
	SecureVector!ubyte salt;
	size_t iterations, key_length;
	
	BERDecoder(kdf_algo.parameters)
		.startCons(ASN1Tag.SEQUENCE)
			.decode(salt, ASN1Tag.OCTET_STRING)
			.decode(iterations)
			.decodeOptional(key_length, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL)
			.decodeOptional(prf_algo, ASN1Tag.SEQUENCE, ASN1Tag.CONSTRUCTED,
				AlgorithmIdentifier("HMAC(SHA-160)",
					AlgorithmIdentifierImpl.USE_NULL_PARAM))
			.verifyEnd()
			.endCons();
	
	const string cipher = OIDS.lookup(enc_algo.oid);
	const Vector!string cipher_spec = splitter(cipher, '/');
	if(cipher_spec.length != 2)
		throw new DecodingError("PBE-PKCS5 v2.0: Invalid cipher spec " ~ cipher);
	if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
		throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
	
	if(salt.length < 8)
		throw new DecodingError("PBE-PKCS5 v2.0: Encoded salt is too small");
	
	SecureVector!ubyte iv;
	BERDecoder(enc_algo.parameters).decode(iv, ASN1Tag.OCTET_STRING).verifyEnd();
	
	const string prf = OIDS.lookup(prf_algo.oid);
	
	Unique!PBKDF pbkdf = getPbkdf("PBKDF2(" ~ prf ~ ")");

	Unique!KeyedTransform dec;
	static if (BOTAN_HAS_AEAD_GCM) {
		if (cipher_spec[1] == "GCM")
			dec = new GCMDecryption(af.makeBlockCipher(cipher_spec[0]));
		else if (cipher_spec[1] == "CBC")
			dec = new CBCDecryption(af.makeBlockCipher(cipher_spec[0]), new PKCS7Padding);
		else
			throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
	} else {	
		if (cipher_spec[1] == "CBC")
			dec = new CBCDecryption(af.makeBlockCipher(cipher_spec[0]), new PKCS7Padding);
		else
			throw new DecodingError("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
	}

	if(key_length == 0)
		key_length = dec.keySpec().maximumKeylength();
	
	dec.setKey(pbkdf.deriveKey(key_length, passphrase, salt.ptr, salt.length, iterations));
	
	dec.start(iv);
	
	SecureVector!ubyte buf = key_bits.ptr[0 .. key_bits.length];
	dec.finish(buf);
	
	return buf.move();
}