/**
* PKCS #8
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.pkcs8;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

alias pkcs8 = botan.pubkey.pkcs8;

public import botan.rng.rng;
public import botan.pubkey.pubkey;
import botan.pubkey.x509_key;
import std.datetime;
import botan.filters.pipe;
import botan.pbe.factory;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.codec.pem;
import botan.pubkey.pk_algs;
import botan.utils.types;
import botan.pbe.pbe;
import std.range : empty;
import botan.algo_base.scan_token;

/**
* PKCS #8 General Exception
*/
final class PKCS8Exception : DecodingError
{
    this(in string error)
    {
        super("PKCS #8: " ~ error);
    }
}

/**
* BER encode a private key
* Params:
*  key = the private key to encode
* Returns: BER encoded key
*/
SecureArray!ubyte BER_encode(in PrivateKey key)
{
    __gshared immutable size_t PKCS8_VERSION = 0;
    auto vec = DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(key.pkcs8AlgorithmIdentifier())
            .encode(key.pkcs8PrivateKey(), ASN1Tag.OCTET_STRING)
            .endCons()
            .getContentsRef();
    return vec;
}

/**
* Get a string containing a PEM encoded private key.
* Params:
*  key = the key to encode
* Returns: encoded key
*/
string PEM_encode(in PrivateKey key)
{
    auto ret = BER_encode(key);
    return PEM.encode(ret, "PRIVATE KEY");
}

/**
* Encrypt a key using PKCS #8 encryption
* Params:
*  key = the key to encode
*  rng = the rng to use
*  pass = the password to use for encryption
*  dur = number of time to run the password derivation
*  pbe_algo = the name of the desired password-based encryption
            algorithm; if empty ("") a reasonable (portable/secure)
            default will be chosen.
* Returns: encrypted key in binary BER form
*/
Vector!ubyte BER_encode(in PrivateKey key,
                        RandomNumberGenerator rng,
                        in string pass,
                        Duration dur = 300.msecs,
                        in string pbe_algo = "")
{
	const auto pbe_params = choosePbeParams(pbe_algo, key.algo_name());
	
	const Pair!(AlgorithmIdentifier, Vector!ubyte) pbe_info =
		pbes2Encrypt(pkcs8.BER_encode(key), pass, msec, pbe_params.first, pbe_params.second, rng);
	
	return DER_Encoder()
		    .startCons(SEQUENCE)
			.encode(pbe_info.first)
			.encode(pbe_info.second, OCTET_STRING)
			.endCons()
			.getContentsUnlocked();
}

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* Params:
*  key = the key to encode
*  rng = the rng to use
*  pass = the password to use for encryption
*  dur = number of milliseconds to run the password derivation
*  pbe_algo = the name of the desired password-based encryption
            algorithm; if empty ("") a reasonable (portable/secure)
            default will be chosen.
* Returns: encrypted key in PEM form
*/
string PEM_encode(in PrivateKey key,
                  RandomNumberGenerator rng,
                  in string pass,
                  Duration dur = 300.msecs,
                  in string pbe_algo = "")
{
    if (pass == "")
        return PEM_encode(key);
    auto contents = BER_encode(key, rng, pass, dur, pbe_algo);
    //logTrace("PEM got contents");
    return PEM.encode(contents, "ENCRYPTED PRIVATE KEY");
}

/**
* Load a key from a data source.
* Params:
*  source = the data source providing the encoded key
*  rng = the rng to use
*  get_pass = a function that returns passphrases
* Returns: loaded private key object
*/
PrivateKey loadKey(DataSource source,
                   RandomNumberGenerator rng,
                   string delegate() get_pass)
{
     auto alg_id = AlgorithmIdentifier();
    SecureVector!ubyte pkcs8_key = PKCS8_decode(source, get_pass, alg_id);
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "" || alg_name == alg_id.oid.toString())
        throw new PKCS8Exception("Unknown algorithm OID: " ~ alg_id.oid.toString());
    //logTrace("loadKey alg id: ", OIDS.lookup(alg_id.oid));
    return makePrivateKey(alg_id, pkcs8_key, rng);
}

/** Load a key from a data source.
* Params:
*  source = the data source providing the encoded key
*  rng = the rng to use
*  pass = the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* Returns: loaded private key object
*/
PrivateKey loadKey(DataSource source,
                   RandomNumberGenerator rng,
                   in string pass = "")
{
	return loadKey(source, rng, { return pass; });
}

/**
* Load a key from a file.
* Params:
*  filename = the path to the file containing the encoded key
*  rng = the rng to use
*  get_pass = a function that returns passphrases
* Returns: loaded private key object
*/
PrivateKey loadKey(in string filename,
                   RandomNumberGenerator rng,
                   string delegate() get_pass)
{
    auto source = DataSourceStream(filename, true);
    return loadKey(cast(DataSource)source, rng, get_pass);
}

/** Load a key from a file.
* Params:
*  filename = the path to the file containing the encoded key
*  rng = the rng to use
*  pass = the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* Returns: loaded private key object
*/
PrivateKey loadKey(in string filename,
                   RandomNumberGenerator rng,
                   in string pass = "")
{
	return loadKey(filename, rng, { return pass; });
}


/**
* Copy an existing encoded key object.
* Params:
*  key = the key to copy
*  rng = the rng to use
* Returns: new copy of the key
*/
PrivateKey copyKey(in PrivateKey key,
                   RandomNumberGenerator rng)
{
    auto source = DataSourceMemory(PEM_encode(key));
    return loadKey(cast(DataSource)source, rng);
}

/*
* Get info from an EncryptedPrivateKeyInfo
*/
SecureVector!ubyte PKCS8_extract(DataSource source,
                                 AlgorithmIdentifier pbe_alg_id)
{
    SecureVector!ubyte key_data;
    
    BERDecoder(source)
            .startCons(ASN1Tag.SEQUENCE)
            .decode(pbe_alg_id)
            .decode(key_data, ASN1Tag.OCTET_STRING)
            .verifyEnd();
    
    //logTrace("PKCS8 extract key data finished", pbe_alg_id.toString());
    return key_data.move;
}

/*
* PEM decode and/or decrypt a private key
*/
SecureVector!ubyte PKCS8_decode(DataSource source, in string delegate() get_pass, ref AlgorithmIdentifier pk_alg_id)
{
    auto pbe_alg_id = AlgorithmIdentifier();
    SecureVector!ubyte key_data, key;
    bool is_encrypted = true;
    try {
        if (maybeBER(source) && !PEM.matches(source))
            key_data = PKCS8_extract(source, pbe_alg_id);
        else
        {
            string label;
			import std.algorithm : endsWith;
            key_data = PEM.decode(source, label);
            if (label == "PRIVATE KEY") {
                //logTrace("Detected private key");
                is_encrypted = false;
            }
            else if (label == "ENCRYPTED PRIVATE KEY")
            {
                auto key_source = DataSourceMemory(key_data);
                key_data = PKCS8_extract(cast(DataSource)key_source, pbe_alg_id);
            }
			else if (label == "RSA PRIVATE KEY") {
				throw new PKCS8Exception("Unsupported format: PKCS#1 RSA Private Key file");
			}
            else
                throw new PKCS8Exception("Unsupported PKCS#/Private Key format, you must convert your certificate to PKCS#8");
        }
        
        if (key_data.empty)
            throw new PKCS8Exception("No key data found");
    }
    catch(DecodingError e)
    {
        throw new DecodingError("PKCS #8 private key decoding failed: " ~ e.msg);
    }
    
    if (!is_encrypted)
        key = key_data.dup;
    
    __gshared immutable size_t MAX_TRIES = 3;
    
    size_t tries = 0;
    while (true)
    {
        try {
            if (MAX_TRIES && tries >= MAX_TRIES)
                break;
            
            if (is_encrypted)
            {

				if(OIDS.lookup(pbe_alg_id.oid) != "PBE-PKCS5v20")
				    throw new Exception("Unknown PBE type " ~ pbe_alg_id.oid.toString());
                
				key = pbes2Decrypt(key_data, get_pass(), pbe_alg_id.parameters);
			}
			
			BERDecoder(key)
                    .startCons(ASN1Tag.SEQUENCE)
                    .decodeAndCheck!size_t(0, "Unknown PKCS #8 version number")
                    .decode(pk_alg_id)
                    .decode(key, ASN1Tag.OCTET_STRING)
                    .discardRemaining()
                    .endCons();
            break;
        }
        catch(DecodingError e)
        {
			//logError("Decoding error: ", e.toString());
            ++tries;
        }
    }
    
    if (key.empty)
        throw new DecodingError("PKCS #8 private key decoding failed");
    return key.move;
}

private Pair!(string, string)
	choosePbeParams(const string pbe_algo, const string key_algo)
{
	if(pbe_algo == "")
	{
		// Defaults:
		if(key_algo == "Curve25519" || key_algo == "McEliece")
			return makePair("AES-256/GCM", "SHA-512");
		else // for everything else (RSA, DSA, ECDSA, GOST, ...)
			return makePair("AES-256/CBC", "SHA-256");
	}
	
	SCANToken request = SCANToken(pbe_algo);
	if(request.algoName() != "PBE-PKCS5v20" || request.argCount() != 2)
		throw new Exception("Unsupported PBE " ~ pbe_algo);
	return makePair(request.arg(1), request.arg(0));
}