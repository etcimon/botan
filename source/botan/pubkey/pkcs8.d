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
    //logTrace("PKCS8 PEM encode with password");
    const string DEFAULT_PBE = "PBE-PKCS5v20(SHA-1,AES-256/CBC)";
    
    PBE pbe = getPbe(((pbe_algo != "") ? pbe_algo : DEFAULT_PBE), pass, dur, rng);
    
    AlgorithmIdentifier pbe_algid = AlgorithmIdentifier(pbe.getOid(), pbe.encodeParams());
    
    Pipe key_encrytor = Pipe(pbe);
    auto ber = BER_encode(key);
    key_encrytor.processMsg(ber);
    auto enc = DEREncoder().startCons(ASN1Tag.SEQUENCE);
    enc.encode(pbe_algid);
    //logTrace("Encoded algid: ", pbe_algid.toString());
    enc.encode(key_encrytor.readAll(), ASN1Tag.OCTET_STRING)
        .endCons();
    auto contents = enc.getContentsUnlocked();
    //logTrace("Contents: ", contents[]);
    return contents.move();
}

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* Params:
*  key = the key to encode
*  rng = the rng to use
*  pass = the password to use for encryption
*  msec = number of milliseconds to run the password derivation
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
                   SingleShotPassphrase get_pass)
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
    return loadKey(source, rng, SingleShotPassphrase(pass));
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
                   SingleShotPassphrase get_pass)
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
    return loadKey(filename, rng, SingleShotPassphrase(pass));
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
SecureVector!ubyte PKCS8_decode(DataSource source, SingleShotPassphrase get_pass, ref AlgorithmIdentifier pk_alg_id)
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
            else
                throw new PKCS8Exception("Unknown PEM label " ~ label);
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
                Pair!(bool, string) pass = get_pass();
                
                if (pass.first == false)
                    break;
                
                //logTrace("PKCS8 get pkcs8 alg id");
                Pipe decryptor = Pipe(getPbe(pbe_alg_id.oid, pbe_alg_id.parameters, pass.second));
                
                decryptor.processMsg(key_data);
                key = decryptor.readAll();
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
        catch(DecodingError)
        {
            ++tries;
        }
    }
    
    if (key.empty)
        throw new DecodingError("PKCS #8 private key decoding failed");
    return key.move;
}


private struct SingleShotPassphrase
{
public:
    this(in string pass) 
    {
        passphrase = pass;
        first = true;
    }
    
    Pair!(bool, string) opCall()
    {
        if (first)
        {
            first = false;
            return makePair(true, passphrase);
        }
        else
            return makePair(false, "");
    }
    
private:
    string passphrase;
    bool first;
}
