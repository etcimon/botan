/**
* Keypair Checks
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.keypair;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.pubkey.pk_keys;
public import botan.pubkey.pubkey;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* Params:
*  rng = the rng to use
*  key = the key to test
*  padding = the encryption padding method to use
* Returns: true if consistent otherwise false
*/
bool encryptionConsistencyCheck(RandomNumberGenerator rng,
                                in PrivateKey key,
                                in string padding)
{
    //logTrace("Encryption consistency check");
    auto encryptor = scoped!PKEncryptorEME(key, padding);
    auto decryptor = scoped!PKDecryptorEME(key, padding);
    
    /*
    Weird corner case, if the key is too small to encrypt anything at
    all. This can happen with very small RSA keys with PSS
    */
    if (encryptor.maximumInputSize() == 0)
        return true;
    
    Vector!ubyte plaintext = unlock(rng.randomVec(encryptor.maximumInputSize() - 1));
    Vector!ubyte ciphertext = encryptor.encrypt(plaintext, rng);
    if (ciphertext == plaintext)
        return false;
    
    Vector!ubyte decrypted = unlock(decryptor.decrypt(ciphertext));
    
    return (plaintext == decrypted);
}

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* Params:
*  rng = the rng to use
*  key = the key to test
*  padding = the signature padding method to use
* Returns: true if consistent otherwise false
*/
bool signatureConsistencyCheck(RandomNumberGenerator rng,
                               in PrivateKey key,
                               in string padding)
{
    //logTrace("Signature consistency check");
    //logTrace("key: ", key.algoName);
    //logTrace("Pad: ", padding);
    PKSigner signer = PKSigner(key, padding);
    PKVerifier verifier = PKVerifier(key, padding);
    Vector!ubyte message = unlock(rng.randomVec(16));
    
    Vector!ubyte signature;
    try
    {
        signature = signer.signMessage(message, rng);
    }
    catch(EncodingError)
    {
        return false;
    }
    if (!verifier.verifyMessage(message, signature))
        return false;
    
    // Now try to check a corrupt signature, ensure it does not succeed
    ++message[0];
    
    if (verifier.verifyMessage(message, signature))
        return false;
    
    return true;
}
