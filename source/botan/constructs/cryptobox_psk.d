/**
* Cryptobox Message Routines
* 
* Copyright:
* (C) 2009,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.cryptobox_psk;

import botan.constants;
static if (BOTAN_HAS_CRYPTOBOX):

import botan.rng.rng;
import botan.algo_base.symkey;
import botan.filters.pipe;
import botan.libstate.lookup;
import botan.mac.mac;
import botan.utils.mem_ops;
import botan.utils.loadstor;
import botan.utils.types;
/**
* This namespace holds various high-level crypto functions
*/
struct CryptoBox {

    /**
    * Encrypt a message using a shared secret key
    * Params:
    *  input = the input data
    *  input_len = the length of input in bytes
    *  key = the key used to encrypt the message
    *  rng = a ref to a random number generator, such as AutoSeededRNG
    */
    static Vector!ubyte encrypt(const(ubyte)* input, size_t input_len,
                                in SymmetricKey master_key,
                                RandomNumberGenerator rng)
    {
        Unique!KDF kdf = getKdf(CRYPTOBOX_KDF);
        
        const SecureVector!ubyte cipher_key_salt = rng.randomVec(KEY_KDF_SALT_LENGTH);
        
        const SecureVector!ubyte mac_key_salt = rng.randomVec(KEY_KDF_SALT_LENGTH);
        
        SymmetricKey cipher_key = kdf.deriveKey(CIPHER_KEY_LENGTH, master_key.bitsOf(), cipher_key_salt);
        
        SymmetricKey mac_key = kdf.deriveKey(MAC_KEY_LENGTH, master_key.bitsOf(), mac_key_salt);
        
        InitializationVector cipher_iv = InitializationVector(rng, 16);
        
        Unique!MessageAuthenticationCode mac = retrieveMac(CRYPTOBOX_MAC).clone();
        mac.setKey(mac_key);
        
        Pipe pipe = Pipe(getCipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, ENCRYPTION));
        pipe.processMsg(input, input_len);
        SecureVector!ubyte ctext = pipe.readAll(0);
        
        SecureVector!ubyte output = SecureVector!ubyte(MAGIC_LENGTH);
        storeBigEndian(CRYPTOBOX_MAGIC, output.ptr);
        output ~= cipher_key_salt[];
        output ~= mac_key_salt[];
        output ~= cipher_iv.bitsOf()[];
        output ~= ctext[];

        mac.update(output);
        
        output ~= mac.finished();
        return output.unlock();
    }

    /**
    * Encrypt a message using a shared secret key
    * Params:
    *  input = the input data
    *  input_len = the length of input in bytes
    *  key = the key used to encrypt the message
    *  rng = a ref to a random number generator, such as AutoSeededRNG
    */
    static SecureVector!ubyte decrypt(const(ubyte)* input, size_t input_len, in SymmetricKey master_key)
    {
        __gshared immutable size_t MIN_CTEXT_SIZE = 16; // due to using CBC with padding
        
        __gshared immutable size_t MIN_POSSIBLE_LENGTH = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH + 
                                                         MIN_CTEXT_SIZE + MAC_OUTPUT_LENGTH;
        
        if (input_len < MIN_POSSIBLE_LENGTH)
            throw new DecodingError("Encrypted input too short to be valid");
        
        if (loadBigEndian!uint(input, 0) != CRYPTOBOX_MAGIC)
            throw new DecodingError("Unknown header value in cryptobox");
        
        Unique!KDF kdf = getKdf(CRYPTOBOX_KDF);
        
        const(ubyte)* cipher_key_salt = &input[MAGIC_LENGTH];
        
        const(ubyte)* mac_key_salt = &input[MAGIC_LENGTH + KEY_KDF_SALT_LENGTH];
        
        SymmetricKey mac_key = kdf.deriveKey(MAC_KEY_LENGTH,
                                              master_key.bitsOf(),
                                              mac_key_salt,
                                              KEY_KDF_SALT_LENGTH);
        
        Unique!MessageAuthenticationCode mac = retrieveMac(CRYPTOBOX_MAC).clone();
        mac.setKey(mac_key);
        
        mac.update(input, input_len - MAC_OUTPUT_LENGTH);
        SecureVector!ubyte computed_mac = mac.finished();
        
        if (!sameMem(&input[input_len - MAC_OUTPUT_LENGTH], computed_mac.ptr, computed_mac.length))
            throw new DecodingError("MAC verification failed");
        
        SymmetricKey cipher_key = kdf.deriveKey(CIPHER_KEY_LENGTH, master_key.bitsOf(), cipher_key_salt, KEY_KDF_SALT_LENGTH);
        
        InitializationVector cipher_iv = InitializationVector(&input[MAGIC_LENGTH+2*KEY_KDF_SALT_LENGTH], CIPHER_IV_LENGTH);
        
        const size_t CTEXT_OFFSET = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH;
        
        Pipe pipe = Pipe(getCipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, DECRYPTION));
        pipe.processMsg(&input[CTEXT_OFFSET],
        input_len - (MAC_OUTPUT_LENGTH + CTEXT_OFFSET));
        return pipe.readAll();
    }

}

private:

__gshared immutable uint CRYPTOBOX_MAGIC = 0x571B0E4F;
__gshared immutable string CRYPTOBOX_CIPHER = "AES-256/CBC";
__gshared immutable string CRYPTOBOX_MAC = "HMAC(SHA-256)";
__gshared immutable string CRYPTOBOX_KDF = "KDF2(SHA-256)";

__gshared immutable size_t MAGIC_LENGTH = 4;
__gshared immutable size_t KEY_KDF_SALT_LENGTH = 10;
__gshared immutable size_t MAC_KEY_LENGTH = 32;
__gshared immutable size_t CIPHER_KEY_LENGTH = 32;
__gshared immutable size_t CIPHER_IV_LENGTH = 16;
__gshared immutable size_t MAC_OUTPUT_LENGTH = 32;
