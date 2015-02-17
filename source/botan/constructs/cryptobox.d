/**
* Cryptobox Message Routines
* 
* Copyright:
* (C) 2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.cryptobox;

import botan.constants;
static if (BOTAN_HAS_SHA2_64 && BOTAN_HAS_PBKDF2 && BOTAN_HAS_SERPENT && BOTAN_HAS_CTR_BE):

import botan.rng.rng;
import botan.algo_base.symkey;
import botan.filters.filters;
import botan.filters.pipe;
import botan.libstate.lookup;
import botan.hash.sha2_64;
import botan.mac.hmac;
import botan.pbkdf.pbkdf2;
import botan.codec.pem;
import botan.utils.get_byte;
import botan.utils.mem_ops;
import botan.filters.data_src;

/**
* This namespace holds various high-level crypto functions
*/
struct CryptoBox {

    /**
    * Encrypt a message using a passphrase
    * Params:
    *  input = the input data
    *  input_len = the length of input in bytes
    *  passphrase = the passphrase used to encrypt the message
    *  rng = a ref to a random number generator, such as AutoSeededRNG
    */
    static string encrypt(const(ubyte)* input, size_t input_len,
                          in string passphrase,
                          RandomNumberGenerator rng)
    {
        SecureVector!ubyte pbkdf_salt = SecureVector!ubyte(PBKDF_SALT_LEN);
        rng.randomize(pbkdf_salt.ptr, pbkdf_salt.length);

        auto pbkdf = scoped!PKCS5_PBKDF2(new HMAC(new SHA512));
        
        OctetString master_key = pbkdf.deriveKey(PBKDF_OUTPUT_LEN, passphrase, pbkdf_salt.ptr, pbkdf_salt.length, PBKDF_ITERATIONS);
        
        const(const(ubyte)*) mk = master_key.ptr;
        
        SymmetricKey cipher_key = SymmetricKey(mk, CIPHER_KEY_LEN);
        SymmetricKey mac_key = SymmetricKey(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
        InitializationVector iv = InitializationVector(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);
        
        Pipe pipe = Pipe(getCipher("Serpent/CTR-BE", cipher_key, iv, ENCRYPTION),
                         new Fork(null,
                                  new MACFilter(new HMAC(new SHA512),
                                                mac_key, MAC_OUTPUT_LEN)));
        
        pipe.processMsg(input, input_len);
        
        /*
        Output format is:
            version # (4 bytes)
            salt (10 bytes)
            mac (20 bytes)
            ciphertext
        */
        const size_t ciphertext_len = pipe.remaining(0);
        
        SecureVector!ubyte out_buf = SecureVector!ubyte(VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN + ciphertext_len);
        
        foreach (size_t i; 0 .. VERSION_CODE_LEN)
            out_buf[i] = get_byte(i, CRYPTOBOX_VERSION_CODE);
        
        copyMem(&out_buf[VERSION_CODE_LEN], pbkdf_salt.ptr,  PBKDF_SALT_LEN);
        
        pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN], MAC_OUTPUT_LEN, 1);
        pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN],
        ciphertext_len, 0);
        
        return PEM.encode(out_buf, "BOTAN CRYPTOBOX MESSAGE");
    }

    /**
    * Decrypt a message encrypted with CryptoBox::encrypt
    * Params:
    *  input = the input data
    *  input_len = the length of input in bytes
    *  passphrase = the passphrase used to encrypt the message
    */
    static string decrypt(const(ubyte)* input, size_t input_len, in string passphrase)
    {
        auto input_src = DataSourceMemory(input, input_len);
        SecureVector!ubyte ciphertext = PEM.decodeCheckLabel(cast(DataSource)input_src, "BOTAN CRYPTOBOX MESSAGE");
        
        if (ciphertext.length < (VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN))
            throw new DecodingError("Invalid CryptoBox input");
        
        foreach (size_t i; 0 .. VERSION_CODE_LEN)
            if (ciphertext[i] != get_byte(i, CRYPTOBOX_VERSION_CODE))
                throw new DecodingError("Bad CryptoBox version");
        
        const(ubyte)* pbkdf_salt = &ciphertext[VERSION_CODE_LEN];
        
        auto pbkdf = scoped!PKCS5_PBKDF2(new HMAC(new SHA512));
        
        OctetString master_key = pbkdf.deriveKey(PBKDF_OUTPUT_LEN,
                                                 passphrase,
                                                 pbkdf_salt,
                                                 PBKDF_SALT_LEN,
                                                 PBKDF_ITERATIONS);
        
        const(ubyte)* mk = master_key.ptr;
        
        SymmetricKey cipher_key = SymmetricKey(mk, CIPHER_KEY_LEN);
        SymmetricKey mac_key = SymmetricKey(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
        InitializationVector iv = InitializationVector(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);

        Pipe pipe = Pipe(new Fork(getCipher("Serpent/CTR-BE", cipher_key, iv, DECRYPTION),
                                  new MACFilter(new HMAC(new SHA512), mac_key, MAC_OUTPUT_LEN)));
        
        const size_t ciphertext_offset = VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN;
        
        pipe.processMsg(&ciphertext[ciphertext_offset],
                            ciphertext.length - ciphertext_offset);

        ubyte[MAC_OUTPUT_LEN] computed_mac;
        pipe.read(computed_mac.ptr, MAC_OUTPUT_LEN, 1);
        
        if (!sameMem(computed_mac.ptr, &ciphertext[VERSION_CODE_LEN + PBKDF_SALT_LEN], MAC_OUTPUT_LEN))
            throw new DecodingError("CryptoBox integrity failure");
        
        return pipe.toString(0);
    }


    /**
    * Decrypt a message encrypted with CryptoBox::encrypt
    * Params:
    *  input = the input data
    *  passphrase = the passphrase used to encrypt the message
    */
    static string decrypt(in string input, in string passphrase)
    {
        return decrypt(cast(const(ubyte)*)(input.ptr), input.length, passphrase);
    }


}

private:
/*
First 24 bits of SHA-256("Botan Cryptobox"), followed by 8 0 bits
for later use as flags, etc if needed
*/
__gshared immutable uint CRYPTOBOX_VERSION_CODE = 0xEFC22400;

__gshared immutable size_t VERSION_CODE_LEN = 4;
__gshared immutable size_t CIPHER_KEY_LEN = 32;
__gshared immutable size_t CIPHER_IV_LEN = 16;
__gshared immutable size_t MAC_KEY_LEN = 32;
__gshared immutable size_t MAC_OUTPUT_LEN = 20;
__gshared immutable size_t PBKDF_SALT_LEN = 10;
__gshared immutable size_t PBKDF_ITERATIONS = 8 * 1024;

__gshared immutable size_t PBKDF_OUTPUT_LEN = CIPHER_KEY_LEN + CIPHER_IV_LEN + MAC_KEY_LEN;

import botan.constants;
static if (BOTAN_TEST):

import botan.test;
import botan.rng.auto_rng;

static if (!SKIP_CRYPTOBOX_TEST) unittest
{
    logDebug("Testing cryptobox.d ...");
    import botan.libstate.global_state;
    auto state = globalState(); // ensure initialized
    size_t fails = 0;
    
    auto rng = AutoSeededRNG();
    
    __gshared immutable ubyte[3] msg = [ 0xAA, 0xBB, 0xCC ];
    string ciphertext = CryptoBox.encrypt(msg.ptr, msg.length, "secret password", rng);
    
    try
    {
        string plaintext = CryptoBox.decrypt(ciphertext, "secret password");
        
        if (plaintext.length != msg.length || !sameMem(cast(const(ubyte)*)(plaintext.ptr), msg.ptr, msg.length))
            ++fails;
        
    }
    catch(Exception e)
    {
        logTrace("Error during Cryptobox test " ~ e.msg);
        ++fails;
    }
    
    testReport("Cryptobox", 2, fails);
}