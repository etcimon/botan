/**
* Key Derivation Function interfaces
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.kdf;

import botan.constants;
static if (BOTAN_HAS_TLS || BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import memutils.vector;
import botan.utils.types;

import botan.libstate.libstate;
import botan.algo_base.scan_token;
import botan.constants;
static if (BOTAN_HAS_KDF1)             import botan.kdf.kdf1;
static if (BOTAN_HAS_KDF2)             import botan.kdf.kdf2;
static if (BOTAN_HAS_X942_PRF)         import botan.kdf.prf_x942;
static if (BOTAN_HAS_SSL_V3_PRF)       import botan.kdf.prf_ssl3;
static if (BOTAN_HAS_TLS_V10_PRF)      import botan.kdf.prf_tls;

/**
* Key Derivation Function
*/
class KDF
{
public:
    ~this() {}

    abstract @property string name() const;

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  salt = a diversifier
    */
    SecureVector!ubyte deriveKey()(size_t key_len,
                                   auto const ref SecureVector!ubyte secret,
                                   in string salt = "") const
    {
        return deriveKey(key_len, secret.ptr, secret.length,
                         cast(const(ubyte)*)(salt.ptr),
                         salt.length);
    }

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  salt = a diversifier
    */
    
    SecureVector!ubyte deriveKey(Alloc)(size_t key_len,
                                        auto const ref SecureVector!ubyte secret,
                                        auto const ref Vector!( ubyte, Alloc ) salt) const
    {
        return deriveKey(key_len, secret.ptr, secret.length, salt.ptr, salt.length);
    }

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  salt = a diversifier
    *  salt_len = size of salt in bytes
    */
    SecureVector!ubyte deriveKey()(size_t key_len,
                                   auto const ref SecureVector!ubyte secret,
                                   const(ubyte)* salt,
                                   size_t salt_len) const
    {
        return deriveKey(key_len,
                         secret.ptr, secret.length,
                         salt, salt_len);
    }

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  secret_len = size of secret in bytes
    *  salt = a diversifier
    */
    SecureVector!ubyte deriveKey(size_t key_len,
                                 const(ubyte)* secret,
                                 size_t secret_len,
                                 in string salt = "") const
    {
        return deriveKey(key_len, secret, secret_len,
                         cast(const(ubyte)*)(salt.ptr),
                         salt.length);
    }

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  secret_len = size of secret in bytes
    *  salt = a diversifier
    *  salt_len = size of salt in bytes
    */
    SecureVector!ubyte deriveKey(size_t key_len,
                                 const(ubyte)* secret,
                                 size_t secret_len,
                                 const(ubyte)* salt,
                                 size_t salt_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len);
    }

    abstract KDF clone() const;

protected:
    abstract SecureVector!ubyte
        derive(size_t key_len,
               const(ubyte)* secret, size_t secret_len,
               const(ubyte)* salt, size_t salt_len) const;
}

/**
* Factory method for KDF (key derivation function)
* Params:
*  algo_spec = the name of the KDF to create
* Returns: pointer to newly allocated object of that type
*/
KDF getKdf(in string algo_spec)
{
    SCANToken request = SCANToken(algo_spec);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    if (request.algoName == "Raw")
        return null; // No KDF
    
    static if (BOTAN_HAS_KDF1) {
        if (request.algoName == "KDF1" && request.argCount() == 1)
            return new KDF1(af.makeHashFunction(request.arg(0)));
    }
        
    static if (BOTAN_HAS_KDF2) {
        if (request.algoName == "KDF2" && request.argCount() == 1)
            return new KDF2(af.makeHashFunction(request.arg(0)));
    }
        
    static if (BOTAN_HAS_X942_PRF) { 
        if (request.algoName == "X9.42-PRF" && request.argCount() == 1)
            return new X942PRF(request.arg(0)); // OID
    }
        
    static if (BOTAN_HAS_SSL_V3_PRF) {
        if (request.algoName == "SSL3-PRF" && request.argCount() == 0)
            return new SSL3PRF;
    }
        
    static if (BOTAN_HAS_TLS_V10_PRF) {
        if (request.algoName == "TLS-PRF" && request.argCount() == 0)
            return new TLSPRF;
    }
        
    static if (BOTAN_HAS_TLS_V12_PRF) {
        if (request.algoName == "TLS-12-PRF" && request.argCount() == 1)
            return new TLS12PRF(af.makeMac("HMAC(" ~ request.arg(0) ~ ")"));
    }
    
    throw new AlgorithmNotFound(algo_spec);
}

static if (BOTAN_TEST):

import botan.libstate.lookup;
import botan.codec.hex;
import botan.test;
import memutils.hashmap;
import core.atomic;
shared(int) g_total_tests;
static if (!SKIP_KDF_TEST) unittest
{
    logDebug("Testing kdf.d ...");
    auto test = delegate(string input) {
        return runTests(input, "KDF", "Output", true,
            (ref HashMap!(string, string) vec)
            {
                atomicOp!"+="(g_total_tests, 1);
                Unique!KDF kdf = getKdf(vec["KDF"]);
                
                const size_t outlen = to!uint(vec["OutputLen"]);
                const auto salt = hexDecode(vec["Salt"]);
                const auto secret = hexDecodeLocked(vec["Secret"]);
                
                const auto key = kdf.deriveKey(outlen, secret, salt);
                auto encoded = hexEncode(key);
                return encoded;
            });
        };
        
    size_t fails = runTestsInDir("../test_data/kdf", test);
    
    testReport("kdf", g_total_tests, fails);
}
