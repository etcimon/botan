/**
* Key Derivation Function interfaces
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
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
static if (BOTAN_HAS_SP800_108)        import botan.kdf.sp800_108;
static if (BOTAN_HAS_SP800_56A)        import botan.kdf.sp800_56a;
static if (BOTAN_HAS_SP800_56C)        import botan.kdf.sp800_56c;
static if (BOTAN_HAS_KDF1_18033)       import botan.kdf.kdf1_iso18033;
static if (BOTAN_HAS_HKDF)             import botan.prf.hkdf;

/**
* Key Derivation Function
*/
class KDF
{
public:
    ~this() {}

    /// Human-readable algorithm name, e.g. "HKDF(SHA-256)".
    abstract @property string name() const;

    /**
    * Derive a key
    * Params:
    *  key_len = the desired output length in bytes
    *  secret = the secret input
    *  salt = a diversifier
    */
    SecureVector!ubyte deriveKey()(size_t key_len,
                                   const auto ref SecureVector!ubyte secret,
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
                                        const auto ref SecureVector!ubyte secret,
                                        const auto ref Vector!( ubyte, Alloc ) salt) const
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
                                   const auto ref SecureVector!ubyte secret,
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
        return derive(key_len, secret, secret_len, salt, salt_len, null, 0);
    }

    /**
    * Derive a key with an explicit label (SP 800-108 / 56A / 56C).
    * Existing KDFs ignore `label`.
    * Params:
    *  key_len = desired output length
    *  secret = IKM
    *  secret_len = length of secret
    *  salt = salt / nonce
    *  salt_len = length of salt
    *  label = context / label (ignored by IEEE / TLS PRFs)
    *  label_len = length of label
    * Returns: derived key
    */
    SecureVector!ubyte deriveKey(size_t key_len,
                                 const(ubyte)* secret,
                                 size_t secret_len,
                                 const(ubyte)* salt,
                                 size_t salt_len,
                                 const(ubyte)* label,
                                 size_t label_len) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len, label, label_len);
    }

    SecureVector!ubyte deriveKey(Alloc, Alloc2)(size_t key_len,
                                                const auto ref SecureVector!ubyte secret,
                                                const auto ref Vector!(ubyte, Alloc) salt,
                                                const auto ref Vector!(ubyte, Alloc2) label) const
    {
        return derive(key_len, secret.ptr, secret.length,
                      salt.ptr, salt.length, label.ptr, label.length);
    }

    abstract KDF clone() const;
    final @disable KDF dup() const;

protected:
    /**
    * Default: ignore label (IEEE / TLS PRFs). SP 800-* override this.
    */
    SecureVector!ubyte derive(size_t key_len,
                              const(ubyte)* secret, size_t secret_len,
                              const(ubyte)* salt, size_t salt_len,
                              const(ubyte)*, size_t) const
    {
        return derive(key_len, secret, secret_len, salt, salt_len);
    }

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

    static if (BOTAN_HAS_KDF1_18033) {
        if (request.algoName == "KDF1-18033" && request.argCount() == 1)
            return new KDF1_18033(af.makeHashFunction(request.arg(0)));
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

    static if (BOTAN_HAS_SP800_108) {
        if (request.algoName == "SP800-108-Counter" && request.argCountBetween(1, 3))
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new SP800_108_Counter(mac, request.argAsInteger(1, 32), request.argAsInteger(2, 32));
        }
        if (request.algoName == "SP800-108-Feedback" && request.argCountBetween(1, 3))
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new SP800_108_Feedback(mac, request.argAsInteger(1, 32), request.argAsInteger(2, 32));
        }
        if (request.algoName == "SP800-108-Pipeline" && request.argCountBetween(1, 3))
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new SP800_108_Pipeline(mac, request.argAsInteger(1, 32), request.argAsInteger(2, 32));
        }
    }

    static if (BOTAN_HAS_SP800_56A) {
        if (request.algoName == "SP800-56A" && request.argCount() == 1)
        {
            if (auto hash = af.prototypeHashFunction(request.arg(0)))
                return new SP800_56A_Hash(hash.clone());
            static if (BOTAN_HAS_KMAC) {
                if (request.arg(0) == "KMAC-128")
                    return new SP800_56A_KMAC128;
                if (request.arg(0) == "KMAC-256")
                    return new SP800_56A_KMAC256;
            }
            if (auto mac = af.prototypeMac(request.arg(0)))
                return new SP800_56A_HMAC(mac.clone());
        }
    }

    static if (BOTAN_HAS_SP800_56C && BOTAN_HAS_SP800_108) {
        if (request.algoName == "SP800-56C" && request.argCount() == 1)
        {
            if (auto exp_mac = macOrHmac(af, request.arg(0)))
            {
                auto exp = new SP800_108_Feedback(exp_mac, 32, 32);
                if (auto prf = macOrHmac(af, request.arg(0)))
                    return new SP800_56C_TwoStep(prf, exp);
            }
        }
    }

    static if (BOTAN_HAS_HKDF) {
        if (request.algoName == "HKDF" && request.argCount() == 1)
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new HKDF(mac);
        }
        if (request.algoName == "HKDF-Extract" && request.argCount() == 1)
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new HKDF_Extract(mac);
        }
        if (request.algoName == "HKDF-Expand" && request.argCount() == 1)
        {
            if (auto mac = macOrHmac(af, request.arg(0)))
                return new HKDF_Expand(mac);
        }
    }
    
    throw new AlgorithmNotFound(algo_spec);
}

private MessageAuthenticationCode macOrHmac(AlgorithmFactory af, in string nm)
{
    // Prefer the argument as a MAC ("HMAC(SHA-256)", "CMAC(AES-128)").
    // Wrapping first as HMAC(HMAC(...)) makes findMac call makeHashFunction
    // on the inner HMAC name, which throws AlgorithmNotFound instead of
    // returning null.
    try
    {
        if (const proto = af.prototypeMac(nm))
            return proto.clone();
    }
    catch (AlgorithmNotFound) {}
    try
    {
        if (const proto = af.prototypeMac("HMAC(" ~ nm ~ ")"))
            return proto.clone();
    }
    catch (AlgorithmNotFound) {}
    return null;
}

static if (BOTAN_TEST):

import botan.libstate.lookup;
import botan.codec.hex;
import botan.test;
import memutils.hashmap;
import core.atomic;
shared(int) g_total_tests;
import botan.utils.mem_ops;

private string optField(ref HashMap!(string, string) m, string key)
{
    if (auto p = key in m)
        return *p;
    return "";
}

static if (BOTAN_HAS_TESTS && !SKIP_KDF_TEST) unittest
{
    logDebug("Testing kdf.d ...");
    auto test = delegate(string input) {
        File vec = File(input, "r");
        return runTestsBb(vec, "KDF", "Output", true,
            (ref HashMap!(string, string) m)
            {
                atomicOp!"+="(g_total_tests, 1);
                KDF kdf;
                try { kdf = getKdf(m["KDF"]); }
                catch (AlgorithmNotFound)
                {
                    logTrace("Unknown KDF " ~ m["KDF"]);
                    return 0;
                }
                Unique!KDF owned = kdf;

                auto expected = hexDecode(m["Output"]);
                size_t outlen;
                if (auto p = "OutputLen" in m)
                    outlen = to!uint(*p);
                else
                    outlen = expected.length;

                const auto salt = hexDecode(optField(m, "Salt"));
                const auto label = hexDecode(optField(m, "Label"));
                const auto secret = hexDecodeLocked(m["Secret"]);

                const auto key = owned.deriveKey(outlen, secret, salt, label);
                if (key.length != expected.length || !sameMem(key.ptr, expected.ptr, expected.length))
                {
                    logError(m["KDF"] ~ " got " ~ hexEncode(key) ~ " != " ~ hexEncode(expected));
                    return 1;
                }
                return 0;
            });
        };

    size_t fails = runTestsInDir("test_data/kdf", test);

    static if (BOTAN_HAS_HKDF)
    {
        fails += checkMemutilsRepeat("kdf hkdf", {
            Unique!KDF k = getKdf("HKDF(SHA-256)");
            ubyte[8] secret = 1;
            auto outp = k.deriveKey(16, secret.ptr, secret.length, null, 0);
            if (outp.length != 16)
                throw new Exception("kdf leak probe");
        });
    }

    testReport("kdf", g_total_tests, fails);
}
