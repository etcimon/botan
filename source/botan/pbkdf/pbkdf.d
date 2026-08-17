/**
* PBKDF
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.pbkdf;

import botan.constants;
import botan.algo_base.symkey;
import std.datetime;
import std.exception;
import botan.utils.types;

/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*/
interface PBKDF
{
public:
    /**
    * Returns: new instance of this same algorithm
    */
    PBKDF clone() const;

    @property string name() const;

    /**
    * Derive a key from a passphrase
    * Params:
    *  output_len = the desired length of the key to produce
    *  passphrase = the password to derive the key from
    *  salt = a randomly chosen salt
    *  salt_len = length of salt in bytes
    *  iterations = the number of iterations to use (use 10K or more)
    */
    final OctetString deriveKey(size_t output_len,
                                in string passphrase,
                                const(ubyte)* salt, size_t salt_len,
                                size_t iterations) const
    {
        if (iterations == 0)
            throw new InvalidArgument(name ~ ": Invalid iteration count");
        
        auto derived = keyDerivation(output_len, passphrase,
                                     salt, salt_len, iterations,
                                     Duration.zero);
        
        assert(derived.first == iterations,
                     "PBKDF used the correct number of iterations");
        
        return derived.second;
    }

    /**
    * Derive a key from a passphrase
    * Params:
    *  output_len = the desired length of the key to produce
    *  passphrase = the password to derive the key from
    *  salt = a randomly chosen salt
    *  iterations = the number of iterations to use (use 10K or more)
    */
    final OctetString deriveKey(Alloc)(size_t output_len,
                                       in string passphrase,
                                       const ref Vector!( ubyte, Alloc ) salt,
                                       size_t iterations) const
    {
        return deriveKey(output_len, passphrase, salt.ptr, salt.length, iterations);
    }

    /**
    * Derive a key from a passphrase
    * Params:
    *  output_len = the desired length of the key to produce
    *  passphrase = the password to derive the key from
    *  salt = a randomly chosen salt
    *  salt_len = length of salt in bytes
    *  loop_for = is how long to run the PBKDF
    *  iterations = is set to the number of iterations used
    */
    final OctetString deriveKey(size_t output_len,
                           in string passphrase,
                           const(ubyte)* salt, size_t salt_len,
                           Duration loop_for,
                           ref size_t iterations) const
    {
        auto derived = keyDerivation(output_len, passphrase, salt, salt_len, 0, loop_for);
        
        iterations = derived.first;
        
        return derived.second;
    }

    /**
    * Derive a key from a passphrase using a certain amount of time
    * Params:
    *  output_len = the desired length of the key to produce
    *  passphrase = the password to derive the key from
    *  salt = a randomly chosen salt
    *  loop_for = is how long to run the PBKDF
    *  iterations = is set to the number of iterations used
    */
    final OctetString deriveKey(Alloc)(size_t output_len,
                                       in string passphrase,
                                       const ref Vector!( ubyte, Alloc ) salt,
                                       Duration loop_for,
                                       ref size_t iterations) const
    {
        return deriveKey(output_len, passphrase, salt.ptr, salt.length, loop_for, iterations);
    }

    /**
    * Derive a key from a passphrase for a number of iterations
    * specified by either iterations or if iterations == 0 then
    * running until seconds time has elapsed.
    *
    * Params:
    *  output_len = the desired length of the key to produce
    *  passphrase = the password to derive the key from
    *  salt = a randomly chosen salt
    *  salt_len = length of salt in bytes
    *  iterations = the number of iterations to use (use 10K or more)
    *  loop_for = if iterations is zero, then instead the PBKDF is
    *          run until duration has passed.
    * Returns: the number of iterations performed and the derived key
    */
    Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration loop_for) const;
}

static if (BOTAN_HAS_TESTS && !SKIP_PBKDF_TEST) unittest {
    logDebug("Testing pbkdf.d ...");
    import botan.test;
    import botan.codec.hex;
    import botan.utils.mem_ops;
    import memutils.hashmap;
    import botan.libstate.libstate;
    import botan.libstate.lookup;
    int total_tests;
    auto test = delegate(string input) {
        File vec = File(input, "r");
        return runTestsBb(vec, "PBKDF", "Output", true,
             (ref HashMap!(string, string) m) {
                total_tests += 1;
                PBKDF pbkdf;
                try { pbkdf = getPbkdf(m["PBKDF"]); }
                catch (AlgorithmNotFound)
                {
                    logTrace("Unknown PBKDF " ~ m["PBKDF"]);
                    return 0;
                }
                Unique!PBKDF owned = pbkdf;

                auto expected = hexDecode(m["Output"]);
                size_t outlen;
                if (auto p = "OutputLen" in m)
                    outlen = to!size_t(*p);
                else
                    outlen = expected.length;

                string salt_hex;
                if (auto p = "Salt" in m)
                    salt_hex = *p;
                const auto salt = hexDecode(salt_hex);
                string pass;
                if (auto p = "Passphrase" in m)
                    pass = *p;
                const size_t iterations = to!size_t(m["Iterations"]);
                auto octet_string = owned.deriveKey(outlen, pass, salt.ptr, salt.length, iterations);
                const auto key = octet_string.bitsOf();
                if (key.length != expected.length || !sameMem(key.ptr, expected.ptr, expected.length))
                {
                    logError(m["PBKDF"] ~ " got " ~ hexEncode(key) ~ " != " ~ hexEncode(expected));
                    return 1;
                }
                return 0;
            });
    };

    size_t fails = runTestsInDir("test_data/pbkdf", test);

    fails += checkMemutilsRepeat("pbkdf2", {
        Unique!PBKDF p = getPbkdf("PBKDF2(SHA-256)");
        ubyte[8] salt;
        auto k = p.deriveKey(16, "pass", salt.ptr, salt.length, 1);
        if (k.length != 16)
            throw new Exception("pbkdf leak probe");
    });

    testReport("pbkdf", total_tests, fails);
}