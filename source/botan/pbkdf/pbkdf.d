/**
* PBKDF
* 
* Copyright:
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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
    abstract PBKDF clone() const;

    abstract @property string name() const;

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
    abstract Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration loop_for) const;
}

static if (!SKIP_PBKDF_TEST) unittest {
    logDebug("Testing pbkdf.d ...");
    import botan.test;
    import botan.codec.hex;
    import memutils.hashmap;
    int total_tests;
    auto test = delegate(string input) {
        return runTests(input, "PBKDF", "Output", true,
             (ref HashMap!(string, string) vec) {
                total_tests += 1;
                Unique!PBKDF pbkdf = getPbkdf(vec["PBKDF"]);
                
                const size_t iterations = to!size_t(vec["Iterations"]);
                const size_t outlen = to!size_t(vec["OutputLen"]);
                const auto salt = hexDecode(vec["Salt"]);
                const string pass = vec["Passphrase"];
                
                const auto key = pbkdf.deriveKey(outlen, pass, salt.ptr, salt.length, iterations).bitsOf();
                return hexEncode(key);
            });
    };
    
    size_t fails = runTestsInDir("../test_data/pbkdf", test);

    testReport("pbkdf", total_tests, fails);
}