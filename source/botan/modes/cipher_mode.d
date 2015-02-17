/**
* Cipher Modes
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.cipher_mode;

public import botan.algo_base.transform;
import botan.constants; 

/**
* Interface for cipher modes
*/
abstract class CipherMode : KeyedTransform, Transformation
{
public:
    /**
    * Returns true iff this mode provides authentication as well as
    * confidentiality.
    */
    abstract bool authenticated() const { return false; }
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.lookup;
import botan.filters.filters;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;
SecureVector!ubyte runMode()(string algo, CipherDir dir, 
                             auto const ref SecureVector!ubyte pt, 
                             auto const ref SecureVector!ubyte nonce, 
                             auto const ref SecureVector!ubyte key)
{
    /*
    Unique!CipherMode cipher = getCipher(algo, dir);

    cipher.setKey(key);
    cipher.startVec(nonce);

    SecureVector!ubyte ct = pt;
    cipher.finish(ct);
    */
    
    Pipe pipe = Pipe(getCipher(algo, SymmetricKey(key.dup), InitializationVector(nonce.dup), dir));
    
    pipe.processMsg(pt.ptr, pt.length);
    
    return pipe.readAll();
}

size_t modeTest(string algo, string pt, string ct, string key_hex, string nonce_hex)
{
    auto nonce = hexDecodeLocked(nonce_hex);
    auto key = hexDecodeLocked(key_hex);
    
    size_t fails = 0;
    
    const string ct2 = hexEncode(runMode(algo, ENCRYPTION, hexDecodeLocked(pt), nonce, key));
    atomicOp!"+="(total_tests, 1);
    if (ct != ct2)
    {
        logError(algo ~ " got ct " ~ ct2 ~ " expected " ~ ct);
        ++fails;
    }
    
    const string pt2 = hexEncode(runMode(algo, DECRYPTION, hexDecodeLocked(ct), nonce, key));
    atomicOp!"+="(total_tests, 1);
    if (pt != pt2)
    {
        logError(algo ~ " got pt " ~ pt2 ~ " expected " ~ pt);
        ++fails;
    }
    
    return fails;
}

static if (!SKIP_CIPHER_MODE_TEST) unittest {
    logDebug("Testing cipher_mode.d ...");
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mode", "Out", true,
            (ref HashMap!(string, string) m) {
                return modeTest(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
            });
    };
    
    size_t fails = runTestsInDir("../test_data/modes", test);

    testReport("cipher_mode", total_tests, fails);
}
