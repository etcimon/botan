/**
* Cipher Modes
* 
* Copyright:
* (C) 2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
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
                             const auto ref SecureVector!ubyte pt, 
                             const auto ref SecureVector!ubyte nonce, 
                             const auto ref SecureVector!ubyte key)
{
    /*
    Unique!CipherMode cipher = getCipher(algo, dir);

    cipher.setKey(key);
    cipher.start(nonce);

    SecureVector!ubyte ct = pt;
    cipher.finish(ct);
    */
    
    Pipe pipe = Pipe(getCipher(algo, SymmetricKey(key.clone), InitializationVector(nonce.clone), dir));
    
    pipe.processMsg(pt.ptr, pt.length);
    
    return pipe.readAll();
}

size_t modeTest(string algo, string pt, string ct, string key_hex, string nonce_hex)
{
    auto nonce = hexDecodeLocked(nonce_hex);
    auto key = hexDecodeLocked(key_hex);
    
    size_t fails = 0;

    string ct2;
    try
        ct2 = hexEncode(runMode(algo, ENCRYPTION, hexDecodeLocked(pt), nonce, key));
    catch (Exception e)
    {
        logTrace("Unknown or unsupported mode " ~ algo ~ " " ~ e.msg);
        return 0;
    }
    atomicOp!"+="(total_tests, 1);
    if (hexDecodeLocked(ct) != hexDecodeLocked(ct2))
    {
        logError(algo ~ " got ct " ~ ct2 ~ " expected " ~ ct);
        ++fails;
    }
    
    const string pt2 = hexEncode(runMode(algo, DECRYPTION, hexDecodeLocked(ct), nonce, key));
    atomicOp!"+="(total_tests, 1);
    if (hexDecodeLocked(pt) != hexDecodeLocked(pt2))
    {
        logError(algo ~ " got pt " ~ pt2 ~ " expected " ~ pt);
        ++fails;
    }
    
    return fails;
}

static if (BOTAN_HAS_TESTS && !SKIP_CIPHER_MODE_TEST) unittest {
    logDebug("Testing cipher_mode.d ...");
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mode", "Out", true,
            (ref HashMap!(string, string) m) {
                return modeTest(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
            });
    };
    
    size_t fails = runTestsInDir("test_data/modes", test);

    fails += checkMemutilsRepeat("mode AES-128/CBC", {
        ubyte[16] k, n, pt;
        Pipe pipe = Pipe(getCipher("AES-128/CBC/PKCS7",
            SymmetricKey(k.ptr, 16), InitializationVector(n.ptr, 16), ENCRYPTION));
        pipe.processMsg(pt.ptr, pt.length);
        auto ct = pipe.readAll();
        if (ct.length < 16)
            throw new Exception("mode leak probe");
    });

    {
        ubyte[16] k, n;
        ubyte[3] pt = [0xFF, 0xFF, 0xFF];
        Pipe enc = Pipe(getCipher("AES-128/CBC/ESP",
            SymmetricKey(k.ptr, 16), InitializationVector(n.ptr, 16), ENCRYPTION));
        enc.processMsg(pt.ptr, pt.length);
        auto ct = enc.readAll();
        Pipe dec = Pipe(getCipher("AES-128/CBC/ESP",
            SymmetricKey(k.ptr, 16), InitializationVector(n.ptr, 16), DECRYPTION));
        dec.processMsg(ct.ptr, ct.length);
        auto rec = dec.readAll();
        atomicOp!"+="(total_tests, 1);
        if (rec.length != 3 || rec[0] != 0xFF || rec[1] != 0xFF || rec[2] != 0xFF)
            ++fails;
    }

    testReport("cipher_mode", total_tests, fails);
}
