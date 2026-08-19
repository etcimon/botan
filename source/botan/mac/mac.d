/**
* Base class for message authentiction codes
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.mac;

import botan.constants;
public import botan.algo_base.sym_algo;
public import botan.algo_base.buf_comp;
import botan.utils.mem_ops;

/**
* This class represents Message Authentication Code (MAC) objects.
*/
interface MessageAuthenticationCode : BufferedComputation, SymmetricAlgorithm
{
public:
    /**
    * Verify a MAC.
    *
    * Params:
    *  mac = the MAC to verify as a ubyte array
    *  length = the length of param in
    * Returns: true if the MAC is valid, false otherwise
    */
    final bool verifyMac(const(ubyte)* mac, size_t length)
    {
        SecureVector!ubyte our_mac = finished();
        
        if (our_mac.length != length)
            return false;
        
        return sameMem(our_mac.ptr, mac, length);
    }

    /**
    * Get a new object representing the same algorithm as this
    */
    abstract MessageAuthenticationCode clone() const;

    /**
    * Get the name of this algorithm.
    * Returns: name of this algorithm
    */
    abstract @property string name() const;
}

/**
* Optional nonce / customization input. GMAC uses a fresh IV; KMAC uses
* the SP 800-185 customization string. Existing MACs do not implement this.
*/
interface MacStart
{
    /**
    * Params:
    *  nonce = IV (GMAC) or customization string (KMAC)
    *  nonce_len = length of nonce
    */
    void start(const(ubyte)* nonce, size_t nonce_len);
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import memutils.hashmap;
import core.atomic;

private shared size_t total_tests;

size_t macTest(string algo, string key_hex, string in_hex, string out_hex, string iv_hex = "")
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;

    atomicOp!"+="(total_tests, 1);
    if (providers.empty)
    {
        logTrace("Unknown algo " ~ algo);
        return 0;
    }
    
    foreach (provider; providers[])
    {
        atomicOp!"+="(total_tests, 1);
        auto proto = af.prototypeMac(algo, provider);
        
        if (!proto)
        {
            logError("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!MessageAuthenticationCode mac = proto.clone();
        
        mac.setKey(hexDecode(key_hex));
        if (iv_hex.length)
        {
            if (auto s = cast(MacStart)*mac)
            {
                auto iv = hexDecode(iv_hex);
                s.start(iv.ptr, iv.length);
            }
            else
            {
                logError(algo ~ " has IV but no MacStart");
                ++fails;
                continue;
            }
        }
        mac.update(hexDecode(in_hex));
        
        auto h = mac.finished();

        atomicOp!"+="(total_tests, 1);
        if (h != hexDecodeLocked(out_hex))
        {
            logError(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

static if (BOTAN_HAS_TESTS && !SKIP_MAC_TEST) unittest {  
    logDebug("Testing mac.d ...");  
    auto test = delegate(string input) {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mac", "Out", true,
            (ref HashMap!(string, string) m) {
                string iv;
                if (auto p = "IV" in m)
                    iv = *p;
                else if (auto p = "Nonce" in m)
                    iv = *p;
                string inhex;
                if (auto p = "In" in m)
                    inhex = *p;
                return macTest(m["Mac"], m["Key"], inhex, m["Out"], iv);
            });
    };
    
    size_t fails = runTestsInDir("test_data/mac", test);

    import botan.libstate.lookup;
    fails += checkMemutilsRepeat("mac HMAC(SHA-256)", {
        Unique!MessageAuthenticationCode m = retrieveMac("HMAC(SHA-256)").clone();
        ubyte[32] k;
        m.setKey(k.ptr, k.length);
        m.update(cast(const(ubyte)[])"abc");
        auto t = m.finished();
        if (t.length != 32)
            throw new Exception("mac leak probe");
    });

    testReport("mac", total_tests, fails);
}
