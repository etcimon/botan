/**
* Base class for message authentiction codes
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import memutils.hashmap;
import core.atomic;

private shared size_t total_tests;

size_t macTest(string algo, string key_hex, string in_hex, string out_hex)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;

    atomicOp!"+="(total_tests, 1);
    if(providers.empty)
    {
        logTrace("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers[])
    {
        atomicOp!"+="(total_tests, 1);
        auto proto = af.prototypeMac(algo, provider);
        
        if(!proto)
        {
            logError("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!MessageAuthenticationCode mac = proto.clone();
        
        mac.setKey(hexDecode(key_hex));
        mac.update(hexDecode(in_hex));
        
        auto h = mac.finished();

        atomicOp!"+="(total_tests, 1);
        if(h != hexDecodeLocked(out_hex))
        {
            logError(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

static if (!SKIP_MAC_TEST) unittest {  
    logDebug("Testing mac.d ...");  
    auto test = delegate(string input) {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mac", "Out", true,
            (ref HashMap!(string, string) m) {
                return macTest(m["Mac"], m["Key"], m["In"], m["Out"]);
            });
    };
    
    size_t fails = runTestsInDir("../test_data/mac", test);

    testReport("mac", total_tests, fails);
}
