/**
* Hash Function Base Class
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.hash;

import botan.constants;
import botan.algo_base.buf_comp;

/**
* This class represents hash function (message digest) objects
*/
interface HashFunction : BufferedComputation
{
public:
    /**
    * Returns: new object representing the same algorithm as this
    */
    HashFunction clone() const;

    void clear();

    @property string name() const;

    /**
    * Returns: hash block size as defined for this algorithm
    */
    @property size_t hashBlockSize() const;
}

static if (BOTAN_TEST):
import botan.test;

import botan.libstate.libstate;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t hashTest(string algo, string in_hex, string out_hex)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;
    atomicOp!"+="(total_tests, cast(size_t)1);
    if (providers.empty)
    {
        logTrace("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers[])
    {
        auto proto = af.prototypeHashFunction(algo, provider);

        atomicOp!"+="(total_tests, 1);

        if (!proto)
        {
            logError("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!HashFunction hash = proto.clone();
        auto decoded = hexDecode(in_hex);
        hash.update(decoded);
        
        auto h = hash.finished();

        atomicOp!"+="(total_tests, 1);

        if (h != hexDecodeLocked(out_hex))
        {
            logError(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
        
        // Test to make sure clear() resets what we need it to
        hash.update("some discarded input");
        hash.clear();
        
        hash.update(hexDecode(in_hex));
        
        h = hash.finished();

        atomicOp!"+="(total_tests, 1);

        if (h != hexDecodeLocked(out_hex))
        {
            logError(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

static if (!SKIP_HASH_TEST) unittest
{
    logDebug("Testing hash.d ...");
    import botan.libstate.libstate : globalState;
    globalState();
    auto test = delegate(string input)
    {
        File vec = File(input, "r");

        return runTestsBb(vec, "Hash", "Out", true,
            (ref HashMap!(string, string) m) {
                return hashTest(m["Hash"], m["In"], m["Out"]);
            });
    };
    
    size_t fails = runTestsInDir("../test_data/hash", test);

    testReport("hash", total_tests, fails);
}
