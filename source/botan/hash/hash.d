/**
* Hash Function Base Class
* 
* Copyright:
* (C) 2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
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
    final @disable HashFunction dup() const;

    /// Clear the digest state (object looks newly allocated).
    void clear();

    /// Human-readable algorithm name, e.g. "SHA-256".
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
        return 0;
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

static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest
{
    logDebug("Testing hash.d ...");
    import botan.libstate.libstate : globalState;
    globalState();
    auto test = delegate(string input)
    {
        File vec = File(input, "r");

        return runTestsBb(vec, "Hash", "Out", true,
            (ref HashMap!(string, string) m) {
                string inhex;
                if (auto p = "In" in m)
                    inhex = *p;
                return hashTest(m["Hash"], inhex, m["Out"]);
            });
    };
    
    size_t fails = runTestsInDir("test_data/hash", test);

    import botan.libstate.lookup;
    {
        File mc = File("test_data/hash_mc.vec", "r");
        fails += runTestsBb(mc, "Hash", "Output", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Seed" in m) || !("Count" in m) || !("Output" in m))
                    return 0;
                auto proto = globalState().algorithmFactory().prototypeHashFunction(m["Hash"]);
                if (!proto)
                    return 0;
                Unique!HashFunction hash = proto.clone();
                import std.conv : to;
                const size_t count = to!size_t(m["Count"]);
                auto seed = hexDecode(m["Seed"]);
                auto expected = hexDecode(m["Output"]);
                Vector!ubyte[3] input;
                input[0] = Vector!ubyte(seed[]);
                input[1] = Vector!ubyte(seed[]);
                input[2] = Vector!ubyte(seed[]);
                foreach (size_t j; 0 .. count + 1)
                {
                    foreach (size_t i; 3 .. 1003)
                    {
                        hash.update(input[0].ptr, input[0].length);
                        hash.update(input[1].ptr, input[1].length);
                        hash.update(input[2].ptr, input[2].length);
                        auto dig = hash.finished();
                        input[0] = input[1].clone;
                        input[1] = input[2].clone;
                        input[2] = Vector!ubyte(dig[]);
                    }
                    if (j < count)
                    {
                        input[0] = input[2].clone;
                        input[1] = input[2].clone;
                    }
                }
                if (input[2][] != expected[])
                {
                    logError("hash_mc ", m["Hash"], " got ", hexEncode(input[2]),
                             " expected ", m["Output"]);
                    return 1;
                }
                return 0;
            });
    }
    {
        File rep = File("test_data/hash_rep.vec", "r");
        fails += runTestsBb(rep, "Hash", "Digest", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Input" in m) || !("TotalLength" in m) || !("Digest" in m))
                    return 0;
                import std.conv : to;
                const size_t total_len = to!size_t(m["TotalLength"]);
                if (total_len > 1_000_000)
                    return 0;
                auto proto = globalState().algorithmFactory().prototypeHashFunction(m["Hash"]);
                if (!proto)
                    return 0;
                Unique!HashFunction hash = proto.clone();
                auto chunk = hexDecode(m["Input"]);
                Vector!ubyte expanded;
                while (expanded.length < 256)
                    expanded ~= chunk[];
                const size_t full = total_len / expanded.length;
                const size_t leftover = total_len % expanded.length;
                foreach (size_t i; 0 .. full)
                    hash.update(expanded.ptr, expanded.length);
                if (leftover)
                    hash.update(expanded.ptr, leftover);
                auto got = hash.finished();
                auto expect = hexDecode(m["Digest"]);
                if (got[] != expect[])
                {
                    logError("hash_rep ", m["Hash"], " mismatch");
                    return 1;
                }
                return 0;
            });
    }
    fails += checkMemutilsRepeat("hash SHA-256", {
        Unique!HashFunction h = retrieveHash("SHA-256").clone();
        h.update(cast(const(ubyte)[])"abc");
        auto d = h.finished();
        if (d.length != 32)
            throw new Exception("hash leak probe");
    });

    testReport("hash", total_tests, fails);
}
