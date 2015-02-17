/**
* Unit tests for RNG
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.test;

import botan.constants;
static if (BOTAN_TEST):
import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import botan.rng.rng;
import botan.utils.parsing;
import core.atomic;
import std.stdio;
public import memutils.hashmap;

class FixedOutputRNG : RandomNumberGenerator
{
public:
    override bool isSeeded() const { return !m_buf.empty; }
    
    ubyte random()
    {
        if (!isSeeded())
            throw new Exception("Out of bytes");

        ubyte output = m_buf.front();
        m_buf.removeFront();
        return output;
    }
    
    override void reseed(size_t) {}
    
    override void randomize(ubyte* output, size_t len)
    {
        if (len <= m_buf.length) {
            output[0 .. len] = m_buf.ptr[0 .. len];
            auto new_buf = Vector!ubyte(m_buf.ptr[len .. m_buf.length]);
            m_buf = new_buf.move();
        } else {
            for(size_t j = 0; j != len; j++)
                output[j] = random();
        }
    }
    
    override void addEntropy(const(ubyte)* b, size_t s)
    {
        m_buf.insert(b[0 .. s]);
    }
    
    override @property string name() const { return "Fixed_Output_RNG"; }
    
    override void clear() {}

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }
    
    this(const ref Vector!ubyte input)
    {    
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this(string in_str)
    {
        Vector!ubyte input = hexDecode(in_str);
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this() {}
protected:
    size_t remaining() const { return m_buf.length; }
private:
    Vector!ubyte m_buf;
}

RandomNumberGenerator getRng(string algo_str, string ikm_hex)
{
    //logDebug("getRng: ", algo_str);
    class AllOnceRNG : FixedOutputRNG
    {
    public:
        this(const ref Vector!ubyte input) {
            super(input);
        }
        
        override SecureVector!ubyte randomVec(size_t)
        {
            SecureVector!ubyte vec = SecureVector!ubyte(this.remaining());
            this.randomize(vec.ptr, vec.length);
            return vec;
        }
    }
    
    const auto ikm = hexDecode(ikm_hex);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto algo_name = parseAlgorithmName(algo_str);
    
    const string rng_name = algo_name[0];
    
    static if (BOTAN_HAS_HMAC_DRBG) {
        import botan.rng.hmac_drbg;
        if (rng_name == "HMAC_DRBG") {
            auto mac = af.makeMac("HMAC(" ~ algo_name[1] ~ ")");
            if (!mac) logDebug("No Mac found");
            return new HMAC_DRBG(mac, new AllOnceRNG(ikm));
        }
    }
    
    static if (BOTAN_HAS_X931_RNG) {
        import botan.rng.x931_rng;
        if (rng_name == "X9.31-RNG")
            return new ANSIX931RNG(af.makeBlockCipher(algo_name[1]), new FixedOutputRNG(ikm));
    }
    
    return null;
}


shared size_t total_tests;
static if (BOTAN_HAS_X931_RNG)
size_t x931Test(string algo,
                 string ikm,
                 string output,
                 size_t L)
{
    atomicOp!"+="(total_tests, 1);
    Unique!RandomNumberGenerator rng = getRng(algo, ikm);
    
    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    const string got = hexEncode(rng.randomVec(L));
    
    if (got != output)
    {
        logTrace("X9.31 " ~ got ~ " != " ~ output);
        return 1;
    }
    
    return 0;
}

static if (BOTAN_HAS_HMAC_DRBG)
size_t hmacDrbgTest(ref HashMap!(string, string) m)
{
    atomicOp!"+="(total_tests, 1);
    const string algo = m["RNG"];
    const string ikm = m["EntropyInput"];
    
    Unique!RandomNumberGenerator rng = getRng(algo, ikm);

    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    rng.reseed(0); // force initialization
    
    // now reseed
    const auto reseed_input = hexDecode(m["EntropyInputReseed"]);
    rng.addEntropy(reseed_input.ptr, reseed_input.length);
    
    const string output = m["Out"];
    
    const size_t out_len = output.length / 2;
    
    rng.randomVec(out_len); // gen 1st block (discarded)
    
    const string got = hexEncode(rng.randomVec(out_len));
    
    if (got != output)
    {
        logError(algo ~ " " ~ got ~ " != " ~ output);
        return 1;
    }
    
    return 0;
}

static if (!SKIP_RNG_TEST) unittest
{
    logDebug("Testing rng/test.d ...");
    File hmac_drbg_vec = File("../test_data/hmac_drbg.vec", "r");
    File x931_vec = File("../test_data/x931.vec", "r");
    
    size_t fails = 0;

    import std.functional : toDelegate;

    static if (BOTAN_HAS_HMAC_DRBG)
    fails += runTestsBb(hmac_drbg_vec, "RNG", "Out", true, toDelegate(&hmacDrbgTest));
    
    static if (BOTAN_HAS_X931_RNG)
    fails += runTestsBb(x931_vec, "RNG", "Out", true,
        (ref HashMap!(string, string) m) {
            return x931Test(m["RNG"], m["IKM"], m["Out"], to!uint(m["L"]));
        });


    testReport("rng", total_tests, fails);
}
