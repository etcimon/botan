/**
* ChaCha_RNG — HMAC-SHA-256 + ChaCha20 DRBG
*
* Copyright:
* (C) 2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.chacha_rng;

import botan.constants;
static if (BOTAN_HAS_CHACHA_RNG):

static assert(BOTAN_HAS_STATEFUL_RNG, "ChaCha_RNG requires Stateful_RNG");
static assert(BOTAN_HAS_CHACHA, "ChaCha_RNG requires ChaCha");

import botan.rng.stateful_rng;
import botan.mac.mac;
import botan.stream.stream_cipher;
import botan.stream.chacha;
import botan.libstate.lookup;
import botan.utils.mem_ops;
import botan.utils.types;

/**
* Fast ad-hoc RNG: HK = HMAC-SHA-256 key, CK = ChaCha20 key.
* CK' = HMAC(HK, input); HK' = ChaCha20(CK')[0..32].
*/
final class ChaChaRNG : StatefulRNG
{
public:
    /// Empty ChaCha_RNG (unseeded until addEntropy/reseed).
    this()
    {
        super();
        initCiphers();
        clearState();
    }

    /**
    * Params:
    *  seed = initial entropy
    *  seed_len = length of seed
    */
    this(const(ubyte)* seed, size_t seed_len)
    {
        super();
        initCiphers();
        clearState();
        addEntropy(seed, seed_len);
    }

    /// ditto
    this(const(ubyte)[] seed)
    {
        this(seed.ptr, seed.length);
    }

    /**
    * Params:
    *  underlying = RNG used for reseed
    *  reseed_interval = requests between reseeds
    */
    this(RandomNumberGenerator underlying, size_t reseed_interval = StatefulRNG.defaultReseedInterval)
    {
        super(underlying, reseed_interval);
        initCiphers();
        clearState();
    }

    override @property string name() const { return "ChaCha_RNG"; }
    override size_t securityLevel() const { return 256; }
    override size_t maxBytesPerRequest() const { return 0; }

protected:
    override void clearState()
    {
        auto z = SecureVector!ubyte(m_hmac.outputLength);
        m_hmac.setKey(z);
        auto ck = m_hmac.finished();
        m_chacha.setKey(ck.ptr, ck.length);
    }

    override void update(const(ubyte)* input, size_t in_len)
    {
        m_hmac.update(input, in_len);
        auto ck = m_hmac.finished();
        m_chacha.setKey(ck.ptr, ck.length);
        auto mac_key = SecureVector!ubyte(m_hmac.outputLength);
        m_chacha.cipher1(mac_key.ptr, mac_key.length);
        m_hmac.setKey(mac_key);
    }

    override void generateOutput(ubyte* output, size_t out_len,
                                 const(ubyte)* input, size_t in_len)
    {
        if (in_len)
            update(input, in_len);
        foreach (i; 0 .. out_len)
            output[i] = 0;
        m_chacha.cipher1(output, out_len);
    }

private:
    void initCiphers()
    {
        m_hmac = retrieveMac("HMAC(SHA-256)").clone();
        m_chacha = new ChaCha(20);
    }

    Unique!MessageAuthenticationCode m_hmac;
    Unique!StreamCipher m_chacha;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.codec.hex;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_CHACHA_RNG_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing chacha_rng.d ...");
    size_t fails = 0;

    File vec = File("test_data/rng/chacha_rng.vec", "r");
    fails += runTestsBb(vec, "ChaCha_RNG", "Out", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Out" in m) || !("EntropyInput" in m) || !("EntropyInputReseed" in m))
                return 0;
            auto seed = hexDecode(m["EntropyInput"]);
            auto reseed = hexDecode(m["EntropyInputReseed"]);
            auto exp = hexDecode(m["Out"]);
            Vector!ubyte ad1, ad2;
            if (auto p = "AdditionalInput1" in m)
                ad1 = hexDecode(*p);
            if (auto p = "AdditionalInput2" in m)
                ad2 = hexDecode(*p);

            Unique!ChaChaRNG rng = new ChaChaRNG;
            rng.initializeWith(seed.ptr, seed.length);
            rng.addEntropy(reseed.ptr, reseed.length);

            auto outbuf = SecureVector!ubyte(exp.length);
            rng.randomizeWithInput(outbuf.ptr, outbuf.length, ad1.ptr, ad1.length);
            rng.randomizeWithInput(outbuf.ptr, outbuf.length, ad2.ptr, ad2.length);
            if (outbuf[] != exp[])
                return 1;
            return 0;
        });

    fails += checkMemutilsRepeat("chacha_rng", {
        Unique!ChaChaRNG r = new ChaChaRNG;
        ubyte[32] seed = 1;
        r.initializeWith(seed.ptr, seed.length);
        ubyte[16] outp;
        r.randomize(outp.ptr, outp.length);
    });

    testReport("chacha_rng", 0, fails);
    assert(fails == 0);
}
