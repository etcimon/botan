/**
* Runtime benchmarking
* 
* Copyright:
* (C) 2008-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.benchmark.benchmark;

import botan.constants;
static if (BOTAN_HAS_BENCHMARK):

import botan.algo_factory.algo_factory;
import botan.algo_base.buf_comp;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.modes.aead.aead;
import botan.hash.hash;
import botan.mac.mac;
import std.datetime;
import std.conv;
import botan.utils.types;
import std.datetime;
import botan.rng.rng;
import memutils.hashmap;
// import string;
import std.datetime;

/**
* Time aspects of an algorithm/provider
* Params:
*  name = the name of the algorithm to test
*  af = the algorithm factory used to create objects
*  provider = the provider to use
*  rng = the rng to use to generate random inputs
*  runtime = total time for the benchmark to run
*  buf_size = size of buffer to benchmark against, in KiB
* Returns: results a map from op type to operations per second
*/
HashMapRef!(string, double)
    timeAlgorithmOps(in string name,
                       AlgorithmFactory af,
                       in string provider,
                       RandomNumberGenerator rng,
                       Duration runtime,
                       size_t buf_size)
{
    const size_t Mebibyte = 1024*1024;
    
    SecureVector!ubyte buffer = SecureVector!ubyte(buf_size * 1024);
    rng.randomize(buffer.ptr, buffer.length);
    
    const double mb_mult = buffer.length / cast(double)(Mebibyte);
    

    {

        const BlockCipher proto = af.prototypeBlockCipher(name, provider);
        if (proto) {
            Unique!BlockCipher bc = proto.clone();
            
            const SymmetricKey key = SymmetricKey(rng, bc.maximumKeylength());
            
            HashMapRef!(string, double) ret;
            ret["key schedule"] = timeOp(runtime / 8, { bc.setKey(key); });
            ret["encrypt"] = mb_mult * timeOp(runtime / 2, { bc.encrypt(buffer); });
            ret["decrypt"] = mb_mult * timeOp(runtime / 2, { bc.decrypt(buffer); });
            return ret;
        }
    }
    {
        const StreamCipher proto = af.prototypeStreamCipher(name, provider);
        if (proto) {
            Unique!StreamCipher sc = proto.clone();
            
            const SymmetricKey key = SymmetricKey(rng, sc.maximumKeylength());
            HashMapRef!(string, double) ret;
            ret["key schedule"] = timeOp(runtime / 8, { sc.setKey(key); });
            ret[""] = mb_mult * timeOp(runtime, { sc.encipher(buffer); });
            return ret;
        }
    }
    {
        const HashFunction proto = af.prototypeHashFunction(name, provider);
        if (proto) {
            Unique!HashFunction h = proto.clone();
            HashMapRef!(string, double) ret;
            ret[""] = mb_mult * timeOp(runtime, { h.update(buffer); });
            return ret;
        }
    }
    {
        const MessageAuthenticationCode proto = af.prototypeMac(name, provider);
        
        if (proto) {
            Unique!MessageAuthenticationCode mac = proto.clone();
            
            const SymmetricKey key = SymmetricKey(rng, mac.maximumKeylength());
            HashMapRef!(string, double) ret;
            ret["key schedule"] =timeOp(runtime / 8, { mac.setKey(key); });
            ret[""] = mb_mult * timeOp(runtime, { mac.update(buffer); });
            return ret;
        }
    }
    {
        Unique!AEADMode enc = getAead(name, ENCRYPTION);
        Unique!AEADMode dec = getAead(name, DECRYPTION);
        
        if (!enc.isEmpty && !dec.isEmpty)
        {
            const SymmetricKey key = SymmetricKey(rng, enc.keySpec().maximumKeylength());
            HashMapRef!(string, double) ret;
            ret["key schedule"] = timeOp(runtime / 4, { enc.setKey(key); dec.setKey(key); }) / 2;
            ret["encrypt"] = mb_mult * timeOp(runtime / 2, { enc.update(buffer, 0); buffer.resize(buf_size*1024); });
            ret["decrypt"] = mb_mult * timeOp(runtime / 2, { dec.update(buffer, 0); buffer.resize(buf_size*1024); });
            return ret;
        }
    }
    
            
    return HashMapRef!(string, double)();
}

/**
* Algorithm benchmark
* Params:
*  name = the name of the algorithm to test (cipher, hash, or MAC)
*  af = the algorithm factory used to create objects
*  rng = the rng to use to generate random inputs
*  milliseconds = total time for the benchmark to run
*  buf_size = size of buffer to benchmark against, in KiB
* Returns: results a map from provider to speed in mebibytes per second
*/
HashMapRef!(string, double)
    algorithmBenchmark(in string name,
                        AlgorithmFactory af,
                        RandomNumberGenerator rng,
                        Duration milliseconds,
                        size_t buf_size)
{
    const Vector!string providers = af.providersOf(name);
    
    HashMapRef!(string, double) all_results; // provider . ops/sec
    
    if (!providers.empty)
    {
        const Duration ns_per_provider = milliseconds / providers.length;
        
        foreach (provider; providers)
        {
            auto results = timeAlgorithmOps(name, af, provider, rng, ns_per_provider, buf_size);
            all_results[provider] = findFirstIn(results, ["", "update", "encrypt"]);
        }
    }
    
    return all_results;
}


double timeOp(Duration runtime, void delegate() op)
{
    StopWatch sw;
    sw.start();
    int reps = 0;
    while (sw.peek().to!Duration < runtime)
    {
        op();
        ++reps;
    }
    sw.stop();
    return reps.to!double / sw.peek().seconds.to!double; // ie, return ops per second
}

private double findFirstIn(in HashMapRef!(string, double) m, 
                             const ref Vector!string keys)
{
    foreach (key; keys[])
    {
        auto val = m.get(key, double.nan);
        if (val != double.nan)
            return val;
    }
    
    throw new Exception("algorithmFactory no usable keys found in result");
}
