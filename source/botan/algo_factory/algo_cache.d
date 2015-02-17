/**
* An algorithm cache (used by AlgorithmFactory)
* 
* Copyright:
* (C) 2008-2009,2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_factory.algo_cache;

import botan.constants;
import botan.utils.types;
import memutils.hashmap;
/**
* Params:
*  prov_name = a provider name
* 
* Returns: weight for this provider
*/
ubyte staticProviderWeight(in string prov_name)
{
    /*
    * Prefer asm over D, but prefer anything over OpenSSL or GNU MP; to use
    * them, set the provider explicitly for the algorithms you want
    */    
    if (prov_name == "aes_isa") return 9;
    if (prov_name == "simd") return 8;
    if (prov_name == "asm") return 7;
    
    if (prov_name == "core") return 5;
    
    if (prov_name == "openssl") return 2;
    if (prov_name == "gmp") return 1;
    
    return 0; // other/unknown
}


/**
* AlgorithmCache (used by AlgorithmFactory)
*/
final class AlgorithmCache(T)
{
public:
    /**
    * Look for an algorithm implementation by a particular provider
    * 
    * Params:
    *  algo_spec = names the requested algorithm
    *  requested_provider = suggests a preferred provider
    * 
    * Returns: prototype object, or NULL
    */
    const(T) get(string algo_spec, string requested_provider) const
    {
        HashMapRef!(string, T) algo = findAlgorithm(algo_spec);

        // logTrace("Searching ", algo_spec, " in algo length: ", m_algorithms.length);
        if (algo.length == 0) // algo not found at all (no providers)
            return null;
        
        // If a provider is requested specifically, return it or fail entirely
        if (requested_provider != "")
        {
            return algo.get(requested_provider);
        }

        T prototype = null;
        string prototype_provider;
        size_t prototype_prov_weight = 0;
        
        const string pref_provider = m_pref_providers.get(algo_spec);

        if (algo.get(pref_provider))
            return algo.get(pref_provider);

        foreach(const ref string provider, const ref T instance; algo) 
        {
            const ubyte prov_weight = staticProviderWeight(provider);
            
            if (prototype is null || prov_weight > prototype_prov_weight)
            {
                prototype = cast(T)instance;
                prototype_provider = provider;
                prototype_prov_weight = prov_weight;
            }
        }

        // logTrace("Returning provider: ", prototype_provider);
        return cast(const)prototype;
    }

    /**
    * Add a new algorithm implementation to the cache
    * 
    * Params:
    *  algo = the algorithm prototype object
    *  requested_name = how this name will be requested
    *  provider = the name of the provider of this prototype
    */
    void add(T algo,
             in string requested_name,
             in string provider)
    {
        //logTrace("Start adding ", requested_name, " provider ", provider);
        if (!algo) {
            logError("Tried adding null algorithm");
            return;
        }
                
        if (algo.name != requested_name && m_aliases.get(requested_name) == null)
        {
            m_aliases[requested_name] = algo.name;
        }
        if (!m_algorithms.get(algo.name)) {
            m_algorithms[algo.name] = HashMapRef!(string, T)();
        }

        if (m_algorithms[algo.name].get(provider) is null) {
            m_algorithms[algo.name][provider] = algo;
        }

    }


    /**
    * Set the preferred provider for an algorithm
    * 
    * Params:
    *  algo_spec = names the algorithm
    *  provider = names the preferred provider
    */
    void setPreferredProvider(in string algo_spec,
                              in string provider)
    {        
        m_pref_providers[algo_spec] = provider;
    }

    /**
    * Find the providers of this algo (if any)
    * 
    * Params:
    *  algo_name = names the algorithm
    * 
    * Returns: list of providers of this algorithm
    */
    Vector!string providersOf(in string algo_name)
    {
        Vector!string providers;
        string algo = m_aliases.get(algo_name);
        if (m_algorithms.get(algo).length == 0)
            algo = algo_name;
        if (m_algorithms.get(algo).length == 0) {
            return Vector!string();
        }
        foreach(const ref string provider, const ref T instance; *(m_algorithms[algo])) {
            providers.pushBack(provider);
        }
        return providers.move();
    }

    /**
    * Clear the cache
    */
    void clearCache()
    {
        foreach (const ref string provider, ref HashMapRef!(string, T) algorithms; m_algorithms)
        {
            foreach (const ref string name, ref T instance; algorithms) {
                if (instance) destroy(instance);
            }
        }

        m_algorithms.clear();
    }

    ~this() { clearCache(); }
private:

    /*
    * Look for an algorithm implementation in the cache, also checking aliases
    * Assumes object lock is held
    */
    HashMapRef!(string, T) findAlgorithm(in string algo_spec) const
    {
        HashMapRef!(string, T) algo = m_algorithms.get(algo_spec);
        // Not found? Check if a known alias
        if (!algo)
        {

            string _alias = m_aliases.get(algo_spec);

            if (_alias) {
                return m_algorithms.get(_alias);
            }
            else {
                return HashMapRef!(string, T)();
            }
        }
        return algo;
    }

    HashMap!(string, string) m_aliases;
    HashMap!(string, string) m_pref_providers;

             // algo_name     //provider // instance
    HashMap!(string, HashMapRef!(string, T)) m_algorithms;
}

shared(int) threads;
static this() {
    import core.atomic;
    atomicOp!"+="(threads, 1);
    logTrace("Starting, Threads: ", atomicLoad(threads));
}

static ~this() {
    import core.atomic;
    atomicOp!"-="(threads, 1);
    logTrace("Closing, Threads: ", atomicLoad(threads));
}