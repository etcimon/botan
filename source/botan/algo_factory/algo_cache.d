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
    if (prov_name == "aes_isa") return 8;
    if (prov_name == "simd") return 7;
    if (prov_name == "asm") return 6;
    
    if (prov_name == "core") return 5;
    
    if (prov_name == "openssl") return 9;
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
        auto algo_providers = findAlgorithm(algo_spec);
        // logTrace("Searching ", algo_spec, " in algo length: ", m_algorithms.length);
        if (algo_providers.length == 0) // algo not found at all (no providers)
            return null;
        
        // If a provider is requested specifically, return it or fail entirely
        if (requested_provider != "")
        {
            return get(algo_providers, requested_provider).instance;
        }

        T prototype = null;
        string prototype_provider;
        size_t prototype_prov_weight = 0;
        
        const string pref_provider = m_pref_providers.get(algo_spec);
        auto prov_match = get(algo_providers, pref_provider);
        if (prov_match.instance)
            return prov_match.instance;

        foreach(ref CachedAlgorithm ca; *algo_providers) 
        {
            const ubyte prov_weight = staticProviderWeight(ca.provider);
            
            if (prototype is null || prov_weight > prototype_prov_weight)
            {
                prototype = cast(T)(ca.instance);
                prototype_provider = ca.provider;
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

        // Add alias if not exists
        if (algo.name != requested_name && m_aliases.get(requested_name) == null)
        {
            m_aliases[requested_name] = algo.name;
        }

        // default init
        {
	        Algorithm algo_cache = get(m_algorithms, algo.name);
	        if (!algo_cache.name) 
	        { 
	        	m_algorithms ~= Algorithm(algo.name, Array!CachedAlgorithm());
	        }
	    }
	    // add if not exists
	    {
	        Algorithm algo_cache = get(m_algorithms, algo.name);
	        if (get(algo_cache.providers, provider).instance is null) {
	        	algo_cache.providers ~= CachedAlgorithm(provider, algo);
			} else algo.destroy();
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
		Algorithm algo_cache;
		{
			algo_cache = get(m_algorithms, algo);
	        if (algo_cache.providers.length == 0)
	            algo = algo_name;
		}
		{
			algo_cache = get(m_algorithms, algo);
	        if (get(m_algorithms, algo).providers.length == 0) {
	            return Vector!string();
	        }
		}
		auto arr = algo_cache.providers;
        foreach(ref CachedAlgorithm ca; *arr) {
            providers.pushBack(ca.provider);
        }
        return providers.move();
    }

    /**
    * Clear the cache
    */
    void clearCache()
    {
        foreach (ref Algorithm algo; m_algorithms)
        {
        	auto providers = algo.providers;
            foreach (ref CachedAlgorithm ca; *providers) {
                if (ca.instance) destroy(ca.instance);
            }
        }

        m_algorithms.destroy();
    }

    ~this() { clearCache(); }
private:

    /*
    * Look for an algorithm implementation in the cache, also checking aliases
    * Assumes object lock is held
    */
    Array!CachedAlgorithm findAlgorithm(in string algo_spec) const
    {
        Algorithm algo = get(m_algorithms, algo_spec);
        // Not found? Check if a known alias
        if (!algo.name)
        {
            string _alias = m_aliases.get(algo_spec);

            if (_alias) {
                return get(m_algorithms, _alias).providers;
            }
            else {
                return Array!CachedAlgorithm();
            }
        }
        return algo.providers;
    }

    HashMap!(string, string) m_aliases;
    HashMap!(string, string) m_pref_providers;

    Vector!Algorithm m_algorithms;

private:
    struct Algorithm {
    	string name;
    	Array!CachedAlgorithm providers;
    }

	struct CachedAlgorithm {
		string provider;
		T instance;
	}

	CachedAlgorithm get(Array!CachedAlgorithm arr, string provider) const {
		foreach (ref CachedAlgorithm ca; *arr) {
			if (provider == ca.provider)
				return ca;
		}
		return CachedAlgorithm.init;
	}

	Algorithm get(inout ref Vector!Algorithm arr, inout string name) const {
		foreach (ref Algorithm algo; arr) {
			if (name == algo.name)
				return algo;
		}
		return Algorithm.init;
	}

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