/**
* Algorithm Factory
* 
* Copyright:
* (C) 2008-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_factory.algo_factory;

import botan.constants;
import botan.algo_factory.algo_cache;
import botan.engine.engine;
import botan.utils.exceptn;

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;
import botan.pbkdf.pbkdf;
import botan.utils.types;
import std.algorithm;

/**
* Algorithm Factory
*/
final class AlgorithmFactory
{
public:
    ~this() {
        foreach(engine; m_engines) {
            destroy(engine);
        }
        m_engines.clear();

    }

    /**
    * Params:
    *  engine = the engine to add to $(D AlgorithmFactory) and gives ownership of it.
    */
    void addEngine(Engine engine)
    {
        clearCaches();
        m_engines.pushBack(engine);
    }
    
    /**
    * Clear out any cached objects
    */
    void clearCaches()
    {
        m_block_cipher_cache.clearCache();
        m_stream_cipher_cache.clearCache();
        m_hash_cache.clearCache();
        m_mac_cache.clearCache();
        m_pbkdf_cache.clearCache();
    }
    
    /**
    * Possible providers of a request assuming you don't have 
    * different types by the same name
    * 
    * Params:
    *  m algo_spec = the algorithm we are querying
    * 
    * Returns: list of providers of this algorithm
    */
    Vector!string providersOf(in string algo_spec)
    {
        /* The checks with if (prototype_X(algo_spec)) have the effect of
        forcing a full search, since otherwise there might not be any
        providers at all in the cache.
        */
        
        if (prototypeBlockCipher(algo_spec))
            return m_block_cipher_cache.providersOf(algo_spec);
        else if (prototypeStreamCipher(algo_spec))
            return m_stream_cipher_cache.providersOf(algo_spec);
        else if (prototypeHashFunction(algo_spec))
            return m_hash_cache.providersOf(algo_spec);
        else if (prototypeMac(algo_spec))
            return m_mac_cache.providersOf(algo_spec);
        else if (prototypePbkdf(algo_spec))
            return m_pbkdf_cache.providersOf(algo_spec);
        else
            return Vector!string();
    }

    
    /**
    * Set the preferred provider for an algorithm
    * 
    * Params:
    *  algo_spec = the algorithm we are setting a provider for
    *  provider = the provider we would like to use
    */
    void setPreferredProvider(in string algo_spec, in string provider = "")
    {
        if (prototypeBlockCipher(algo_spec))
            m_block_cipher_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeStreamCipher(algo_spec))
            m_stream_cipher_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeHashFunction(algo_spec))
            m_hash_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypeMac(algo_spec))
            m_mac_cache.setPreferredProvider(algo_spec, provider);
        else if (prototypePbkdf(algo_spec))
            m_pbkdf_cache.setPreferredProvider(algo_spec, provider);
    }
    
    /**
    * Prototypical block cipher retrieval by name, it must be cloned to be used
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to const prototype object, ready to $(D clone()), or NULL
    */
    const(BlockCipher) prototypeBlockCipher(in string algo_spec, in string provider = "")
    {
        return factoryPrototype!BlockCipher(algo_spec, provider, engines, this, *m_block_cipher_cache);
    }
    
    /**
    * Makes a ready-to-use block cipher according to its name
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to freshly created instance of the request algorithm
    */
    BlockCipher makeBlockCipher(in string algo_spec, in string provider = "")
    {
        if (const BlockCipher proto = prototypeBlockCipher(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
    
    /**
    * Add a new block cipher
    * Params:
    *  algo = the algorithm to add
    *  provider = the provider of this algorithm
    */
    void addBlockCipher(BlockCipher block_cipher, in string provider = "")
    {
        m_block_cipher_cache.add(block_cipher, block_cipher.name, provider);
    }
    
    /**
    * Return the prototypical stream cipher corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: Pointer to const prototype object, ready to $(D clone()), or NULL
    */
    const(StreamCipher) prototypeStreamCipher(in string algo_spec, in string provider = "")
    {
        return factoryPrototype!StreamCipher(algo_spec, provider, engines, this, *m_stream_cipher_cache);
    }

    
    /**
    * Return a new stream cipher corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: Pointer to freshly created instance of the request algorithm
    */
    StreamCipher makeStreamCipher(in string algo_spec, in string provider = "")
    {
        if (const StreamCipher proto = prototypeStreamCipher(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }

    
    /**
    * Add a new stream cipher
    * 
    * Params:
    *  stream_cipher = the algorithm to add
    *  provider = the provider of this algorithm
    */
    void addStreamCipher(StreamCipher stream_cipher, in string provider = "")
    {
        m_stream_cipher_cache.add(stream_cipher, stream_cipher.name, provider);
    }
    
    /**
    * Return the prototypical object corresponding to this request (if found)
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to const prototype object, ready to $(D clone()), or NULL
    */
    const(HashFunction) prototypeHashFunction(in string algo_spec, in string provider = "")
    {
        return factoryPrototype!HashFunction(algo_spec, provider, engines, this, *m_hash_cache);
    }

    
    /**
    * Return a new object corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * Returns: pointer to freshly created instance of the request algorithm
    */
    HashFunction makeHashFunction(in string algo_spec, in string provider = "")
    {
        if (const HashFunction proto = prototypeHashFunction(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
        
    /**
    * Add a new hash
    * 
    * Params:
    *  hash = the algorithm to add
    *  provider = the provider of this algorithm
    */
    void addHashFunction(HashFunction hash, in string provider = "")
    {
        m_hash_cache.add(hash, hash.name, provider);
    }
    
    /**
    * Return the prototypical object corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to const prototype object, ready to $(D clone()), or NULL
    */
    const(MessageAuthenticationCode) prototypeMac(in string algo_spec, in string provider = "")
    {
        return factoryPrototype!MessageAuthenticationCode(algo_spec, provider, engines, this, *m_mac_cache);
    }
    
    /**
    * Return a new object corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to freshly created instance of the request algorithm
    */
    MessageAuthenticationCode makeMac(in string algo_spec, in string provider = "")
    {
        if (const MessageAuthenticationCode proto = prototypeMac(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }

    
    /**
    * Params:
    *  mac = the algorithm to add
    *  provider = the provider of this algorithm
    */
    void addMac(MessageAuthenticationCode mac, in string provider = "")
    {
        m_mac_cache.add(mac, mac.name, provider);
    }

    
    /**
    * Return the prototypical object corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to const prototype object, ready to $(D clone()), or NULL
    */
    const(PBKDF) prototypePbkdf(in string algo_spec, in string provider = "")
    {
        return factoryPrototype!PBKDF(algo_spec, provider, engines, this, *m_pbkdf_cache);
    }

    
    /**
    * Returns a new Pbkdf object corresponding to this request
    * 
    * Params:
    *  algo_spec = the algorithm we want
    *  provider = the provider we would like to use
    * 
    * Returns: pointer to freshly created instance of the request algorithm
    */
    PBKDF makePbkdf(in string algo_spec, in string provider = "")
    {
        if (const PBKDF proto = prototypePbkdf(algo_spec, provider))
            return proto.clone();
        throw new AlgorithmNotFound(algo_spec);
    }
    
    /**
    * Add a new Pbkdf
    *
	* Params:
    *  pbkdf = the algorithm to add
    *  provider = the provider of this algorithm
    */
    void addPbkdf(PBKDF pbkdf, in string provider = "")
    {
        m_pbkdf_cache.add(pbkdf, pbkdf.name, provider);
    }

    /// List of engines available
    @property ref Vector!Engine engines() {
        return m_engines;
    }

    this() {
        m_block_cipher_cache = new AlgorithmCache!BlockCipher;
        m_stream_cipher_cache = new AlgorithmCache!StreamCipher;
        m_hash_cache = new AlgorithmCache!HashFunction;
        m_mac_cache = new AlgorithmCache!MessageAuthenticationCode;
        m_pbkdf_cache = new AlgorithmCache!PBKDF;
    }

private:
    Engine getEngineN(size_t n) const
    {
        // Get an engine out of the list
        if (n >= m_engines.length)
            return null;
        return m_engines[n];
    }
    
    Vector!Engine m_engines;
    
    Unique!(AlgorithmCache!BlockCipher) m_block_cipher_cache;
    Unique!(AlgorithmCache!StreamCipher) m_stream_cipher_cache;
    Unique!(AlgorithmCache!HashFunction) m_hash_cache;
    Unique!(AlgorithmCache!MessageAuthenticationCode) m_mac_cache;
    Unique!(AlgorithmCache!PBKDF) m_pbkdf_cache;
}

private:

/*
* Template functions for the factory prototype/search algorithm
*/
T engineGetAlgo(T)(Engine, in SCANToken, AlgorithmFactory)
{ static assert(false, "Invalid engine"); }

BlockCipher engineGetAlgo(T : BlockCipher)(Engine engine, 
                                           auto ref SCANToken request, 
                                           AlgorithmFactory af)
{ return engine.findBlockCipher(request, af); }

StreamCipher engineGetAlgo(T : StreamCipher)(Engine engine, 
                                             auto ref SCANToken request, 
                                             AlgorithmFactory af)
{ return engine.findStreamCipher(request, af); }

HashFunction engineGetAlgo(T : HashFunction)(Engine engine, 
                                             auto ref SCANToken request, 
                                             AlgorithmFactory af)
{ return engine.findHash(request, af); }

MessageAuthenticationCode engineGetAlgo(T : MessageAuthenticationCode)(Engine engine, 
                                                                       auto ref SCANToken request,
                                                                       AlgorithmFactory af)
{ return engine.findMac(request, af); }

PBKDF engineGetAlgo(T : PBKDF)(Engine engine, 
                               auto ref SCANToken request, 
                               AlgorithmFactory af)
{ return engine.findPbkdf(request, af); }

const(T) factoryPrototype(T)(in string algo_spec,
                             in string provider,
                             ref Vector!( Engine ) engines,
                             AlgorithmFactory af,
                             AlgorithmCache!T cache) {

    logTrace("Searching for algo ", algo_spec, " | engine: ", provider ? provider : "All");

    if (const T cache_hit = cache.get(algo_spec, provider)) 
        return cache_hit;

    SCANToken scan_name = SCANToken(algo_spec);

    if (scan_name.cipherMode() != "")
        return null;

    foreach (engine; engines[])
    {
        if (provider == "" || engine.providerName() == provider)
            if (T impl = engineGetAlgo!T(engine, scan_name, af))
                cache.add(impl, algo_spec, engine.providerName());
        
    }

    return cache.get(algo_spec, provider);
}
