/**
* Dynamically Loaded Engine
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.engine.dyn_engine;

import botan.constants;
import botan.engine.engine;
import botan.utils.dyn_load.dyn_load;

/**
* Dynamically_Loaded_Engine just proxies the requests to the underlying
* Engine object, and handles load/unload details
*/
final class DynamicallyLoadedEngine : Engine
{
private:
    DynamicallyLoadedLibrary m_lib;
    Engine m_engine;
public:
    /**
    * Params:
    *  lib_path = full pathname to DLL to load
    */
    this(in string library_path) 
    {
        m_engine = null;
        m_lib = new DynamicallyLoadedLibrary(library_path);
        
        try
        {
            ModuleVersionFunc get_version = m_lib.resolve!ModuleVersionFunc("module_version");
            
            const uint mod_version = get_version();
            
            if (mod_version != 20101003)
                throw new Exception("Incompatible version in " ~ library_path ~ " of " ~ to!string(mod_version));
            
            CreatorFunc creator = m_lib.resolve!CreatorFunc("create_engine");
            
            m_engine = creator();

            if (!m_engine)
                throw new Exception("Creator function in " ~ library_path ~ " failed");
        }
        catch (Throwable)
        {
            destroy(m_lib);
            m_lib = null;
            throw new Exception("Error in dynamic library constructor");
        }
    }


    @disable this(in DynamicallyLoadedEngine);

    @disable void opAssign(DynamicallyLoadedEngine);

    ~this()
    {
        destroy(m_engine);
        destroy(m_lib);
    }

    string providerName() const { return m_engine.providerName(); }

    BlockCipher findBlockCipher(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findBlockCipher(algo_spec, af);
    }

    StreamCipher findStreamCipher(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findStreamCipher(algo_spec, af);
    }

    HashFunction findHash(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findHash(algo_spec, af);
    }

    MessageAuthenticationCode findMac(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findMac(algo_spec, af);
    }

    PBKDF findPbkdf(in SCANToken algo_spec, AlgorithmFactory af) const
    {
        return m_engine.findPbkdf(algo_spec, af);
    }


    KeyedFilter getCipher(in string algo_spec, CipherDir dir, AlgorithmFactory af) const
    {
        return m_engine.getCipher(algo_spec, dir, af);
    }

    static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

    ModularExponentiator modExp(const ref BigInt n, PowerMod.UsageHints hints) const
    {
        return m_engine.modExp(n, hints);
    }

    KeyAgreement getKeyAgreementOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getKeyAgreementOp(key, rng);
    }

    Signature getSignatureOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getSignatureOp(key, rng);
    }

    Verification getVerifyOp(in PublicKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getVerifyOp(key, rng);
    }

    Encryption getEncryptionOp(in PublicKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getEncryptionOp(key, rng);
    }

    Decryption getDecryptionOp(in PrivateKey key, RandomNumberGenerator rng) const
    {
        return m_engine.getDecryptionOp(key, rng);
    }

}

private nothrow @nogc extern(C):

alias CreatorFunc = Engine function();
alias ModuleVersionFunc = uint function();