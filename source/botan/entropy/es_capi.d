/**
* Win32 CAPI EntropySource
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.es_capi;

version(Windows):
static if (BOTAN_HAS_ENTROPY_SRC_CAPI):

import botan.entropy.entropy_src;
import botan.utils.types;
import botan.utils.parsing;
import windows.h;
import wincrypt.h;

/**
* Win32 CAPI Entropy Source
*/
final class Win32CAPIEntropySource : EntropySource
{
public:
    @property string name() const { return "Win32 CryptoGenRandom"; }

    /*
    * Gather Entropy from Win32 CAPI
    */
    void poll(ref EntropyAccumulator accum)
    {
        SecureVector!ubyte io_buffer = accum.getIoBuffer(32);
        
        foreach (prov_type; m_prov_types[])
        {
            CSPHandle csp = CSPHandle(prov_type);
            
            size_t got = csp.genRandom(io_buffer.ptr, io_buffer.length);
            
            if (got)
            {
                accum.add(io_buffer.ptr, io_buffer.length, 6);
                break;
            }
        }
    }

    /**
    * Win32_Capi_Entropysource Constructor
    * Params:
    *  provs = list of providers, separated by ':'
    */
    this(in string provs = "")
    {
        Vector!string capi_provs = splitter(provs, ':');
        
        foreach (capi_prov; capi_provs)
        {
            if (capi_prov == "RSA_FULL")  m_prov_types.pushBack(PROV_RSA_FULL);
            if (capi_prov == "INTEL_SEC") m_prov_types.pushBack(PROV_INTEL_SEC);
            if (capi_prov == "FORTEZZA")  m_prov_types.pushBack(PROV_FORTEZZA);
            if (capi_prov == "RNG")       m_prov_types.pushBack(PROV_RNG);
        }
        
        if (m_prov_types.length == 0)
            m_prov_types.pushBack(PROV_RSA_FULL);
    }

    private:
        Vector!( ulong ) m_prov_types;
}

final class CSPHandle
{
public:
    this(ulong capi_provider)
    {
        m_valid = false;
        DWORD prov_type = cast(DWORD)capi_provider;
        
        if (CryptAcquireContext(&m_handle, 0, 0,
                                prov_type, CRYPT_VERIFYCONTEXT))
            m_valid = true;
    }
    
    ~this()
    {
        if (isValid())
            CryptReleaseContext(m_handle, 0);
    }
    
    size_t genRandom(ubyte* output) const
    {
        if (isValid() && CryptGenRandom(m_handle, cast(DWORD)(output.length), output))
            return output.length;
        return 0;
    }
    
    bool isValid() const { return m_valid; }
    
    HCRYPTPROV getHandle() const { return m_handle; }
private:
    HCRYPTPROV m_handle;
    bool m_valid;
}
