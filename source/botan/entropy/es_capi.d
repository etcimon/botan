/**
* Win32 CAPI EntropySource
* 
* Copyright:
* (C) 1999-2007,2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.es_capi;

version(Windows):
import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_CAPI):

import botan.entropy.entropy_src;
import botan.utils.types;
import botan.utils.parsing;

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
        m_buf.length = 32;
        
        foreach (prov_type; m_prov_types[])
        {
            auto csp = new CSPHandle(prov_type);
			scope(exit) csp.destroy();
            
            if (size_t got = csp.genRandom(m_buf.ptr, m_buf.length))
            {
                accum.add(m_buf.ptr, got, 6);
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
        
        foreach (capi_prov; capi_provs[])
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
    SecureVector!ubyte m_buf;
}

final class CSPHandle
{
public:
    this(ulong capi_provider)
    {
        DWORD prov_type = cast(DWORD)capi_provider;
        
        if (CryptAcquireContext(&m_handle, null, null, prov_type, cast(DWORD) CRYPT_VERIFYCONTEXT))
            m_valid = true;
    }
    
    ~this()
    {
        if (isValid())
            CryptReleaseContext(m_handle, 0);
    }
    
    size_t genRandom(ubyte* output, size_t length) const
    {
        if (isValid() && CryptGenRandom(m_handle, cast(DWORD) length, output))
            return length;
        return 0;
    }
    
    bool isValid() const { return m_valid; }
    
    HCRYPTPROV getHandle() const { return m_handle; }
private:
    HCRYPTPROV m_handle;
    bool m_valid;
}

private:

alias ULONG = uint;
alias DWORD = ULONG;
alias HCRYPTPROV = ULONG;
alias PBYTE = ubyte*;
enum {
    PROV_RSA_FULL = 1,
    PROV_FORTEZZA = 4,
    PROV_RNG = 21,
    PROV_INTEL_SEC = 22
}
alias BOOL = int;
alias LPCSTR = const(char)*;
alias LPCWSTR = const(wchar)*;
enum {
    CRYPT_VERIFYCONTEXT = 0xF0000000,
}

extern (Windows) {
    BOOL CryptReleaseContext(HCRYPTPROV, DWORD);
    BOOL CryptGenRandom(HCRYPTPROV, DWORD, PBYTE);
    
    version(Unicode) { 
        BOOL CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
        alias CryptAcquireContext = CryptAcquireContextW;
    }
    else {
        BOOL CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
        alias CryptAcquireContext = CryptAcquireContextA;
    }
}