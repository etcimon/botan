/**
* TLS Handshake Hash
* 
* Copyright:
* (C) 2004-2006,2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.handshake_hash;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import memutils.vector;
import botan.tls.version_;
import botan.tls.magic;
import botan.tls.exceptn;
import botan.hash.hash;
import botan.libstate.libstate;
import botan.tls.exceptn;
import botan.libstate.libstate;
import botan.hash.hash;
import botan.utils.types;

/**
* TLS Handshake Hash
*/
struct HandshakeHash
{
public:
    void update(const(ubyte)* input, size_t length)
    { m_data ~= input[0 .. length]; }

    void update(ALLOC)(auto const ref Vector!(ubyte, ALLOC) input)
    { m_data ~= input[]; }

    /**
    * Return a TLS Handshake Hash
    */
    SecureVector!ubyte flushInto(TLSProtocolVersion _version, in string mac_algo) const
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        
        Unique!HashFunction hash;
        
        if (_version.supportsCiphersuiteSpecificPrf())
        {
            if (mac_algo == "MD5" || mac_algo == "SHA-1")
                hash = af.makeHashFunction("SHA-256");
            else
                hash = af.makeHashFunction(mac_algo);
        }
        else
            hash = af.makeHashFunction("Parallel(MD5,SHA-160)");
        
        hash.update(m_data);
        return hash.finished();
    }

    ref const(Vector!ubyte) getContents() const return
    { return m_data; }

	void reset() { if (m_data.length == 0) m_data.reserve(2048); else m_data.clear(); }

    @property HandshakeHash clone() const 
    { 
        HandshakeHash ret;
        ret.m_data = m_data.clone;
        return ret;
    }
private:
    Vector!ubyte m_data;
}