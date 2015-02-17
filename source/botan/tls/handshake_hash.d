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

    /**
    * Return a SSLv3 Handshake Hash
    */
    SecureVector!ubyte finalSSL3()(auto const ref SecureVector!ubyte secret) const
    {
        const ubyte PAD_INNER = 0x36, PAD_OUTER = 0x5C;
        
        AlgorithmFactory af = globalState().algorithmFactory();
        
        Unique!HashFunction md5 = af.makeHashFunction("MD5");
        Unique!HashFunction sha1 = af.makeHashFunction("SHA-1");
        
        md5.update(m_data);
        sha1.update(m_data);
        
        md5.update(secret);
        sha1.update(secret);
        
        foreach (size_t i; 0 .. 48)
            md5.update(PAD_INNER);
        foreach (size_t i; 0 .. 40)
            sha1.update(PAD_INNER);
        
        SecureVector!ubyte inner_md5 = md5.finished(), inner_sha1 = sha1.finished();
        
        md5.update(secret);
        sha1.update(secret);
        
        foreach (size_t i; 0 .. 48)
            md5.update(PAD_OUTER);
        foreach (size_t i; 0 .. 40)
            sha1.update(PAD_OUTER);
        
        md5.update(inner_md5);
        sha1.update(inner_sha1);
        
        SecureVector!ubyte output;
        output ~= md5.finished();
        output ~= sha1.finished();
        return output;
    }

    ref const(Vector!ubyte) getContents() const
    { return m_data; }

    void reset() { m_data.clear(); }

    @property HandshakeHash dup() const 
    { 
        HandshakeHash ret;
        ret.m_data = m_data.dup;
        return ret;
    }
private:
    Vector!ubyte m_data;
}