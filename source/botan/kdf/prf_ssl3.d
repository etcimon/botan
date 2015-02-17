/**
* SSLv3 PRF
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.prf_ssl3;

import botan.constants;
static if (BOTAN_HAS_TLS || BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.kdf.kdf;
import botan.algo_base.symkey;
import botan.utils.exceptn;
import botan.hash.hash;
import botan.hash.sha160;
import botan.hash.md5;
import botan.utils.types;
import std.algorithm : min;

/**
* PRF used in SSLv3
*/
class SSL3PRF : KDF
{
public:    
    /*
    * SSL3 PRF
    */
    override SecureVector!ubyte derive(size_t key_len,
                            const(ubyte)* secret, size_t secret_len,
                            const(ubyte)* seed, size_t seed_len) const
    {
        if (key_len > 416)
            throw new InvalidArgument("SSL3_PRF: Requested key length is too large");

        Unique!MD5 md5 = new MD5();
        Unique!SHA160 sha1 = new SHA160();
        
        OctetString output = OctetString("");
        
        int counter = 0;
        while (key_len)
        {
            size_t produce = min(key_len, md5.outputLength);
            
            output ~= nextHash(counter++, produce, *md5, *sha1, secret, secret_len, seed, seed_len);
            
            key_len -= produce;
        }
        return output.bitsOf().dup;
    }

    override @property string name() const { return "SSL3-PRF"; }
    override KDF clone() const { return new SSL3PRF; }
}

private:

/*
* Return the next inner hash
*/
OctetString nextHash(size_t where, size_t want,
                      HashFunction md5, HashFunction sha1,
                      const(ubyte)* secret, size_t secret_len,
                      const(ubyte)* seed, size_t seed_len)
{
    assert(want <= md5.outputLength,
                 "Output size producable by MD5");
    
    __gshared immutable ubyte ASCII_A_CHAR = 0x41;
    
    foreach (size_t j; 0 .. where + 1)
        sha1.update(cast(ubyte)(ASCII_A_CHAR + where));
    sha1.update(secret, secret_len);
    sha1.update(seed, seed_len);
    SecureVector!ubyte sha1_hash = sha1.finished();
    
    md5.update(secret, secret_len);
    md5.update(sha1_hash);
    SecureVector!ubyte md5_hash = md5.finished();
    
    return OctetString(md5_hash.ptr, want);
}