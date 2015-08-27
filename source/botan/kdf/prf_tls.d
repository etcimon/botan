/**
* TLS v1.0 and v1.2 PRFs
* 
* Copyright:
* (C) 2004-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.kdf.prf_tls;

import botan.constants;
static if (BOTAN_HAS_TLS || BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.kdf.kdf;
import botan.mac.mac;
import botan.utils.xor_buf;
import botan.mac.hmac;
import botan.hash.md5;
import botan.hash.sha160;
import std.conv : to;

/**
* PRF used in TLS 1.0/1.1
*/
class TLSPRF : KDF
{
public:
    /*
    * TLS PRF
    */
    override SecureVector!ubyte derive(size_t key_len,
                                       const(ubyte)* secret, size_t secret_len,
                                       const(ubyte)* seed, size_t seed_len) const
    {
        SecureVector!ubyte output = SecureVector!ubyte(key_len);
        
        size_t S1_len = (secret_len + 1) / 2;
        size_t S2_len = (secret_len + 1) / 2;
        const(ubyte)* S1 = secret;
        const(ubyte)* S2 = secret + (secret_len - S2_len);
        
        P_hash(output, cast() *m_hmac_md5,  S1, S1_len, seed, seed_len);
        P_hash(output, cast() *m_hmac_sha1, S2, S2_len, seed, seed_len);
        
        return output;
    }

    override @property string name() const { return "TLS-PRF"; }
    override KDF clone() const { return new TLSPRF; }

    /*
    * TLS PRF Constructor and Destructor
    */
    this()
    {
        m_hmac_md5 = new HMAC(new MD5);
        m_hmac_sha1= new HMAC(new SHA160);
    }

private:
    Unique!MessageAuthenticationCode m_hmac_md5;
    Unique!MessageAuthenticationCode m_hmac_sha1;
}

/**
* PRF used in TLS 1.2
*/
class TLS12PRF : KDF
{
public:
    override SecureVector!ubyte derive(size_t key_len,
                                   const(ubyte)* secret, size_t secret_len,
                                   const(ubyte)* seed, size_t seed_len) const
    {
        SecureVector!ubyte output = SecureVector!ubyte(key_len);
        
        P_hash(output, cast() *m_hmac, secret, secret_len, seed, seed_len);
        
        return output;
    }

    override @property string name() const { return "TLSv12-PRF(" ~ m_hmac.name ~ ")"; }
    override KDF clone() const { return new TLS12PRF(m_hmac.clone()); }

    /*
    * TLS v1.2 PRF Constructor and Destructor
    */
    this(MessageAuthenticationCode mac)
    {
        m_hmac = mac;
    }
private:
    Unique!MessageAuthenticationCode m_hmac;
}


private:
/*
* TLS PRF P_hash function
*/
void P_hash(ref SecureVector!ubyte output,
            MessageAuthenticationCode mac,
            const(ubyte)* secret, size_t secret_len,
            const(ubyte)* seed, size_t seed_len) 
{
    try
    {
        mac.setKey(secret, secret_len);
    }
    catch(InvalidKeyLength)
    {
        throw new InternalError("The premaster secret of " ~ to!string(secret_len) ~ " bytes is too long for the PRF");
    }
    
    SecureVector!ubyte A = SecureVector!ubyte(seed[0 .. seed_len]);
    
    size_t offset = 0;
    
    while (offset != output.length)
    {
        const size_t this_block_len = std.algorithm.min(mac.outputLength, output.length - offset);
        
        A = mac.process(A);
        
        mac.update(A);
        mac.update(seed, seed_len);
        SecureVector!ubyte block = mac.finished();
        
        xorBuf(&output[offset], block.ptr, this_block_len);
        offset += this_block_len;
    }
}