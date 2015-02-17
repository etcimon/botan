/**
* HMAC_DRBG (SP800-90A)
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.hmac_drbg;

import botan.constants;
static if (BOTAN_HAS_HMAC_DRBG):

import botan.rng.rng;
import botan.mac.mac;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm;

/**
* HMAC_DRBG (SP800-90A)
*/
final class HMAC_DRBG : RandomNumberGenerator
{
public:
    override void randomize(ubyte* output, size_t length)
    {
        if (!isSeeded() || m_reseed_counter > BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED)
            reseed(m_mac.outputLength * 8);
        
        if (!isSeeded())
            throw new PRNGUnseeded(name);
        
        while (length)
        {
            const size_t to_copy = std.algorithm.min(length, m_V.length);
            m_V = m_mac.process(m_V);
            copyMem(output, m_V.ptr, to_copy);
            
            length -= to_copy;
            output += to_copy;
        }
        
        m_reseed_counter += length;
        
        update(null, 0); // additional_data is always empty
    }

    override bool isSeeded() const
    {
        return m_reseed_counter > 0;
    }

    override void clear()
    {
        zeroise(m_V);
        
        m_mac.clear();
        
        if (m_prng)
            m_prng.clear();
    }

    override @property string name() const
    {
        return "HMAC_DRBG(" ~ m_mac.name ~ ")";
    }

    override void reseed(size_t poll_bits)
    {
        if (m_prng)
        {
            m_prng.reseed(poll_bits);
            
            if (m_prng.isSeeded())
            {
                SecureVector!ubyte input = m_prng.randomVec(m_mac.outputLength);
                update(input.ptr, input.length);
                m_reseed_counter = 1;
            }
        }
    }

    override void addEntropy(const(ubyte)* input, size_t length)
    {
        update(input, length);
        m_reseed_counter = 1;
    }

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }
    /**
    * Params:
    *  mac = the underlying mac function (eg HMAC(SHA-512))
    *  underlying_rng = RNG used generating inputs (eg HMAC_RNG)
    */
    this(MessageAuthenticationCode mac,
         RandomNumberGenerator prng)
    { 
        // logDebug("Loading with mac: ", mac.name);
        import std.algorithm : fill;
        m_mac = mac.clone();
        m_prng = prng;
        m_V = SecureVector!ubyte(m_mac.outputLength);
        fill(m_V.ptr[0 .. m_V.length], cast(ubyte)0x01);
        m_reseed_counter = 0;
        auto mac_key = SecureVector!ubyte(m_mac.outputLength);
        fill(mac_key.ptr[0 .. mac_key.length], cast(ubyte)0x00);
        m_mac.setKey(mac_key);
    }

private:
    /*
    * Reset V and the mac key with new values
    */
    void update(const(ubyte)* input, size_t input_len)
    {
        m_mac.update(m_V);
        m_mac.update(0x00);
        m_mac.update(input, input_len);
        m_mac.setKey(m_mac.finished());
        
        m_V = m_mac.process(m_V);
        
        if (input_len)
        {
            m_mac.update(m_V);
            m_mac.update(0x01);
            m_mac.update(input, input_len);
            m_mac.setKey(m_mac.finished());
            
            m_V = m_mac.process(m_V);
        }
    }

    Unique!MessageAuthenticationCode m_mac;
    Unique!RandomNumberGenerator m_prng;

    SecureVector!ubyte m_V;
    size_t m_reseed_counter;
}