/**
* HMAC RNG
* 
* Copyright:
* (C) 2008,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.hmac_rng;

import botan.mac.mac;
import botan.rng.rng;
import botan.utils.types;
import botan.libstate.libstate;
import botan.utils.get_byte;
import botan.entropy.entropy_src;
import botan.utils.xor_buf;
import std.algorithm;
import std.datetime;
import botan.constants;
/**
* HMAC_RNG - based on the design described in "On Extract-then-Expand
* Key Derivation Functions and an HMAC-based KDF" by Hugo Krawczyk
* (henceforce, 'E-t-E')
*
* However it actually can be parameterized with any two MAC functions,
* not restricted to HMAC (this variation is also described in
* Krawczyk's paper), for instance one could use HMAC(SHA-512) as the
* extractor and CMAC(AES-256) as the PRF.
*/
final class HMAC_RNG : RandomNumberGenerator
{
public:
    /*
    * Generate a buffer of random bytes
    */
    override void randomize(ubyte* output, size_t length)
    {
        if (!isSeeded())
        {
            reseed(256);
            if (!isSeeded())
                throw new PRNGUnseeded(name);
        }
        
        const size_t max_per_prf_iter = m_prf.outputLength / 2;
        
        /*
         HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
        */
        while (length)
        {
            hmacPrf(*m_prf, m_K, m_counter, "rng");
            
            const size_t copied = std.algorithm.min(length, max_per_prf_iter);
            
            copyMem(output, m_K.ptr, copied);
            output += copied;
            length -= copied;
            
            m_output_since_reseed += copied;
            
            if (m_output_since_reseed >= BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED)
                reseed(BOTAN_RNG_RESEED_POLL_BITS);
        }
    }

    override bool isSeeded() const
    {
        return (m_collected_entropy_estimate >= 256);
    }

    /*
    * Clear memory of sensitive data
    */
    override void clear()
    {
        m_collected_entropy_estimate = 0;
        m_extractor.clear();
        m_prf.clear();
        zeroise(m_K);
        m_counter = 0;
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "HMAC_RNG(" ~ m_extractor.name ~ "," ~ m_prf.name ~ ")";
    }

    /*
    * Poll for entropy and reset the internal keys
    */
    override void reseed(size_t poll_bits)
    {
        /*
        Using the terminology of E-t-E, XTR is the MAC function (normally
        HMAC) seeded with XTS (below) and we form SKM, the key material, by
        polling as many sources as we think needed to reach our polling
        goal. We then also include feedback of the current PRK so that
        a bad poll doesn't wipe us out.
        */
        
        double bits_collected = 0;
        
        EntropyAccumulator accum = EntropyAccumulator(
            (const(ubyte)* input, size_t in_len, double entropy_estimate)
            {
                m_extractor.update(input, in_len);
                bits_collected += entropy_estimate;
                return (bits_collected >= poll_bits);
            }
        );
        
        globalState().pollAvailableSources(accum);
        
        /*
        * It is necessary to feed forward poll data. Otherwise, a good poll
        * (collecting a large amount of conditional entropy) followed by a
        * bad one (collecting little) would be unsafe. Do this by
        * generating new PRF outputs using the previous key and feeding
        * them into the extractor function.
        *
        * Cycle the RNG once (CTXinfo="rng"), then generate a new PRF
        * output using the CTXinfo "reseed". Provide these values as input
        * to the extractor function.
        */
        hmacPrf(*m_prf, m_K, m_counter, "rng");
        m_extractor.update(m_K); // K is the CTXinfo=rng PRF output
        
        hmacPrf(*m_prf, m_K, m_counter, "reseed");
        m_extractor.update(m_K); // K is the CTXinfo=reseed PRF output
        
        /* Now derive the new PRK using everything that has been fed into
        the extractor, and set the PRF key to that */
        m_prf.setKey(m_extractor.finished());
        
        // Now generate a new PRF output to use as the XTS extractor salt
        hmacPrf(*m_prf, m_K, m_counter, "xts");
        m_extractor.setKey(m_K);
        
        // Reset state
        zeroise(m_K);
        m_counter = 0;
        
        m_collected_entropy_estimate = cast(size_t)std.algorithm.min(m_collected_entropy_estimate + bits_collected,
                                                         m_extractor.outputLength * 8);
        
        m_output_since_reseed = 0;
    }

    /*
    * Add user-supplied entropy to the extractor input
    */
    override void addEntropy(const(ubyte)* input, size_t length)
    {
        m_extractor.update(input, length);
        reseed(BOTAN_RNG_RESEED_POLL_BITS);
    }

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }

    /**
    * Params:
    *  extractor = a MAC used for extracting the entropy
    *  prf = a MAC used as a PRF using HKDF construction
    */
    this(MessageAuthenticationCode extractor, MessageAuthenticationCode prf)
    {
        m_extractor = extractor; // swap
        m_prf = prf; // swap
        this();
    }

private:
    this() {
        assert(!m_prf.isEmpty && !m_extractor.isEmpty);

        if (!m_prf.validKeylength(m_extractor.outputLength) ||
            !m_extractor.validKeylength(m_prf.outputLength))
            throw new InvalidArgument("HMAC_RNG: Bad algo combination " ~
                m_extractor.name ~ " and " ~
                m_prf.name);
        
        // First PRF inputs are all zero, as specified in section 2
        m_K.resize(m_prf.outputLength);
        
        /*
        Normally we want to feedback PRF outputs to the extractor function
        to ensure a single bad poll does not reduce entropy. Thus in reseed
        we'll want to invoke the PRF before we reset the PRF key, but until
        the first reseed the PRF is unkeyed. Rather than trying to keep
        track of this, just set the initial PRF key to constant zero.
        Since all PRF inputs in the first reseed are constants, this
        amounts to suffixing the seed in the first poll with a fixed
        constant string.

        The PRF key will not be used to generate outputs until after reseed
        sets m_seeded to true.
        */
        SecureVector!ubyte prf_key = SecureVector!ubyte(m_extractor.outputLength);
        m_prf.setKey(prf_key);
        /*
        Use PRF("Botan HMAC_RNG XTS") as the intitial XTS key.

        This will be used during the first extraction sequence; XTS values
        after this one are generated using the PRF.

        If I understand the E-t-E paper correctly (specifically Section 4),
        using this fixed extractor key is safe to do.
        */
        m_extractor.setKey(m_prf.process("Botan HMAC_RNG XTS"));

    }

    Unique!MessageAuthenticationCode m_extractor;
    Unique!MessageAuthenticationCode m_prf;

    size_t m_collected_entropy_estimate = 0;
    size_t m_output_since_reseed = 0;

    SecureVector!ubyte m_K;
    uint m_counter = 0;
}



private:

void hmacPrf()(MessageAuthenticationCode prf,
               ref SecureVector!ubyte K,
               ref uint counter,
               in string label)
{
    
    auto timestamp = Clock.currStdTime();
    
    prf.update(K);
    prf.update(label);
    prf.updateBigEndian(timestamp);
    prf.updateBigEndian(counter);
    prf.flushInto(K.ptr);
    
    ++counter;
}
