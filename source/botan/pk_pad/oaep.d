/**
* OAEP
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.oaep;

import botan.constants;
static if (BOTAN_HAS_EME_OAEP):

import botan.pk_pad.eme;
import botan.kdf.kdf;
import botan.hash.hash;
import botan.rng.rng;
import botan.pk_pad.mgf1;
import botan.utils.mem_ops;
import botan.utils.types;

/**
* OAEP (called EME1 in IEEE 1363 and in earlier versions of the library)
*/
final class OAEP : EME
{
public:
    /*
    * Return the max input size for a given key size
    */
    override size_t maximumInputSize(size_t keybits) const
    {
        if (keybits / 8 > 2*m_Phash.length + 1)
            return ((keybits / 8) - 2*m_Phash.length - 1);
        else
            return 0;
    }

    /**
    * Params:
    *  hash = object to use for hashing (takes ownership)
    *  P = an optional label. Normally empty.
    */
    this(HashFunction hash, in string P = "")
    {
        m_hash = hash;
        m_Phash = m_hash.process(P);
    }

    /*
    * OAEP Pad Operation
    */
    override SecureVector!ubyte pad(const(ubyte)* input, size_t in_length, size_t key_length,
                                    RandomNumberGenerator rng) const
    {
        key_length /= 8;
        
        if (key_length < in_length + 2*m_Phash.length + 1)
            throw new InvalidArgument("OAEP: Input is too large");
        
        SecureVector!ubyte output = SecureVector!ubyte(key_length);
        rng.randomize(output.ptr, m_Phash.length);
        
        bufferInsert(output, m_Phash.length, m_Phash.ptr, m_Phash.length);
        output[output.length - in_length - 1] = 0x01;
        bufferInsert(output, output.length - in_length, input, in_length);
        
        mgf1Mask(cast() *m_hash, output.ptr, m_Phash.length, &output[m_Phash.length], output.length - m_Phash.length);
        
        mgf1Mask(cast() *m_hash, &output[m_Phash.length], output.length - m_Phash.length,
        output.ptr, m_Phash.length);
        
        return output;
    }

    /*
    * OAEP Unpad Operation
    */
    override SecureVector!ubyte unpad(const(ubyte)* input_, size_t in_length, size_t key_length) const
    {
        /*
        Must be careful about error messages here; if an attacker can
        distinguish them, it is easy to use the differences as an oracle to
        find the secret key, as described in "A Chosen Ciphertext Attack on
        RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
        PKCS #1 v2.0", James Manger, Crypto 2001

        Also have to be careful about timing attacks! Pointed out by Falko
        Strenzke.
        */
        
        key_length /= 8;
        
        // Invalid input: truncate to zero length input, causing later
        // checks to fail
        if (in_length > key_length)
            in_length = 0;
        
        SecureVector!ubyte input = SecureVector!ubyte(key_length);
        bufferInsert(input, key_length - in_length, input_, in_length);
        
        mgf1Mask(cast() *m_hash, &input[m_Phash.length], input.length - m_Phash.length, input.ptr, m_Phash.length);        
        mgf1Mask(cast() *m_hash, input.ptr, m_Phash.length, &input[m_Phash.length], input.length - m_Phash.length);
        
        bool waiting_for_delim = true;
        bool bad_input = false;
        size_t delim_idx = 2 * m_Phash.length;
        
        /*
        * GCC 4.5 on x86-64 compiles this in a way that is still vunerable
        * to timing analysis. Other compilers, or GCC on other platforms,
        * may or may not.
        */
        for (size_t i = delim_idx; i < input.length; ++i)
        {
            const bool zero_p = !input[i];
            const bool one_p = input[i] == 0x01;
            
            const bool add_1 = waiting_for_delim && zero_p;
            
            bad_input |= waiting_for_delim && !(zero_p || one_p);
            
            delim_idx += add_1;
            
            waiting_for_delim &= zero_p;
        }
        
        // If we never saw any non-zero ubyte, then it's not valid input
        bad_input |= waiting_for_delim;
        
        bad_input |= !sameMem(&input[m_Phash.length], m_Phash.ptr, m_Phash.length);
        
        if (bad_input)
            throw new DecodingError("Invalid OAEP encoding");

        return SecureVector!ubyte(input.ptr[delim_idx + 1 .. input.length]);
    }

    SecureVector!ubyte m_Phash;
    Unique!HashFunction m_hash;
}