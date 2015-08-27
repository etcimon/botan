/**
* EMSA Classes
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.emsa;

import memutils.vector;
public import botan.rng.rng;
/**
* Encoding Method for Signatures, Appendix
*/
interface EMSA
{
public:
    /**
    * Add more data to the signature computation
    * Params:
    *  input = some data
    *  length = length of input in bytes
    */
    abstract void update(const(ubyte)* input, size_t length);

    /**
    * Returns: raw hash
    */
    abstract SecureVector!ubyte rawData();

    /**
    * Return the encoding of a message
    * Params:
    *  msg = the result of rawData()
    *  output_bits = the desired output bit size
    *  rng = a random number generator
    * Returns: encoded signature
    */
    abstract SecureVector!ubyte encodingOf(const ref SecureVector!ubyte msg,
                                           size_t output_bits,
                                           RandomNumberGenerator rng);

    /// ditto
    final SecureVector!ubyte encodingOf(const SecureVector!ubyte msg,
                                          size_t output_bits,
                                          RandomNumberGenerator rng)
    {
        return encodingOf(msg, output_bits, rng);
    }

    /**
    * Verify the encoding
    * Params:
    *  coded = the received (coded) message representative
    *  raw = the computed (local, uncoded) message representative
    *  key_bits = the size of the key in bits
    * Returns: true if coded is a valid encoding of raw, otherwise false
    */
    abstract bool verify(const ref SecureVector!ubyte coded,
                         const ref SecureVector!ubyte raw,
                         size_t key_bits);
}