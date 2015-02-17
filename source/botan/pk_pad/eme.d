/**
* EME Classes
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.eme;

import memutils.vector;
public import botan.rng.rng;
/**
* Encoding Method for Encryption
*/
class EME
{
public:
    /**
    * Return the maximum input size in bytes we can support
    * Params:
    *  keybits = the size of the key in bits
    * Returns: upper bound of input in bytes
    */
    abstract size_t maximumInputSize(size_t keybits) const;

    /**
    * Encode an input
    * Params:
    *  msg = the plaintext
    *  msg_len = length of plaintext in bytes
    *  key_bits = length of the key in bits
    *  rng = a random number generator
    * Returns: encoded plaintext
    */
    final SecureVector!ubyte encode(const(ubyte)* msg, size_t msg_len,
                                    size_t key_bits,
                                    RandomNumberGenerator rng) const
    {
        return pad(msg, msg_len, key_bits, rng);
    }

    /**
    * Encode an input
    * Params:
    *  msg = the plaintext
    *  key_bits = length of the key in bits
    *  rng = a random number generator
    * Returns: encoded plaintext
    */
    final SecureVector!ubyte encode(const ref SecureVector!ubyte msg, size_t key_bits, RandomNumberGenerator rng) const
    {
        return pad(msg.ptr, msg.length, key_bits, rng);
    }

    /**
    * Decode an input
    * Params:
    *  msg = the encoded plaintext
    *  msg_len = length of encoded plaintext in bytes
    *  key_bits = length of the key in bits
    * Returns: plaintext
    */
    final SecureVector!ubyte decode(const(ubyte)* msg, size_t msg_len, size_t key_bits) const
    {
        return unpad(msg, msg_len, key_bits);
    }


    /**
    * Decode an input
    * Params:
    *  msg = the encoded plaintext
    *  key_bits = length of the key in bits
    * Returns: plaintext
    */
    final SecureVector!ubyte decode(const ref SecureVector!ubyte msg, size_t key_bits) const
    {
        return unpad(msg.ptr, msg.length, key_bits);
    }

    ~this() {}
protected:
    /**
    * Encode an input
    * Params:
    *  input = the plaintext
    *  in_length = length of plaintext in bytes
    *  key_length = length of the key in bits
    *  rng = a random number generator
    * Returns: encoded plaintext
    */
    abstract SecureVector!ubyte pad(const(ubyte)* input,
                                     size_t in_length,
                                     size_t key_length,
                                     RandomNumberGenerator rng) const;

    /**
    * Decode an input
    * Params:
    *  input = the encoded plaintext
    *  in_length = length of encoded plaintext in bytes
    *  key_length = length of the key in bits
    * Returns: plaintext
    */
    abstract SecureVector!ubyte unpad(const(ubyte)* input, size_t in_length, size_t key_length) const;
}
