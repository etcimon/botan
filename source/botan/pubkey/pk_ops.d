/**
* PK Operation Types
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.pk_ops;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.alg_id;
public import botan.rng.rng;
public import botan.pubkey.pk_keys;
import memutils.vector;

/**
* Public key encryption interface
*/
interface Encryption
{
public:
    abstract size_t maxInputBits() const;

    abstract SecureVector!ubyte encrypt(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng);

}

/**
* Public key decryption interface
*/
interface Decryption
{
public:
    abstract size_t maxInputBits() const;

    abstract SecureVector!ubyte decrypt(const(ubyte)* msg, size_t msg_len);

}

/**
* Public key signature creation interface
*/
interface Signature
{
public:
    /**
    * Find out the number of message parts supported by this scheme.
    * Returns: number of message parts
    */
    abstract size_t messageParts() const;

    /**
    * Find out the message part size supported by this scheme/key.
    * Returns: size of the message parts
    */
    abstract size_t messagePartSize() const;

    /**
    * Get the maximum message size in bits supported by this public key.
    * Returns: maximum message in bits
    */
    abstract size_t maxInputBits() const;

    /*
    * Perform a signature operation
    * Params:
    *  msg = the message
    *  msg_len = the length of msg in bytes
    *  rng = a random number generator
    */
    abstract SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng);

}

/**
* Public key signature verification interface
*/
interface Verification
{
public:
    /**
    * Get the maximum message size in bits supported by this public key.
    * Returns: maximum message in bits
    */
    abstract size_t maxInputBits() const;

    /**
    * Find out the number of message parts supported by this scheme.
    * Returns: number of message parts
    */
    abstract size_t messageParts() const;

    /**
    * Find out the message part size supported by this scheme/key.
    * Returns: size of the message parts
    */
    abstract size_t messagePartSize() const;

    /**
    * Returns: boolean specifying if this key type supports message
    * recovery and thus if you need to call verify() or verifyMr()
    */
    abstract bool withRecovery() const;

    /*
    * Perform a signature check operation
    * Params:
    *  msg = the message
    *  msg_len = the length of msg in bytes
    *  sig = the signature
    *  sig_len = the length of sig in bytes
    * Returns: true if signature is a valid one for message
    */
    abstract bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len);

    /*
    * Perform a signature operation (with message recovery)
    * Only call this if withRecovery() returns true
    * Params:
    *  msg = the message
    *  msg_len = the length of msg in bytes
    * Returns:s recovered message
    */
    abstract SecureVector!ubyte verifyMr(const(ubyte)* msg, size_t msg_len);

}

/**
* A generic key agreement Operation (eg DH or ECDH)
*/
interface KeyAgreement
{
public:
    /*
    * Perform a key agreement operation
    * Params:
    *  w = the other key value
    *  w_len = the length of w in bytes
    * Returns:s the agreed key
    */
    abstract SecureVector!ubyte agree(const(ubyte)* w, size_t w_len);
}