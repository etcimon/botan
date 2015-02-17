/**
* PK Key Types
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.pk_keys;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.asn1.alg_id;
import memutils.vector;
import botan.asn1.asn1_oid;
import botan.rng.rng;
import botan.asn1.der_enc;
import botan.asn1.oids;
import botan.utils.types;

/**
* Public Key Base Class.
*/
interface PublicKey
{
public:
    /**
    * Get the name of the underlying public key scheme.
    * Returns: name of the public key scheme
    */
    abstract @property string algoName() const;

    /**
    * Return the estimated strength of the underlying key against
    * the best currently known attack. Note that this ignores anything
    * but pure attacks against the key itself and do not take into
    * account padding schemes, usage mistakes, etc which might reduce
    * the strength. However it does suffice to provide an upper bound.
    *
    * Returns: estimated strength in bits
    */
    abstract size_t estimatedStrength() const;

    /**
    * Get the OID of the underlying public key scheme.
    * Returns: OID of the public key scheme
    */
    final OID getOid() const
    {
        try {
            return OIDS.lookup(algoName);
        }
        catch(LookupError)
        {
            throw new LookupError("PK algo " ~ algoName ~ " has no defined OIDs");
        }
    }


    /**
    * Test the key values for consistency.
    *
    * Params:
    *  rng = rng to use
    *  strong = whether to perform strong and lengthy version
    * of the test
    * Returns: true if the test is passed
    */
    abstract bool checkKey(RandomNumberGenerator rng, bool strong) const;

    /**
    * Find out the number of message parts supported by this scheme.
    * Returns: number of message parts
    */
    abstract size_t messageParts() const;

    /**
    * Find out the message part size supported by this scheme/key.
    * Returns: size of the message parts in bits
    */
    abstract size_t messagePartSize() const; 

    /**
    * Get the maximum message size in bits supported by this public key.
    * Returns: maximum message size in bits
    */
    abstract size_t maxInputBits() const;

    /**
    * Returns: X.509 AlgorithmIdentifier for this key
    */
    abstract AlgorithmIdentifier algorithmIdentifier() const;

    /**
    * Returns: X.509 subject key encoding for this key object
    */
    abstract Vector!ubyte x509SubjectPublicKey() const;

    /**
    * Self-test after loading a key
    * Params:
    *  rng = a random number generator
    */
    final void loadCheck(RandomNumberGenerator rng) const
    {
        if (!checkKey(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
            throw new InvalidArgument(algoName ~ ": Invalid public key");
    }
}

/**
* Private Key Base Class
*/
interface PrivateKey : PublicKey
{
public:
    /**
    * Returns: PKCS #8 private key encoding for this key object
    */
    abstract SecureVector!ubyte pkcs8PrivateKey() const;

    /**
    * Returns: PKCS #8 AlgorithmIdentifier for this key
    * Might be different from the X.509 identifier, but normally is not
    */
    abstract AlgorithmIdentifier pkcs8AlgorithmIdentifier() const;

    /**
    * Self-test after loading a key
    * Params:
    *  rng = a random number generator
    */
    final void loadCheck(RandomNumberGenerator rng) const
    {
        if (!checkKey(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD))
            throw new InvalidArgument(algoName ~ ": Invalid private key");
    }

    /**
    * Self-test after generating a key
    * Params:
    *  rng = a random number generator
    */
    final void genCheck(RandomNumberGenerator rng) const
    {
        if (!checkKey(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE))
            throw new SelfTestFailure(algoName ~ " private key generation failed");
    }
}

/**
* PK Secret Value Derivation Key
*/
interface PKKeyAgreementKey : PrivateKey
{
public:
    /*
    * Returns: public component of this key
    */
    abstract Vector!ubyte publicValue() const;

}

/*
* Typedefs
*/
alias X509PublicKey = PublicKey;
alias PKCS8PrivateKey = PrivateKey;

template UnConst(T) {
    static if (is(T U == const(U))) {
        alias UnConst = U;
    } else static if (is(T V == immutable(V))) {
        alias UnConst = V;
    } else static if (is(T W == inout(W))) {
        alias UnConst = W;
    } else alias UnConst = T;
}