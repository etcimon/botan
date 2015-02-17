/**
* PBKDF1
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.pbkdf1;

import botan.constants;
static if (BOTAN_HAS_PBKDF1):

import botan.pbkdf.pbkdf;
import botan.hash.hash;
import std.datetime;
import botan.utils.exceptn;
import botan.utils.types;
import botan.algo_base.symkey;

/**
* PKCS #5 v1 PBKDF, aka PBKDF1
* Can only generate a key up to the size of the hash output.
* Unless needed for backwards compatability, use PKCS5_PBKDF2
*/
final class PKCS5_PBKDF1 : PBKDF
{
public:
    /**
    * Create a PKCS #5 instance using the specified hash function.
    *
    * Params:
    *  hash_in = pointer to a hash function object to use
    */
    this(HashFunction hash_input)
    {
        m_hash = hash_input;
    }

    override @property string name() const
    {
        return "PBKDF1(" ~ m_hash.name ~ ")";
    }

    override PBKDF clone() const
    {
        return new PKCS5_PBKDF1(m_hash.clone());
    }

    /*
    * Return a PKCS#5 PBKDF1 derived key
    */
    override Pair!(size_t, OctetString) keyDerivation(size_t key_len,
                                                      in string passphrase,
                                                      const(ubyte)* salt, size_t salt_len,
                                                      size_t iterations,
                                                      Duration loop_for) const
    {
        if (key_len > m_hash.outputLength)
            throw new InvalidArgument("PKCS5_PBKDF1: Requested output length too long");
        Unique!HashFunction hash = m_hash.clone();
        hash.update(passphrase);
        hash.update(salt, salt_len);
        SecureVector!ubyte key = hash.finished();

        const start = Clock.currTime();
        size_t iterations_performed = 1;
        
        while (true)
        {
            if (iterations == 0)
            {
                if (iterations_performed % 10000 == 0)
                {
                    auto time_taken = Clock.currTime() - start;
                    if (time_taken > loop_for)
                        break;
                }
            }
            else if (iterations_performed == iterations)
                break;
            
            hash.update(key);
            hash.flushInto(key.ptr);
            
            ++iterations_performed;
        }
        
        return makePair(iterations_performed, OctetString(key.ptr, std.algorithm.min(key_len, key.length)));
    }
private:
    Unique!HashFunction m_hash;
}

