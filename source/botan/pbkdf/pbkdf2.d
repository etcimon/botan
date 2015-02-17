/**
* PBKDF2
* 
* Copyright:
* (C) 1999-2007,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbkdf.pbkdf2;

import botan.constants;
static if (BOTAN_HAS_PBKDF2):

import botan.pbkdf.pbkdf;
import botan.mac.mac;
import botan.utils.get_byte;
import botan.utils.xor_buf;
import botan.utils.rounding;
import std.datetime;
import std.conv : to;

/**
* PKCS #5 PBKDF2
*/
final class PKCS5_PBKDF2 : PBKDF
{
public:
    override @property string name() const
    {
        return "PBKDF2(" ~ m_mac.name ~ ")";
    }

    override PBKDF clone() const
    {
        return new PKCS5_PBKDF2(m_mac.clone());
    }

    /*
    * Return a PKCS #5 PBKDF2 derived key
    */
    override 
    Pair!(size_t, OctetString)
        keyDerivation(size_t key_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration loop_for) const
    {
        if (key_len == 0)
            return makePair(iterations, OctetString());
        Unique!MessageAuthenticationCode mac = m_mac.clone();
        try
        {
            mac.setKey(cast(const(ubyte)*)(passphrase.ptr), passphrase.length);
        }
        catch(InvalidKeyLength)
        {
            throw new Exception(name ~ " cannot accept passphrases of length " ~ to!string(passphrase.length));
        }
        
        SecureVector!ubyte key = SecureVector!ubyte(key_len);
        
        ubyte* T = key.ptr;
        
        SecureVector!ubyte U = SecureVector!ubyte(mac.outputLength);
        
        const size_t blocks_needed = roundUp(key_len, mac.outputLength) / mac.outputLength;
        
        Duration dur_per_block = loop_for / blocks_needed;
        
        uint counter = 1;
        while (key_len)
        {
            size_t T_size = std.algorithm.min(mac.outputLength, key_len);
            
            mac.update(salt, salt_len);
            mac.updateBigEndian(counter);
            mac.flushInto(U.ptr);
            
            xorBuf(T, U.ptr, T_size);
            
            if (iterations == 0)
            {
                /*
                If no iterations set, run the first block to calibrate based
                on how long hashing takes on whatever machine we're running on.
                */
                
                const auto start = Clock.currTime();
                
                iterations = 1; // the first iteration we did above
                
                while (true)
                {
                    mac.update(U);
                    mac.flushInto(U.ptr);
                    xorBuf(T, U.ptr, T_size);
                    iterations++;
                    
                    /*
                    Only break on relatively 'even' iterations. For one it
                    avoids confusion, and likely some broken implementations
                    break on getting completely randomly distributed values
                    */
                    if (iterations % 10000 == 0)
                    {
                        auto time_taken = Clock.currTime() - start;
                        if (time_taken > dur_per_block)
                            break;
                    }
                }
            }
            else
            {
                foreach (size_t i; 1 .. iterations)
                {
                    mac.update(U);
                    mac.flushInto(U.ptr);
                    xorBuf(T, U.ptr, T_size);
                }
            }
            
            key_len -= T_size;
            T += T_size;
            ++counter;
        }
        
        return makePair(iterations, OctetString(key));
    }

    /**
    * Create a PKCS #5 instance using the specified message auth code
    * Params:
    *  mac_fn = the MAC object to use as PRF
    */
    this(MessageAuthenticationCode mac_fn) 
    {
        m_mac = mac_fn;
    }
private:
    Unique!MessageAuthenticationCode m_mac;
}