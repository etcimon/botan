/**
* Blinding for public key operations
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.blinding;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.bigint.bigint;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;

/**
* Blinding Function Object
*/
struct Blinder
{
public:
    /*
    * Blind a number
    */
    BigInt blind()(auto const ref BigInt i)
    {
        if (!m_reducer.initialized()) 
            return i.dup;

        m_e = m_reducer.square(m_e);
        m_d = m_reducer.square(m_d);
        return m_reducer.multiply(i, m_e);
    }

    /*
    * Unblind a number
    */
    BigInt unblind()(auto const ref BigInt i) const
    {
        if (!m_reducer.initialized())
            return i.dup;
        return m_reducer.multiply(i, m_d);
    }

    bool initialized() const { return m_reducer.initialized(); }

    /**
    * Construct a blinder
    * Params:
    *  e = the forward (blinding) mask
    *  d = the inverse of mask (depends on algo)
    *  n = modulus of the group operations are performed in
    */
    this()(auto const ref BigInt e, 
           auto const ref BigInt d, 
           auto const ref BigInt n)
    {
        if (e < 1 || d < 1 || n < 1)
            throw new InvalidArgument("Blinder: Arguments too small");
        
        m_reducer = ModularReducer(n);
        m_e = e.dup;
        m_d = d.dup;
    }

private:
    ModularReducer m_reducer;
    BigInt m_e, m_d;
}