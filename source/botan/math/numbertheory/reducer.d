/**
* Modular Reducer
* 
* Copyright:
* (C) 1999-2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.numbertheory.reducer;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.numbertheory.numthry;
import botan.math.mp.mp_core;

/**
* Modular Reducer (using Barrett's technique)
*/
struct ModularReducer
{
public:
    ref const(BigInt) getModulus() const { return m_modulus; }

    /*
    * Barrett Reduction
    */
    BigInt reduce(BigInt x) const
    {
        if (m_mod_words == 0)
            throw new InvalidState("ModularReducer: Never initalized");
        if (x.cmp(m_modulus, false) < 0)
        {
            if (x.isNegative())
                return x + m_modulus; // make positive
            return x.move;
        }
        else if (x.cmp(m_modulus_2, false) < 0)
        {
            BigInt t1 = x.dup;
            t1.setSign(BigInt.Positive);
            t1 >>= (MP_WORD_BITS * (m_mod_words - 1));
            t1 *= m_mu;
            
            t1 >>= (MP_WORD_BITS * (m_mod_words + 1));
            t1 *= m_modulus;
            
            t1.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            BigInt t2 = x.move;
            t2.setSign(BigInt.Positive);
            t2.maskBits(MP_WORD_BITS * (m_mod_words + 1));
            
            t2 -= t1;
            
            if (t2.isNegative())
            {
                t2 += BigInt.powerOf2(MP_WORD_BITS * (m_mod_words + 1));
            }
            while (t2 >= m_modulus)
                t2 -= m_modulus;            

            if (x.isPositive())
                return t2.move();
            else
                return m_modulus - t2;
        }
        else
        {
            // too big, fall back to normal division
            return (x % m_modulus);
        }
    }

    /**
    * Multiply mod p
    * Params:
    *  x
    *  y
    * Returns: (x * y) % p
    */
    BigInt multiply()(auto const ref BigInt x, auto const ref BigInt y) const
    { 
        return reduce(x * y);
    }

    /**
    * Square mod p
    * Params:
    *  x
    * Returns: (x * x) % p
    */
    BigInt square()(auto const ref BigInt x) const
    {
        return reduce(x.square());
    }

    /**
    * Cube mod p
    * Params:
    *  x
    * Returns: (x * x * x) % p
    */
    BigInt cube()(auto const ref BigInt x) const
    { return multiply(x, this.square(x)); }

    bool initialized() const { return (m_mod_words != 0); }
    /*
    * ModularReducer Constructor
    */
    this(const ref BigInt mod)
    {
        if (mod <= 0)
            throw new InvalidArgument("ModularReducer: modulus must be positive");
        m_modulus = mod.dup;
        m_mod_words = m_modulus.sigWords();
        m_modulus_2 = .square(m_modulus);
        m_mu = BigInt.powerOf2(2 * MP_WORD_BITS * m_mod_words) / m_modulus;
    }

    @property ModularReducer dup() const {
        return ModularReducer(m_modulus);
    }

private:
    BigInt m_modulus, m_modulus_2, m_mu;
    size_t m_mod_words;
}