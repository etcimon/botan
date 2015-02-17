/**
* Modular Exponentiation
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.numbertheory.def_powm;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.mp.mp_core;
import botan.math.numbertheory.pow_mod;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;
import botan.math.bigint.bigint;
import botan.utils.types;
import botan.constants;

/**
* Fixed Window Exponentiator
*/
final class FixedWindowExponentiator : ModularExponentiator
{
public:
    /*
    * Set the exponent
    */
    override void setExponent(const ref BigInt e)
    {
        m_exp = e.dup;
    }

    /*
    * Set the base
    */
    override void setBase(const ref BigInt base)
    {
        m_window_bits = PowerMod.windowBits(m_exp.bits(), base.bits(), m_hints);
        auto base_2 = base.dup;
        m_g.resize(1 << m_window_bits);
        m_g[0] = RefCounted!BigInt(1);
        m_g[1] = RefCounted!BigInt(base_2);
        
        for (size_t i = 2; i != m_g.length; ++i)
            m_g[i] = RefCounted!BigInt(m_reducer.multiply(*(m_g[i-1]), *(m_g[0])));
    }

    /*
    * Compute the result
    */
    override BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;
        
        BigInt x = BigInt(1);
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            foreach (size_t j; 0 .. m_window_bits)
                x = m_reducer.square(x);
            
            const uint nibble = m_exp.getSubstring(m_window_bits*(i-1), m_window_bits);
            
            x = m_reducer.multiply(x, *(m_g[nibble]));
        }
        return x.move();
    }

    override ModularExponentiator copy() const
    { 
        FixedWindowExponentiator ret = new FixedWindowExponentiator;
        ret.m_reducer = m_reducer.dup;
        ret.m_exp = m_exp.dup;
        ret.m_window_bits = m_window_bits;
        ret.m_g = m_g.dup;
        ret.m_hints = m_hints;
        return ret;
    }

    this()(auto const ref BigInt n, PowerMod.UsageHints _hints)
    {
        m_reducer = ModularReducer(n);
        m_hints = _hints;
        m_window_bits = 0;
    }

private:
    this() { }
    ModularReducer m_reducer;
    BigInt m_exp;
    size_t m_window_bits;
    Vector!(RefCounted!BigInt) m_g;
    PowerMod.UsageHints m_hints;
}

/**
* Montgomery Exponentiator
*/
class MontgomeryExponentiator : ModularExponentiator
{
public:
    /*
    * Set the exponent
    */
    override void setExponent(const ref BigInt exp)
    {
        m_exp = exp.dup;
        m_exp_bits = exp.bits();
    }

    /*
    * Set the base
    */
    override void setBase(const ref BigInt base)
    {
        m_window_bits = PowerMod.windowBits(m_exp.bits(), base.bits(), m_hints);
        m_g.resize((1 << m_window_bits));
        
        BigInt z = BigInt(BigInt.Positive, 2 * (m_mod_words + 1));
        SecureVector!word workspace = SecureVector!word(z.length);
        
        m_g[0] = RefCounted!BigInt(1);
        
        bigint_monty_mul(z.mutablePtr(), z.length, m_g[0].ptr, m_g[0].length, m_g[0].sigWords(), m_R2_mod.ptr, 
                         m_R2_mod.length, m_R2_mod.sigWords(), m_modulus.ptr, m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[0] = RefCounted!BigInt(z.dup);
        
        m_g[1] = (base >= m_modulus) ? RefCounted!BigInt(base % m_modulus) : RefCounted!BigInt(base.dup);
        
        bigint_monty_mul(z.mutablePtr(), z.length, m_g[1].ptr, m_g[1].length, m_g[1].sigWords(), m_R2_mod.ptr, 
                         m_R2_mod.length, m_R2_mod.sigWords(), m_modulus.ptr, m_mod_words, m_mod_prime, workspace.ptr);
        
        m_g[1] = RefCounted!BigInt(z.dup);
        
        const BigInt* x = &*(m_g[1]);
        const size_t x_sig = x.sigWords();
        
        for (size_t i = 2; i != m_g.length; ++i)
        {
            const BigInt* y = &*(m_g[i-1]);
            const size_t y_sig = y.sigWords();
            
            bigint_monty_mul(z.mutablePtr(), z.length,
                             x.ptr, x.length, x_sig,
                             y.ptr, y.length, y_sig,
                             m_modulus.ptr, m_mod_words, m_mod_prime,
                             workspace.ptr);
            
            m_g[i] = RefCounted!BigInt(z.dup);
        }
    }

    /*
    * Compute the result
    */
    override BigInt execute() const
    {
        const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;
        
        BigInt x = m_R_mod.dup;
        
        const size_t z_size = 2*(m_mod_words + 1);
        
        BigInt z = BigInt(BigInt.Positive, z_size);
        SecureVector!word workspace = SecureVector!word(z_size);
        
        for (size_t i = exp_nibbles; i > 0; --i)
        {
            for (size_t k = 0; k != m_window_bits; ++k)
            {
                bigint_monty_sqr(z.mutablePtr(), z_size, x.ptr, x.length, x.sigWords(),
                                 m_modulus.ptr, m_mod_words, m_mod_prime, workspace.ptr);
                
                x.growTo(z.length);
                x.mutablePtr[0..x.length] = z.mutablePtr[0..z.length];
            }
            
            const uint nibble = m_exp.getSubstring(m_window_bits*(i-1), m_window_bits);
            
            const BigInt* y = &*m_g[nibble];


            bigint_monty_mul(z.mutablePtr(), z_size, x.ptr, x.length, x.sigWords(), y.ptr, y.length, y.sigWords(),
                             m_modulus.ptr, m_mod_words, m_mod_prime, workspace.ptr);
            x.growTo(z.length);
            x.mutablePtr[0..x.length] = z.mutablePtr[0..z.length];
        }
        
        x.growTo(2*m_mod_words + 1);
        
        bigint_monty_redc(x.mutablePtr(), m_modulus.ptr, m_mod_words, m_mod_prime, workspace.ptr);
        return x.move();
    }

    override ModularExponentiator copy() const
    { 
        MontgomeryExponentiator ret = new MontgomeryExponentiator;
        ret.m_exp = m_exp.dup;
        ret.m_modulus = m_modulus.dup;
        ret.m_R_mod = m_R_mod.dup;
        ret.m_R2_mod = m_R2_mod.dup;
        ret.m_mod_prime = m_mod_prime;
        ret.m_mod_words = m_mod_words;
        ret.m_exp_bits = m_exp_bits;
        ret.m_window_bits = m_window_bits;
        ret.m_hints = m_hints;
        ret.m_g = m_g.dup;
        return ret;
    }

    /*
    * Montgomery_Exponentiator Constructor
    */
    this()(auto const ref BigInt mod, PowerMod.UsageHints hints)
    {
        m_modulus = mod.dup;
        m_mod_words = m_modulus.sigWords();
        m_window_bits = 1;
        m_hints = hints;
        // Montgomery reduction only works for positive odd moduli
        if (!m_modulus.isPositive() || m_modulus.isEven())
            throw new InvalidArgument("Montgomery_Exponentiator: invalid modulus");
        
        m_mod_prime = montyInverse(mod.wordAt(0));
        
        BigInt r = BigInt.powerOf2(m_mod_words * BOTAN_MP_WORD_BITS);
        m_R_mod = r % m_modulus;
        m_R2_mod = (m_R_mod * m_R_mod) % m_modulus;
    }
private:
    this() { }
    BigInt m_exp, m_modulus, m_R_mod, m_R2_mod;
    word m_mod_prime;
    size_t m_mod_words, m_exp_bits, m_window_bits;
    PowerMod.UsageHints m_hints;
    Vector!(RefCounted!BigInt) m_g;
}

