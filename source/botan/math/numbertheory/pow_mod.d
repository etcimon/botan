/**
* Modular Exponentiator
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.numbertheory.pow_mod;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.constants;
import botan.math.bigint.bigint;
import botan.libstate.libstate;
import botan.engine.engine;

alias FixedExponentPowerMod = RefCounted!FixedExponentPowerModImpl;
alias FixedBasePowerMod = RefCounted!FixedBasePowerModImpl;

/**
* Modular Exponentiator Interface
*/
interface ModularExponentiator
{
public:
    void setBase(const ref BigInt);
    void setExponent(const ref BigInt);
    BigInt execute() const;
    ModularExponentiator copy() const;
}

/**
* Modular Exponentiator Proxy
*/
class PowerMod
{
public:
    alias UsageHints = ushort;
    enum : UsageHints {
        NO_HINTS          = 0x0000,

        BASE_IS_FIXED    = 0x0001,
        BASE_IS_SMALL    = 0x0002,
        BASE_IS_LARGE    = 0x0004,
        BASE_IS_2         = 0x0008,

        EXP_IS_FIXED     = 0x0100,
        EXP_IS_SMALL     = 0x0200,
        EXP_IS_LARGE     = 0x0400
    }

    /*
    * Try to choose a good window size
    */
    static size_t windowBits(size_t exp_bits, size_t,
                             PowerMod.UsageHints hints)
    {
        __gshared immutable size_t[2][] wsize = [
            [ 1434, 7 ],
            [  539, 6 ],
            [  197, 4 ],
            [    70, 3 ],
            [    25, 2 ],
            [     0, 0 ]
        ];
        
        size_t window_bits = 1;
        
        if (exp_bits)
        {
            for (size_t j = 0; wsize[j][0]; ++j)
            {
                if (exp_bits >= wsize[j][0])
                {
                    window_bits += wsize[j][1];
                    break;
                }
            }
        }
        
        if (hints & PowerMod.BASE_IS_FIXED)
            window_bits += 2;
        if (hints & PowerMod.EXP_IS_LARGE)
            ++window_bits;
        
        return window_bits;
    }

    /*
    * Set the modulus
    */
    void setModulus()(auto const ref BigInt n, UsageHints hints = NO_HINTS)
    {
        m_core.free();
        if (n != 0)
        {
            AlgorithmFactory af = globalState().algorithmFactory();

            foreach (Engine engine; af.engines[]) {
                m_core = engine.modExp(n, hints);
                
                if (m_core)
                    break;
            }
            if (!m_core)
                throw new LookupError("PowerMod: Unable to find a working engine");
        }
    }

    /*
    * Set the base
    */
    void setBase()(auto const ref BigInt b)
    {

        if (b.isZero() || b.isNegative())
            throw new InvalidArgument("PowerMod.setBase: arg must be > 0");
        
        if (!m_core)
            throw new InternalError("PowerMod.setBase: core was NULL");

        m_core.setBase(b);
    }

    /*
    * Set the exponent
    */
    void setExponent()(auto const ref BigInt e)
    {
        if (e.isNegative())
            throw new InvalidArgument("PowerMod.setExponent: arg must be > 0");
        
        if (!m_core)
            throw new InternalError("PowerMod.setExponent: core was NULL");
        m_core.setExponent(e);
    }

    /*
    * Compute the result
    */
    BigInt execute()
    {
        if (!m_core)
            throw new InternalError("PowerMod.execute: core was NULL");
        return m_core.execute();
    }

    this()(auto const ref BigInt n, UsageHints hints = NO_HINTS)
    {
        setModulus(n, hints);
    }

    this(PowerMod other)
    {
        if (other.m_core)
            m_core = other.m_core.release();
    }

private:
    Unique!ModularExponentiator m_core;
}

/**
* Fixed Exponent Modular Exponentiator Proxy
*/
class FixedExponentPowerModImpl : PowerMod
{
public:
    BigInt opCall()(auto const ref BigInt b)
    { setBase(b); return execute(); }

    /*
    * FixedExponentPowerMod Constructor
    */
    this()(auto const ref BigInt e,
           auto const ref BigInt n,
           UsageHints hints = NO_HINTS)
    { 
        super(n, UsageHints(hints | EXP_IS_FIXED | chooseExpHints(e, n)));
        setExponent(e);
    }
    

}

/**
* Fixed Base Modular Exponentiator Proxy
*/
class FixedBasePowerModImpl : PowerMod
{
public:
    BigInt opCall()(auto const ref BigInt e)
    { setExponent(e); return execute(); }

    /*
    * FixedBasePowerMod Constructor
    */
    this()(auto const ref BigInt b, auto const ref BigInt n, UsageHints hints = NO_HINTS)
    {
        super(n, UsageHints(hints | BASE_IS_FIXED | chooseBaseHints(b, n)));
        setBase(b);
    }

}


/*
* Choose potentially useful hints
*/
PowerMod.UsageHints chooseBaseHints()(auto const ref BigInt b, auto const ref BigInt n)
{
    if (b == 2)
        return cast(PowerMod.UsageHints)(PowerMod.BASE_IS_2 | PowerMod.BASE_IS_SMALL);
    
    const size_t b_bits = b.bits();
    const size_t n_bits = n.bits();

    if (b_bits < n_bits / 32)
        return PowerMod.BASE_IS_SMALL;
    if (b_bits > n_bits / 4)
        return PowerMod.BASE_IS_LARGE;

    return PowerMod.NO_HINTS;
}

/*
* Choose potentially useful hints
*/
PowerMod.UsageHints chooseExpHints()(auto const ref BigInt e, auto const ref BigInt n)
{
    const size_t e_bits = e.bits();
    const size_t n_bits = n.bits();

    if (e_bits < n_bits / 32)
        return PowerMod.BASE_IS_SMALL;
    if (e_bits > n_bits / 4)
        return PowerMod.BASE_IS_LARGE;
    return PowerMod.NO_HINTS;
}