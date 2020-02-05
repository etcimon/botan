/*
* NIST curve reduction
*
* Copyright:
* (C) 2014 Jack LLoyd
* (C) 2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.math.ec_gfp.curve_nistp;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.ec_gfp.curve_gfp;
import botan.math.bigint.bigint;
import botan.math.mp.mp_core;
import botan.codec.hex;
import botan.utils.types;
import botan.utils.mem_ops;

abstract class CurveGFpNIST : CurveGFpRepr
{
    this()(size_t p_bits, BigInt* a, BigInt* b)
    {
        m_a = a.dup;
        m_b = b.dup;
        m_p_words = (p_bits + BOTAN_MP_WORD_BITS - 1) / BOTAN_MP_WORD_BITS;
    }

    override ref const(BigInt) getA() const { return m_a; }
    
    override ref const(BigInt) getB() const { return m_b; }
    
    override ref const(BigInt) getARep() const { return m_a; }
    
    override ref const(BigInt) getBRep() const { return m_b; }

    override size_t getPWords() const { return m_p_words; }

    override void toCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        redc(x, ws);
    }
    
    override void fromCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        redc(x, ws);
    }
    
    /**
    * Montgomery multiplication/reduction
    * Notes: z cannot alias x or y
    * Params:
    *  z = output
    *  x = first multiplicand
    *  y = second multiplicand
    */
    override void curveMul(BigInt* z, const(BigInt)* x, const(BigInt)* y, ref SecureVector!word ws) const
    {
        if (x.isZero() || y.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }
        
        const size_t p_words = getPWords();
        const size_t output_size = 2*p_words + 1;
        ws.resize(2*(p_words+2));
        
        z.growTo(output_size);
        z.clear();
        
        bigint_mul(z.mutablePtr(), output_size, ws.ptr,
            x.ptr, x.length, x.sigWords(),
            y.ptr, y.length, y.sigWords());
        
        this.redc(z, ws);
    }
    
    /**
    * Montgomery squaring/reduction
    * Notes: z cannot alias x
    * Params:
    *  z = output
    *  x = multiplicand
    */
    override void curveSqr(BigInt* z, const(BigInt)* x, ref SecureVector!word ws) const
    {
        if (x.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }
        
        const size_t p_words = getPWords();
        const size_t output_size = 2*p_words + 1;
        
        ws.resize(2*(p_words+2));
        
        z.growTo(output_size);
        z.clear();
        
        bigint_sqr(z.mutablePtr(), output_size, ws.ptr,
            x.ptr, x.length, x.sigWords());
        
        this.redc(z, ws);
    }
    
    override Vector!char toVector() const
    {
        Vector!char ret;
        ret ~= "\nm_a: ";
        ret ~= m_a.toString();
        ret ~= "\nm_b: ";
        ret ~= m_b.toString();
        ret ~= "\nm_p_words: ";
        ret ~= m_p_words.to!string;
        ret ~= "\n";
        return ret.move();
    }
    
    override void swap(CurveGFpRepr other_) {
        auto other = cast(CurveGFpNIST) other_;
        m_a.swap(&other.m_a);
        m_b.swap(&other.m_b);
        import std.algorithm.mutation : swap;
        swap(m_p_words, other.m_p_words);
    }

protected:
    abstract void redc(BigInt* x, ref SecureVector!word ws) const;

    abstract size_t maxRedcSubstractions() const;
private:
    // Curve parameters
    BigInt m_a, m_b;
    
    size_t m_p_words; // cache of m_p.sigWords()    
}

/**
* The NIST P-521 curve
*/
class CurveGFpP521 : CurveGFpNIST
{
public:
    this()(BigInt* a, BigInt* b)
    {
		if (prime is BigInt.init)
			prime = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

        super(521, a, b);
    }

    override ref const(BigInt) getP() const { return prime; }

    override void redc(BigInt* x, ref SecureVector!word ws) const
    {
        const size_t p_words = getPWords();
        
        const size_t shift_words = 521 / MP_WORD_BITS,
            shift_bits  = 521 % MP_WORD_BITS;
        
        const size_t x_sw = x.sigWords();
        
        if (x_sw < p_words)
            return; // already smaller
        
        if (ws.length < p_words + 1)
            ws.resize(p_words + 1);
        
        clearMem(ws.ptr, ws.length);
        bigint_shr2(ws.ptr, x.ptr, x_sw, shift_words, shift_bits);
        
        x.maskBits(521);
        
        bigint_add3(x.mutablePtr(), x.ptr, p_words, ws.ptr, p_words);
        
        normalize(x, ws, maxRedcSubstractions());
    }

    override size_t maxRedcSubstractions() const
    {
        return 1;
    }

    __gshared BigInt prime; 
}

