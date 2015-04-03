/**
* Elliptic curves over GF(p)
*
* Copyright:
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010-2011,2012,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.ec_gfp.curve_gfp;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.numbertheory.numthry;
import botan.math.mp.mp_types;
import botan.math.mp.mp_core;
import std.algorithm : swap;
import botan.constants;
import memutils.unique;

interface CurveGFpRepr
{
public:

    ref const(BigInt) getP() const;
    
    ref const(BigInt) getA() const;
    
    ref const(BigInt) getB() const;

    /// Returns toCurveRep(getA())
    ref const(BigInt) getARep() const;

    /// Returns toCurveRep(getB())
    ref const(BigInt) getBRep() const;

    void toCurveRep(ref BigInt x, ref SecureVector!word ws) const;

    void fromCurveRep(ref BigInt x, ref SecureVector!word ws) const;

    void curveMul(ref BigInt z, const ref BigInt x, const ref BigInt y, ref SecureVector!word ws) const;

    void curveSqr(ref BigInt z, const ref BigInt x, ref SecureVector!word ws) const;

    Vector!char toVector() const;
}

class CurveGFpMontgomery : CurveGFpRepr
{
    this()(auto const ref BigInt p, auto const ref BigInt a, auto const ref BigInt b)
    {
        m_p = p.dup;
        m_a = a.dup;
        m_b = b.dup;
        m_p_words = m_p.sigWords();
        m_p_dash = montyInverse(m_p.wordAt(0));
        BigInt r = BigInt.powerOf2(m_p_words * BOTAN_MP_WORD_BITS);
        m_r2  = (r * r) % m_p;
        m_a_r = (m_a * r) % m_p;
        m_b_r = (m_b * r) % m_p;
    }

    ref const(BigInt) getP() const { return m_p; }

    ref const(BigInt) getA() const { return m_a; }

    ref const(BigInt) getB() const { return m_b; }
        
    ref const(BigInt) getARep() const { return m_a_r; }

    ref const(BigInt) getBRep() const { return m_b_r; }

    void toCurveRep(ref BigInt x, ref SecureVector!word ws) const
    {
        const BigInt tx = x.dup;
        curveMul(x, tx, m_r2, ws);
    }

    void fromCurveRep(ref BigInt x, ref SecureVector!word ws) const
    {
        const BigInt tx = x.dup;
        BigInt bi = BigInt(1);
        curveMul(x, tx, bi, ws);
    }

    /**
    * Montgomery multiplication/reduction
    * Notes: z cannot alias x or y
    * Params:
    *  z = output
    *  x = first multiplicand
    *  y = second multiplicand
    */
    void curveMul(ref BigInt z, const ref BigInt x, const ref BigInt y, ref SecureVector!word ws) const
    {
        
        if (x.isZero() || y.isZero())
        {
            z = 0;
            return;
        }

        const size_t output_size = 2*m_p_words + 1;
        ws.resize(2*(m_p_words+2));

        z.growTo(output_size);
        z.clear();
        
        bigint_monty_mul(z.mutablePtr(), output_size,
            x.ptr, x.length, x.sigWords(),
            y.ptr, y.length, y.sigWords(),
            m_p.ptr, m_p_words, m_p_dash,
            ws.ptr);
    }

    /**
    * Montgomery squaring/reduction
    * Notes: z cannot alias x
    * Params:
    *  z = output
    *  x = multiplicand
    */
    void curveSqr(ref BigInt z, const ref BigInt x, ref SecureVector!word ws) const
    {
        if (x.isZero())
        {
            z = 0;
            return;
        }

        const size_t output_size = 2*m_p_words + 1;
        ws.resize(2*(m_p_words+2));
        
        z.growTo(output_size);
        z.clear();
        bigint_monty_sqr(z.mutablePtr(), output_size,
            x.ptr, x.length, x.sigWords(),
            m_p.ptr, m_p_words, m_p_dash,
            ws.ptr);
    }

    Vector!char toVector() const
    {
        Vector!char ret;
        ret ~= "m_p: ";
        ret ~= m_p.toString();
        ret ~= "\nm_a: ";
        ret ~= m_a.toString();
        ret ~= "\nm_b: ";
        ret ~= m_b.toString();
        ret ~= "\nm_r2: ";
        ret ~= m_r2.toString();
        ret ~= "\nm_a_r: ";
        ret ~= m_a_r.toString();
        ret ~= "\nm_b_r: ";
        ret ~= m_b_r.toString();
        ret ~= "\nm_p_dash: ";
        ret ~= m_p_dash.to!string;
        ret ~= "\nm_p_words: ";
        ret ~= m_p_words.to!string;
        ret ~= "\n";
        return ret.move();
    }

private:
    // Curve parameters
    BigInt m_p, m_a, m_b;
    
    size_t m_p_words; // cache of m_p.sigWords()
    
    // Montgomery parameters
    BigInt m_r2, m_a_r, m_b_r;
    word m_p_dash;

}

/**
* This class represents an elliptic curve over GF(p)
*/
struct CurveGFp
{
    /**
    * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
    * Params:
    *  p = prime number of the field
    *  a = first coefficient
    *  b = second coefficient
    */
    this()(auto const ref BigInt p, auto const ref BigInt a, auto const ref BigInt b)
    {
        m_repr = chooseRepr(p, a, b);
    }

    /**
    * Returns: curve coefficient a
    */
    ref const(BigInt) getA() const { return m_repr.getA(); }

    /**
    * Returns: curve coefficient b
    */
    ref const(BigInt) getB() const { return m_repr.getB(); }

    /**
    * Get prime modulus of the field of the curve
    * Returns: prime modulus of the field of the curve
    */
    ref const(BigInt) getP() const { return m_repr.getP(); }

    /**
    * Returns: a * r mod p
    */
    ref const(BigInt) getARep() const { return m_repr.getARep(); }

    /**
    * Returns: b * r mod p
    */
    ref const(BigInt) getBRep() const { return m_repr.getBRep(); }

    void toRep()(ref BigInt x, SecureVector!word* ws) const
    { 
        m_repr.toCurveRep(x, *ws); 
    }
    
    void fromRep(ref BigInt x, SecureVector!word* ws) const 
    { 
        m_repr.fromCurveRep(x, *ws);
    }

    BigInt fromRep()(auto const ref BigInt x, SecureVector!word* ws) const
    { 
        BigInt xt = x.dup;
        m_repr.fromCurveRep(xt, *ws);
        return xt.move;
    }

    /**
    * swaps the states of this and other, does not throw
    * Params:
    *  other = curve to swap values with
    */
    void swap()(auto ref CurveGFp other)
    {
        .swap(m_repr, other.m_repr);
    }

    /**
    * Equality operator
    * Params:
    *  other = curve to compare with
    * Returns: true iff this is the same curve as other
    */
    bool opEquals(const ref CurveGFp other) const
    {
        return (getP() == other.getP() &&
                  getA() == other.getA() &&
                  getB() == other.getB());
    }

    /**
    * Equality operator
    * Params:
    *  rhs = a curve
    * Returns: true iff lhs is not the same as rhs
    */
    int opCmp(ref CurveGFp rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

    @property CurveGFp dup() const {
        return CurveGFp(getP(), getA(), getB());
    }

    void mul()(ref BigInt z, auto const ref BigInt x, auto const ref BigInt y, SecureVector!word* ws) const
    {
        m_repr.curveMul(z, x, y, *ws);
    }

    BigInt mul()(auto const ref BigInt x, auto const ref BigInt y, SecureVector!word* ws) const
    {
        BigInt z;
        m_repr.curveMul(z, x, y, *ws);
        return z.move;
    }

    void sqr()(auto ref BigInt z, auto const ref BigInt x, SecureVector!word* ws) const
    {
        m_repr.curveSqr(z, x, *ws);
    }

    BigInt sqr()(auto const ref BigInt x, SecureVector!word* ws) const
    {
        BigInt z;
        m_repr.curveSqr(z, x, *ws);
        return z.move;
    }

    @disable this(this);

    string toString() const {
        return toVector()[].idup;
    }

    Vector!char toVector() const {
        return m_repr.toVector();
    }

    ~this() {
    }

    static CurveGFpRepr chooseRepr()(auto const ref BigInt p, auto const ref BigInt a, auto const ref BigInt b)
    {
        return cast(CurveGFpRepr) new CurveGFpMontgomery(p, a, b);
    }

    Unique!CurveGFpRepr m_repr;
}
