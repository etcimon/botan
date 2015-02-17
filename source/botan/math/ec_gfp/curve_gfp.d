/**
* Elliptic curves over GF(p)
*
* Copyright:
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010-2011,2012 Jack Lloyd
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
import std.algorithm : swap;
import botan.constants;
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

    /**
    * Returns: curve coefficient a
    */
    ref const(BigInt) getA() const { return m_a; }

    /**
    * Returns: curve coefficient b
    */
    ref const(BigInt) getB() const { return m_b; }

    /**
    * Get prime modulus of the field of the curve
    * Returns: prime modulus of the field of the curve
    */
    ref const(BigInt) getP() const { return m_p; }

    /**
    * Returns: Montgomery parameter r^2 % p
    */
    ref const(BigInt) getR2() const { return m_r2; }

    /**
    * Returns: a * r mod p
    */
    ref const(BigInt) getAR() const { return m_a_r; }

    /**
    * Returns: b * r mod p
    */
    ref const(BigInt) getBR() const { return m_b_r; }

    /**
    * Returns: Montgomery parameter p-dash
    */
    word getPDash() const { return m_p_dash; }

    /**
    * Returns: p.sigWords()
    */
    size_t getPWords() const { return m_p_words; }

    /**
    * swaps the states of this and other, does not throw
    * Params:
    *  other = curve to swap values with
    */
    void swap()(auto ref CurveGFp other)
    {
        m_p.swap(other.m_p);
        m_a.swap(other.m_a);
        m_b.swap(other.m_b);
        m_a_r.swap(other.m_a_r);
        m_b_r.swap(other.m_b_r);
        m_p_words = other.m_p_words;
        m_r2.swap(other.m_r2);
        m_p_dash = other.m_p_dash;
    }

    /**
    * Equality operator
    * Params:
    *  other = curve to compare with
    * Returns: true iff this is the same curve as other
    */
    bool opEquals(const ref CurveGFp other) const
    {
        return (m_p == other.m_p &&
                  m_a == other.m_a &&
                  m_b == other.m_b);
    }

    /**
    * Equality operator
    * Params:
    *  lhs = a curve
    *  rhs = a curve
    * Returns: true iff lhs is not the same as rhs
    */
    int opCmp(ref CurveGFp rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

    @property CurveGFp dup() const {
        return CurveGFp(m_p, m_a, m_b);
    }



    @disable this(this);

    string toString() const {
        return toVector()[].idup;
    }

    Vector!ubyte toVector() const {
        Vector!ubyte ret;
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

    ~this() {
    }

    // Curve parameters
    BigInt m_p, m_a, m_b;
    
    size_t m_p_words; // cache of m_p.sigWords()
    
    // Montgomery parameters
    BigInt m_r2, m_a_r, m_b_r;
    word m_p_dash;

}
