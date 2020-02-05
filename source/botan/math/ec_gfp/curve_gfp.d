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
import botan.math.ec_gfp.curve_nistp;
import std.algorithm : swap;
import botan.constants;
import memutils.unique;
import std.conv : to;

abstract class CurveGFpRepr
{
public:

    abstract ref const(BigInt) getP() const;
    
    abstract ref const(BigInt) getA() const;
    
    abstract ref const(BigInt) getB() const;

    abstract size_t getPWords() const;

    /// Returns toCurveRep(getA())
    abstract ref const(BigInt) getARep() const;

    /// Returns toCurveRep(getB())
    abstract ref const(BigInt) getBRep() const;

    abstract void toCurveRep(BigInt* x, ref SecureVector!word ws) const;

    abstract void fromCurveRep(BigInt* x, ref SecureVector!word ws) const;

    abstract void curveMul(BigInt* z, const(BigInt)* x, const(BigInt)* y, ref SecureVector!word ws) const;

    abstract void curveSqr(BigInt* z, const(BigInt)* x, ref SecureVector!word ws) const;

    void normalize(BigInt* x, ref SecureVector!word ws, size_t bound) const {
        const(BigInt)* p = &getP();
        
        while(x.isNegative())
            *x += *p;
        
        const size_t p_words = getPWords();
        const word* prime = p.ptr;
        
        x.growTo(p_words + 1);
        
        if (ws.length < p_words + 1)
            ws.resize(p_words + 1);
        
        //FIXME: take into account bound if > 0
        while(true)
        {
            if (bigint_sub3(ws.ptr, x.ptr, p_words, prime, p_words)) // borrow?
                break;
            
            x.swapReg(ws);
        }
    }

    abstract Vector!char toVector() const;

    abstract void swap(CurveGFpRepr);
}

class CurveGFpMontgomery : CurveGFpRepr
{

	static if (BOTAN_HAS_ENGINE_OPENSSL) {
		import deimos.openssl.bn;
		~this() {
			m_p_bn.d = null; m_p_bn.top = cast(int)0;
			m_x_.d = null; m_x_.top = cast(int)0;
			m_y_.d = null; m_y_.top = cast(int)0;
			m_z_.d = null; m_z_.top = cast(int)0;
			BN_free(m_z_);
			BN_free(m_y_);
			BN_free(m_x_);
			BN_free(m_p_bn);
			BN_CTX_free(m_ctx);
			BN_MONT_CTX_free(m_mont);
		}
		BIGNUM* m_z_;
		BIGNUM* m_x_;
		BIGNUM* m_y_;
		BIGNUM* m_p_bn;
		BN_CTX* m_ctx;
		BN_MONT_CTX* m_mont;
	}

    this()(BigInt* p, BigInt* a, BigInt* b)
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
		static if (BOTAN_HAS_ENGINE_OPENSSL) {
			m_z_ = BN_new();
			m_x_ = BN_new();
			m_y_ = BN_new();
			m_p_bn = BN_new();
			m_p_bn.d = cast(BN_ULONG*)m_p.ptr;
			m_p_bn.top = cast(int)m_p.sigWords();
			m_ctx = BN_CTX_new();
			m_mont = BN_MONT_CTX_new();
			BN_MONT_CTX_set(m_mont, m_p_bn, m_ctx);
		}
    }

    override ref const(BigInt) getP() const { return m_p; }

    override ref const(BigInt) getA() const { return m_a; }

    override ref const(BigInt) getB() const { return m_b; }
        
    override ref const(BigInt) getARep() const { return m_a_r; }

    override ref const(BigInt) getBRep() const { return m_b_r; }

    override size_t getPWords() const { return m_p_words; }

    override void toCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        const BigInt tx = x.dup;
        curveMul(x, &tx, &m_r2, ws);
    }

    override void fromCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        const BigInt tx = x.dup;
        BigInt bi = BigInt(1);
        curveMul(x, &tx, &bi, ws);
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
            z.swap(zero);
            return;
        }

		const size_t output_size = 2*m_p_words + 1;
		
		z.growTo(output_size);
		z.clear();

		static if (BOTAN_HAS_ENGINE_OPENSSL) {
			// about 2-3x faster than the optimized botan-math
			CurveGFpMontgomery this_ = cast()this;
			this_.m_x_.neg = cast(int)0;
			this_.m_x_.d = cast(BN_ULONG*)x.ptr;
			this_.m_x_.top = cast(int) x.sigWords();
			this_.m_y_.neg = cast(int)0;
			this_.m_y_.d = cast(BN_ULONG*)y.ptr;
			this_.m_y_.top = cast(int) y.sigWords();
			BN_CTX* ctx_ = BN_CTX_new();
			scope(exit) BN_CTX_free(ctx_);
			BN_mod_mul_montgomery(this_.m_z_, this_.m_x_, this_.m_y_, this_.m_mont, ctx_);
			memcpy(cast(ubyte*)z.mutablePtr(), cast(ubyte*)this_.m_z_.d, cast(ubyte*)(this_.m_z_.top*word.sizeof));
		}
		else {
			ws.resize(2*(m_p_words+2));	        
	        bigint_monty_mul(z.mutablePtr(), output_size,
	            x.ptr, x.length, x.sigWords(),
	            y.ptr, y.length, y.sigWords(),
	            m_p.ptr, m_p_words, m_p_dash,
	            ws.ptr);
		}
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
		const size_t output_size = 2*m_p_words + 1;	
		z.growTo(output_size);
		z.clear();
		static if (BOTAN_HAS_ENGINE_OPENSSL) {
			// about 2-3x faster than the optimized botan-math
			CurveGFpMontgomery this_ = cast()this;
			this_.m_x_.neg = cast(int)0;
			this_.m_x_.d = cast(BN_ULONG*)x.ptr;
			this_.m_x_.top = cast(int) x.sigWords();
			BN_CTX* ctx_ = BN_CTX_new();
			scope(exit) BN_CTX_free(ctx_);
			BN_mod_mul_montgomery(this_.m_z_, this_.m_x_, this_.m_x_, this_.m_mont, ctx_);
			memcpy(cast(ubyte*)z.mutablePtr(), cast(ubyte*)this_.m_z_.d, cast(ubyte*)(this_.m_z_.top*word.sizeof));
		}
		else {
	        ws.resize(2*(m_p_words+2));
	        
	        bigint_monty_sqr(z.mutablePtr(), output_size,
	            x.ptr, x.length, x.sigWords(),
	            m_p.ptr, m_p_words, m_p_dash,
	            ws.ptr);
		}
    }

    override Vector!char toVector() const
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

    override void swap(CurveGFpRepr other_)
    {
        auto other = cast(CurveGFpMontgomery) other_;
        m_p.swap(&other.m_p);
        m_a.swap(&other.m_a);
        m_b.swap(&other.m_b);
        m_r2.swap(&other.m_r2);
        m_a_r.swap(&other.m_a_r);
        m_b_r.swap(&other.m_b_r);
        import std.algorithm.mutation : swap;
        swap(m_p_words, other.m_p_words);
        swap(m_p_dash, other.m_p_dash);
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
    this()(BigInt* p, BigInt* a, BigInt* b)
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

    void toRep()(BigInt* x, SecureVector!word ws) const
    { 
        m_repr.toCurveRep(x, ws); 
    }

    void toRep()(BigInt* x, ref SecureVector!word ws) const
    { 
        m_repr.toCurveRep(x, ws); 
    }
    
    void fromRep(BigInt* x, SecureVector!word ws) const 
    { 
        m_repr.fromCurveRep(x, ws);
    }

    void fromRep(BigInt* x, ref SecureVector!word ws) const 
    { 
        m_repr.fromCurveRep(x, ws);
    }
    
    BigInt fromRep()(const(BigInt)* x, ref SecureVector!word ws) const
    { 
        BigInt xt = x.dup;
        m_repr.fromCurveRep(&xt, ws);
        return xt.move;
    }

    /**
    * swaps the states of this and other, does not throw
    * Params:
    *  other = curve to swap values with
    */
    void swap(T)(T other)
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
        BigInt p = getP().dup;
        BigInt a = getA().dup;
        BigInt b = getB().dup;
        return CurveGFp(&p, &a, &b);
    }

    // TODO: fromRep taking && ref

    void mul()(BigInt* z, const(BigInt)* x, const(BigInt*) y, SecureVector!word ws) const
    {
        m_repr.curveMul(z, x, y, ws);
    }

    BigInt mul()(const(BigInt)* x, const(BigInt*) y, SecureVector!word ws) const
    {
        BigInt z;
        m_repr.curveMul(z, x, y, ws);
        return z.move;
    }

    void sqr()(BigInt* z, const(BigInt)* x, SecureVector!word ws) const
    {
        m_repr.curveSqr(z, x, ws);
    }

    BigInt sqr()(const(BigInt)* x, SecureVector!word ws) const
    {
        BigInt z;
        m_repr.curveSqr(z, x, ws);
        return z.move;
    }

    /**
     * Adjust x to be in [0,p)
     * @param bound if greater than zero, assume that no more than bound
     * additions or subtractions are required to move x into range.
     */
    void normalize(BigInt* x, ref SecureVector!word ws, size_t bound = 0) const
    {
        m_repr.normalize(x, ws, bound);
    }

    @disable this(this);

    string toString() const {
        return toVector()[].idup;
    }

    Vector!char toVector() const {
        return m_repr.toVector();
    }

    static CurveGFpRepr chooseRepr()(BigInt* p, BigInt* a, BigInt* b)
    {
        //if (p == CurveGFpP521.prime)
        //    return cast(CurveGFpRepr) new CurveGFpP521(a, b);
        return cast(CurveGFpRepr) new CurveGFpMontgomery(p, a, b);
    }

    Unique!CurveGFpRepr m_repr;
}
