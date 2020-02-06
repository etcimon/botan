/**
* Point arithmetic on elliptic curves over GF(p)
*
* Copyright:
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011, 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.ec_gfp.point_gfp;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.constants;
import botan.math.ec_gfp.curve_gfp;
import botan.utils.types;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.math.mp.mp_core;
import std.algorithm : max, swap;
import std.conv : to;
import std.traits : isPointer;
/**
* Exception thrown if you try to convert a zero point to an affine
* coordinate
*/
class IllegalTransformation : Exception
{
    this(in string err = "Requested transformation is not possible")
    {
        super(err);
    }
}

/**
* Exception thrown if some form of illegal point is decoded
*/
class IllegalPoint : Exception
{
    this(in string err = "Malformed ECP point detected") { super(err); }
}


/**
* This class represents one point on a curve of GF(p)
*/
struct PointGFp
{
public:
    alias CompressionType = ubyte;
    enum : CompressionType {
        UNCOMPRESSED      = 0,
        COMPRESSED        = 1,
        HYBRID            = 2
    }

    /**
    * Construct the zero point
    * Params:
    *  curve = The base curve
    */
    this()(auto const ref CurveGFp curve) 
    {
        m_curve = curve.dup;
        m_ws.resize(16);
        m_coord_x = BigInt(0);
        auto b1 = BigInt(1);
        m_coord_y = b1.move;
        m_coord_z = BigInt(0);
        m_curve.toRep(&m_coord_x, m_ws_ref);
        m_curve.toRep(&m_coord_y, m_ws_ref);
        m_curve.toRep(&m_coord_z, m_ws_ref);
    }


    /**
    * Move Constructor
    */
    this()(PointGFp* other)
    {
        m_curve = CurveGFp.init;
        swap(other);
    }

    /**
    * Move Assignment
    */
    ref PointGFp opAssign(PointGFp* other)
    {
        swap(other);
        return this;
    }

    /**
    * Construct a point from its affine coordinates
    * Params:
    *  curve = the base curve
    *  x = affine x coordinate
    *  y = affine y coordinate
    */
    this(const ref CurveGFp curve, const BigInt* x, const BigInt* y)
    { 
		if (*x <= 0 || *x >= curve.getP())
			throw new InvalidArgument("Invalid PointGFp affine x");
		if (*y <= 0 || *y >= curve.getP())
			throw new InvalidArgument("Invalid PointGFp affine y");
        m_curve = curve.dup;
        //m_ws.resize(2 * (curve.getPWords() + 2));
        m_coord_x = x.dup;
        m_coord_y = y.dup;
        auto bi = BigInt(1);
        m_coord_z = bi.move;
        m_curve.toRep(&m_coord_x, m_ws_ref);
        m_curve.toRep(&m_coord_y, m_ws_ref);
        m_curve.toRep(&m_coord_z, m_ws_ref);
    }

    /**
    * += Operator
    * Params:
    *  rhs = the PointGFp to add to the local value
    * Returns: resulting PointGFp
    */
    void opOpAssign(string op)(const ref PointGFp rhs)
        if (op == "+")
    {
        Vector!(RefCounted!BigInt) ws = Vector!(RefCounted!BigInt)(9);

        add(rhs, ws);
    }

    /**
    * -= Operator
    * Params:
    *  rhs = the PointGFp to subtract from the local value
    * Returns: resulting PointGFp
    */
    void opOpAssign(string op)(const ref PointGFp rhs)
        if (op == "-")
    {
        auto tdup = rhs.dup;
        if (isZero()) {
            auto tmp = PointGFp(&tdup).negate();
            this.swap( &tmp );
        } else {
            auto tmp = PointGFp(&tdup).negate();
            this += tmp;
        }
        
    }

    /**
    * *= Operator
    * Params:
    *  scalar = the PointGFp to multiply with this
    * Returns: resulting PointGFp
    */
    void opOpAssign(string op, T)(T scalar)
        if (op == "*" && !isPointer!T)
    {
        import std.traits : isNumeric;
        static if (isNumeric!T)
            this.swap(this * BigInt(scalar));
        else this.swap(this * &scalar);
    }

    /**
    * Multiplication Operator
    * Params:
    *  scalar = the scalar value
    * Returns: scalar*point on the curve
    */
    PointGFp opBinary(string op, T)(T scalar) const
        if (op == "*")
    {
        const PointGFp* point = &this;
        
        if (scalar.isZero()) {
            return PointGFp(point.getCurve()); // zero point
        }
        Vector!(RefCounted!BigInt) ws = Vector!(RefCounted!BigInt)(9);
		if (scalar.abs() <= 2) // special cases for small values
		{
		    ubyte value = scalar.abs().byteAt(0);
		    
		    PointGFp result = point.dup;
	    
		    if (value == 2)
			        result.mult2(ws);
		    if (scalar.isNegative())
			        result.negate();
	    
		    return result.move();
		}
        const size_t scalar_bits = scalar.bits();

        
        PointGFp x1 = PointGFp(m_curve);
        PointGFp x2 = point.dup;
        
        size_t bits_left = scalar_bits;
        
        // Montgomery Ladder
        while (bits_left)
        {
            const bool bit_set = scalar.getBit(bits_left - 1);
            
            if (bit_set)
            {
                x1.add(x2, ws);
                x2.mult2(ws);
            }
            else
            {
                x2.add(x1, ws);
                x1.mult2(ws);
            }
            
            --bits_left;
        }
        
        if (scalar.isNegative())
            x1.negate();
        
        return x1.move;
      
    }

    /**
    * Multiexponentiation
    * Params:
    *  p1 = a point
    *  z1 = a scalar
    *  p2 = a point
    *  z2 = a scalar
    * Returns: (p1 * z1 + p2 * z2)
    */
    static PointGFp multiExponentiate(const ref PointGFp p1, const BigInt* z1,
                                      const ref PointGFp p2, const BigInt* z2)
    {
        const PointGFp p3 = p1 + p2;
        
        PointGFp H = PointGFp(p1.m_curve); // create as zero
        size_t bits_left = max(z1.bits(), z2.bits());
        
        Vector!(RefCounted!BigInt) ws = Vector!(RefCounted!BigInt)(9);
        logTrace("got ws with capacity: ", ws.capacity.to!string);
        while (bits_left)
        {
            H.mult2(ws);
            const bool z1_b = z1.getBit(bits_left - 1);
            const bool z2_b = z2.getBit(bits_left - 1);
            
            if (z1_b == true && z2_b == true)
                H.add(p3, ws);
            else if (z1_b)
                H.add(p1, ws);
            else if (z2_b)
                H.add(p2, ws);
            
            --bits_left;
        }
        
        if (z1.isNegative() != z2.isNegative())
            H.negate();
        
        return H.move();
    }

    /**
    * Negate this point
    * Returns: this
    */
    PointGFp negate()
    {
        if (!isZero())
            m_coord_y = m_curve.getP() - m_coord_y;
        return this.dup;
    }

    /**
    * Return base curve of this point
    * Returns: the curve over GF(p) of this point
    */
    ref const(CurveGFp) getCurve() const { return m_curve; }

    /**
    * get affine x coordinate
    * Returns: affine x coordinate
    */
    BigInt getAffineX() const
    {
        if (isZero())
            throw new IllegalTransformation("Cannot convert zero point to affine");
                
        BigInt z2 = curveSqr(cast(BigInt*)&m_coord_z);
        m_curve.fromRep(&z2, m_ws_const.move());
        auto p = m_curve.getP().dup;
        z2 = inverseMod(&z2, &p);
        
        return curveMult(&z2, cast(BigInt*)&m_coord_x);
    }

    /**
    * get affine y coordinate
    * Returns: affine y coordinate
    */
    BigInt getAffineY() const
    {
        if (isZero())
            throw new IllegalTransformation("Cannot convert zero point to affine");
                
        auto sqr_1 = curveSqr(&m_coord_z);
        BigInt z3 = curveMult(&m_coord_z, &sqr_1);
        z3 = inverseMod(&z3, &m_curve.getP());
        m_curve.toRep(&z3, m_ws_const.move());
        return curveMult(&z3, &m_coord_y);
    }

    /**
    * Is this the point at infinity?
    * Returns: true, if this point is at infinity, false otherwise.
    */
    bool isZero() const
    { return (m_coord_x.isZero() && m_coord_z.isZero()); }

    /**
    * Checks whether the point is to be found on the underlying
    * curve; used to prevent fault attacks.
    * Returns: if the point is on the curve
    */
    bool onTheCurve() const
    {
        /*
        Is the point still on the curve?? (If everything is correct, the
        point is always on its curve; then the function will return true.
        If somehow the state is corrupted, which suggests a fault attack
        (or internal computational error), then return false.
        */
        if (isZero()) {
            return true;
        }

        auto y2 = cast(BigInt)curveSqr(&m_coord_y);
        m_curve.fromRep(&y2, m_ws_const.move());
        auto x3_0 = curveSqr(&m_coord_x);
        BigInt x3 = curveMult(&m_coord_x, &x3_0);        
        BigInt ax = curveMult(&m_coord_x, &m_curve.getARep());        
        BigInt z2 = curveSqr(&m_coord_z);
        
        if (m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
        {
            auto y2_0 = x3 + ax + m_curve.getBRep();
            m_curve.fromRep(&y2_0, m_ws_const.move());
            if (y2 != y2_0) {
                return false;
            }
        }
        
        BigInt z3 = curveMult(&m_coord_z, &z2);  
        auto z2_sqr = curveSqr(&z2);      
        BigInt ax_z4 = curveMult(&ax, &z2_sqr);
        auto z3_sqr = curveSqr(&z3);
        BigInt b_z6 = curveMult(&m_curve.getBRep(), &z3_sqr);
        auto y2_1 = x3 + ax_z4 + b_z6;
        m_curve.fromRep(&y2_1, m_ws_const.move());
        if (y2 != y2_1) {
            return false;
        }
        return true;
    }


    /**
    * swaps the states of this and other, does not throw!
    * Params:
    *  other = the object to swap values with
    */
    void swap(PointGFp* other)
    {
        m_curve.swap(&other.m_curve);
        m_coord_x.swap(&other.m_coord_x);
        m_coord_y.swap(&other.m_coord_y);
        m_coord_z.swap(&other.m_coord_z);
        //import std.algorithm.mutation : swap;
        m_ws.swap(other.m_ws);
    }
    
    void swap(T)(T other)
        if (!isPointer!T)
    {
        this.swap(&other);
    }

    @property PointGFp dup() const
    {
        auto point = PointGFp(m_curve);
        point.m_coord_x = m_coord_x.dup;
        point.m_coord_y = m_coord_y.dup;
        point.m_coord_z = m_coord_z.dup;
        point.m_ws = m_ws.dup;
        return point;
    }

    /**
    * Equality operator
    */
    bool opEquals(const ref PointGFp other) const
    {
        if (getCurve() != other.getCurve())
            return false;
        
        // If this is zero, only equal if other is also zero
        if (isZero())
            return other.isZero();

        return (getAffineX() == other.getAffineX() &&
                getAffineY() == other.getAffineY());
    }

private:
    
    /**
    * Montgomery multiplication/reduction
    * Params:
    *   x = first multiplicand
    *   y = second multiplicand
    */
    BigInt curveMult()(const(BigInt)* x, const(BigInt*) y) const
    {
        BigInt z = BigInt(0);
        m_curve.mul(&z, x, y, m_ws_const.move());
        return z.move();
    }
    
    /**
    * Montgomery multiplication/reduction
    * Params:
    *   z = output
    *   x = first multiplicand
    *   y = second multiplicand
    */
    void curveMult()(BigInt* z, const(BigInt)* x, const(BigInt*) y) const
    {
        m_curve.mul(z, x, y, m_ws_const.move());
    }

    /**
    * Montgomery squaring/reduction
    * Params:
    *   x = multiplicand
    */
    BigInt curveSqr()(const(BigInt)* x) const
    {
        BigInt z;
        m_curve.sqr(&z, x, m_ws_const.move());
        return z.move();
    }

    /**
    * Montgomery squaring/reduction
    * Params:
    *   z = output
    *   x = multiplicand
    */
    void curveSqr(T, U)(T* z, U* x) const
        if (!isPointer!T && !isPointer!U)
    {
        m_curve.sqr(z, x, m_ws_const.move());
    }

    /**
    * Point addition
    * Params:
    *  workspace = temp space, at least 11 elements
    */
    void add(const ref PointGFp rhs, ref Vector!(RefCounted!BigInt) ws_bn)
    {
        if (isZero())
        {
            m_coord_x = rhs.m_coord_x.dup;
            m_coord_y = rhs.m_coord_y.dup;
            m_coord_z = rhs.m_coord_z.dup;
            return;
        }
        else if (rhs.isZero())
            return;
        const BigInt* p = &m_curve.getP();
        auto rhs_z = cast(BigInt*) &rhs.m_coord_z;
        auto rhs_z2 = cast(BigInt*)&*(ws_bn[0]);
        auto U1 = cast(BigInt*) &*(ws_bn[1]);
        auto S1 = cast(BigInt*) &*(ws_bn[2]);
        
        auto lhs_z2 = cast(BigInt*) &*(ws_bn[3]);
        auto U2 = cast(BigInt*) &*(ws_bn[4]);
        auto S2 = cast(BigInt*) &*(ws_bn[5]);
        
        auto H = cast(BigInt*) &*(ws_bn[6]);
        auto r = cast(BigInt*) &*(ws_bn[7]);
        *U2 = BigInt(0);
        curveSqr(rhs_z2, &rhs.m_coord_z);
        curveMult(U1, &m_coord_x, rhs_z2);
        auto mult_0 = curveMult(&rhs.m_coord_z, rhs_z2);
        curveMult(S1, &m_coord_y, &mult_0);
        
        curveSqr(lhs_z2, &m_coord_z);
        curveMult(U2, &rhs.m_coord_x, lhs_z2);
        auto mult_1 = curveMult(&m_coord_z, lhs_z2);
        curveMult(S2, &rhs.m_coord_y, &mult_1);
        
        *H = U2.dup;
        *H -= *U1;

        if (H.isNegative())
            *H += *p;
        
        *r = S2.dup;
        *r -= *S1;
        if (r.isNegative())
            *r += *p;
        
        if (H.isZero())
        {
            if (r.isZero())
            {
                mult2(ws_bn);
                return;
            }
            
            this.swap( PointGFp(m_curve) ); // setting myself to zero
            return;
        }
        
        curveSqr(U2, H);
        
        curveMult(S2, U2, H);
        
        *U2 = curveMult(U1, U2);
        
        curveSqr(&m_coord_x, r);
        m_coord_x -= *S2;
        m_coord_x -= (*U2 << 1);
        while (m_coord_x.isNegative())
            m_coord_x += *p;
        
        *U2 -= m_coord_x;
        if (U2.isNegative())
            *U2 += *p;
        
        curveMult(&m_coord_y, r, U2);
        m_coord_y -= curveMult(S1, S2);
        if (m_coord_y.isNegative())
            m_coord_y += *p;
        
        auto mult_3 = curveMult(&m_coord_z, rhs_z);
        curveMult(&m_coord_z, &mult_3, H);
    }


    /**
    * Point doubling
    * Params:
    *  workspace = temp space, at least 9 elements
    */
    void mult2(ref Vector!(RefCounted!BigInt) ws_bn)
    {
        if (isZero())
            return;
        else if (m_coord_y.isZero())
        {
            this = PointGFp(m_curve); // setting myself to zero
            return;
        }
        const BigInt* p = &m_curve.getP();
        logTrace("");
        auto y_2 = cast(BigInt*) &*(ws_bn[0]);
        auto S = cast(BigInt*) &*(ws_bn[1]);
        auto z4 = cast(BigInt*) &*(ws_bn[2]);
        auto a_z4 = cast(BigInt*) &*(ws_bn[3]);
        auto M = cast(BigInt*) &*(ws_bn[4]);
        auto U = cast(BigInt*) &*(ws_bn[5]);
        auto x = cast(BigInt*) &*(ws_bn[6]);
        auto y = cast(BigInt*) &*(ws_bn[7]);
        auto z = cast(BigInt*) &*(ws_bn[8]);
        
        curveSqr(y_2, &m_coord_y);
        
        curveMult(S, &m_coord_x, y_2);
        *S <<= 2; // * 4
        while (*S >= *p)
            *S -= *p;
        
        auto sqr_1 = cast(BigInt) curveSqr(&m_coord_z);
        curveSqr(z4, &sqr_1);
        auto a_rep = m_curve.getARep().dup;
        curveMult(a_z4, &a_rep, z4);
        
        *M = curveSqr(&m_coord_x);
        *M *= 3;
        *M += *a_z4;
        while (*M >= *p)
            *M -= *p;
        
        curveSqr(x, M);
        *x -= (*S << 1);
        while (x.isNegative())
            *x += *p;
        
        curveSqr(U, y_2);
        *U <<= 3;
        while (*U >= *p)
            *U -= *p;
        
        *S -= *x;
        while (S.isNegative())
            *S += *p;
        
        curveMult(y, M, S);
        *y -= *U;
        if (y.isNegative())
            *y += *p;
        
        curveMult(z, &m_coord_y, &m_coord_z);
        *z <<= 1;
        if (*z >= *p)
            *z -= *p;
        
        m_coord_x = (*x).dup;
        m_coord_y = (*y).dup;
        m_coord_z = (*z).dup;
        
    }
public:
    // relational operators
    int opCmp(const ref PointGFp rhs) const
    {
        if  (this == rhs) return 0;
        else return -1;
    }
    
    // arithmetic operators
    PointGFp opUnary(string op)() const
        if (op == "-")
    {
        PointGFp ret = this.dup;
        return ret.negate().dup;
    }
    
    PointGFp opBinary(string op)(auto const ref PointGFp rhs) const
        if (op == "+")
    {
        PointGFp ret = this.dup;
        ret += rhs;
        return ret;
    }
    
    PointGFp opBinary(string op)(auto const ref PointGFp rhs) const
        if (op == "-")
    {
        PointGFp ret = this.dup;
        ret -= rhs;
        return ret;
    }
    
    PointGFp opBinary(string op)(auto const ref PointGFp point) const
        if (op == "*")
    {
        PointGFp ret = this.dup;
        ret *= point;
        return ret;
    }

    @disable this(this);

    public Vector!char toVector() const {
        Vector!char ret;
        ret ~= "m_curve: ";
        ret ~= m_curve.toVector()[];
        ret ~= "\nm_coord_x: ";
        ret ~= m_coord_x.toVector()[];
        ret ~= "\nm_coord_y: ";
        ret ~= m_coord_y.toVector()[];
        ret ~= "\nm_coord_z: ";
        ret ~= m_coord_z.toVector()[];
        ret ~= "\nm_ws: ";
        ret ~= m_ws.ptr[0 .. m_ws.length].to!string;
        return ret.move;
    }

    public string toString() const {
        return toVector()[].idup;
    }

    public PointGFp move() {
        return PointGFp(&this);
    }

    CurveGFp m_curve;
    BigInt m_coord_x, m_coord_y, m_coord_z;
    SecureVector!word m_ws; // workspace for Montgomery
    @property ref SecureVector!word m_ws_ref() { return m_ws; }
    @property SecureVector!word m_ws_const() const { return m_ws.dup; }
    alias mutable = SecureVector!word*;
}

// encoding and decoding
SecureVector!ubyte EC2OSP(const ref PointGFp point, ubyte format)
{
    if (point.isZero())
        return SecureVector!ubyte(1); // single 0 ubyte
    
    const size_t p_bytes = point.getCurve().getP().bytes();
    
    BigInt x = point.getAffineX();
    BigInt y = point.getAffineY();
    
    SecureVector!ubyte bX = BigInt.encode1363(x, p_bytes);
    SecureVector!ubyte bY = BigInt.encode1363(y, p_bytes);
    
    if (format == PointGFp.UNCOMPRESSED)
    {
        SecureVector!ubyte result;
        result.pushBack(0x04);
        
        result ~= bX[];
        result ~= bY[];
        
        return result.move();
    }
    else if (format == PointGFp.COMPRESSED)
    {
        SecureVector!ubyte result;
        result.pushBack(0x02 | cast(ubyte)(y.getBit(0)));
        
        result ~= bX[];
        
        return result.move();
    }
    else if (format == PointGFp.HYBRID)
    {
        SecureVector!ubyte result;
        result.pushBack(0x06 | cast(ubyte)(y.getBit(0)));
        
        result ~= bX[];
        result ~= bY[];
        
        return result.move();
    }
    else
        throw new InvalidArgument("EC2OSP illegal point encoding");
}

PointGFp OS2ECP()(const(ubyte)* data, size_t data_len, auto const ref CurveGFp curve)
{
    if (data_len <= 1) {
        return PointGFp(curve); // return zero
    }
    const ubyte pc = data[0];
    BigInt x, y;
    
    if (pc == 2 || pc == 3)
    {
        //compressed form
        x = BigInt.decode(&data[1], data_len - 1);
        
        const bool y_mod_2 = ((pc & 0x01) == 1);
        y = decompressPoint(y_mod_2, &x, curve);
    }
    else if (pc == 4)
    {
        const size_t l = (data_len - 1) / 2;
        
        // uncompressed form
        x = BigInt.decode(&data[1], l);
        y = BigInt.decode(&data[l+1], l);
    }
    else if (pc == 6 || pc == 7)
    {
        const size_t l = (data_len - 1) / 2;
        
        // hybrid form
        x = BigInt.decode(&data[1], l); 
        y = BigInt.decode(&data[l+1], l);
        
        const bool y_mod_2 = ((pc & 0x01) == 1);
        
        if (decompressPoint(y_mod_2, &x, curve) != y)
            throw new IllegalPoint("OS2ECP: Decoding error in hybrid format");
    }
    else
        throw new InvalidArgument("OS2ECP: Unknown format type " ~ to!string(pc));
    PointGFp result = PointGFp(curve, &x, &y);
    if (!result.onTheCurve())
        throw new IllegalPoint("OS2ECP: Decoded point was not on the curve");
    return result.move();
}

PointGFp OS2ECP(Alloc)(auto const ref Vector!( ubyte, Alloc ) data, auto const ref CurveGFp curve)
{ return OS2ECP(data.ptr, data.length, curve); }

private:

BigInt decompressPoint(bool yMod2,
                       BigInt* x,
                       const ref CurveGFp curve)
{
    BigInt xpow3 = *x * x;
    xpow3 *= x;
    const BigInt* p = &curve.getP();

    BigInt g = curve.getA() * x;
    g += xpow3;
    g += curve.getB();
    g = g % (*p);
    
    BigInt z = ressol(&g, p);
    
    if (z < 0)
        throw new IllegalPoint("error during EC point decompression");
    
    if (z.getBit(0) != yMod2)
        z = *p - z;
    return z;
}
