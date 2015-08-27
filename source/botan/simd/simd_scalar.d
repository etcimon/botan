/**
* Scalar emulation of SIMD
* 
* Copyright:
* (C) 2009,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.simd.simd_scalar;

import botan.constants;
static if (BOTAN_HAS_SIMD_SCALAR):
import botan.utils.loadstor;
import botan.utils.bswap;
import botan.utils.rotate;

/**
* Fake SIMD, using plain scalar operations
* Often still faster than iterative on superscalar machines
*/
struct SIMDScalar(T, size_t N)
{
public:
    static bool enabled() { return true; }

    static size_t size() { return N; }

    this(in T[N] B)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = B[i];
    }

    this(T B)
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = B;
    }

    static SIMDScalar!(T, N) loadLittleEndian(in void* input)
    {
        SIMDScalar!(T, N) output;
        const(ubyte)* in_b = cast(const(ubyte)*)(input);

        for (size_t i = 0; i != size(); ++i)
            output.m_v[i] = .loadLittleEndian!T(in_b, i);

        return output;
    }

    static SIMDScalar!(T, N) loadBigEndian(in void* input)
    {
        SIMDScalar!(T, N) output;
        const(ubyte)* in_b = cast(const(ubyte)*)(input);

        for (size_t i = 0; i != size(); ++i)
            output.m_v[i] = .loadBigEndian!T(in_b, i);

        return output;
    }

    void storeLittleEndian(ubyte* output)
    {
        for (size_t i = 0; i != size(); ++i)
            .storeLittleEndian(m_v[i], output + i*T.sizeof);
    }

    void storeBigEndian(ubyte* output)
    {
        for (size_t i = 0; i != size(); ++i)
            .storeBigEndian(m_v[i], output + i*T.sizeof);
    }

    void rotateLeft(int rot)()
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = .rotateLeft(m_v[i], rot);
    }

    void rotateRight(int rot)()
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] = .rotateRight(m_v[i], rot);
    }

    void opOpAssign(string op)(in SIMDScalar!(T, N) other)
        if (op == "+")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] += other.m_v[i];
    }

    void opOpAssign(string op)(in SIMDScalar!(T, N) other)
        if (op == "-")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] -= other.m_v[i];
    }

    SIMDScalar!(T, N) opBinary(string op)(in SIMDScalar!(T, N) other)
        if (op == "+")
    {
        this += other;
        return this;
    }

    SIMDScalar!(T, N) opBinary(string op)(in SIMDScalar!(T, N) other)
        if (op == "-")
    {
        this -= other;
        return this;
    }

    void opOpAssign(string op)(in SIMDScalar!(T, N) other)
        if (op == "^")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] ^= other.m_v[i];
    }

    SIMDScalar!(T, N) opBinary(string op)(in SIMDScalar!(T, N) other)
        if (op == "^")
    {
        this ^= other;
        return this;
    }

    void opOpAssign(string op)(in SIMDScalar!(T, N) other)
        if (op == "|")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] |= other.m_v[i];
    }

    void opOpAssign(string op)(in SIMDScalar!(T, N) other)
        if (op == "&")
    {
        for (size_t i = 0; i != size(); ++i)
            m_v[i] &= other.m_v[i];
    }

    SIMDScalar!(T, N) opBinary(string op)(in SIMDScalar!(T, N) other)
        if (op == "&")
    {
        SIMDScalar!(T, N) ret;
        ret &= other;
        return ret;
    }

    SIMDScalar!(T, N) lshift(size_t shift)()
    {
        SIMDScalar!(T, N) ret;
        ret.m_v = m_v;
        for (size_t i = 0; i != size(); ++i)
            ret.m_v[i] <<= shift;
        return ret;
    }

    SIMDScalar!(T, N) rshift(size_t shift)()
    {
        SIMDScalar!(T, N) ret;
        ret.m_v = m_v;
        for (size_t i = 0; i != size(); ++i)
            ret.m_v[i] >>= shift;
        return ret;
    }

    SIMDScalar!(T, N) opUnary(string op)()
        if (op == "~")
    {
        SIMDScalar!(T, N) ret;
        for (size_t i = 0; i != size(); ++i)
            ret.m_v[i] = ~m_v[i];
        return ret;
    }

    // (~reg) & other
    SIMDScalar!(T, N) andc(in SIMDScalar!(T, N) other)
    {
        SIMDScalar!(T, N) ret;
        for (size_t i = 0; i != size(); ++i)
            ret.m_v[i] = (~m_v[i]) & other.m_v[i];
        return ret;
    }

    SIMDScalar!(T, N) bswap()
    {
        SIMDScalar!(T, N) ret;
        for (size_t i = 0; i != size(); ++i)
            ret.m_v[i] = reverseBytes(m_v[i]);
        return ret;
    }

    static void transpose(ref SIMDScalar!(T, N) B0, ref SIMDScalar!(T, N) B1,
                          ref SIMDScalar!(T, N) B2, ref SIMDScalar!(T, N) B3)
    {
        static assert(N == 4, "4x4 transpose");
        SIMDScalar!(T, N) T0 = SIMDScalar!(T, N)([B0.m_v[0], B1.m_v[0], B2.m_v[0], B3.m_v[0]]);
        SIMDScalar!(T, N) T1 = SIMDScalar!(T, N)([B0.m_v[1], B1.m_v[1], B2.m_v[1], B3.m_v[1]]);
        SIMDScalar!(T, N) T2 = SIMDScalar!(T, N)([B0.m_v[2], B1.m_v[2], B2.m_v[2], B3.m_v[2]]);
        SIMDScalar!(T, N) T3 = SIMDScalar!(T, N)([B0.m_v[3], B1.m_v[3], B2.m_v[3], B3.m_v[3]]);

        B0 = T0;
        B1 = T1;
        B2 = T2;
        B3 = T3;
    }

private:
    this(T)(T[] B)
    {
        foreach(i, v; B)
            m_v[i] = v;
    }

    T[N] m_v;
}