/**
* Constant-time helpers (C++ Botan CT::Mask / constant_time_compare)
*
* Copyright:
* (C) 2010 Falko Strenzke
* (C) 2015,2016,2018,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.ct;

import botan.constants;
import std.traits : isUnsigned, Unqual;

/// Block the compiler from reasoning about `x` (C++ CT::value_barrier).
/// Identity when `BOTAN_HAS_CT` is false (default / `No_CT`).
Unqual!T ctValueBarrier(T)(T x)
    if (isUnsigned!(Unqual!T))
{
    static if (BOTAN_HAS_CT)
    {
        import core.volatile : volatileLoad, volatileStore;
        alias U = Unqual!T;
        U tmp = void;
        volatileStore(&tmp, cast(U) x);
        return volatileLoad(&tmp);
    }
    else
        return cast(Unqual!T) x;
}

/// If the top bit of `a` is set, return all-1, else all-0.
T ctExpandTopBit(T)(T a)
    if (isUnsigned!T)
{
    const T top = ctValueBarrier(cast(T)(a >> (T.sizeof * 8 - 1)));
    return cast(T)(0 - top);
}

/// If `x` is 0 return all-1, else all-0.
T ctIsZero(T)(T x)
    if (isUnsigned!T)
{
    x = ctValueBarrier(x);
    return ctExpandTopBit(cast(T)(~x & (x - 1)));
}

/// If `mask` is all-1 return `a`, if all-0 return `b`.
T ctChoose(T)(T mask, T a, T b)
    if (isUnsigned!T)
{
    return cast(T)(b ^ (mask & (a ^ b)));
}

/**
* Mask that is either all-0 or all-1.
* When `BOTAN_HAS_CT` (`version(CT)`), arithmetic only (no data-dependent branches).
* Default / `No_CT`: ordinary compares / branches for speed.
*/
struct CTMask(T)
    if (isUnsigned!T && !is(T == bool))
{
    private T m_mask;

    this(T v)
    {
        static if (BOTAN_HAS_CT)
            m_mask = ctValueBarrier(v);
        else
            m_mask = v;
    }

    T value() const
    {
        static if (BOTAN_HAS_CT)
            return ctValueBarrier(m_mask);
        else
            return m_mask;
    }

    static CTMask set() { return CTMask(cast(T)~cast(T)0); }
    static CTMask cleared() { return CTMask(0); }

    static CTMask isZero(T x)
    {
        static if (BOTAN_HAS_CT)
            return CTMask(ctIsZero(x));
        else
            return x == 0 ? set() : cleared();
    }

    static CTMask isEqual(T x, T y)
    {
        static if (BOTAN_HAS_CT)
            return isZero(cast(T)(ctValueBarrier(x) ^ ctValueBarrier(y)));
        else
            return x == y ? set() : cleared();
    }

    /// Set if `v != 0`.
    static CTMask expand(T v)
    {
        static if (BOTAN_HAS_CT)
            return CTMask(cast(T)~ctIsZero(ctValueBarrier(v)));
        else
            return v != 0 ? set() : cleared();
    }

    static CTMask expandTopBit(T v) { return CTMask(ctExpandTopBit(v)); }

    static CTMask isLt(T x, T y)
    {
        static if (BOTAN_HAS_CT)
        {
            T u = cast(T)(x ^ ((x ^ y) | ((x - y) ^ x)));
            return expandTopBit(u);
        }
        else
            return x < y ? set() : cleared();
    }

    static CTMask isGt(T x, T y) { return isLt(y, x); }
    static CTMask isLte(T x, T y) { return CTMask(cast(T)~isGt(x, y).value()); }
    static CTMask isGte(T x, T y) { return CTMask(cast(T)~isLt(x, y).value()); }

    /// Set if `l <= v <= u` (C++ `CT::Mask::is_within_range`).
    static CTMask isWithinRange(T v, T l, T u)
    {
        static if (BOTAN_HAS_CT)
        {
            const T v_lt_l = cast(T)(v ^ ((v ^ l) | ((v - l) ^ v)));
            const T v_gt_u = cast(T)(u ^ ((u ^ v) | ((u - v) ^ u)));
            const T either = ctValueBarrier(v_lt_l) | ctValueBarrier(v_gt_u);
            return CTMask(cast(T)~ctExpandTopBit(either));
        }
        else
            return (v >= l && v <= u) ? set() : cleared();
    }

    /// Set if `v` equals any element of `accepted` (C++ `CT::Mask::is_any_of`).
    static CTMask isAnyOf(T v, const(T)[] accepted)
    {
        static if (BOTAN_HAS_CT)
        {
            T accept = 0;
            foreach (a; accepted)
            {
                const T diff = cast(T)(a ^ v);
                const T eq_zero = ctValueBarrier(cast(T)(~diff & (diff - 1)));
                accept |= eq_zero;
            }
            return expandTopBit(accept);
        }
        else
        {
            foreach (a; accepted)
                if (a == v)
                    return set();
            return cleared();
        }
    }

    CTMask opUnary(string op)() const if (op == "~")
    {
        return CTMask(cast(T)~value());
    }

    CTMask opBinary(string op)(const CTMask o) const if (op == "&")
    {
        return CTMask(value() & o.value());
    }

    CTMask opBinary(string op)(const CTMask o) const if (op == "|")
    {
        return CTMask(value() | o.value());
    }

    T ifSetReturn(T x) const
    {
        static if (BOTAN_HAS_CT)
            return value() & x;
        else
            return m_mask ? x : 0;
    }
    T ifNotSetReturn(T x) const
    {
        static if (BOTAN_HAS_CT)
            return cast(T)(~value() & x);
        else
            return m_mask ? 0 : x;
    }
    T select(T x, T y) const
    {
        static if (BOTAN_HAS_CT)
            return ctChoose(value(), x, y);
        else
            return m_mask ? x : y;
    }
    bool asBool() const { return value() != 0; }
}

/// Widen a ubyte mask to size_t (all-0 or all-1).
CTMask!size_t ctExpandU8(CTMask!ubyte m)
{
    return CTMask!size_t(cast(size_t)~ctIsZero!size_t(m.value()));
}

/// Equal-length compare; `len` is the number of bytes.
bool constantTimeCompare(const(ubyte)* x, const(ubyte)* y, size_t len)
{
    static if (BOTAN_HAS_CT)
    {
        ubyte difference = 0;
        foreach (i; 0 .. len)
            difference = cast(ubyte)(difference | (x[i] ^ y[i]));
        difference = ctValueBarrier(difference);
        return CTMask!ubyte.isZero(difference).asBool();
    }
    else
    {
        foreach (i; 0 .. len)
            if (x[i] != y[i])
                return false;
        return true;
    }
}

/// Compare ranges; unequal lengths are not equal (length is not secret).
bool constantTimeCompare(const(ubyte)[] x, const(ubyte)[] y)
{
    static if (BOTAN_HAS_CT)
    {
        const size_t min_size = CTMask!size_t.isLte(x.length, y.length).select(x.length, y.length);
        const auto equal_size = CTMask!size_t.isEqual(x.length, y.length);
        ubyte difference = 0;
        foreach (i; 0 .. min_size)
            difference = cast(ubyte)(difference | (x[i] ^ y[i]));
        difference = ctValueBarrier(difference);
        const auto equal_content = ctExpandU8(CTMask!ubyte.isZero(difference));
        return (equal_content & equal_size).asBool();
    }
    else
    {
        if (x.length != y.length)
            return false;
        return constantTimeCompare(x.ptr, y.ptr, x.length);
    }
}

/**
* Wipe memory so the compiler should not elide the stores (C++ secure_scrub_memory).
*/
void secureScrubMemory(void* ptr, size_t n)
{
    if (!ptr || !n)
        return;
    import core.volatile : volatileStore;
    auto p = cast(ubyte*) ptr;
    foreach (i; 0 .. n)
        volatileStore(p + i, cast(ubyte)0);
}

static if (BOTAN_HAS_TESTS) unittest
{
    import botan.test;
    size_t fails;
    ubyte[4] a = [1, 2, 3, 4];
    ubyte[4] b = [1, 2, 3, 4];
    ubyte[4] c = [1, 2, 3, 5];
    ubyte[3] d = [1, 2, 3];
    if (!constantTimeCompare(a.ptr, b.ptr, 4))
        ++fails;
    if (constantTimeCompare(a.ptr, c.ptr, 4))
        ++fails;
    if (constantTimeCompare(a[], d[]))
        ++fails;
    if (!constantTimeCompare(a[], b[]))
        ++fails;
    if (!CTMask!ubyte.isEqual(3, 3).asBool())
        ++fails;
    if (CTMask!ubyte.isEqual(3, 4).asBool())
        ++fails;
    if (CTMask!size_t.isLt(5, 3).asBool())
        ++fails;
    if (!CTMask!size_t.isLt(3, 5).asBool())
        ++fails;
    if (CTMask!ubyte.isZero(1).select(9, 7) != 7)
        ++fails;
    if (CTMask!ubyte.expand(1).select(9, 7) != 9)
        ++fails;
    if (!CTMask!ubyte.isWithinRange('M', 'A', 'Z').asBool())
        ++fails;
    if (CTMask!ubyte.isWithinRange('1', 'A', 'Z').asBool())
        ++fails;
    immutable ubyte[4] ws = [' ', '\t', '\n', '\r'];
    if (!CTMask!ubyte.isAnyOf(cast(ubyte)' ', ws[]).asBool())
        ++fails;
    if (CTMask!ubyte.isAnyOf(cast(ubyte)'X', ws[]).asBool())
        ++fails;
    ubyte[8] wipe = 0xAA;
    secureScrubMemory(wipe.ptr, wipe.length);
    foreach (v; wipe)
        if (v != 0)
            ++fails;
    testReport("ct", 14, fails);
    assert(fails == 0);
}
