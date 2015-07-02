/**
* A minimal 128-bit integer type for curve25519-donna
*
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.donna128;

import botan.utils.mul128;

struct donna128
{
public:
	this(ulong ll = 0, ulong hh = 0) { l = ll; h = hh;}

	donna128 opBinary(string op)(size_t shift)
		if (op == ">>")
	{
		donna128 z = this;
		const ulong carry = z.h << (64 - shift);
		z.h = (z.h >> shift);
		z.l = (z.l >> shift) | carry;
		return z;
	}

	donna128 opBinary(string op)(size_t shift)
		if (op == "<<")
	{
		donna128 z = this;
		const ulong carry = z.l >> (64 - shift);
		z.l = (z.l << shift);
		z.h = (z.h << shift) | carry;
		return z;
	}

	ulong opBinary(string op)(ulong mask)
		if (op == "&")
	{
		return l & mask;
	}

	ulong opOpAssign(string op)(ulong mask)
		if (op == "&=")
	{
		h = 0;
		l &= mask;
		return l;
	}

	ref typeof(this) opOpAssign(string op)(auto const ref donna128 x)
		if (op == "+=")
	{
		l += x.l;
		h += (l < x.l);
		h += x.h;
		return this;
	}

	ref typeof(this) opOpAssign(string op)(ulong x)
		if (op == "+=")
	{
		l += x;
		h += (l < x);
		return this;
	}

	donna128 opBinary(string op)(ulong y)
		if (op == "*")
	{
		assert(x.hi() == 0, "High 64 bits of donna128 set to zero during multiply");

		ulong lo = 0, hi = 0;
		mul64x64_128(x.lo(), y, &lo, &hi);
		return donna128(lo, hi);
	}

	donna128 opBinary(string op)(auto const ref y) const
		if (op == "+")
	{
		donna128 z = this;
		z += y;
		return z;
	}

	donna128 opBinary(string op)(ulong y) const
		if (op == "+")
	{
		donna128 z = x;
		z += y;
		return z;
	}

	donna128 opBinary(string op)(auto const ref donna128 y) const
		if (op == "|")
	{
		return donna128(x.lo() | y.lo(), x.hi() | y.hi());
	}

	ulong lo() const { return l;}
	ulong hi() const { return h;}
private:
	ulong h = 0, l = 0;
};


ulong carry_shift(const ref donna128 a, size_t shift)
{
    return (a >> shift).lo();
}

ulong combine_lower(const donna128 a, size_t s1,
                    const donna128 b, size_t s2)
{
    donna128 z = (a >> s1) | (b << s2);
    return z.lo();
}