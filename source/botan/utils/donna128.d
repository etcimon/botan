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
version(LDC)
import ldc.attributes;
else {
	struct optStrategy {
		string strategy;
	}
}
struct donna128
{

@optStrategy("none"):
public:
	void opAssign(donna128 other) {
		this.l = other.l;
		this.h = other.h;
	}

	void opAssign(in ulong other) {
		this.l = other;
	}

	donna128 opBinary(string op)(size_t shift) const
		if (op == ">>")
	{
		donna128 z = this;
		const ulong carry = z.h << (64 - shift);
		z.h = (z.h >> shift);
		z.l = (z.l >> shift) | carry;
		return z;
	}

	donna128 opBinary(string op)(size_t shift) const
		if (op == "<<")
	{
		donna128 z = donna128(l, h);
		const ulong carry = z.l >> (64 - shift);
		z.l = (z.l << shift);
		z.h = (z.h << shift) | carry;
		return z;
	}

	ulong opBinary(string op)(ulong mask) const
		if (op == "&")
	{
		return l & mask;
	}

	ulong opOpAssign(string op)(ulong mask)
		if (op == "&")
	{
		h = 0;
		l &= mask;
		return l;
	}

	donna128 opOpAssign(string op)(auto const ref donna128 x)
		if (op == "+")
	{
		l += x.l;
		h += (l < x.l);
		h += x.h;
		return donna128(l, h);
	}

	donna128 opOpAssign(string op)(ulong x)
		if (op == "+")
	{
		l += x;
		h += (l < x);
		return donna128(l, h);
	}

	donna128 opBinary(string op)(ulong y)
		if (op == "*")
	{
		assert(hi() == 0, "High 64 bits of donna128 set to zero during multiply");

		ulong[2] lohi;
		mul64x64_128(this.lo(), y, lohi);
		return donna128(lohi[0], lohi[1]);
	}

	donna128 opBinary(string op)(auto const ref donna128 y) const
		if (op == "+")
	{
		donna128 z = donna128(l, h);
		z += y;
		return z;
	}

	donna128 opBinary(string op)(ulong y) const
		if (op == "+")
	{
		donna128 z = donna128(l, h);
		z += y;
		return z;
	}

	donna128 opBinary(string op)(auto const ref donna128 y) const
		if (op == "|")
	{
		return donna128(this.lo() | y.lo(), this.hi() | y.hi());
	}

	@property ulong lo() const { return l;}
	@property ulong hi() const { return h;}
private:
	ulong l;
	ulong h;
}


ulong carry_shift(const donna128 a, size_t shift)
{
    return (a >> shift).lo();
}

ulong combine_lower(in donna128 a, size_t s1,
                    in donna128 b, size_t s2)
{
    donna128 z = (a >> s1) | (b << s2);
    return z.lo();
}