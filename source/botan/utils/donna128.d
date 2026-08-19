/**
* A minimal 128-bit integer type for curve25519-donna
*
* (C) 2014 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.donna128;

import botan.utils.mul128 : BotanLdcX64Asm, mul64x64_128;
version (LDC)
	import ldc.intrinsics : llvm_uadd_with_overflow;

struct donna128
{
public:
	pragma(inline, true)
	void opAssign(donna128 other) {
		this.l = other.l;
		this.h = other.h;
	}

	pragma(inline, true)
	void opAssign(in ulong other) {
		this.l = other;
		this.h = 0;
	}

	pragma(inline, true)
	donna128 opBinary(string op)(size_t shift) const
		if (op == ">>")
	{
		if (shift == 0)
			return donna128(l, h);
		donna128 z = this;
		const ulong carry = z.h << (64 - shift);
		z.h = (z.h >> shift);
		z.l = (z.l >> shift) | carry;
		return z;
	}

	pragma(inline, true)
	donna128 opBinary(string op)(size_t shift) const
		if (op == "<<")
	{
		donna128 z = donna128(l, h);
		const ulong carry = z.l >> (64 - shift);
		z.l = (z.l << shift);
		z.h = (z.h << shift) | carry;
		return z;
	}

	pragma(inline, true)
	ulong opBinary(string op)(ulong mask) const
		if (op == "&")
	{
		return l & mask;
	}

	pragma(inline, true)
	ulong opOpAssign(string op)(ulong mask)
		if (op == "&")
	{
		h = 0;
		l &= mask;
		return l;
	}

	pragma(inline, true)
	donna128 opOpAssign(string op)(const auto ref donna128 x)
		if (op == "+")
	{
		version (LDC) {
			auto r = llvm_uadd_with_overflow(l, x.l);
			l = r.result;
			h += x.h + (r.overflow ? 1UL : 0);
			return donna128(l, h);
		} else {
			l += x.l;
			h += (l < x.l);
			h += x.h;
			return donna128(l, h);
		}
	}

	pragma(inline, true)
	donna128 opOpAssign(string op)(ulong x)
		if (op == "+")
	{
		version (LDC) {
			auto r = llvm_uadd_with_overflow(l, x);
			l = r.result;
			h += (r.overflow ? 1UL : 0);
			return donna128(l, h);
		} else {
			l += x;
			h += (l < x);
			return donna128(l, h);
		}
	}

	pragma(inline, true)
	donna128 opBinary(string op)(ulong y)
		if (op == "*")
	{
		// Full (h:l)*y. The old path multiplied only `l` and `assert`ed
		// `h==0`; release builds drop asserts, so TLS 1.3 X25519 SS
		// started with 8 zero bytes and OpenSSL rejected EE (bad MAC).
		ulong[2] lohi;
		mul64x64_128(this.l, y, lohi);
		if (this.h)
		{
			ulong[2] hihi;
			mul64x64_128(this.h, y, hihi);
			lohi[1] += hihi[0];
		}
		return donna128(lohi[0], lohi[1]);
	}

	pragma(inline, true)
	donna128 opBinary(string op)(const auto ref donna128 y) const
		if (op == "+")
	{
		donna128 z = donna128(l, h);
		z += y;
		return z;
	}

	pragma(inline, true)
	donna128 opBinary(string op)(ulong y) const
		if (op == "+")
	{
		donna128 z = donna128(l, h);
		z += y;
		return z;
	}

	pragma(inline, true)
	donna128 opBinary(string op)(const auto ref donna128 y) const
		if (op == "|")
	{
		return donna128(this.lo() | y.lo(), this.hi() | y.hi());
	}

	pragma(inline, true)
	@property ulong lo() const { return l;}
	pragma(inline, true)
	@property ulong hi() const { return h;}
private:
	ulong l;
	ulong h;
}


pragma(inline, true)
ulong carry_shift(const donna128 a, size_t shift)
{
	// (hi:lo) >> shift, low 64 bits. Shift is 51 in the donna-c64 hot path.
	return (a.lo() >> shift) | (a.hi() << (64 - shift));
}

pragma(inline, true)
ulong combine_lower(in donna128 a, size_t s1,
                    in donna128 b, size_t s2)
{
    donna128 z = (a >> s1) | (b << s2);
    return z.lo();
}

unittest
{
	auto p = donna128(ulong.max) * 3UL;
	assert(p.lo == ulong.max - 2);
	assert(p.hi == 2);

	// (1<<64)*2 = 2<<64. Release used to drop `h` and return 0.
	auto wide = donna128(0, 1) * 2UL;
	assert(wide.lo == 0);
	assert(wide.hi == 2);

	donna128 s = donna128(ulong.max, 1);
	s += donna128(1, 0);
	assert(s.lo == 0);
	assert(s.hi == 2);

	s += 1UL;
	assert(s.lo == 1);
	assert(s.hi == 2);

	auto r = donna128(0, 1) >> 1;
	assert(r.lo == (1UL << 63));
	assert(r.hi == 0);

	auto lft = donna128(1UL << 63, 0) << 1;
	assert(lft.lo == 0);
	assert(lft.hi == 1);

	assert(carry_shift(donna128(1UL << 51, 3), 51) == (1 | (3UL << 13)));
}
