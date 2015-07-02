/*
* curve25519-donna-c64.c from github.com/agl/curve25519-donna
* revision 80ad9b9930c9baef5829dd2a235b6b7646d32a8e
*/

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *     http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */
module botan.pubkey.algo.curve22519_donna;

import botan.constants;
static if (BOTAN_HAS_CURVE22519):
import botan.utils.donna128;
import botan.utils.mul128;
import botan.utils.loadstor;
import botan.utils.mem_ops;

package
int curve25519Donna(ubyte* mypublic, const ubyte* secret, const ubyte* basepoint) {
	limb[5] bp;
	limb[5] x;
	limb[5] z;
	limb[5] zmone;
	ubyte[32] e;
	int i;
	
	for (i = 0;i < 32;++i) e[i] = secret[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	
	fexpand(bp.ptr, basepoint);
	cmult(x.ptr, z.ptr, e.ptr, bp.ptr);
	crecip(zmone.ptr, z.ptr);
	fmul(z.ptr, x.ptr, zmone.ptr);
	fcontract(mypublic, z.ptr);
	return 0;
}

private:

alias uint128_t = donna128;
alias limb = ulong;

/* Sum two numbers: output += in */
void fsum(limb* output, const limb* input)
{
	output[0] += input[0];
	output[1] += input[1];
	output[2] += input[2];
	output[3] += input[3];
	output[4] += input[4];
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */
void fdifferenceBackwards(limb* output, const limb* input) 
{
	/* 152 is 19 << 3 */
	immutable limb two54m152 = ((cast(limb)1) << 54) - 152;
	immutable limb two54m8 = ((cast(limb)1) << 54) - 8;
	
	output[0] = input[0] + two54m152 - output[0];
	output[1] = input[1] + two54m8 - output[1];
	output[2] = input[2] + two54m8 - output[2];
	output[3] = input[3] + two54m8 - output[3];
	output[4] = input[4] + two54m8 - output[4];
}

/* Multiply a number by a scalar: output = in * scalar */
void fscalarProduct(limb* output, const limb* input, const limb scalar) {
	uint128_t a = uint128_t(input[0]) * scalar;
	output[0] = a & 0x7ffffffffffff;
	
	a = uint128_t(input[1]) * scalar + carry_shift(a, 51);
	output[1] = a & 0x7ffffffffffff;
	
	a = uint128_t(input[2]) * scalar + carry_shift(a, 51);
	output[2] = a & 0x7ffffffffffff;
	
	a = uint128_t(input[3]) * scalar + carry_shift(a, 51);
	output[3] = a & 0x7ffffffffffff;
	
	a = uint128_t(input[4]) * scalar + carry_shift(a, 51);
	output[4] = a & 0x7ffffffffffff;
	
	output[0] += carry_shift(a, 51) * 19;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
void fmul(limb* output, const limb* input2, const limb* input) 
{
	uint128_t[5] t = void;
	limb r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;
	
	r0 = input[0];
	r1 = input[1];
	r2 = input[2];
	r3 = input[3];
	r4 = input[4];
	
	s0 = input2[0];
	s1 = input2[1];
	s2 = input2[2];
	s3 = input2[3];
	s4 = input2[4];
	
	t[0] = uint128_t(r0) * s0;
	t[1] = uint128_t(r0) * s1 + uint128_t(r1) * s0;
	t[2] = uint128_t(r0) * s2 + uint128_t(r2) * s0 + uint128_t(r1) * s1;
	t[3] = uint128_t(r0) * s3 + uint128_t(r3) * s0 + uint128_t(r1) * s2 + uint128_t(r2) * s1;
	t[4] = uint128_t(r0) * s4 + uint128_t(r4) * s0 + uint128_t(r3) * s1 + uint128_t(r1) * s3 + uint128_t(r2) * s2;
	
	r4 *= 19;
	r1 *= 19;
	r2 *= 19;
	r3 *= 19;
	
	t[0] += uint128_t(r4) * s1 + uint128_t(r1) * s4 + uint128_t(r2) * s3 + uint128_t(r3) * s2;
	t[1] += uint128_t(r4) * s2 + uint128_t(r2) * s4 + uint128_t(r3) * s3;
	t[2] += uint128_t(r4) * s3 + uint128_t(r3) * s4;
	t[3] += uint128_t(r4) * s4;
	
	r0 = t[0] & 0x7ffffffffffff; c = carry_shift(t[0], 51);
	t[1] += c; r1 = t[1] & 0x7ffffffffffff; c = carry_shift(t[1], 51);
	t[2] += c; r2 = t[2] & 0x7ffffffffffff; c = carry_shift(t[2], 51);
	t[3] += c; r3 = t[3] & 0x7ffffffffffff; c = carry_shift(t[3], 51);
	t[4] += c; r4 = t[4] & 0x7ffffffffffff; c = carry_shift(t[4], 51);
	r0 +=     c * 19; c = carry_shift(uint128_t(r0), 51); r0 = r0 & 0x7ffffffffffff;
	r1 +=     c;      c = carry_shift(uint128_t(r1), 51); r1 = r1 & 0x7ffffffffffff;
	r2 +=     c;
	
	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

void fsquareTimes(limb* output, const limb* input, limb count) 
{
	uint128_t[5] t;
	limb r0,r1,r2,r3,r4,c;
	limb d0,d1,d2,d4,d419;
	
	r0 = input[0];
	r1 = input[1];
	r2 = input[2];
	r3 = input[3];
	r4 = input[4];
	
	do {
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;
		
		t[0] = uint128_t(r0) * r0 + uint128_t(d4) * r1 + uint128_t(d2) * (r3     );
		t[1] = uint128_t(d0) * r1 + uint128_t(d4) * r2 + uint128_t(r3) * (r3 * 19);
		t[2] = uint128_t(d0) * r2 + uint128_t(r1) * r1 + uint128_t(d4) * (r3     );
		t[3] = uint128_t(d0) * r3 + uint128_t(d1) * r2 + uint128_t(r4) * (d419   );
		t[4] = uint128_t(d0) * r4 + uint128_t(d1) * r3 + uint128_t(r2) * (r2     );
		
		r0 = t[0] & 0x7ffffffffffff; c = carry_shift(t[0], 51);
		t[1] += c; r1 = t[1] & 0x7ffffffffffff; c = carry_shift(t[1], 51);
		t[2] += c; r2 = t[2] & 0x7ffffffffffff; c = carry_shift(t[2], 51);
		t[3] += c; r3 = t[3] & 0x7ffffffffffff; c = carry_shift(t[3], 51);
		t[4] += c; r4 = t[4] & 0x7ffffffffffff; c = carry_shift(t[4], 51);
		r0 += c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
		r1 += c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
		r2 += c;
	} while(--count);
	
	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

/* Load a little-endian 64-bit number    */
limb loadLimb(const ubyte* input)
{
	return loadLittleEndian!ulong(input, 0);
}

void storeLimb(ubyte* output, limb input)
{
	storeLittleEndian!limb(input, output);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void fexpand(limb* output, const ubyte* input) {
	output[0] = loadLimb(input) & 0x7ffffffffffff;
	output[1] = (loadLimb(input+6) >> 3) & 0x7ffffffffffff;
	output[2] = (loadLimb(input+12) >> 6) & 0x7ffffffffffff;
	output[3] = (loadLimb(input+19) >> 1) & 0x7ffffffffffff;
	output[4] = (loadLimb(input+24) >> 12) & 0x7ffffffffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
void fcontract(ubyte* output, const limb* input)
{
	uint128_t[5] t;
	
	t[0] = input[0];
	t[1] = input[1];
	t[2] = input[2];
	t[3] = input[3];
	t[4] = input[4];
	
	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;
	
	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;
	
	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
	
	t[0] += 19;
	
	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;
	
	/* now between 19 and 2^255-1 in both cases, and offset by 19. */
	
	t[0] += 0x8000000000000 - 19;
	t[1] += 0x8000000000000 - 1;
	t[2] += 0x8000000000000 - 1;
	t[3] += 0x8000000000000 - 1;
	t[4] += 0x8000000000000 - 1;
	
	/* now between 2^255 and 2^256-20, and offset by 2^255. */
	
	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[4] &= 0x7ffffffffffff;
	
	storeLimb(output,    combine_lower(t[0], 0, t[1], 51));
	storeLimb(output+8,  combine_lower(t[1], 13, t[2], 38));
	storeLimb(output+16, combine_lower(t[2], 26, t[3], 25));
	storeLimb(output+24, combine_lower(t[3], 39, t[4], 12));
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 * x2 z3: long form
 * x3 z3: long form
 * x z: short form, destroyed
 * xprime zprime: short form, destroyed
 * qmqp: short form, preserved
 */
void fmonty(limb* x2, limb* z2, /* output 2Q */
	limb* x3, limb* z3, /* output Q + Q' */
	limb* x, limb* z,     /* input Q */
	limb* xprime, limb* zprime, /* input Q' */
	const limb* qmqp /* input Q - Q' */) 
{
	limb[5] origx;
	limb[5] origxprime;
	limb[5] zzz;
	limb[5] xx;
	limb[5] zz;
	limb[5] xxprime;
	limb[5] zzprime;
	limb[5] zzzprime;
	
	copyMem(origx.ptr, x, 5);
	fsum(x, z);
	fdifferenceBackwards(z, origx.ptr);    // does x - z
	
	copyMem(origxprime.ptr, xprime, 5);
	fsum(xprime, zprime);
	fdifferenceBackwards(zprime, origxprime.ptr);
	fmul(xxprime.ptr, xprime, z);
	fmul(zzprime.ptr, x, zprime);
	copyMem(origxprime.ptr, xxprime.ptr, 5);
	fsum(xxprime.ptr, zzprime.ptr);
	fdifferenceBackwards(zzprime.ptr, origxprime.ptr);
	fsquareTimes(x3, xxprime.ptr, 1);
	fsquareTimes(zzzprime.ptr, zzprime.ptr, 1);
	fmul(z3, zzzprime.ptr, qmqp);
	
	fsquareTimes(xx.ptr, x, 1);
	fsquareTimes(zz.ptr, z, 1);
	fmul(x2, xx.ptr, zz.ptr);
	fdifferenceBackwards(zz.ptr, xx.ptr);    // does zz = xx - zz
	fscalarProduct(zzz.ptr, zz.ptr, 121665);
	fsum(zzz.ptr, xx.ptr);
	fmul(z2, zz.ptr, zzz.ptr);
}

// -----------------------------------------------------------------------------
// Maybe swap the contents of two limb arrays (@a and @b), each @len elements
// long. Perform the swap iff @swap is non-zero.
//
// This function performs the swap without leaking any side-channel
// information.
// -----------------------------------------------------------------------------
void swapConditional(limb* a, limb* b, limb iswap) {
	const limb swap = cast(limb)(-iswap);
	
	for (size_t i = 0; i < 5; ++i) {
		const limb x = swap & (a[i] ^ b[i]);
		a[i] ^= x;
		b[i] ^= x;
	}
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *     resultx/resultz: the x coordinate of the resulting curve point (short form)
 *     n: a little endian, 32-byte number
 *     q: a point of the curve (short form)
 */
void cmult(limb* resultx, limb* resultz, const ubyte* n, const limb* q) {
	limb[5] a;
	limb[5] b; b[0] = 1;
	limb[5] c; c[0] = 1;
	limb[5] d;
	limb* nqpqx = a.ptr;
	limb* nqpqz = b.ptr;
	limb* nqx = c.ptr;
	limb* nqz = d.ptr;
	limb* t;
	limb[5] e;
	limb[5] f; f[0] = 1;
	limb[5] g;
	limb[5] h; h[0] = 1;
	limb* nqpqx2 = e.ptr;
	limb* nqpqz2 = f.ptr;
	limb* nqx2 = g.ptr;
	limb* nqz2 = h.ptr;
	
	size_t i, j;
	
	copyMem(nqpqx, q, 5);
	
	for (i = 0; i < 32; ++i) {
		ubyte by = n[31 - i];
		for (j = 0; j < 8; ++j) {
			const limb bit = cast(limb)(by >> 7);
			
			swapConditional(nqx, nqpqx, bit);
			swapConditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
				nqpqx2, nqpqz2,
				nqx, nqz,
				nqpqx, nqpqz,
				q);
			swapConditional(nqx2, nqpqx2, bit);
			swapConditional(nqz2, nqpqz2, bit);
			
			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;
			
			by <<= 1;
		}
	}
	
	copyMem(resultx, nqx, 5);
	copyMem(resultz, nqz, 5);
}


// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code, tightened a little
// -----------------------------------------------------------------------------
void crecip(limb* output, const limb* z) {
	limb[5] a_ = void;
	limb[5] t0_ = void;
	limb[5] b_ = void;
	limb[5] c_ = void;
	limb* a = a_.ptr;
	limb* t0 = t0_.ptr;
	limb* b = b_.ptr;
	limb* c = c_.ptr;

	/* 2 */ fsquareTimes(a, z, 1); // a = 2
	/* 8 */ fsquareTimes(t0, a, 2);
	/* 9 */ fmul(b, t0, z); // b = 9
	/* 11 */ fmul(a, b, a); // a = 11
	/* 22 */ fsquareTimes(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
	/* 2^10 - 2^5 */ fsquareTimes(t0, b, 5);
	/* 2^10 - 2^0 */ fmul(b, t0, b);
	/* 2^20 - 2^10 */ fsquareTimes(t0, b, 10);
	/* 2^20 - 2^0 */ fmul(c, t0, b);
	/* 2^40 - 2^20 */ fsquareTimes(t0, c, 20);
	/* 2^40 - 2^0 */ fmul(t0, t0, c);
	/* 2^50 - 2^10 */ fsquareTimes(t0, t0, 10);
	/* 2^50 - 2^0 */ fmul(b, t0, b);
	/* 2^100 - 2^50 */ fsquareTimes(t0, b, 50);
	/* 2^100 - 2^0 */ fmul(c, t0, b);
	/* 2^200 - 2^100 */ fsquareTimes(t0, c, 100);
	/* 2^200 - 2^0 */ fmul(t0, t0, c);
	/* 2^250 - 2^50 */ fsquareTimes(t0, t0, 50);
	/* 2^250 - 2^0 */ fmul(t0, t0, b);
	/* 2^255 - 2^5 */ fsquareTimes(t0, t0, 5);
	/* 2^255 - 21 */ fmul(output, t0, a);
}
