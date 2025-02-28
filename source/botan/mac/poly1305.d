/**
* Derived from poly1305-donna-64.h by Andrew Moon <liquidsun@gmail.com>
* in https://github.com/floodyberry/poly1305-donna
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014 Andrew Moon
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.poly1305;

import botan.constants;
static if (BOTAN_HAS_POLY1305):
import botan.mac.mac;
import botan.utils.mul128;
import botan.utils.donna128;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.loadstor;

/**
* DJB's Poly1305
* Important note: each key can only be used once
*/
class Poly1305 : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm
{
public:
	/*
    * Return the name of this type
    */
	override @property string name() const
	{
		return "Poly1305";
	}
	
	override @property size_t outputLength() const { return 16; }

	/*
    * Return a clone of this object
    */
	override MessageAuthenticationCode clone() const
	{
		return new Poly1305;
	}
	
	/*
    * Clear memory of sensitive data
    */
	override void clear() {
		zap(m_poly);
		zap(m_buf);
		m_buf_pos = 0;
	}
	
	override KeyLengthSpecification keySpec() const
	{
		return KeyLengthSpecification(32);
	}
	
protected:
	override void addData(const(ubyte)* input, size_t length) {
		assert(m_poly.length == 8, "Initialized");
		
		if(m_buf_pos)
		{
			bufferInsert(m_buf, m_buf_pos, input, length);
			
			if(m_buf_pos + length >= m_buf.length)
			{
				poly1305_blocks(m_poly.ptr, m_buf.ptr, 1);
				input += (m_buf.length - m_buf_pos);
				length -= (m_buf.length - m_buf_pos);
				m_buf_pos = 0;
			}
		}
		
		const size_t full_blocks = length / m_buf.length;
		const size_t remaining   = length % m_buf.length;
		
		if(full_blocks)
			poly1305_blocks(m_poly.ptr, input, full_blocks);
		
		bufferInsert(m_buf, m_buf_pos, input + full_blocks * m_buf.length, remaining);
		m_buf_pos += remaining;
	}
	
	override void finalResult(ubyte* output) {
		assert(m_poly.length == 8, "Initialized");
		
		if(m_buf_pos != 0)
		{
			m_buf[m_buf_pos] = 1;
			const auto len = m_buf.length - m_buf_pos - 1;
			if (len > 0) {
				clearMem(m_buf.ptr + m_buf_pos + 1, len);
			}
			poly1305_blocks(m_poly.ptr, m_buf.ptr, 1, true);
		}
		
		poly1305_finish(m_poly.ptr, output);
		
		m_poly.clear();
		m_buf_pos = 0;
	}
	
	
	override void keySchedule(const(ubyte)* key, size_t length) {	
		assert(length == 32);
		m_buf_pos = 0;
		m_buf.resize(16);
		m_poly.resize(8);
		poly1305_init(m_poly.ptr, key);
	}
	
	SecureVector!ulong m_poly;
	SecureVector!ubyte m_buf;
	size_t m_buf_pos;
};

private:

void poly1305_init(ulong* X, const ubyte* key)
{
	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	const ulong t0 = loadLittleEndian!ulong(key, 0);
	const ulong t1 = loadLittleEndian!ulong(key, 1);
	
	X[0] = ( t0                    ) & 0xffc0fffffff;
	X[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	X[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;
	
	/* h = 0 */
	X[3] = 0;
	X[4] = 0;
	X[5] = 0;
	
	/* save pad for later */
	X[6] = loadLittleEndian!ulong(key, 2);
	X[7] = loadLittleEndian!ulong(key, 3);
}

void poly1305_blocks(ulong* X, const(ubyte)* m, size_t blocks, bool is_final = false)
{
	alias uint128_t = donna128;
	
	const ulong hibit = is_final ? 0 : (1UL << 40); /* 1 << 128 */
	
	const ulong r0 = X[0];
	const ulong r1 = X[1];
	const ulong r2 = X[2];
	
	ulong h0 = X[3+0];
	ulong h1 = X[3+1];
	ulong h2 = X[3+2];
	
	const ulong s1 = r1 * (5 << 2);
	const ulong s2 = r2 * (5 << 2);
	
	while(blocks--)
	{
		/* h += m[i] */
		const ulong t0 = loadLittleEndian!ulong(m, 0);
		const ulong t1 = loadLittleEndian!ulong(m, 1);
		
		h0 += (( t0                    ) & 0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;
		
		/* h *= r */
		uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
		uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2;
		uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0;
		
		/* (partial) h %= p */
		        ulong c = carry_shift(d0, 44); h0 = d0 & 0xfffffffffff;
		d1 += c;      c = carry_shift(d1, 44); h1 = d1 & 0xfffffffffff;
		d2 += c;      c = carry_shift(d2, 42); h2 = d2 & 0x3ffffffffff;
		h0  += c * 5; c = carry_shift(uint128_t(h0), 44); h0 = h0 & 0xfffffffffff;
		h1  += c;
		
		m += 16;
	}
	
	X[3+0] = h0;
	X[3+1] = h1;
	X[3+2] = h2;
}

void poly1305_finish(ulong* X, ubyte* mac)
{
	/* fully carry h */
	ulong h0 = X[3+0];
	ulong h1 = X[3+1];
	ulong h2 = X[3+2];
	
	ulong c;
	c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;
	
	/* compute h + -p */
	ulong g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
	ulong g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
	ulong g2 = h2 + c - (1UL << 42);
	
	/* select h if h < p, or h + -p if h >= p */
	c = (g2 >> ((ulong.sizeof * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;
	
	/* h = (h + pad) */
	const ulong t0 = X[6];
	const ulong t1 = X[7];
	
	h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;
	
	/* mac = h % (2^128) */
	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));
	
	storeLittleEndian(mac, h0, h1);
	
	/* zero out the state */
	clearMem(X, 8);
}
