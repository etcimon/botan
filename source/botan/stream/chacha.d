/**
* ChaCha20
* 
* Copyright:
* (C) 2014,2018,2023 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.stream.chacha;

import botan.constants;
static if (BOTAN_HAS_CHACHA):

import botan.stream.stream_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.cpuid;
import std.format : format;
static if (BOTAN_HAS_CHACHA_SIMD && BOTAN_HAS_SIMD_SSE2)
    import botan.stream.chacha_sse2;
static if (BOTAN_HAS_CHACHA_AVX2)
    import botan.stream.chacha_avx2;

/**
* DJB's ChaCha (http://cr.yp.to/chacha.html)
*/
final class ChaCha : StreamCipher, SymmetricAlgorithm
{
public:
    /**
    * Params:
    *  rounds = 8, 12, or 20 (ChaCha20)
    */
	this(size_t rounds) {
		m_rounds = rounds;
		if (m_rounds != 8 && m_rounds != 12 && m_rounds != 20)
			throw new InvalidArgument("ChaCha only supports 8, 12 or 20 rounds");
	}

    /*
    * Combine cipher stream with message
    */
    override void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        while (length >= m_buffer.length - m_position)
        {
            xorBuf(output, input, m_buffer.ptr + m_position, m_buffer.length - m_position);
            length -= (m_buffer.length - m_position);
            input += (m_buffer.length - m_position);
            output += (m_buffer.length - m_position);
			chachaRefill(m_buffer, m_state, m_rounds);
			m_position = 0;
        }
        
        xorBuf(output, input, &m_buffer[m_position], length);
        
        m_position += length;
    }

    /*
    * Return the name of this type
    */
    override void setIv(const(ubyte)* iv, size_t length)
    {
        if (!validIvLength(length))
            throw new InvalidIVLength(name, length);
        
        initializeState();
        
		if(length == 0)
		{
			// Treat zero length IV same as an all-zero IV
			m_state[14] = 0;
			m_state[15] = 0;
		} else if (length == 8) {
	        m_state[14] = loadLittleEndian!uint(iv, 0);
	        m_state[15] = loadLittleEndian!uint(iv, 1);
		} else if (length == 12) {
			m_state[13] = loadLittleEndian!uint(iv, 0);
			m_state[14] = loadLittleEndian!uint(iv, 1);
			m_state[15] = loadLittleEndian!uint(iv, 2);
		} else if (length == 24) {
			m_state[12] = loadLittleEndian!uint(iv, 0);
			m_state[13] = loadLittleEndian!uint(iv, 1);
			m_state[14] = loadLittleEndian!uint(iv, 2);
			m_state[15] = loadLittleEndian!uint(iv, 3);

			auto hc = SecureVector!uint(8);
			hchacha(*cast(uint[8]*) hc.ptr, *cast(uint[16]*) m_state.ptr, m_rounds);

			m_state[ 4] = hc[0];
			m_state[ 5] = hc[1];
			m_state[ 6] = hc[2];
			m_state[ 7] = hc[3];
			m_state[ 8] = hc[4];
			m_state[ 9] = hc[5];
			m_state[10] = hc[6];
			m_state[11] = hc[7];
			m_state[12] = 0;
			m_state[13] = 0;

			m_state[14] = loadLittleEndian!uint(iv, 4);
			m_state[15] = loadLittleEndian!uint(iv, 5);
		}
		m_iv_length = length;
		m_state13_post_iv = m_state[13];
		chachaRefill(m_buffer, m_state, m_rounds);
		m_position = 0;
    }

    override void seek(ulong offset)
    {
        const ulong block = offset / 64;
        if (m_iv_length == 12)
        {
            if ((block >> 32) != 0)
                throw new InvalidArgument("ChaCha seek with 96-bit nonce limited to 2^32 blocks");
            m_state[12] = cast(uint) block;
            m_state[13] = m_state13_post_iv;
        }
        else
        {
            m_state[12] = cast(uint) block;
            m_state[13] = m_state13_post_iv + cast(uint)(block >> 32);
        }
        chachaRefill(m_buffer, m_state, m_rounds);
        m_position = cast(size_t)(offset % 64);
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len == 0 || iv_len == 8 || iv_len == 12 || iv_len == 24); }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(16, 32, 16);
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_key);
        zap(m_state);
        zap(m_buffer);
        m_position = 0;
        m_iv_length = 0;
        m_state13_post_iv = 0;
    }

    /*
    * Return the name of this type
    */
    @property string name() const
    {
        return "ChaCha(" ~ m_rounds.to!string ~ ")";
    }

    override StreamCipher clone() const { return new ChaCha(m_rounds); }
   

protected:
    void initializeState()
    {
        __gshared immutable uint[] TAU =    [ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 ];

        __gshared immutable uint[] SIGMA = [ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 ];

        m_state[4] = m_key[0];
        m_state[5] = m_key[1];
        m_state[6] = m_key[2];
        m_state[7] = m_key[3];

        if(m_key.length == 4)
        {
            m_state[0] = TAU[0];
            m_state[1] = TAU[1];
            m_state[2] = TAU[2];
            m_state[3] = TAU[3];

            m_state[8] = m_key[0];
            m_state[9] = m_key[1];
            m_state[10] = m_key[2];
            m_state[11] = m_key[3];
        }
        else
        {
            m_state[0] = SIGMA[0];
            m_state[1] = SIGMA[1];
            m_state[2] = SIGMA[2];
            m_state[3] = SIGMA[3];

            m_state[8] = m_key[4];
            m_state[9] = m_key[5];
            m_state[10] = m_key[6];
            m_state[11] = m_key[7];
        }

        m_state[12] = 0;
        m_state[13] = 0;
        m_state[14] = 0;
        m_state[15] = 0;

        m_position = 0;
    }

    /*
    * ChaCha Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_key.resize(length / 4);
        loadLittleEndian!uint(m_key.ptr, key, m_key.length);

        m_state.resize(16);
        static if (BOTAN_HAS_CHACHA_AVX2)
            m_buffer.resize(8 * 64);
        else
            m_buffer.resize(4 * 64);

        setIv(null, 0);
    }

    SecureVector!uint m_key;
	SecureVector!uint m_state;
    SecureVector!ubyte m_buffer;
    size_t m_position = 0;
	size_t m_rounds;
    size_t m_iv_length = 0;
    uint m_state13_post_iv = 0;
}

enum string CHACHA_QUARTER_ROUND(alias _a, alias _b, alias _c, alias _d) = q{
    %1$s += %2$s; %4$s ^= %1$s; %4$s = rotateLeft(%4$s, 16);
    %3$s += %4$s; %2$s ^= %3$s; %2$s = rotateLeft(%2$s, 12);
    %1$s += %2$s; %4$s ^= %1$s; %4$s = rotateLeft(%4$s, 8);
    %3$s += %4$s; %2$s ^= %3$s; %2$s = rotateLeft(%2$s, 7);
}.format(__traits(identifier, _a), __traits(identifier, _b), __traits(identifier, _c), __traits(identifier, _d));

/*
* Generate HChaCha cipher stream (for XChaCha IV setup)
*/
private void hchacha(ref uint[8] output, const(uint)[16] input, size_t rounds)
{
    assert(rounds % 2 == 0, "Valid rounds");

    uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
        x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
        x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
        x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

    for (size_t i = 0; i != rounds / 2; ++i)
    {
        mixin(CHACHA_QUARTER_ROUND!(x00, x04, x08, x12) ~
            CHACHA_QUARTER_ROUND!(x01, x05, x09, x13) ~
            CHACHA_QUARTER_ROUND!(x02, x06, x10, x14) ~
            CHACHA_QUARTER_ROUND!(x03, x07, x11, x15) ~

            CHACHA_QUARTER_ROUND!(x00, x05, x10, x15) ~
            CHACHA_QUARTER_ROUND!(x01, x06, x11, x12) ~
            CHACHA_QUARTER_ROUND!(x02, x07, x08, x13) ~
            CHACHA_QUARTER_ROUND!(x03, x04, x09, x14)
            );
    }

    output[0] = x00;
    output[1] = x01;
    output[2] = x02;
    output[3] = x03;
    output[4] = x12;
    output[5] = x13;
    output[6] = x14;
    output[7] = x15;
}

private void chachaOneBlock(ubyte* output, ref uint[16] input, size_t rounds)
{
    ubyte[64 * 4] tmp;
    // Portable x4 would emit 4 blocks; do one via the first iteration only.
    uint[16] one = input;
    chachaPortableX4(tmp, one, rounds);
    // chachaPortableX4 advances the counter by 4; restore a single-step increment.
    input[12]++;
    if (input[12] == 0)
        input[13]++;
    output[0 .. 64] = tmp[0 .. 64];
}

private void chachaRefill(ref SecureVector!ubyte buf, ref SecureVector!uint state, size_t rounds)
{
    auto st = *cast(uint[16]*) state.ptr;
    const size_t nblocks = buf.length / 64;
    // SIMD x4/x8 increments the 32-bit word by 4/8 without carrying mid-batch.
    if (nblocks && st[12] > uint.max - (nblocks - 1))
    {
        foreach (i; 0 .. nblocks)
            chachaOneBlock(buf.ptr + 64 * i, st, rounds);
        state[] = st[];
        return;
    }
    static if (BOTAN_HAS_CHACHA_AVX2)
    {
        if (CPUID.hasAvx2() && buf.length >= 64 * 8)
        {
            chachaAvx2x8(*cast(ubyte[64 * 8]*) buf.ptr, st, rounds);
            state[] = st[];
            return;
        }
    }
    static if (BOTAN_HAS_CHACHA_SIMD && BOTAN_HAS_SIMD_SSE2)
    {
        if (CPUID.hasSse2())
        {
            chachaSse2x4(*cast(ubyte[64 * 4]*) buf.ptr, st, rounds);
            if (buf.length >= 64 * 8)
                chachaSse2x4(*cast(ubyte[64 * 4]*)(buf.ptr + 256), st, rounds);
            state[] = st[];
            return;
        }
    }
    chachaPortableX4(*cast(ubyte[64 * 4]*) buf.ptr, st, rounds);
    if (buf.length >= 64 * 8)
        chachaPortableX4(*cast(ubyte[64 * 4]*)(buf.ptr + 256), st, rounds);
    state[] = st[];
}

package void chachaPortableX4(ref ubyte[64*4] output, ref uint[16] input, size_t rounds)
{
	assert(rounds % 2 == 0, "Valid rounds");
	for(int i = 0; i < 4; i++)
	{
		uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
			x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
			x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
			x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];
		
		
		for (int j = 0; j < rounds/2; j++)
		{
			mixin(CHACHA_QUARTER_ROUND!(x00, x04, x08, x12) ~
				CHACHA_QUARTER_ROUND!(x01, x05, x09, x13) ~
				CHACHA_QUARTER_ROUND!(x02, x06, x10, x14) ~
				CHACHA_QUARTER_ROUND!(x03, x07, x11, x15) ~
				
				CHACHA_QUARTER_ROUND!(x00, x05, x10, x15) ~
				CHACHA_QUARTER_ROUND!(x01, x06, x11, x12) ~
				CHACHA_QUARTER_ROUND!(x02, x07, x08, x13) ~
				CHACHA_QUARTER_ROUND!(x03, x04, x09, x14)
				);
		}
		
		storeLittleEndian(x00 + input[ 0], output.ptr + 64 * i + 4 *  0);
		storeLittleEndian(x01 + input[ 1], output.ptr + 64 * i + 4 *  1);
		storeLittleEndian(x02 + input[ 2], output.ptr + 64 * i + 4 *  2);
		storeLittleEndian(x03 + input[ 3], output.ptr + 64 * i + 4 *  3);
		storeLittleEndian(x04 + input[ 4], output.ptr + 64 * i + 4 *  4);
		storeLittleEndian(x05 + input[ 5], output.ptr + 64 * i + 4 *  5);
		storeLittleEndian(x06 + input[ 6], output.ptr + 64 * i + 4 *  6);
		storeLittleEndian(x07 + input[ 7], output.ptr + 64 * i + 4 *  7);
		storeLittleEndian(x08 + input[ 8], output.ptr + 64 * i + 4 *  8);
		storeLittleEndian(x09 + input[ 9], output.ptr + 64 * i + 4 *  9);
		storeLittleEndian(x10 + input[10], output.ptr + 64 * i + 4 * 10);
		storeLittleEndian(x11 + input[11], output.ptr + 64 * i + 4 * 11);
		storeLittleEndian(x12 + input[12], output.ptr + 64 * i + 4 * 12);
		storeLittleEndian(x13 + input[13], output.ptr + 64 * i + 4 * 13);
		storeLittleEndian(x14 + input[14], output.ptr + 64 * i + 4 * 14);
		storeLittleEndian(x15 + input[15], output.ptr + 64 * i + 4 * 15);

		input[12]++;
		if (input[12] == 0)
			input[13]++;
	}
}

