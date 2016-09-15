/**
* ChaCha20
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
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

/**
* DJB's ChaCha (http://cr.yp.to/chacha.html)
*/
final class ChaCha : StreamCipher, SymmetricAlgorithm
{
public:
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

			if (CPUID.hasSse2())
				chachaSSE2x4(*cast(ubyte[64*4]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr, m_rounds);
			else 
				chachax4(*cast(ubyte[64*4]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr, m_rounds);
                        
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
        
        m_state[12] = 0;

        m_state[13] = 0;
        
		if (length == 8) {
	        m_state[14] = loadLittleEndian!uint(iv, 0);
	        m_state[15] = loadLittleEndian!uint(iv, 1);
		} else if (length == 12) {
			m_state[13] = loadLittleEndian!uint(iv, 0);
			m_state[14] = loadLittleEndian!uint(iv, 1);
			m_state[15] = loadLittleEndian!uint(iv, 2);
		}
        
        if (CPUID.hasSse2())
			chachaSSE2x4(*cast(ubyte[64*4]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr, m_rounds);
		else chachax4(*cast(ubyte[64*4]*) m_buffer.ptr, *cast(uint[16]*) m_state.ptr, m_rounds);
        
        m_position = 0;
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len == 8 || iv_len == 12); }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(16, 32, 16);
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_state);
        zap(m_buffer);
        m_position = 0;
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
    /*
    * ChaCha Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        __gshared immutable uint[] TAU =    [ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 ];
        
        __gshared immutable uint[] SIGMA = [ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 ];
        
        const uint[] CONSTANTS = (length == 16) ? TAU : SIGMA;

		// Repeat the key if 128bits
		const(ubyte)* key2 = (length == 32) ? key + 16 : key;
		m_position = 0;
        m_state.resize(16);
        m_buffer.resize(4*64);
        
        m_state[0] = CONSTANTS[0];
        m_state[1] = CONSTANTS[1];
        m_state[2] = CONSTANTS[2];
        m_state[3] = CONSTANTS[3];
        
        m_state[4] = loadLittleEndian!uint(key, 0);
        m_state[5] = loadLittleEndian!uint(key, 1);
        m_state[6] = loadLittleEndian!uint(key, 2);
        m_state[7] = loadLittleEndian!uint(key, 3);
                
        m_state[8] = loadLittleEndian!uint(key2, 0);
        m_state[9] = loadLittleEndian!uint(key2, 1);
        m_state[10] = loadLittleEndian!uint(key2, 2);
        m_state[11] = loadLittleEndian!uint(key2, 3);
        
		// Default all-zero IV
        
        const ubyte[8] ZERO;
        setIv(ZERO.ptr, ZERO.length);
    }

	SecureVector!uint m_state;
    SecureVector!ubyte m_buffer;
    size_t m_position = 0;
	size_t m_rounds;
}

enum string CHACHA_QUARTER_ROUND(alias _a, alias _b, alias _c, alias _d) = q{
    %1$s += %2$s; %4$s ^= %1$s; %4$s = rotateLeft(%4$s, 16);
    %3$s += %4$s; %2$s ^= %3$s; %2$s = rotateLeft(%2$s, 12);
    %1$s += %2$s; %4$s ^= %1$s; %4$s = rotateLeft(%4$s, 8);
    %3$s += %4$s; %2$s ^= %3$s; %2$s = rotateLeft(%2$s, 7);
}.format(__traits(identifier, _a), __traits(identifier, _b), __traits(identifier, _c), __traits(identifier, _d));

private void chachax4(ref ubyte[64*4] output, ref uint[16] input, size_t rounds)
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
		input[13] += (input[12] < i) ? 1 : 0;
	}
}

/** SSE2 ChaCha
*   (C) 2016 Jack Lloyd
*/
private void chachaSSE2x4(ref ubyte[64*4] output, ref uint[16] input, size_t rounds)
{
	import botan.utils.simd.emmintrin;
	assert(rounds % 2 == 0, "Valid rounds");
	
	const __m128i* input_mm = cast(const(__m128i*)) input;
	__m128i* output_mm = cast(__m128i*) output;
	
	__m128i input0 = _mm_loadu_si128(input_mm);
	__m128i input1 = _mm_loadu_si128(input_mm + 1);
	__m128i input2 = _mm_loadu_si128(input_mm + 2);
	__m128i input3 = _mm_loadu_si128(input_mm + 3);
	
	// TODO: try transposing, which would avoid the permutations each round

	__m128i r0_0 = input0;
	__m128i r0_1 = input1;
	__m128i r0_2 = input2;
	__m128i r0_3 = input3;
	
	__m128i r1_0 = input0;
	__m128i r1_1 = input1;
	__m128i r1_2 = input2;
	__m128i r1_3 = input3;
	r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));
	
	__m128i r2_0 = input0;
	__m128i r2_1 = input1;
	__m128i r2_2 = input2;
	__m128i r2_3 = input3;
	r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));
	
	__m128i r3_0 = input0;
	__m128i r3_1 = input1;
	__m128i r3_2 = input2;
	__m128i r3_3 = input3;
	r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));
	
	for(size_t r = 0; r != rounds / 2; ++r)
	{
		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);
		
		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);
		
		r0_3 = _mm_or_si128(_mm_slli_epi32!16(r0_3), _mm_srli_epi32!16(r0_3)); //mm_rotl(r0_3, 16);
		r1_3 = _mm_or_si128(_mm_slli_epi32!16(r1_3), _mm_srli_epi32!16(r1_3)); //mm_rotl(r1_3, 16);
		r2_3 = _mm_or_si128(_mm_slli_epi32!16(r2_3), _mm_srli_epi32!16(r2_3)); //mm_rotl(r2_3, 16);
		r3_3 = _mm_or_si128(_mm_slli_epi32!16(r3_3), _mm_srli_epi32!16(r3_3)); //mm_rotl(r3_3, 16);
		
		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);
		
		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);
		
		r0_1 = _mm_or_si128(_mm_slli_epi32!12(r0_1), _mm_srli_epi32!20(r0_1)); //mm_rotl(r0_1, 12);
		r1_1 = _mm_or_si128(_mm_slli_epi32!12(r1_1), _mm_srli_epi32!20(r1_1)); //mm_rotl(r1_1, 12);
		r2_1 = _mm_or_si128(_mm_slli_epi32!12(r2_1), _mm_srli_epi32!20(r2_1)); //mm_rotl(r2_1, 12);
		r3_1 = _mm_or_si128(_mm_slli_epi32!12(r3_1), _mm_srli_epi32!20(r3_1)); //mm_rotl(r3_1, 12);
		
		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);
		
		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);
		
		r0_3 = _mm_or_si128(_mm_slli_epi32!8(r0_3), _mm_srli_epi32!24(r0_3)); //mm_rotl(r0_3, 8);
		r1_3 = _mm_or_si128(_mm_slli_epi32!8(r1_3), _mm_srli_epi32!24(r1_3)); //mm_rotl(r1_3, 8);
		r2_3 = _mm_or_si128(_mm_slli_epi32!8(r2_3), _mm_srli_epi32!24(r2_3)); //mm_rotl(r2_3, 8);
		r3_3 = _mm_or_si128(_mm_slli_epi32!8(r3_3), _mm_srli_epi32!24(r3_3)); //mm_rotl(r3_3, 8);
		
		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);
		
		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);
		
		r0_1 = _mm_or_si128(_mm_slli_epi32!7(r0_1), _mm_srli_epi32!25(r0_1)); //mm_rotl(r0_1, 7);
		r1_1 = _mm_or_si128(_mm_slli_epi32!7(r1_1), _mm_srli_epi32!25(r1_1)); //mm_rotl(r1_1, 7);
		r2_1 = _mm_or_si128(_mm_slli_epi32!7(r2_1), _mm_srli_epi32!25(r2_1)); //mm_rotl(r2_1, 7);
		r3_1 = _mm_or_si128(_mm_slli_epi32!7(r3_1), _mm_srli_epi32!25(r3_1)); //mm_rotl(r3_1, 7);
		
		r0_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r0_1);
		r0_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r0_2);
		r0_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r0_3);
		
		r1_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r1_1);
		r1_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r1_2);
		r1_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r1_3);
		
		r2_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r2_1);
		r2_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r2_2);
		r2_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r2_3);
		
		r3_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r3_1);
		r3_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r3_2);
		r3_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r3_3);
		
		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);
		
		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);
		
		r0_3 = _mm_or_si128(_mm_slli_epi32!16(r0_3), _mm_srli_epi32!16(r0_3)); //mm_rotl(r0_3, 16);
		r1_3 = _mm_or_si128(_mm_slli_epi32!16(r1_3), _mm_srli_epi32!16(r1_3)); //mm_rotl(r1_3, 16);
		r2_3 = _mm_or_si128(_mm_slli_epi32!16(r2_3), _mm_srli_epi32!16(r2_3)); //mm_rotl(r2_3, 16);
		r3_3 = _mm_or_si128(_mm_slli_epi32!16(r3_3), _mm_srli_epi32!16(r3_3)); //mm_rotl(r3_3, 16);
		
		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);
		
		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);
		
		r0_1 = _mm_or_si128(_mm_slli_epi32!12(r0_1), _mm_srli_epi32!20(r0_1)); //mm_rotl(r0_1, 12);
		r1_1 = _mm_or_si128(_mm_slli_epi32!12(r1_1), _mm_srli_epi32!20(r1_1)); //mm_rotl(r1_1, 12);
		r2_1 = _mm_or_si128(_mm_slli_epi32!12(r2_1), _mm_srli_epi32!20(r2_1)); //mm_rotl(r2_1, 12);
		r3_1 = _mm_or_si128(_mm_slli_epi32!12(r3_1), _mm_srli_epi32!20(r3_1)); //mm_rotl(r3_1, 12);
		
		r0_0 = _mm_add_epi32(r0_0, r0_1);
		r1_0 = _mm_add_epi32(r1_0, r1_1);
		r2_0 = _mm_add_epi32(r2_0, r2_1);
		r3_0 = _mm_add_epi32(r3_0, r3_1);
		
		r0_3 = _mm_xor_si128(r0_3, r0_0);
		r1_3 = _mm_xor_si128(r1_3, r1_0);
		r2_3 = _mm_xor_si128(r2_3, r2_0);
		r3_3 = _mm_xor_si128(r3_3, r3_0);
		
		r0_3 = _mm_or_si128(_mm_slli_epi32!8(r0_3), _mm_srli_epi32!24(r0_3)); //mm_rotl(r0_3, 8);
		r1_3 = _mm_or_si128(_mm_slli_epi32!8(r1_3), _mm_srli_epi32!24(r1_3)); //mm_rotl(r1_3, 8);
		r2_3 = _mm_or_si128(_mm_slli_epi32!8(r2_3), _mm_srli_epi32!24(r2_3)); //mm_rotl(r2_3, 8);
		r3_3 = _mm_or_si128(_mm_slli_epi32!8(r3_3), _mm_srli_epi32!24(r3_3)); //mm_rotl(r3_3, 8);
		
		r0_2 = _mm_add_epi32(r0_2, r0_3);
		r1_2 = _mm_add_epi32(r1_2, r1_3);
		r2_2 = _mm_add_epi32(r2_2, r2_3);
		r3_2 = _mm_add_epi32(r3_2, r3_3);
		
		r0_1 = _mm_xor_si128(r0_1, r0_2);
		r1_1 = _mm_xor_si128(r1_1, r1_2);
		r2_1 = _mm_xor_si128(r2_1, r2_2);
		r3_1 = _mm_xor_si128(r3_1, r3_2);
		
		r0_1 = _mm_or_si128(_mm_slli_epi32!7(r0_1), _mm_srli_epi32!25(r0_1)); //mm_rotl(r0_1, 7);
		r1_1 = _mm_or_si128(_mm_slli_epi32!7(r1_1), _mm_srli_epi32!25(r1_1)); //mm_rotl(r1_1, 7);
		r2_1 = _mm_or_si128(_mm_slli_epi32!7(r2_1), _mm_srli_epi32!25(r2_1)); //mm_rotl(r2_1, 7);
		r3_1 = _mm_or_si128(_mm_slli_epi32!7(r3_1), _mm_srli_epi32!25(r3_1)); //mm_rotl(r3_1, 7);
		
		r0_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r0_1);
		r0_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r0_2);
		r0_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r0_3);
		
		r1_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r1_1);
		r1_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r1_2);
		r1_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r1_3);
		
		r2_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r2_1);
		r2_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r2_2);
		r2_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r2_3);
		
		r3_1 = _mm_shuffle_epi32!(_MM_SHUFFLE(2, 1, 0, 3))(r3_1);
		r3_2 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 3, 2))(r3_2);
		r3_3 = _mm_shuffle_epi32!(_MM_SHUFFLE(0, 3, 2, 1))(r3_3);
	}
	
	r0_0 = _mm_add_epi32(r0_0, input0);
	r0_1 = _mm_add_epi32(r0_1, input1);
	r0_2 = _mm_add_epi32(r0_2, input2);
	r0_3 = _mm_add_epi32(r0_3, input3);
	
	r1_0 = _mm_add_epi32(r1_0, input0);
	r1_1 = _mm_add_epi32(r1_1, input1);
	r1_2 = _mm_add_epi32(r1_2, input2);
	r1_3 = _mm_add_epi32(r1_3, input3);
	r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));
	
	r2_0 = _mm_add_epi32(r2_0, input0);
	r2_1 = _mm_add_epi32(r2_1, input1);
	r2_2 = _mm_add_epi32(r2_2, input2);
	r2_3 = _mm_add_epi32(r2_3, input3);
	r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));
	
	r3_0 = _mm_add_epi32(r3_0, input0);
	r3_1 = _mm_add_epi32(r3_1, input1);
	r3_2 = _mm_add_epi32(r3_2, input2);
	r3_3 = _mm_add_epi32(r3_3, input3);
	r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));
	
	_mm_storeu_si128(output_mm + 0, r0_0);
	_mm_storeu_si128(output_mm + 1, r0_1);
	_mm_storeu_si128(output_mm + 2, r0_2);
	_mm_storeu_si128(output_mm + 3, r0_3);
	
	_mm_storeu_si128(output_mm + 4, r1_0);
	_mm_storeu_si128(output_mm + 5, r1_1);
	_mm_storeu_si128(output_mm + 6, r1_2);
	_mm_storeu_si128(output_mm + 7, r1_3);
	
	_mm_storeu_si128(output_mm + 8, r2_0);
	_mm_storeu_si128(output_mm + 9, r2_1);
	_mm_storeu_si128(output_mm + 10, r2_2);
	_mm_storeu_si128(output_mm + 11, r2_3);
	
	_mm_storeu_si128(output_mm + 12, r3_0);
	_mm_storeu_si128(output_mm + 13, r3_1);
	_mm_storeu_si128(output_mm + 14, r3_2);
	_mm_storeu_si128(output_mm + 15, r3_3);
		
	input[12] += 4;
	if (input[12] < 4)
		input[13]++;
}