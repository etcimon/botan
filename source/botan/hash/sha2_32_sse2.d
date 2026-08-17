/**
* SHA-{224,256} with SSE2 message expansion
*
* Copyright:
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha2_32_sse2;

import botan.constants;
static if (BOTAN_HAS_SHA2_32 && BOTAN_HAS_SHA2_32_SSE2 && BOTAN_HAS_SIMD_SSE2):

import botan.hash.sha2_32;
import botan.hash.hash;
import botan.utils.rotate;
import botan.utils.loadstor;
import botan.utils.simd.emmintrin;
import botan.utils.types;

private uint sha2Rho(uint x, uint r1, uint r2, uint r3)
{
    return rotateRight(x, r1) ^ rotateRight(x, r2) ^ rotateRight(x, r3);
}

/// SHA-256 F without message expansion (C++ sha2_32_f.h).
private void sha2F(ref uint A, ref uint B, ref uint C, ref uint D,
                   ref uint E, ref uint F, ref uint G, ref uint H, uint M)
{
    H += M + sha2Rho(E, 6, 11, 25) + ((E & F) ^ (~E & G));
    D += H;
    H += sha2Rho(A, 2, 13, 22) + ((A & B) | ((A | B) & C));
}

private __m128i simdRotr(int n)(__m128i x)
{
    return _mm_or_si128(_mm_srli_epi32!n(x), _mm_slli_epi32!(32 - n)(x));
}

/// _mm_alignr_epi8(a, b, 4) via SSE2 (no SSSE3).
private __m128i simdAlignr4(__m128i a, __m128i b)
{
    return _mm_or_si128(_mm_srli_si128!4(b), _mm_slli_si128!12(a));
}

/// C++ sha256_simd_next_w: expand 4 new W words, rotate WS, return the new vector.
private __m128i sha256SimdNextW(ref __m128i[4] x)
{
    const lo_mask = _mm_set_epi32(0, 0, cast(int) 0xFFFFFFFF, cast(int) 0xFFFFFFFF);
    const hi_mask = _mm_set_epi32(cast(int) 0xFFFFFFFF, cast(int) 0xFFFFFFFF, 0, 0);

    auto t0 = simdAlignr4(x[1], x[0]);
    x[0] = _mm_add_epi32(x[0], simdAlignr4(x[3], x[2]));
    auto s0 = _mm_xor_si128(_mm_xor_si128(simdRotr!7(t0), simdRotr!18(t0)), _mm_srli_epi32!3(t0));
    x[0] = _mm_add_epi32(x[0], s0);

    t0 = _mm_shuffle_epi32!(_MM_SHUFFLE(3, 2, 3, 2))(x[3]);
    auto s1 = _mm_xor_si128(_mm_xor_si128(simdRotr!17(t0), simdRotr!19(t0)), _mm_srli_epi32!10(t0));
    x[0] = _mm_add_epi32(x[0], _mm_and_si128(s1, lo_mask));

    t0 = _mm_shuffle_epi32!(_MM_SHUFFLE(1, 0, 1, 0))(x[0]);
    s1 = _mm_xor_si128(_mm_xor_si128(simdRotr!17(t0), simdRotr!19(t0)), _mm_srli_epi32!10(t0));
    x[0] = _mm_add_epi32(x[0], _mm_and_si128(s1, hi_mask));

    const tmp = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = tmp;
    return x[3];
}

private __m128i loadBe4(const(ubyte)* p)
{
    align(16) uint[4] t;
    t[0] = loadBigEndian!uint(p, 0);
    t[1] = loadBigEndian!uint(p, 1);
    t[2] = loadBigEndian!uint(p, 2);
    t[3] = loadBigEndian!uint(p, 3);
    return _mm_loadu_si128(cast(const(__m128i)*) t.ptr);
}

/// SSE2 message-schedule SHA-224/256 compress (C++ sha2_32_simd.cpp).
void compressSha232Sse2(ref uint[8] digest, const(ubyte)* input, size_t blocks)
{
    static immutable uint[64] K = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    ];

    uint A = digest[0], B = digest[1], C = digest[2], D = digest[3];
    uint E = digest[4], F = digest[5], G = digest[6], H = digest[7];
    const(ubyte)* data = input;
    align(16) uint[16] W;

    foreach (size_t _; 0 .. blocks)
    {
        __m128i[4] WS;
        foreach (i; 0 .. 4)
        {
            WS[i] = loadBe4(data + 16 * i);
            auto wk = _mm_add_epi32(WS[i], _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 4 * i)));
            _mm_storeu_si128(cast(__m128i*)(W.ptr + 4 * i), wk);
        }
        data += 64;

        foreach (r; [0, 16, 32])
        {
            auto w = _mm_add_epi32(sha256SimdNextW(WS),
                _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + r + 16)));
            sha2F(A, B, C, D, E, F, G, H, W[0]);
            sha2F(H, A, B, C, D, E, F, G, W[1]);
            sha2F(G, H, A, B, C, D, E, F, W[2]);
            sha2F(F, G, H, A, B, C, D, E, W[3]);
            _mm_storeu_si128(cast(__m128i*) W.ptr, w);

            w = _mm_add_epi32(sha256SimdNextW(WS),
                _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + r + 20)));
            sha2F(E, F, G, H, A, B, C, D, W[4]);
            sha2F(D, E, F, G, H, A, B, C, W[5]);
            sha2F(C, D, E, F, G, H, A, B, W[6]);
            sha2F(B, C, D, E, F, G, H, A, W[7]);
            _mm_storeu_si128(cast(__m128i*)(W.ptr + 4), w);

            w = _mm_add_epi32(sha256SimdNextW(WS),
                _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + r + 24)));
            sha2F(A, B, C, D, E, F, G, H, W[8]);
            sha2F(H, A, B, C, D, E, F, G, W[9]);
            sha2F(G, H, A, B, C, D, E, F, W[10]);
            sha2F(F, G, H, A, B, C, D, E, W[11]);
            _mm_storeu_si128(cast(__m128i*)(W.ptr + 8), w);

            w = _mm_add_epi32(sha256SimdNextW(WS),
                _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + r + 28)));
            sha2F(E, F, G, H, A, B, C, D, W[12]);
            sha2F(D, E, F, G, H, A, B, C, W[13]);
            sha2F(C, D, E, F, G, H, A, B, W[14]);
            sha2F(B, C, D, E, F, G, H, A, W[15]);
            _mm_storeu_si128(cast(__m128i*)(W.ptr + 12), w);
        }

        sha2F(A, B, C, D, E, F, G, H, W[0]);
        sha2F(H, A, B, C, D, E, F, G, W[1]);
        sha2F(G, H, A, B, C, D, E, F, W[2]);
        sha2F(F, G, H, A, B, C, D, E, W[3]);
        sha2F(E, F, G, H, A, B, C, D, W[4]);
        sha2F(D, E, F, G, H, A, B, C, W[5]);
        sha2F(C, D, E, F, G, H, A, B, W[6]);
        sha2F(B, C, D, E, F, G, H, A, W[7]);
        sha2F(A, B, C, D, E, F, G, H, W[8]);
        sha2F(H, A, B, C, D, E, F, G, W[9]);
        sha2F(G, H, A, B, C, D, E, F, W[10]);
        sha2F(F, G, H, A, B, C, D, E, W[11]);
        sha2F(E, F, G, H, A, B, C, D, W[12]);
        sha2F(D, E, F, G, H, A, B, C, W[13]);
        sha2F(C, D, E, F, G, H, A, B, W[14]);
        sha2F(B, C, D, E, F, G, H, A, W[15]);

        A = (digest[0] += A);
        B = (digest[1] += B);
        C = (digest[2] += C);
        D = (digest[3] += D);
        E = (digest[4] += E);
        F = (digest[5] += F);
        G = (digest[6] += G);
        H = (digest[7] += H);
    }
}

class SHA256SSE2 : SHA256
{
public:
    override HashFunction clone() const { return new SHA256SSE2; }

protected:
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        assert(m_digest.length == 8);
        uint[8] digest = m_digest.ptr[0 .. 8];
        compressSha232Sse2(digest, input, blocks);
        m_digest[] = digest.ptr[0 .. 8];
    }
}

class SHA224SSE2 : SHA224
{
public:
    override HashFunction clone() const { return new SHA224SSE2; }

protected:
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        assert(m_digest.length == 8);
        uint[8] digest = m_digest.ptr[0 .. 8];
        compressSha232Sse2(digest, input, blocks);
        m_digest[] = digest.ptr[0 .. 8];
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.rng.auto_rng;

    auto gs = globalState();
    size_t fails;

    void checkPair(string name, HashFunction portable, HashFunction simd, const(ubyte)[] msg)
    {
        portable.update(msg.ptr, msg.length);
        simd.update(msg.ptr, msg.length);
        auto a = portable.finished();
        auto b = simd.finished();
        if (a[] != b[])
        {
            logError(name, " SSE2 mismatch len ", msg.length);
            ++fails;
        }
    }

    {
        Unique!SHA256 p256 = new SHA256;
        Unique!SHA256SSE2 s256 = new SHA256SSE2;
        Unique!SHA224 p224 = new SHA224;
        Unique!SHA224SSE2 s224 = new SHA224SSE2;
        checkPair("SHA-256", p256, s256, null);
        checkPair("SHA-224", p224, s224, null);
        checkPair("SHA-256", p256, s256, cast(const(ubyte)[]) "abc");
        checkPair("SHA-224", p224, s224, cast(const(ubyte)[]) "abc");
        auto longmsg = new ubyte[64 * 3 + 17];
        foreach (i; 0 .. longmsg.length)
            longmsg[i] = cast(ubyte)(i * 17 + 3);
        checkPair("SHA-256", p256, s256, longmsg);
        checkPair("SHA-224", p224, s224, longmsg);
    }

    fails += checkMemutilsRepeat("sha2_32_sse2", {
        Unique!SHA256SSE2 h = new SHA256SSE2;
        ubyte[80] msg = 0x5a;
        h.update(msg.ptr, msg.length);
        auto d = h.finished();
        if (d.length != 32)
            throw new Exception("sha2 sse2 digest");
    });

    testReport("sha2_32_sse2", 6, fails);
    assert(fails == 0);
}
