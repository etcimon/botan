/**
* SHA-{224,256} with Intel SHA-NI (C++ sha2_32_x86)
*
* Copyright:
* (C) 2017,2020,2025,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.sha2_32_x86;

import botan.constants;
static if (BOTAN_HAS_SHA2_32 && BOTAN_HAS_SHA2_32_X86 && BOTAN_HAS_SIMD_SSE2):

import botan.hash.sha2_32;
import botan.hash.hash;
import botan.utils.loadstor;
import botan.utils.simd.emmintrin;
import botan.utils.simd.shaintrin;
import botan.utils.types;

private __m128i loadBePtr(const(ubyte)* p)
{
    // C++ SIMD_4x32::load_be: pshufb each dword. SHA-NI CPUs have SSSE3.
    version (LDC)
    {
        import ldc.gccbuiltins_x86 : __builtin_ia32_pshufb128;
        import core.simd : byte16;
        ulong[2] t = void;
        t[0] = *cast(const ulong*) p;
        t[1] = *(cast(const ulong*) p + 1);
        immutable byte16 m = byte16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);
        return cast(__m128i) __builtin_ia32_pshufb128(*cast(byte16*) t.ptr, m);
    }
    else
    {
        align(16) uint[4] t;
        t[0] = loadBigEndian!uint(p, 0);
        t[1] = loadBigEndian!uint(p, 1);
        t[2] = loadBigEndian!uint(p, 2);
        t[3] = loadBigEndian!uint(p, 3);
        return _mm_loadu_si128(cast(__m128i*) t.ptr);
    }
}

private __m128i alignr4(__m128i a, __m128i b)
{
    version (LDC)
    {
        import ldc.llvmasm : __asm;
        return __asm!__m128i("palignr $$4, $2, $0", "=x,0,x", a, b);
    }
    else
        return _mm_or_si128(_mm_srli_si128!4(b), _mm_slli_si128!12(a));
}

private __m128i alignr8(__m128i a, __m128i b)
{
    version (LDC)
    {
        import ldc.llvmasm : __asm;
        return __asm!__m128i("palignr $$8, $2, $0", "=x,0,x", a, b);
    }
    else
        return _mm_or_si128(_mm_srli_si128!8(b), _mm_slli_si128!8(a));
}

private __m128i blendHi64(__m128i lo_src, __m128i hi_src)
{
    version (LDC)
    {
        import ldc.llvmasm : __asm;
        // pblendw imm 0xF0: high 64 from hi_src, low 64 from lo_src.
        return __asm!__m128i("pblendw $$0xF0, $2, $0", "=x,0,x", lo_src, hi_src);
    }
    else
    {
        const lo = _mm_set_epi32(0, 0, cast(int) 0xFFFFFFFF, cast(int) 0xFFFFFFFF);
        const hi = _mm_set_epi32(cast(int) 0xFFFFFFFF, cast(int) 0xFFFFFFFF, 0, 0);
        return _mm_or_si128(_mm_and_si128(lo_src, lo), _mm_and_si128(hi_src, hi));
    }
}

private void sha256Rnds4(ref __m128i S0, ref __m128i S1, __m128i msg, __m128i k)
{
    auto mk = _mm_add_epi32(msg, k);
    S1 = _mm_sha256rnds2_epu32(S1, S0, mk);
    auto mk2 = _mm_srli_si128!8(mk);
    S0 = _mm_sha256rnds2_epu32(S0, S1, mk2);
}

private void sha256MsgExp(ref __m128i W0, ref __m128i W1, ref __m128i W2, ref __m128i W3)
{
    W2 = _mm_add_epi32(W2, alignr4(W1, W0));
    W0 = _mm_sha256msg1_epu32(W0, W1);
    W2 = _mm_sha256msg2_epu32(W2, W1);
    W3 = _mm_add_epi32(W3, alignr4(W2, W1));
    W1 = _mm_sha256msg1_epu32(W1, W2);
    W3 = _mm_sha256msg2_epu32(W3, W2);
}

private void sha256PermuteState(ref __m128i S0, ref __m128i S1)
{
    S0 = _mm_shuffle_epi32!0b10110001(S0);
    S1 = _mm_shuffle_epi32!0b00011011(S1);
    const T = alignr8(S0, S1);
    S1 = blendHi64(S1, S0);
    S0 = T;
}

package void compressSha232X86(ref uint[8] digest, const(ubyte)* input, size_t blocks)
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

    auto S0 = _mm_loadu_si128(cast(const(__m128i)*) digest.ptr);
    auto S1 = _mm_loadu_si128(cast(const(__m128i)*)(digest.ptr + 4));
    sha256PermuteState(S0, S1);

    const(ubyte)* p = input;
    foreach (size_t _; 0 .. blocks)
    {
        const S0s = S0;
        const S1s = S1;
        auto W0 = loadBePtr(p);
        auto W1 = loadBePtr(p + 16);
        auto W2 = loadBePtr(p + 32);
        auto W3 = loadBePtr(p + 48);

        sha256Rnds4(S0, S1, W0, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 0)));
        sha256Rnds4(S0, S1, W1, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 4)));
        sha256Rnds4(S0, S1, W2, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 8)));
        sha256Rnds4(S0, S1, W3, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 12)));

        W0 = _mm_sha256msg1_epu32(W0, W1);
        W1 = _mm_sha256msg1_epu32(W1, W2);
        sha256MsgExp(W2, W3, W0, W1);
        sha256Rnds4(S0, S1, W0, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 16)));
        sha256Rnds4(S0, S1, W1, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 20)));
        sha256MsgExp(W0, W1, W2, W3);
        sha256Rnds4(S0, S1, W2, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 24)));
        sha256Rnds4(S0, S1, W3, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 28)));
        sha256MsgExp(W2, W3, W0, W1);
        sha256Rnds4(S0, S1, W0, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 32)));
        sha256Rnds4(S0, S1, W1, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 36)));
        sha256MsgExp(W0, W1, W2, W3);
        sha256Rnds4(S0, S1, W2, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 40)));
        sha256Rnds4(S0, S1, W3, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 44)));
        sha256MsgExp(W2, W3, W0, W1);
        sha256Rnds4(S0, S1, W0, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 48)));
        sha256Rnds4(S0, S1, W1, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 52)));
        sha256MsgExp(W0, W1, W2, W3);
        sha256Rnds4(S0, S1, W2, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 56)));
        sha256Rnds4(S0, S1, W3, _mm_loadu_si128(cast(const(__m128i)*)(K.ptr + 60)));

        S0 = _mm_add_epi32(S0, S0s);
        S1 = _mm_add_epi32(S1, S1s);
        p += 64;
    }

    sha256PermuteState(S1, S0);
    _mm_storeu_si128(cast(__m128i*) digest.ptr, S0);
    _mm_storeu_si128(cast(__m128i*)(digest.ptr + 4), S1);
}

class SHA256X86 : SHA256
{
public:
    override HashFunction clone() const { return new SHA256X86; }

protected:
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        assert(m_digest.length == 8);
        uint[8] digest = m_digest.ptr[0 .. 8];
        compressSha232X86(digest, input, blocks);
        m_digest[] = digest.ptr[0 .. 8];
    }
}

class SHA224X86 : SHA224
{
public:
    override HashFunction clone() const { return new SHA224X86; }

protected:
    override void compressN(const(ubyte)* input, size_t blocks)
    {
        assert(m_digest.length == 8);
        uint[8] digest = m_digest.ptr[0 .. 8];
        compressSha232X86(digest, input, blocks);
        m_digest[] = digest.ptr[0 .. 8];
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_HASH_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.utils.cpuid;

    auto gs = globalState();
    size_t fails;

    if (CPUID.hasIntelSha())
    {
        void checkPair(string name, HashFunction portable, HashFunction acc, const(ubyte)[] msg)
        {
            portable.update(msg.ptr, msg.length);
            acc.update(msg.ptr, msg.length);
            auto a = portable.finished();
            auto b = acc.finished();
            if (a[] != b[])
            {
                logError(name, " SHA-NI mismatch len ", msg.length);
                ++fails;
            }
        }

        Unique!SHA256 p256 = new SHA256;
        Unique!SHA256X86 s256 = new SHA256X86;
        Unique!SHA224 p224 = new SHA224;
        Unique!SHA224X86 s224 = new SHA224X86;
        checkPair("SHA-256", p256, s256, null);
        checkPair("SHA-224", p224, s224, null);
        checkPair("SHA-256", p256, s256, cast(const(ubyte)[]) "abc");
        checkPair("SHA-224", p224, s224, cast(const(ubyte)[]) "abc");
        auto longmsg = new ubyte[64 * 3 + 17];
        foreach (i; 0 .. longmsg.length)
            longmsg[i] = cast(ubyte)(i * 17 + 3);
        checkPair("SHA-256", p256, s256, longmsg);
        checkPair("SHA-224", p224, s224, longmsg);

        fails += checkMemutilsRepeat("sha2_32_x86", {
            Unique!SHA256X86 h = new SHA256X86;
            ubyte[80] msg = 0x5a;
            h.update(msg.ptr, msg.length);
            auto d = h.finished();
            if (d.length != 32)
                throw new Exception("sha2 x86 digest");
        });
        testReport("sha2_32_x86", 6, fails);
    }
    else
        testReport("sha2_32_x86", 0, fails);

    assert(fails == 0);
}
