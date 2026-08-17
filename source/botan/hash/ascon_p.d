/**
* Ascon-p (NIST SP.800-232 §3)
*
* Copyright:
* (C) 2025 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.ascon_p;

import botan.constants;
static if (BOTAN_HAS_ASCON_HASH256 || BOTAN_HAS_AEAD_ASCON128 || BOTAN_HAS_ASCON_XOF128):

import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;
import std.algorithm : min;

/**
* 5-word Ascon sponge. Words are little-endian on the rate bytes.
*/
struct AsconP
{
    this(ubyte init_final_rounds, ubyte processing_rounds, size_t bit_rate, ulong[5] initial)
    {
        S = initial;
        cursor = 0;
        this.init_final_rounds = init_final_rounds;
        this.processing_rounds = processing_rounds;
        byte_rate = bit_rate / 8;
    }

    void reset(ulong[5] initial)
    {
        S = initial;
        cursor = 0;
    }

    void permute() { permuteN(processing_rounds); }
    void initialPermute() { permuteN(init_final_rounds); }

    void absorb(const(ubyte)* input, size_t length)
    {
        absorb(input, length, processing_rounds);
    }

    void absorb(const(ubyte)* input, size_t length, ubyte rounds)
    {
        processBytes(length, rounds,
            (ulong sw, size_t off, size_t len, const(ubyte)* p) {
                return sw ^ loadPart(p, off, len);
            },
            (ulong a, ulong b, size_t c, size_t d, ubyte* e) {},
            input, null);
    }

    void squeeze(ubyte* output, size_t length)
    {
        processBytes(length, processing_rounds,
            (ulong sw, size_t off, size_t len, const(ubyte)* p) { return sw; },
            (ulong oldw, ulong neww, size_t off, size_t len, ubyte* p) { storePart(p, oldw, off, len); },
            null, output);
    }

    void percolateIn(ubyte* data, size_t length)
    {
        processBytes(length, processing_rounds,
            (ulong sw, size_t off, size_t len, const(ubyte)* p) {
                return sw ^ loadPart(p, off, len);
            },
            (ulong oldw, ulong neww, size_t off, size_t len, ubyte* p) { storePart(p, neww, off, len); },
            data, data);
    }

    void percolateOut(ubyte* data, size_t length)
    {
        processBytes(length, processing_rounds,
            (ulong sw, size_t off, size_t len, const(ubyte)* p) {
                return maskAssign(sw, loadPart(p, off, len), off, len);
            },
            (ulong oldw, ulong neww, size_t off, size_t len, ubyte* p) {
                storePart(p, oldw ^ loadPart(p, off, len), off, len);
            },
            data, data);
    }

    void finish() { finish(init_final_rounds); }
    void intermediateFinish() { finish(processing_rounds); }

    void finish(ubyte rounds)
    {
        ubyte[16] pad;
        pad[0] = 0x01;
        const size_t n = byte_rate - cursor;
        absorb(pad.ptr, n, rounds);
    }

    void permuteN(ubyte rounds)
    {
        __gshared immutable ulong[16] RC = [
            0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
            0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        ];
        foreach (ubyte i; 0 .. rounds)
        {
            S[2] ^= RC[16 - rounds + i];

            S[0] ^= S[4];
            S[4] ^= S[3];
            S[2] ^= S[1];
            ulong[5] tmp = S;
            tmp[0] = ~tmp[0] & S[1];
            tmp[1] = ~tmp[1] & S[2];
            tmp[2] = ~tmp[2] & S[3];
            tmp[3] = ~tmp[3] & S[4];
            tmp[4] = ~tmp[4] & S[0];
            S[0] ^= tmp[1];
            S[1] ^= tmp[2];
            S[2] ^= tmp[3];
            S[3] ^= tmp[4];
            S[4] ^= tmp[0];
            S[1] ^= S[0];
            S[0] ^= S[4];
            S[3] ^= S[2];
            S[2] = ~S[2];

            S[0] = S[0] ^ rotateRight(S[0], 19) ^ rotateRight(S[0], 28);
            S[1] = S[1] ^ rotateRight(S[1], 61) ^ rotateRight(S[1], 39);
            S[2] = S[2] ^ rotateRight(S[2], 1) ^ rotateRight(S[2], 6);
            S[3] = S[3] ^ rotateRight(S[3], 10) ^ rotateRight(S[3], 17);
            S[4] = S[4] ^ rotateRight(S[4], 7) ^ rotateRight(S[4], 41);
        }
    }

    ulong[5] S;
    size_t cursor;
    ubyte init_final_rounds;
    ubyte processing_rounds;
    size_t byte_rate;

private:
    void processBytes(size_t n, ubyte rounds,
                      ulong delegate(ulong, size_t, size_t, const(ubyte)*) modify,
                      void delegate(ulong, ulong, size_t, size_t, ubyte*) emit,
                      const(ubyte)* rin, ubyte* wout)
    {
        if (n == 0)
            return;

        void step(size_t off, size_t take)
        {
            const ulong oldw = S[cursor / 8];
            const ulong sw = modify(oldw, off, take, rin);
            if (wout)
                emit(oldw, sw, off, take, wout);
            S[cursor / 8] = sw;
            cursor += take;
            if (rin)
                rin += take;
            if (wout)
                wout += take;
        }

        const size_t mis = cursor % 8;
        if (mis)
        {
            const size_t take = min(n, 8 - mis);
            step(mis, take);
            n -= take;
            if (cursor == byte_rate)
            {
                permuteN(rounds);
                cursor = 0;
            }
        }

        while (n >= 8)
        {
            while (n >= 8 && cursor < byte_rate)
            {
                step(0, 8);
                n -= 8;
            }
            if (cursor == byte_rate)
            {
                permuteN(rounds);
                cursor = 0;
            }
        }

        if (n)
            step(0, n);
    }
}

private:

ulong loadPart(const(ubyte)* p, size_t offset, size_t length)
{
    ulong w = 0;
    if (!p)
        return 0;
    foreach (i; 0 .. length)
        w |= cast(ulong) p[i] << (8 * (offset + i));
    return w;
}

void storePart(ubyte* p, ulong w, size_t offset, size_t length)
{
    if (!p)
        return;
    foreach (i; 0 .. length)
        p[i] = cast(ubyte)(w >> (8 * (offset + i)));
}

ulong maskAssign(ulong state_word, ulong in_word, size_t offset, size_t length)
{
    const ulong mask = ((~0UL) >> ((8 - length) * 8)) << (offset * 8);
    return (state_word & ~mask) | (in_word & mask);
}
