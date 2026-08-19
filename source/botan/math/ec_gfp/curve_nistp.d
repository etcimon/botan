/*
* NIST curve reduction
*
* Copyright:
* (C) 2014,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.math.ec_gfp.curve_nistp;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.math.ec_gfp.curve_gfp;
import botan.math.bigint.bigint;
import botan.math.mp.mp_core;
import botan.codec.hex;
import botan.utils.types;
import botan.utils.mem_ops;

abstract class CurveGFpNIST : CurveGFpRepr
{
    this()(size_t p_bits, BigInt* a, BigInt* b)
    {
        m_a = a.clone;
        m_b = b.clone;
        m_p_words = (p_bits + BOTAN_MP_WORD_BITS - 1) / BOTAN_MP_WORD_BITS;
    }

    override ref const(BigInt) getA() const { return m_a; }
    
    override ref const(BigInt) getB() const { return m_b; }
    
    override ref const(BigInt) getARep() const { return m_a; }
    
    override ref const(BigInt) getBRep() const { return m_b; }

    override size_t getPWords() const { return m_p_words; }

    override void toCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        redc(x, ws);
    }
    
    override void fromCurveRep(BigInt* x, ref SecureVector!word ws) const
    {
        redc(x, ws);
    }
    
    /**
    * Montgomery multiplication/reduction
    * Notes: z cannot alias x or y
    * Params:
    *  z = output
    *  x = first multiplicand
    *  y = second multiplicand
    */
    override void curveMul(BigInt* z, const(BigInt)* x, const(BigInt)* y, ref SecureVector!word ws) const
    {
        if (x.isZero() || y.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }
        
        const size_t p_words = getPWords();
        const size_t output_size = 2*p_words + 1;
        ws.resize(2*(p_words+2));
        
        z.growTo(output_size);
        z.clear();
        
        bigint_mul(z.mutablePtr(), output_size, ws.ptr,
            x.ptr, x.length, x.sigWords(),
            y.ptr, y.length, y.sigWords());
        
        this.redc(z, ws);
    }
    
    /**
    * Montgomery squaring/reduction
    * Notes: z cannot alias x
    * Params:
    *  z = output
    *  x = multiplicand
    */
    override void curveSqr(BigInt* z, const(BigInt)* x, ref SecureVector!word ws) const
    {
        if (x.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }
        
        const size_t p_words = getPWords();
        const size_t output_size = 2*p_words + 1;
        
        ws.resize(2*(p_words+2));
        
        z.growTo(output_size);
        z.clear();
        
        bigint_sqr(z.mutablePtr(), output_size, ws.ptr,
            x.ptr, x.length, x.sigWords());
        
        this.redc(z, ws);
    }
    
    override Vector!char toVector() const
    {
        Vector!char ret;
        ret ~= "\nm_a: ";
        ret ~= m_a.toString();
        ret ~= "\nm_b: ";
        ret ~= m_b.toString();
        ret ~= "\nm_p_words: ";
        ret ~= m_p_words.to!string;
        ret ~= "\n";
        return ret.move();
    }
    
    override void swap(CurveGFpRepr other_) {
        auto other = cast(CurveGFpNIST) other_;
        m_a.swap(&other.m_a);
        m_b.swap(&other.m_b);
        import std.algorithm.mutation : swap;
        swap(m_p_words, other.m_p_words);
    }

protected:
    abstract void redc(BigInt* x, ref SecureVector!word ws) const;

    abstract size_t maxRedcSubstractions() const;
private:
    // Curve parameters
    BigInt m_a, m_b;
    
    size_t m_p_words; // cache of m_p.sigWords()    
}

/**
* The NIST P-521 curve
*/
class CurveGFpP521 : CurveGFpNIST
{
public:
    this()(BigInt* a, BigInt* b)
    {
		if (prime == BigInt.init)
			prime = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

        super(521, a, b);
    }

    override ref const(BigInt) getP() const { return prime; }

    override void redc(BigInt* x, ref SecureVector!word ws) const
    {
        const size_t p_words = getPWords();
        
        const size_t shift_words = 521 / MP_WORD_BITS,
            shift_bits  = 521 % MP_WORD_BITS;
        
        const size_t x_sw = x.sigWords();
        
        if (x_sw < p_words)
            return; // already smaller
        
        if (ws.length < p_words + 1)
            ws.resize(p_words + 1);
        
        clearMem(ws.ptr, ws.length);
        bigint_shr2(ws.ptr, x.ptr, x_sw, shift_words, shift_bits);
        
        x.maskBits(521);
        
        bigint_add3(x.mutablePtr(), x.ptr, p_words, ws.ptr, p_words);
        
        normalize(x, ws, maxRedcSubstractions());
    }

    override size_t maxRedcSubstractions() const
    {
        return 1;
    }

    static bool matchesPrime(const BigInt* p)
    {
        static if (BOTAN_MP_WORD_BITS == 64)
            return p.sigWords() == 9
                && p.wordAt(8) == 0x1FF
                && p.wordAt(7) == word.max
                && p.wordAt(6) == word.max
                && p.wordAt(5) == word.max
                && p.wordAt(4) == word.max
                && p.wordAt(3) == word.max
                && p.wordAt(2) == word.max
                && p.wordAt(1) == word.max
                && p.wordAt(0) == word.max;
        else
            return p.sigWords() == 17
                && p.wordAt(16) == 0x1FF
                && p.wordAt(15) == word.max
                && p.wordAt(14) == word.max
                && p.wordAt(13) == word.max
                && p.wordAt(12) == word.max
                && p.wordAt(11) == word.max
                && p.wordAt(10) == word.max
                && p.wordAt(9) == word.max
                && p.wordAt(8) == word.max
                && p.wordAt(7) == word.max
                && p.wordAt(6) == word.max
                && p.wordAt(5) == word.max
                && p.wordAt(4) == word.max
                && p.wordAt(3) == word.max
                && p.wordAt(2) == word.max
                && p.wordAt(1) == word.max
                && p.wordAt(0) == word.max;
    }

    __gshared BigInt prime; 
}

/**
* secp256r1 / NIST P-256 generalized-Mersenne reduction.
*
* Identity field representation (same as P-521): mul/sqr then redc, no Montgomery
* transform. Port of Botan 1.11 `redc_p256` (FIPS 186 / SP 800-186 G.1.2 column
* sums with a 6·P bias). Callgrind after TLSGC/sigWords/m_ws reuse: monty_redc +
* monty_cios4 were ~6.8% Ir of an ECDSA P-256 handshake.
*/
class CurveGFpP256 : CurveGFpNIST
{
public:
    this()(BigInt* a, BigInt* b)
    {
        ensurePrime();
        super(256, a, b);
    }

    override ref const(BigInt) getP() const { return prime; }

    override void curveMul(BigInt* z, const(BigInt)* x, const(BigInt)* y, ref SecureVector!word ws) const
    {
        if (x.isZero() || y.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }

        static if (BOTAN_MP_WORD_BITS == 64)
        {
            if (x.sigWords() <= 4 && y.sigWords() <= 4)
            {
                word[4] x4 = load4(x);
                word[4] y4 = load4(y);
                word[8] prod = void;
                bigint_comba_mul4(prod, x4, y4);
                redc512(prod);
                store4(z, prod);
                return;
            }
        }

        super.curveMul(z, x, y, ws);
    }

    override void curveSqr(BigInt* z, const(BigInt)* x, ref SecureVector!word ws) const
    {
        if (x.isZero())
        {
            BigInt zero = BigInt(0);
            z.swap(&zero);
            return;
        }

        static if (BOTAN_MP_WORD_BITS == 64)
        {
            if (x.sigWords() <= 4)
            {
                word[4] x4 = load4(x);
                word[8] prod = void;
                bigint_comba_sqr4(prod, x4);
                redc512(prod);
                store4(z, prod);
                return;
            }
        }

        super.curveSqr(z, x, ws);
    }

    override void redc(BigInt* x, ref SecureVector!word ws) const
    {
        if (x.isNegative())
            normalize(x, ws, 0);

        const size_t sw = x.sigWords();
        if (sw == 0)
            return;

        static if (BOTAN_MP_WORD_BITS == 64)
        {
            if (sw > 8)
            {
                *x %= getP();
                return;
            }
            word[8] prod = 0;
            const word* xp = x.ptr;
            const size_t n = x.size() < 8 ? x.size() : 8;
            foreach (size_t i; 0 .. n)
                prod[i] = xp[i];
            redc512(prod);
            store4(x, prod);
        }
        else
        {
            *x %= getP();
        }
    }

    override size_t maxRedcSubstractions() const
    {
        return 10;
    }

    static bool matchesPrime(const BigInt* p)
    {
        static if (BOTAN_MP_WORD_BITS == 64)
            return p.sigWords() == 4
                && p.wordAt(0) == 0xFFFFFFFFFFFFFFFF
                && p.wordAt(1) == 0x00000000FFFFFFFF
                && p.wordAt(2) == 0
                && p.wordAt(3) == 0xFFFFFFFF00000001;
        else
            return p.sigWords() == 8
                && p.wordAt(0) == 0xFFFFFFFF
                && p.wordAt(1) == 0xFFFFFFFF
                && p.wordAt(2) == 0xFFFFFFFF
                && p.wordAt(3) == 0
                && p.wordAt(4) == 0
                && p.wordAt(5) == 0
                && p.wordAt(6) == 0x00000001
                && p.wordAt(7) == 0xFFFFFFFF;
    }

    __gshared BigInt prime;

private:
    static void ensurePrime()
    {
        if (prime.isZero())
            prime = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    }

    static if (BOTAN_MP_WORD_BITS == 64)
    {
        enum word P0 = 0xFFFFFFFFFFFFFFFF;
        enum word P1 = 0x00000000FFFFFFFF;
        enum word P2 = 0;
        enum word P3 = 0xFFFFFFFF00000001;

        pragma(inline, true)
        static word[4] load4(const(BigInt)* v)
        {
            const word* p = v.ptr;
            const size_t n = v.size();
            word[4] r = 0;
            if (n > 0) r[0] = p[0];
            if (n > 1) r[1] = p[1];
            if (n > 2) r[2] = p[2];
            if (n > 3) r[3] = p[3];
            return r;
        }

        static void store4(BigInt* z, ref const word[8] prod)
        {
            z.growTo(4);
            word* zp = z.mutablePtr();
            zp[0] = prod[0];
            zp[1] = prod[1];
            zp[2] = prod[2];
            zp[3] = prod[3];
            foreach (size_t i; 4 .. z.size())
                zp[i] = 0;
            z.setSign(BigInt.Positive);
        }

        pragma(inline, true)
        static uint u32(const word* w, size_t i)
        {
            return (i & 1) ? cast(uint)(w[i / 2] >> 32) : cast(uint) w[i / 2];
        }

        pragma(inline, true)
        static void setU32(word* w, size_t i, uint v)
        {
            const word shift_32 = (i % 2) * 32;
            const word keep = (cast(word) 0xFFFFFFFF) << (32 - shift_32);
            w[i / 2] = (w[i / 2] & keep) | (cast(word) v << shift_32);
        }

        // Botan 1.11 redc_p256 on a 512-bit product. Final P-sub is in-place
        // (no BigInt.swapReg) — callgrind showed normalize at 58% inclusive Ir.
        static void redc512(ref word[8] z)
        {
            const uint X8  = u32(z.ptr, 8);
            const uint X9  = u32(z.ptr, 9);
            const uint X10 = u32(z.ptr, 10);
            const uint X11 = u32(z.ptr, 11);
            const uint X12 = u32(z.ptr, 12);
            const uint X13 = u32(z.ptr, 13);
            const uint X14 = u32(z.ptr, 14);
            const uint X15 = u32(z.ptr, 15);

            word[5] r = 0;
            r[0] = z[0];
            r[1] = z[1];
            r[2] = z[2];
            r[3] = z[3];

            long S = 0;
            S = u32(r.ptr, 0);
            S += 0xFFFFFFFA;
            S += X8;
            S += X9;
            S -= X11;
            S -= X12;
            S -= X13;
            S -= X14;
            setU32(r.ptr, 0, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 1);
            S += 0xFFFFFFFF;
            S += X9;
            S += X10;
            S -= X12;
            S -= X13;
            S -= X14;
            S -= X15;
            setU32(r.ptr, 1, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 2);
            S += 0xFFFFFFFF;
            S += X10;
            S += X11;
            S -= X13;
            S -= X14;
            S -= X15;
            setU32(r.ptr, 2, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 3);
            S += 5;
            S += X11;
            S += X11;
            S += X12;
            S += X12;
            S += X13;
            S -= X15;
            S -= X8;
            S -= X9;
            setU32(r.ptr, 3, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 4);
            S += X12;
            S += X12;
            S += X13;
            S += X13;
            S += X14;
            S -= X9;
            S -= X10;
            setU32(r.ptr, 4, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 5);
            S += X13;
            S += X13;
            S += X14;
            S += X14;
            S += X15;
            S -= X10;
            S -= X11;
            setU32(r.ptr, 5, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 6);
            S += 6;
            S += X14;
            S += X14;
            S += X15;
            S += X15;
            S += X14;
            S += X13;
            S -= X8;
            S -= X9;
            setU32(r.ptr, 6, cast(uint) S);
            S >>= 32;

            S += u32(r.ptr, 7);
            S += 0xFFFFFFFA;
            S += X15;
            S += X15;
            S += X15;
            S += X8;
            S -= X10;
            S -= X11;
            S -= X12;
            S -= X13;
            setU32(r.ptr, 7, cast(uint) S);
            S >>= 32;

            S += 5;
            setU32(r.ptr, 8, cast(uint) S);

            while (true)
            {
                word borrow = 0;
                const word t0 = word_sub(r[0], P0, &borrow);
                const word t1 = word_sub(r[1], P1, &borrow);
                const word t2 = word_sub(r[2], P2, &borrow);
                const word t3 = word_sub(r[3], P3, &borrow);
                const word t4 = word_sub(r[4], 0, &borrow);
                if (borrow)
                    break;
                r[0] = t0;
                r[1] = t1;
                r[2] = t2;
                r[3] = t3;
                r[4] = t4;
            }

            z[0] = r[0];
            z[1] = r[1];
            z[2] = r[2];
            z[3] = r[3];
            z[4] = 0;
            z[5] = 0;
            z[6] = 0;
            z[7] = 0;
        }
    }
}

