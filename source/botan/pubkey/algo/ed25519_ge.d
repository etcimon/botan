/**
* Ed25519 group operations
*
* Copyright:
* (C) 2017 Ribose Inc
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ed25519_ge;

import botan.constants;
static if (BOTAN_HAS_ED25519):

import botan.pubkey.algo.ed25519_fe;

struct GeP2
{
    Fe X, Y, Z;

    static GeP2 identity()
    {
        GeP2 h;
        h.X = Fe.zero();
        h.Y = Fe.one();
        h.Z = Fe.one();
        return h;
    }

    static GeP2 from(in GeP1P1 p)
    {
        GeP2 r;
        r.X = p.X * p.T;
        r.Y = p.Y * p.Z;
        r.Z = p.Z * p.T;
        return r;
    }

    GeP1P1 dbl() const
    {
        GeP1P1 r;
        r.X = X.sqr();
        r.Z = Y.sqr();
        r.T = Z.sqr2();
        r.Y = X + Y;
        auto t0 = r.Y.sqr();
        r.Y = r.Z + r.X;
        r.Z = r.Z - r.X;
        r.X = t0 - r.Y;
        r.T = r.T - r.Z;
        return r;
    }

    void serializeTo(ref ubyte[32] s) const
    {
        auto recip = Z.invert();
        auto x = X * recip;
        auto y = Y * recip;
        y.serializeTo(s);
        s[31] ^= x.isNegative() ? 0x80 : 0x00;
    }
}

struct GeP1P1
{
    Fe X, Y, Z, T;
}

struct GeP3
{
    Fe X, Y, Z, T;

    static GeP3 identity()
    {
        GeP3 h;
        h.X = Fe.zero();
        h.Y = Fe.one();
        h.Z = Fe.one();
        h.T = Fe.zero();
        return h;
    }

    static GeP3 from(in GeP1P1 p)
    {
        GeP3 r;
        r.X = p.X * p.T;
        r.Y = p.Y * p.Z;
        r.Z = p.Z * p.T;
        r.T = p.X * p.Y;
        return r;
    }

    GeP1P1 dbl() const
    {
        GeP2 q;
        q.X = X; q.Y = Y; q.Z = Z;
        return q.dbl();
    }

    void serializeTo(ref ubyte[32] s) const
    {
        auto recip = Z.invert();
        auto x = X * recip;
        auto y = Y * recip;
        y.serializeTo(s);
        s[31] ^= x.isNegative() ? 0x80 : 0x00;
    }
}

struct GeCached
{
    Fe YplusX, YminusX, Z, T2d;

    static GeCached from(in GeP3 p)
    {
        immutable Fe d2 = Fe(-21827239, -5839606, -30745221, 13898782, 229458,
                             15978800, -12551817, -6495438, 29715968, 9444199);
        GeCached r;
        r.YplusX = p.Y + p.X;
        r.YminusX = p.Y - p.X;
        r.Z = p.Z;
        r.T2d = p.T * d2;
        return r;
    }
}

GeP1P1 geAdd(in GeP3 p, in GeCached q)
{
    GeP1P1 r;
    r.X = p.Y + p.X;
    r.Y = p.Y - p.X;
    r.Z = r.X * q.YplusX;
    r.Y = r.Y * q.YminusX;
    r.T = q.T2d * p.T;
    r.X = p.Z * q.Z;
    auto t0 = r.X + r.X;
    r.X = r.Z - r.Y;
    r.Y = r.Z + r.Y;
    r.Z = t0 + r.T;
    r.T = t0 - r.T;
    return r;
}

GeP1P1 geSub(in GeP3 p, in GeCached q)
{
    GeP1P1 r;
    r.X = p.Y + p.X;
    r.Y = p.Y - p.X;
    r.Z = r.X * q.YminusX;
    r.Y = r.Y * q.YplusX;
    r.T = q.T2d * p.T;
    r.X = p.Z * q.Z;
    auto t0 = r.X + r.X;
    r.X = r.Z - r.Y;
    r.Y = r.Z + r.Y;
    r.Z = t0 - r.T;
    r.T = t0 + r.T;
    return r;
}

bool geFrombytesNegateVartime(ref GeP3 h, const(ubyte)* s)
{
    immutable Fe d = Fe(-10913610, 13857413, -15372611, 6949391, 114729,
                        -8787816, -6275908, -3247719, -18696448, -12055116);
    immutable Fe sqrtm1 = Fe(-32595792, -7943725, 9377950, 3500415, 12389472,
                             -272473, -25146209, -2005654, 326686, 11406482);

    h = GeP3.identity();
    h.Y = Fe.deserialize(s);
    h.Z = Fe.one();
    auto u = h.Y.sqr();
    auto v = u * d;
    u = u - h.Z;
    v = v + h.Z;

    auto v3 = v.sqr() * v;
    h.X = v3.sqr();
    h.X = h.X * v;
    h.X = h.X * u;
    h.X = h.X.pow22523();
    h.X = h.X * v3;
    h.X = h.X * u;

    auto vxx = h.X.sqr();
    vxx = vxx * v;
    auto check = vxx - u;
    if (!check.isZero())
    {
        check = vxx + u;
        if (!check.isZero())
            return false;
        h.X = h.X * sqrtm1;
    }

    if (h.X.isNegative() == ((s[31] >> 7) != 0))
        h.X = -h.X;

    if (h.X.isZero() && ((s[31] >> 7) != 0))
        return false;

    h.T = h.X * h.Y;
    return true;
}

void geScalarmult(ref GeP3 r, const(ubyte)* a, in GeP3 A)
{
    auto Ai = GeCached.from(A);
    r = GeP3.identity();
    foreach_reverse (i; 0 .. 256)
    {
        auto t = r.dbl();
        r = GeP3.from(t);
        if ((a[i >> 3] >> (i & 7)) & 1)
            r = GeP3.from(geAdd(r, Ai));
    }
}

void ed25519BasepointMul(ubyte* output, const(ubyte)* a)
{
    GeP3 R;
    geScalarmult(R, a, decodeBasepoint());
    ubyte[32] outb;
    R.serializeTo(outb);
    output[0 .. 32] = outb[];
}

bool signatureCheck(const(ubyte)* pk, const(ubyte)* h, const(ubyte)* r, const(ubyte)* s)
{
    GeP3 A;
    if (!geFrombytesNegateVartime(A, pk))
        return false;
    GeP3 sB;
    geScalarmult(sB, s, decodeBasepoint());
    GeP3 hA;
    geScalarmult(hA, h, A);
    auto rcheck = GeP3.from(geAdd(sB, GeCached.from(hA)));
    ubyte[32] got;
    rcheck.serializeTo(got);
    ubyte acc = 0;
    foreach (i; 0 .. 32)
        acc |= got[i] ^ r[i];
    return acc == 0;
}

private:

GeP3 decodeBasepoint()
{
    static immutable ubyte[32] Benc = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    ];
    // Recover the positive-x base point: deserialize y, recover x, do not
    // apply the verify-time extra negate. Mirror frombytes without the
    // "negate if sign matches" used for A in verification.
    GeP3 h;
    immutable Fe d = Fe(-10913610, 13857413, -15372611, 6949391, 114729,
                        -8787816, -6275908, -3247719, -18696448, -12055116);
    immutable Fe sqrtm1 = Fe(-32595792, -7943725, 9377950, 3500415, 12389472,
                             -272473, -25146209, -2005654, 326686, 11406482);
    h.Y = Fe.deserialize(Benc.ptr);
    h.Z = Fe.one();
    auto u = h.Y.sqr();
    auto v = u * d;
    u = u - h.Z;
    v = v + h.Z;
    auto v3 = v.sqr() * v;
    h.X = v3.sqr() * v * u;
    h.X = h.X.pow22523() * v3 * u;
    auto vxx = h.X.sqr() * v;
    auto check = vxx - u;
    if (!check.isZero())
        h.X = h.X * sqrtm1;
    if (h.X.isNegative())
        h.X = -h.X;
    h.T = h.X * h.Y;
    return h;
}
