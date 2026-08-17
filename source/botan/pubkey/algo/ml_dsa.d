/**
* ML-DSA (FIPS 204) plus Dilithium Round 3 (modern and AES-90s)
* pq-crystals/dilithium reference
*
* Copyright:
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ml_dsa;

import botan.constants;
static if (BOTAN_HAS_ML_DSA):

import botan.hash.hash;
import botan.libstate.lookup;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.rng.rng;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.xof.xof;

enum int MLDSA_N = 256;
enum int MLDSA_Q = 8380417;
enum int MLDSA_D = 13;
enum int MLDSA_QINV = 58728449;
enum int MLDSA_NTT_F = 41978;
enum size_t MLDSA_SEED = 32;
enum size_t MLDSA_TR = 64;
enum size_t MLDSA_MU = 64;
enum uint MLDSA_SIGN_BOUND = 814;

enum MLDSAMode : ubyte { Dsa44 = 0, Dsa65 = 1, Dsa87 = 2 }

struct MLDSAParams
{
    MLDSAMode mode;
    ubyte k;
    ubyte l;
    ubyte eta;
    ubyte tau;
    ushort beta;
    uint gamma1;
    uint gamma2;
    ubyte omega;
    ubyte ctilde;
    size_t strength;
    string name;
    bool dilithium_r3;
    bool dilithium_aes;
}

MLDSAParams mldsaParams(MLDSAMode mode, bool dilithium_r3 = false, bool dilithium_aes = false)
{
    MLDSAParams p;
    p.mode = mode;
    p.dilithium_aes = dilithium_aes;
    p.dilithium_r3 = dilithium_r3 || dilithium_aes;
    final switch (mode)
    {
        case MLDSAMode.Dsa44:
            p.k = 4; p.l = 4; p.eta = 2; p.tau = 39; p.beta = 78;
            p.gamma1 = 1u << 17; p.gamma2 = (MLDSA_Q - 1) / 88;
            p.omega = 80; p.ctilde = 32; p.strength = 128;
            p.name = dilithium_aes ? "Dilithium-4x4-AES-r3"
                   : (p.dilithium_r3 ? "Dilithium-4x4-r3" : "ML-DSA-4x4");
            return p;
        case MLDSAMode.Dsa65:
            p.k = 6; p.l = 5; p.eta = 4; p.tau = 49; p.beta = 196;
            p.gamma1 = 1u << 19; p.gamma2 = (MLDSA_Q - 1) / 32;
            p.omega = 55; p.ctilde = p.dilithium_r3 ? 32 : 48; p.strength = 192;
            p.name = dilithium_aes ? "Dilithium-6x5-AES-r3"
                   : (p.dilithium_r3 ? "Dilithium-6x5-r3" : "ML-DSA-6x5");
            return p;
        case MLDSAMode.Dsa87:
            p.k = 8; p.l = 7; p.eta = 2; p.tau = 60; p.beta = 120;
            p.gamma1 = 1u << 19; p.gamma2 = (MLDSA_Q - 1) / 32;
            p.omega = 75; p.ctilde = p.dilithium_r3 ? 32 : 64; p.strength = 256;
            p.name = dilithium_aes ? "Dilithium-8x7-AES-r3"
                   : (p.dilithium_r3 ? "Dilithium-8x7-r3" : "ML-DSA-8x7");
            return p;
    }
}

MLDSAParams mldsaParamsFromName(in string name)
{
    if (name == "ML-DSA-4x4" || name == "ML-DSA-44") return mldsaParams(MLDSAMode.Dsa44);
    if (name == "ML-DSA-6x5" || name == "ML-DSA-65") return mldsaParams(MLDSAMode.Dsa65);
    if (name == "ML-DSA-8x7" || name == "ML-DSA-87") return mldsaParams(MLDSAMode.Dsa87);
    if (name == "Dilithium-4x4-r3") return mldsaParams(MLDSAMode.Dsa44, true);
    if (name == "Dilithium-6x5-r3") return mldsaParams(MLDSAMode.Dsa65, true);
    if (name == "Dilithium-8x7-r3") return mldsaParams(MLDSAMode.Dsa87, true);
    if (name == "Dilithium-4x4-AES-r3") return mldsaParams(MLDSAMode.Dsa44, true, true);
    if (name == "Dilithium-6x5-AES-r3") return mldsaParams(MLDSAMode.Dsa65, true, true);
    if (name == "Dilithium-8x7-AES-r3") return mldsaParams(MLDSAMode.Dsa87, true, true);
    throw new InvalidArgument("Unknown ML-DSA/Dilithium mode: " ~ name);
}

MLDSAMode mldsaModeFromName(in string name)
{
    return mldsaParamsFromName(name).mode;
}

bool isDilithiumR3Name(in string n)
{
    return n == "Dilithium-4x4-r3" || n == "Dilithium-6x5-r3" || n == "Dilithium-8x7-r3";
}

bool isDilithiumAesName(in string n)
{
    return n == "Dilithium-4x4-AES-r3" || n == "Dilithium-6x5-AES-r3" || n == "Dilithium-8x7-AES-r3";
}

bool isMldsaOrDilithiumName(in string n)
{
    return n == "ML-DSA-4x4" || n == "ML-DSA-6x5" || n == "ML-DSA-8x7"
        || isDilithiumR3Name(n) || isDilithiumAesName(n);
}

size_t mldsaPkBytes(const ref MLDSAParams p) { return 32 + 320 * p.k; }
size_t mldsaZPolyBytes(const ref MLDSAParams p) { return p.gamma1 == (1u << 17) ? 576 : 640; }
size_t mldsaW1PolyBytes(const ref MLDSAParams p) { return p.gamma2 == (MLDSA_Q - 1) / 88 ? 192 : 128; }
size_t mldsaSigBytes(const ref MLDSAParams p)
{
    return p.ctilde + p.l * mldsaZPolyBytes(p) + p.omega + p.k;
}
size_t mldsaTrBytes(const ref MLDSAParams p) { return p.dilithium_r3 ? 32 : 64; }
size_t mldsaEtaPolyBytes(const ref MLDSAParams p) { return p.eta == 2 ? 96 : 128; }
size_t mldsaT0PolyBytes() { return 416; }
size_t mldsaExpandedSkBytes(const ref MLDSAParams p)
{
    return 32 + 32 + mldsaTrBytes(p) + p.l * mldsaEtaPolyBytes(p)
         + p.k * mldsaEtaPolyBytes(p) + p.k * mldsaT0PolyBytes();
}

private immutable int[256] ZETAS = [
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
];

private int montgomeryReduce(long a)
{
    const int t = cast(int)(cast(int)a * MLDSA_QINV);
    return cast(int)((a - cast(long)t * MLDSA_Q) >> 32);
}

private int reduce32(int a)
{
    const int t = (a + (1 << 22)) >> 23;
    return a - t * MLDSA_Q;
}

private int caddq(int a)
{
    return a + ((a >> 31) & MLDSA_Q);
}

private void ntt(ref int[256] a)
{
    size_t k = 0;
    for (size_t len = 128; len > 0; len >>= 1)
    {
        for (size_t start = 0, j = 0; start < 256; start = j + len)
        {
            const int zeta = ZETAS[++k];
            for (j = start; j < start + len; ++j)
            {
                const int t = montgomeryReduce(cast(long)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

private void invntt(ref int[256] a)
{
    size_t k = 256;
    for (size_t len = 1; len < 256; len <<= 1)
    {
        for (size_t start = 0, j = 0; start < 256; start = j + len)
        {
            const int zeta = -ZETAS[--k];
            for (j = start; j < start + len; ++j)
            {
                const int t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = montgomeryReduce(cast(long)zeta * (t - a[j + len]));
            }
        }
    }
    foreach (j; 0 .. 256)
        a[j] = montgomeryReduce(cast(long)MLDSA_NTT_F * a[j]);
}

private void polyReduce(ref int[256] a)
{
    foreach (i; 0 .. 256)
        a[i] = reduce32(a[i]);
}

private void polyCaddq(ref int[256] a)
{
    foreach (i; 0 .. 256)
        a[i] = caddq(a[i]);
}

private void polyAdd(ref int[256] c, const ref int[256] b)
{
    foreach (i; 0 .. 256)
        c[i] = c[i] + b[i];
}

private void polySub(ref int[256] c, const ref int[256] b)
{
    foreach (i; 0 .. 256)
        c[i] = c[i] - b[i];
}

private void polyPointwise(ref int[256] c, const ref int[256] a, const ref int[256] b)
{
    foreach (i; 0 .. 256)
        c[i] = montgomeryReduce(cast(long)a[i] * b[i]);
}

private bool polyChkNorm(const ref int[256] a, int bound)
{
    if (bound > (MLDSA_Q - 1) / 8)
        return true;
    foreach (i; 0 .. 256)
    {
        int t = a[i] >> 31;
        t = a[i] - (t & (2 * a[i]));
        if (t >= bound)
            return true;
    }
    return false;
}

private Unique!XOF shakeOf(in string name)
{
    Unique!XOF x = getXof(name);
    if (!x)
        throw new LookupError(name ~ " XOF unavailable");
    return x;
}

private void shake256(const(ubyte)* inp, size_t inlen, ubyte* outp, size_t outlen)
{
    Unique!XOF x = shakeOf("SHAKE-256");
    x.update(inp, inlen);
    x.output(outp, outlen);
}

private XOF dilithiumAbsorb(const ref MLDSAParams p, bool xof128,
                            const(ubyte)* seed, size_t seedlen, ushort nonce)
{
    if (p.dilithium_aes)
    {
        static if (BOTAN_HAS_AES_CTR_XOF)
        {
            XOF x = getXof("CTR-BE(AES-256)");
            if (!x)
                throw new LookupError("CTR-BE(AES-256) XOF unavailable");
            ubyte[12] iv;
            iv[] = 0;
            iv[0] = cast(ubyte) nonce;
            iv[1] = cast(ubyte)(nonce >> 8);
            x.start(iv[], seed[0 .. 32]);
            return x;
        }
        else
            throw new LookupError("Dilithium-AES requires AES_CTR_XOF");
    }
    XOF x = getXof(xof128 ? "SHAKE-128" : "SHAKE-256");
    if (!x)
        throw new LookupError((xof128 ? "SHAKE-128" : "SHAKE-256") ~ " XOF unavailable");
    if (xof128)
    {
        ubyte[34] s;
        s[0 .. 32] = seed[0 .. 32];
        s[32] = cast(ubyte) nonce;
        s[33] = cast(ubyte)(nonce >> 8);
        x.update(s.ptr, 34);
    }
    else
    {
        ubyte[66] s;
        s[0 .. 64] = seed[0 .. 64];
        s[64] = cast(ubyte) nonce;
        s[65] = cast(ubyte)(nonce >> 8);
        x.update(s.ptr, 66);
    }
    return x;
}

private void sampleNtt(const ref MLDSAParams p, ref int[256] r, const(ubyte)* rho, ushort nonce)
{
    Unique!XOF x = dilithiumAbsorb(p, true, rho, 32, nonce);
    size_t ctr;
    ubyte[3] buf;
    while (ctr < 256)
    {
        x.output(buf[]);
        uint t = buf[0] | (cast(uint)buf[1] << 8) | (cast(uint)buf[2] << 16);
        t &= 0x7FFFFF;
        if (t < MLDSA_Q)
            r[ctr++] = t;
    }
}

private void sampleEta(const ref MLDSAParams p, ref int[256] r, const(ubyte)* seed64, ushort nonce, ubyte eta)
{
    Unique!XOF x = dilithiumAbsorb(p, false, seed64, 64, nonce);
    size_t ctr;
    ubyte[1] b;
    while (ctr < 256)
    {
        x.output(b[]);
        uint t0 = b[0] & 0x0F;
        uint t1 = b[0] >> 4;
        if (eta == 2)
        {
            if (t0 < 15)
            {
                t0 = t0 - ((205 * t0) >> 10) * 5;
                r[ctr++] = 2 - t0;
            }
            if (t1 < 15 && ctr < 256)
            {
                t1 = t1 - ((205 * t1) >> 10) * 5;
                r[ctr++] = 2 - t1;
            }
        }
        else
        {
            if (t0 < 9)
                r[ctr++] = 4 - t0;
            if (t1 < 9 && ctr < 256)
                r[ctr++] = 4 - t1;
        }
    }
}

private void unpackZ(ref int[256] r, const(ubyte)* a, uint gamma1)
{
    if (gamma1 == (1u << 17))
    {
        foreach (i; 0 .. 64)
        {
            r[4 * i + 0] = (a[9 * i + 0] | (cast(int)a[9 * i + 1] << 8) | (cast(int)a[9 * i + 2] << 16)) & 0x3FFFF;
            r[4 * i + 1] = ((a[9 * i + 2] >> 2) | (cast(int)a[9 * i + 3] << 6) | (cast(int)a[9 * i + 4] << 14)) & 0x3FFFF;
            r[4 * i + 2] = ((a[9 * i + 4] >> 4) | (cast(int)a[9 * i + 5] << 4) | (cast(int)a[9 * i + 6] << 12)) & 0x3FFFF;
            r[4 * i + 3] = ((a[9 * i + 6] >> 6) | (cast(int)a[9 * i + 7] << 2) | (cast(int)a[9 * i + 8] << 10)) & 0x3FFFF;
            r[4 * i + 0] = gamma1 - r[4 * i + 0];
            r[4 * i + 1] = gamma1 - r[4 * i + 1];
            r[4 * i + 2] = gamma1 - r[4 * i + 2];
            r[4 * i + 3] = gamma1 - r[4 * i + 3];
        }
    }
    else
    {
        foreach (i; 0 .. 128)
        {
            r[2 * i + 0] = (a[5 * i + 0] | (cast(int)a[5 * i + 1] << 8) | (cast(int)a[5 * i + 2] << 16)) & 0xFFFFF;
            r[2 * i + 1] = ((a[5 * i + 2] >> 4) | (cast(int)a[5 * i + 3] << 4) | (cast(int)a[5 * i + 4] << 12));
            r[2 * i + 0] = gamma1 - r[2 * i + 0];
            r[2 * i + 1] = gamma1 - r[2 * i + 1];
        }
    }
}

private void packZ(ubyte* r, const ref int[256] a, uint gamma1)
{
    if (gamma1 == (1u << 17))
    {
        foreach (i; 0 .. 64)
        {
            uint[4] t;
            foreach (j; 0 .. 4)
                t[j] = gamma1 - a[4 * i + j];
            r[9 * i + 0] = cast(ubyte) t[0];
            r[9 * i + 1] = cast(ubyte)(t[0] >> 8);
            r[9 * i + 2] = cast(ubyte)((t[0] >> 16) | (t[1] << 2));
            r[9 * i + 3] = cast(ubyte)(t[1] >> 6);
            r[9 * i + 4] = cast(ubyte)((t[1] >> 14) | (t[2] << 4));
            r[9 * i + 5] = cast(ubyte)(t[2] >> 4);
            r[9 * i + 6] = cast(ubyte)((t[2] >> 12) | (t[3] << 6));
            r[9 * i + 7] = cast(ubyte)(t[3] >> 2);
            r[9 * i + 8] = cast(ubyte)(t[3] >> 10);
        }
    }
    else
    {
        foreach (i; 0 .. 128)
        {
            const uint t0 = gamma1 - a[2 * i + 0];
            const uint t1 = gamma1 - a[2 * i + 1];
            r[5 * i + 0] = cast(ubyte) t0;
            r[5 * i + 1] = cast(ubyte)(t0 >> 8);
            r[5 * i + 2] = cast(ubyte)((t0 >> 16) | (t1 << 4));
            r[5 * i + 3] = cast(ubyte)(t1 >> 4);
            r[5 * i + 4] = cast(ubyte)(t1 >> 12);
        }
    }
}

private void packT1(ubyte* r, const ref int[256] a)
{
    foreach (i; 0 .. 64)
    {
        r[5 * i + 0] = cast(ubyte) a[4 * i + 0];
        r[5 * i + 1] = cast(ubyte)((a[4 * i + 0] >> 8) | (a[4 * i + 1] << 2));
        r[5 * i + 2] = cast(ubyte)((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4));
        r[5 * i + 3] = cast(ubyte)((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6));
        r[5 * i + 4] = cast(ubyte)(a[4 * i + 3] >> 2);
    }
}

private void unpackT1(ref int[256] r, const(ubyte)* a)
{
    foreach (i; 0 .. 64)
    {
        r[4 * i + 0] = (a[5 * i + 0] | (cast(int)a[5 * i + 1] << 8)) & 0x3FF;
        r[4 * i + 1] = ((a[5 * i + 1] >> 2) | (cast(int)a[5 * i + 2] << 6)) & 0x3FF;
        r[4 * i + 2] = ((a[5 * i + 2] >> 4) | (cast(int)a[5 * i + 3] << 4)) & 0x3FF;
        r[4 * i + 3] = ((a[5 * i + 3] >> 6) | (cast(int)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

private void packEta(ubyte* r, const ref int[256] a, ubyte eta)
{
    if (eta == 2)
    {
        foreach (i; 0 .. 32)
        {
            ubyte[8] t;
            foreach (j; 0 .. 8)
                t[j] = cast(ubyte)(2 - a[8 * i + j]);
            r[3 * i + 0] = cast(ubyte)(t[0] | (t[1] << 3) | (t[2] << 6));
            r[3 * i + 1] = cast(ubyte)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
            r[3 * i + 2] = cast(ubyte)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
        }
    }
    else
    {
        foreach (i; 0 .. 128)
        {
            const ubyte t0 = cast(ubyte)(4 - a[2 * i + 0]);
            const ubyte t1 = cast(ubyte)(4 - a[2 * i + 1]);
            r[i] = cast(ubyte)(t0 | (t1 << 4));
        }
    }
}

private void unpackEta(ref int[256] r, const(ubyte)* a, ubyte eta)
{
    if (eta == 2)
    {
        foreach (i; 0 .. 32)
        {
            r[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
            r[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
            r[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
            r[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
            r[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
            r[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
            r[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
            r[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;
            foreach (j; 0 .. 8)
                r[8 * i + j] = 2 - r[8 * i + j];
        }
    }
    else
    {
        foreach (i; 0 .. 128)
        {
            r[2 * i + 0] = 4 - (a[i] & 0x0F);
            r[2 * i + 1] = 4 - (a[i] >> 4);
        }
    }
}

private void packT0(ubyte* r, const ref int[256] a)
{
    enum int dhalf = 1 << (MLDSA_D - 1);
    foreach (i; 0 .. 32)
    {
        uint[8] t;
        foreach (j; 0 .. 8)
            t[j] = dhalf - a[8 * i + j];
        r[13 * i + 0] = cast(ubyte) t[0];
        r[13 * i + 1] = cast(ubyte)((t[0] >> 8) | (t[1] << 5));
        r[13 * i + 2] = cast(ubyte)(t[1] >> 3);
        r[13 * i + 3] = cast(ubyte)((t[1] >> 11) | (t[2] << 2));
        r[13 * i + 4] = cast(ubyte)((t[2] >> 6) | (t[3] << 7));
        r[13 * i + 5] = cast(ubyte)(t[3] >> 1);
        r[13 * i + 6] = cast(ubyte)((t[3] >> 9) | (t[4] << 4));
        r[13 * i + 7] = cast(ubyte)(t[4] >> 4);
        r[13 * i + 8] = cast(ubyte)((t[4] >> 12) | (t[5] << 1));
        r[13 * i + 9] = cast(ubyte)((t[5] >> 7) | (t[6] << 6));
        r[13 * i + 10] = cast(ubyte)(t[6] >> 2);
        r[13 * i + 11] = cast(ubyte)((t[6] >> 10) | (t[7] << 3));
        r[13 * i + 12] = cast(ubyte)(t[7] >> 5);
    }
}

private void unpackT0(ref int[256] r, const(ubyte)* a)
{
    enum int dhalf = 1 << (MLDSA_D - 1);
    foreach (i; 0 .. 32)
    {
        r[8 * i + 0] = (a[13 * i + 0] | (cast(int)a[13 * i + 1] << 8)) & 0x1FFF;
        r[8 * i + 1] = ((a[13 * i + 1] >> 5) | (cast(int)a[13 * i + 2] << 3) | (cast(int)a[13 * i + 3] << 11)) & 0x1FFF;
        r[8 * i + 2] = ((a[13 * i + 3] >> 2) | (cast(int)a[13 * i + 4] << 6)) & 0x1FFF;
        r[8 * i + 3] = ((a[13 * i + 4] >> 7) | (cast(int)a[13 * i + 5] << 1) | (cast(int)a[13 * i + 6] << 9)) & 0x1FFF;
        r[8 * i + 4] = ((a[13 * i + 6] >> 4) | (cast(int)a[13 * i + 7] << 4) | (cast(int)a[13 * i + 8] << 12)) & 0x1FFF;
        r[8 * i + 5] = ((a[13 * i + 8] >> 1) | (cast(int)a[13 * i + 9] << 7)) & 0x1FFF;
        r[8 * i + 6] = ((a[13 * i + 9] >> 6) | (cast(int)a[13 * i + 10] << 2) | (cast(int)a[13 * i + 11] << 10)) & 0x1FFF;
        r[8 * i + 7] = ((a[13 * i + 11] >> 3) | (cast(int)a[13 * i + 12] << 5)) & 0x1FFF;
        foreach (j; 0 .. 8)
            r[8 * i + j] = dhalf - r[8 * i + j];
    }
}

private void packW1(ubyte* r, const ref int[256] a, uint gamma2)
{
    if (gamma2 == (MLDSA_Q - 1) / 88)
    {
        foreach (i; 0 .. 64)
        {
            r[3 * i + 0] = cast(ubyte)(a[4 * i + 0] | (a[4 * i + 1] << 6));
            r[3 * i + 1] = cast(ubyte)((a[4 * i + 1] >> 2) | (a[4 * i + 2] << 4));
            r[3 * i + 2] = cast(ubyte)((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 2));
        }
    }
    else
    {
        foreach (i; 0 .. 128)
            r[i] = cast(ubyte)(a[2 * i + 0] | (a[2 * i + 1] << 4));
    }
}

private void sampleGamma1(const ref MLDSAParams p, ref int[256] r, const(ubyte)* seed64, ushort nonce, uint gamma1)
{
    Unique!XOF x = dilithiumAbsorb(p, false, seed64, 64, nonce);
    auto buf = new ubyte[gamma1 == (1u << 17) ? 576 : 640];
    x.output(buf.ptr, buf.length);
    unpackZ(r, buf.ptr, gamma1);
}

private void sampleInBall(ref int[256] c, const(ubyte)* seed, size_t seedlen, ubyte tau)
{
    Unique!XOF x = shakeOf("SHAKE-256");
    x.update(seed, seedlen);
    ubyte[136] buf;
    x.output(buf.ptr, 136);
    ulong signs;
    foreach (i; 0 .. 8)
        signs |= cast(ulong)buf[i] << (8 * i);
    size_t pos = 8;
    c[] = 0;
    foreach (i; (256 - tau) .. 256)
    {
        ubyte b;
        do
        {
            if (pos >= 136)
            {
                x.output(buf.ptr, 136);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);
        c[i] = c[b];
        c[b] = 1 - 2 * cast(int)(signs & 1);
        signs >>= 1;
    }
}

private void decompose(int a, uint gamma2, out int a1, out int a0)
{
    a1 = (a + 127) >> 7;
    if (gamma2 == (MLDSA_Q - 1) / 32)
    {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    }
    else
    {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    a0 = a - a1 * 2 * cast(int)gamma2;
    a0 -= (((MLDSA_Q - 1) / 2 - a0) >> 31) & MLDSA_Q;
}

private int useHint(int a, int hint, uint gamma2)
{
    int a1, a0;
    decompose(a, gamma2, a1, a0);
    if (hint == 0)
        return a1;
    if (gamma2 == (MLDSA_Q - 1) / 32)
        return (a0 > 0) ? ((a1 + 1) & 15) : ((a1 - 1) & 15);
    if (a0 > 0)
        return (a1 == 43) ? 0 : a1 + 1;
    return (a1 == 0) ? 43 : a1 - 1;
}

private int makeHint(int a0, int a1, uint gamma2)
{
    if (a0 > cast(int)gamma2 || a0 < -cast(int)gamma2 || (a0 == -cast(int)gamma2 && a1 != 0))
        return 1;
    return 0;
}

private void power2round(int a, out int a1, out int a0)
{
    a1 = (a + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
    a0 = a - (a1 << MLDSA_D);
}

private void expandA(const ref MLDSAParams p, ref int[256][][] A, const(ubyte)* rho)
{
    A.length = p.k;
    foreach (i; 0 .. p.k)
    {
        A[i].length = p.l;
        foreach (j; 0 .. p.l)
            sampleNtt(p, A[i][j], rho, cast(ushort)((i << 8) + j));
    }
}

private void matrixMul(ref int[256][] w, const ref int[256][][] A, const ref int[256][] v, ubyte k, ubyte l)
{
    w.length = k;
    foreach (i; 0 .. k)
    {
        w[i][] = 0;
        foreach (j; 0 .. l)
        {
            int[256] prod;
            polyPointwise(prod, A[i][j], v[j]);
            polyAdd(w[i], prod);
        }
    }
}

struct MLDSAPublic
{
    MLDSAParams params;
    ubyte[32] rho;
    int[256][] t1;
    ubyte[64] tr;
}

struct MLDSASecret
{
    MLDSAParams params;
    ubyte[32] xi;
    ubyte[32] kseed;
    int[256][] s1;
    int[256][] s2;
    int[256][] t0;
    MLDSAPublic pub;
}

private void encodePk(const ref MLDSAPublic pk, ubyte* outp)
{
    outp[0 .. 32] = pk.rho[];
    foreach (i; 0 .. pk.params.k)
        packT1(outp + 32 + i * 320, pk.t1[i]);
}

private void hashTr(ref MLDSAPublic pk)
{
    auto ek = new ubyte[mldsaPkBytes(pk.params)];
    encodePk(pk, ek.ptr);
    const n = mldsaTrBytes(pk.params);
    pk.tr[] = 0;
    shake256(ek.ptr, ek.length, pk.tr.ptr, n);
}

private MLDSAPublic decodePk(const(ubyte)* inp, size_t len, MLDSAParams p)
{
    if (len != mldsaPkBytes(p))
        throw new DecodingError("ML-DSA: unexpected public key length");
    MLDSAPublic pk;
    pk.params = p;
    pk.rho[] = inp[0 .. 32];
    pk.t1.length = p.k;
    foreach (i; 0 .. p.k)
        unpackT1(pk.t1[i], inp + 32 + i * 320);
    hashTr(pk);
    return pk;
}

/// FIPS 204 Algorithm 6 KeyGen_internal from seed ξ.
/// Dilithium R3 uses G(ξ) with no k‖l domain separator.
MLDSASecret mldsaKeygenFromSeed(const ref MLDSAParams p, const(ubyte)* xi)
{
    ubyte[128] gout;
    if (p.dilithium_r3)
        shake256(xi, 32, gout.ptr, 128);
    else
    {
        ubyte[34] gin;
        gin[0 .. 32] = xi[0 .. 32];
        gin[32] = p.k;
        gin[33] = p.l;
        shake256(gin.ptr, 34, gout.ptr, 128);
    }
    const(ubyte)* rho = gout.ptr;
    const(ubyte)* rhop = gout.ptr + 32;
    const(ubyte)* K = gout.ptr + 96;

    int[256][][] A;
    expandA(p, A, rho);

    int[256][] s1, s2;
    s1.length = p.l;
    s2.length = p.k;
    ushort nonce;
    foreach (i; 0 .. p.l)
        sampleEta(p, s1[i], rhop, nonce++, p.eta);
    foreach (i; 0 .. p.k)
        sampleEta(p, s2[i], rhop, nonce++, p.eta);

    int[256][] s1hat;
    s1hat.length = p.l;
    foreach (i; 0 .. p.l)
    {
        s1hat[i] = s1[i];
        ntt(s1hat[i]);
    }
    int[256][] t;
    matrixMul(t, A, s1hat, p.k, p.l);
    foreach (i; 0 .. p.k)
    {
        polyReduce(t[i]);
        invntt(t[i]);
        polyAdd(t[i], s2[i]);
        polyCaddq(t[i]);
    }

    MLDSASecret sk;
    sk.params = p;
    sk.xi[] = xi[0 .. 32];
    sk.kseed[] = K[0 .. 32];
    sk.s1 = s1;
    sk.s2 = s2;
    sk.t0.length = p.k;
    sk.pub.params = p;
    sk.pub.rho[] = rho[0 .. 32];
    sk.pub.t1.length = p.k;
    foreach (i; 0 .. p.k)
    {
        foreach (j; 0 .. 256)
        {
            int a1, a0;
            power2round(t[i][j], a1, a0);
            sk.pub.t1[i][j] = a1;
            sk.t0[i][j] = a0;
        }
    }
    hashTr(sk.pub);
    return sk;
}

MLDSASecret mldsaKeygenFromSeed(MLDSAMode mode, const(ubyte)* xi)
{
    auto p = mldsaParams(mode);
    return mldsaKeygenFromSeed(p, xi);
}

MLDSASecret mldsaKeygen(const ref MLDSAParams p, RandomNumberGenerator rng)
{
    ubyte[32] xi;
    rng.randomize(xi.ptr, 32);
    return mldsaKeygenFromSeed(p, xi.ptr);
}

MLDSASecret mldsaKeygen(MLDSAMode mode, RandomNumberGenerator rng)
{
    auto p = mldsaParams(mode);
    return mldsaKeygen(p, rng);
}

private bool packHint(ubyte* sig, const ref int[256][] h, const ref MLDSAParams p)
{
    foreach (i; 0 .. p.omega + p.k)
        sig[i] = 0;
    size_t k;
    foreach (i; 0 .. p.k)
    {
        foreach (j; 0 .. 256)
        {
            if (h[i][j] != 0)
            {
                if (k >= p.omega)
                    return false;
                sig[k++] = cast(ubyte) j;
            }
        }
        sig[p.omega + i] = cast(ubyte) k;
    }
    return true;
}

private bool unpackHint(ref int[256][] h, const(ubyte)* sig, const ref MLDSAParams p)
{
    h.length = p.k;
    size_t k;
    foreach (i; 0 .. p.k)
    {
        h[i][] = 0;
        const size_t end = sig[p.omega + i];
        if (end < k || end > p.omega)
            return false;
        foreach (j; k .. end)
        {
            if (j > k && sig[j] <= sig[j - 1])
                return false;
            h[i][sig[j]] = 1;
        }
        k = end;
    }
    foreach (j; k .. p.omega)
        if (sig[j])
            return false;
    return true;
}

private void computeMu(const ref MLDSAPublic pk, const(ubyte)* msg, size_t msg_len, ubyte* mu)
{
    Unique!XOF x = shakeOf("SHAKE-256");
    x.update(pk.tr.ptr, mldsaTrBytes(pk.params));
    if (!pk.params.dilithium_r3)
    {
        ubyte[2] pre = [0, 0];
        x.update(pre.ptr, 2);
    }
    x.update(msg, msg_len);
    x.output(mu, 64);
}

/// FIPS 204 Algorithm 7 Sign_internal.
/// ML-DSA: `rnd` is 32 bytes (zeros = deterministic). Dilithium R3: `rnd_len` 64
/// is ρ' itself (randomized); `rnd_len` 0 is H(K‖μ) (deterministic).
void mldsaSign(const ref MLDSASecret sk, const(ubyte)* msg, size_t msg_len,
               const(ubyte)* rnd, size_t rnd_len, ubyte* sig)
{
    auto p = sk.params;
    ubyte[64] mu;
    computeMu(sk.pub, msg, msg_len, mu.ptr);

    ubyte[64] rhop;
    if (p.dilithium_r3)
    {
        if (rnd_len == 64)
            rhop[] = rnd[0 .. 64];
        else
        {
            Unique!XOF hx = shakeOf("SHAKE-256");
            hx.update(sk.kseed.ptr, 32);
            hx.update(mu.ptr, 64);
            hx.output(rhop.ptr, 64);
        }
    }
    else
    {
        Unique!XOF hx = shakeOf("SHAKE-256");
        hx.update(sk.kseed.ptr, 32);
        hx.update(rnd, 32);
        hx.update(mu.ptr, 64);
        hx.output(rhop.ptr, 64);
    }

    int[256][][] A;
    expandA(p, A, sk.pub.rho.ptr);
    int[256][] s1n, s2n, t0n;
    s1n.length = p.l;
    s2n.length = p.k;
    t0n.length = p.k;
    foreach (i; 0 .. p.l)
    {
        s1n[i] = sk.s1[i];
        ntt(s1n[i]);
    }
    foreach (i; 0 .. p.k)
    {
        s2n[i] = sk.s2[i];
        ntt(s2n[i]);
        t0n[i] = sk.t0[i];
        ntt(t0n[i]);
    }

    ushort kappa;
    foreach (n; 0 .. MLDSA_SIGN_BOUND)
    {
        int[256][] y;
        y.length = p.l;
        foreach (i; 0 .. p.l)
            sampleGamma1(p, y[i], rhop.ptr, cast(ushort)(p.l * kappa + i), p.gamma1);
        ++kappa;

        int[256][] yhat;
        yhat.length = p.l;
        foreach (i; 0 .. p.l)
        {
            yhat[i] = y[i];
            ntt(yhat[i]);
        }
        int[256][] w;
        matrixMul(w, A, yhat, p.k, p.l);
        foreach (i; 0 .. p.k)
        {
            polyReduce(w[i]);
            invntt(w[i]);
            polyCaddq(w[i]);
        }

        int[256][] w1, w0;
        w1.length = p.k;
        w0.length = p.k;
        foreach (i; 0 .. p.k)
            foreach (j; 0 .. 256)
                decompose(w[i][j], p.gamma2, w1[i][j], w0[i][j]);

        auto w1enc = new ubyte[p.k * mldsaW1PolyBytes(p)];
        foreach (i; 0 .. p.k)
            packW1(w1enc.ptr + i * mldsaW1PolyBytes(p), w1[i], p.gamma2);

        Unique!XOF hc = shakeOf("SHAKE-256");
        hc.update(mu.ptr, 64);
        hc.update(w1enc.ptr, w1enc.length);
        hc.output(sig, p.ctilde);

        int[256] cp;
        sampleInBall(cp, sig, p.ctilde, p.tau);
        ntt(cp);

        int[256][] z;
        z.length = p.l;
        bool zbad;
        foreach (i; 0 .. p.l)
        {
            polyPointwise(z[i], cp, s1n[i]);
            invntt(z[i]);
            polyAdd(z[i], y[i]);
            polyReduce(z[i]);
            if (polyChkNorm(z[i], p.gamma1 - p.beta))
                zbad = true;
        }
        if (zbad)
            continue;

        int[256] tmp;
        bool r0bad;
        foreach (i; 0 .. p.k)
        {
            polyPointwise(tmp, cp, s2n[i]);
            invntt(tmp);
            polySub(w0[i], tmp);
            polyReduce(w0[i]);
            if (polyChkNorm(w0[i], p.gamma2 - p.beta))
                r0bad = true;
        }
        if (r0bad)
            continue;

        int[256][] h;
        h.length = p.k;
        bool ct0bad;
        size_t hints;
        foreach (i; 0 .. p.k)
        {
            polyPointwise(tmp, cp, t0n[i]);
            invntt(tmp);
            polyReduce(tmp);
            if (polyChkNorm(tmp, p.gamma2))
                ct0bad = true;
            polyAdd(w0[i], tmp);
            foreach (j; 0 .. 256)
            {
                h[i][j] = makeHint(w0[i][j], w1[i][j], p.gamma2);
                hints += h[i][j];
            }
        }
        if (ct0bad || hints > p.omega)
            continue;

        const size_t zoff = p.ctilde;
        foreach (i; 0 .. p.l)
            packZ(sig + zoff + i * mldsaZPolyBytes(p), z[i], p.gamma1);
        if (!packHint(sig + zoff + p.l * mldsaZPolyBytes(p), h, p))
            continue;
        return;
    }
    throw new InvalidState("ML-DSA signature loop did not terminate");
}

void mldsaSign(const ref MLDSASecret sk, const(ubyte)* msg, size_t msg_len,
               RandomNumberGenerator rng, ubyte* sig)
{
    if (sk.params.dilithium_r3)
    {
        ubyte[64] rhop;
        rng.randomize(rhop.ptr, 64);
        mldsaSign(sk, msg, msg_len, rhop.ptr, 64, sig);
    }
    else
    {
        ubyte[32] rnd;
        rng.randomize(rnd.ptr, 32);
        mldsaSign(sk, msg, msg_len, rnd.ptr, 32, sig);
    }
}

void mldsaSignDeterministic(const ref MLDSASecret sk, const(ubyte)* msg, size_t msg_len, ubyte* sig)
{
    if (sk.params.dilithium_r3)
        mldsaSign(sk, msg, msg_len, null, 0, sig);
    else
    {
        ubyte[32] rnd;
        rnd[] = 0;
        mldsaSign(sk, msg, msg_len, rnd.ptr, 32, sig);
    }
}

/// FIPS 204 Algorithm 8 Verify_internal. Returns true if the signature is valid.
bool mldsaVerify(const ref MLDSAPublic pk, const(ubyte)* msg, size_t msg_len,
                 const(ubyte)* sig, size_t sig_len)
{
    auto p = pk.params;
    if (sig_len != mldsaSigBytes(p))
        return false;

    int[256][] z;
    z.length = p.l;
    const size_t zoff = p.ctilde;
    const size_t zbytes = mldsaZPolyBytes(p);
    foreach (i; 0 .. p.l)
        unpackZ(z[i], sig + zoff + i * zbytes, p.gamma1);
    int[256][] h;
    if (!unpackHint(h, sig + zoff + p.l * zbytes, p))
        return false;

    foreach (i; 0 .. p.l)
        if (polyChkNorm(z[i], p.gamma1 - p.beta))
            return false;

    ubyte[64] mu;
    computeMu(pk, msg, msg_len, mu.ptr);

    int[256] cp;
    sampleInBall(cp, sig, p.ctilde, p.tau);
    ntt(cp);

    int[256][][] A;
    expandA(p, A, pk.rho.ptr);
    foreach (i; 0 .. p.l)
        ntt(z[i]);
    int[256][] w;
    matrixMul(w, A, z, p.k, p.l);

    foreach (i; 0 .. p.k)
    {
        int[256] t1s = pk.t1[i];
        foreach (j; 0 .. 256)
            t1s[j] <<= MLDSA_D;
        ntt(t1s);
        int[256] ct;
        polyPointwise(ct, cp, t1s);
        polySub(w[i], ct);
        polyReduce(w[i]);
        invntt(w[i]);
        polyCaddq(w[i]);
        foreach (j; 0 .. 256)
            w[i][j] = useHint(w[i][j], h[i][j], p.gamma2);
    }

    auto w1enc = new ubyte[p.k * mldsaW1PolyBytes(p)];
    foreach (i; 0 .. p.k)
        packW1(w1enc.ptr + i * mldsaW1PolyBytes(p), w[i], p.gamma2);
    Unique!XOF hc = shakeOf("SHAKE-256");
    hc.update(mu.ptr, 64);
    hc.update(w1enc.ptr, w1enc.length);
    auto c2 = new ubyte[p.ctilde];
    hc.output(c2.ptr, p.ctilde);
    foreach (i; 0 .. p.ctilde)
        if (sig[i] != c2[i])
            return false;
    return true;
}

Vector!ubyte mldsaEncodePublic(const ref MLDSAPublic pk)
{
    auto v = Vector!ubyte(mldsaPkBytes(pk.params));
    encodePk(pk, v.ptr);
    return v.move();
}

SecureVector!ubyte mldsaEncodeExpandedSk(const ref MLDSASecret sk)
{
    auto p = sk.params;
    auto v = SecureVector!ubyte(mldsaExpandedSkBytes(p));
    size_t off;
    v[0 .. 32] = sk.pub.rho[];
    off = 32;
    v[off .. off + 32] = sk.kseed[];
    off += 32;
    const trn = mldsaTrBytes(p);
    v[off .. off + trn] = sk.pub.tr[0 .. trn];
    off += trn;
    foreach (i; 0 .. p.l)
    {
        packEta(v.ptr + off, sk.s1[i], p.eta);
        off += mldsaEtaPolyBytes(p);
    }
    foreach (i; 0 .. p.k)
    {
        packEta(v.ptr + off, sk.s2[i], p.eta);
        off += mldsaEtaPolyBytes(p);
    }
    foreach (i; 0 .. p.k)
    {
        packT0(v.ptr + off, sk.t0[i]);
        off += mldsaT0PolyBytes();
    }
    return v.move();
}

private void reconstructT1(ref MLDSASecret sk)
{
    auto p = sk.params;
    int[256][][] A;
    expandA(p, A, sk.pub.rho.ptr);
    int[256][] s1hat;
    s1hat.length = p.l;
    foreach (i; 0 .. p.l)
    {
        s1hat[i] = sk.s1[i];
        ntt(s1hat[i]);
    }
    int[256][] t;
    matrixMul(t, A, s1hat, p.k, p.l);
    sk.pub.t1.length = p.k;
    foreach (i; 0 .. p.k)
    {
        polyReduce(t[i]);
        invntt(t[i]);
        polyAdd(t[i], sk.s2[i]);
        polyCaddq(t[i]);
        foreach (j; 0 .. 256)
        {
            int a1, a0;
            power2round(t[i][j], a1, a0);
            sk.pub.t1[i][j] = a1;
        }
    }
}

MLDSASecret mldsaDecodeExpandedSk(const(ubyte)* inp, size_t len, MLDSAParams p)
{
    if (len != mldsaExpandedSkBytes(p))
        throw new DecodingError("Dilithium R3: unexpected private key length");
    MLDSASecret sk;
    sk.params = p;
    sk.pub.params = p;
    size_t off;
    sk.pub.rho[] = inp[0 .. 32];
    off = 32;
    sk.kseed[] = inp[off .. off + 32];
    off += 32;
    const trn = mldsaTrBytes(p);
    sk.pub.tr[] = 0;
    sk.pub.tr[0 .. trn] = inp[off .. off + trn];
    off += trn;
    sk.s1.length = p.l;
    foreach (i; 0 .. p.l)
    {
        unpackEta(sk.s1[i], inp + off, p.eta);
        off += mldsaEtaPolyBytes(p);
    }
    sk.s2.length = p.k;
    foreach (i; 0 .. p.k)
    {
        unpackEta(sk.s2[i], inp + off, p.eta);
        off += mldsaEtaPolyBytes(p);
    }
    sk.t0.length = p.k;
    foreach (i; 0 .. p.k)
    {
        unpackT0(sk.t0[i], inp + off);
        off += mldsaT0PolyBytes();
    }
    reconstructT1(sk);
    return sk;
}

final class MLDSAPublicKey : PublicKey
{
public:
    this(MLDSAParams p, const(ubyte)* bits, size_t len)
    {
        m_pub = decodePk(bits, len, p);
    }

    this(MLDSAMode mode, const(ubyte)* bits, size_t len)
    {
        this(mldsaParams(mode), bits, len);
    }

    this(in string name, const(ubyte)* bits, size_t len)
    {
        this(mldsaParamsFromName(name), bits, len);
    }

    this(const ref MLDSAPublic pub)
    {
        m_pub.params = pub.params;
        m_pub.rho = pub.rho;
        m_pub.tr = pub.tr;
        m_pub.t1.length = pub.t1.length;
        foreach (i; 0 .. pub.t1.length)
            m_pub.t1[i] = pub.t1[i];
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        this(mldsaParamsFromName(OIDS.lookup(alg_id.oid)), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_pub.params.name; }
    override size_t estimatedStrength() const { return m_pub.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_pub.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override Vector!ubyte x509SubjectPublicKey() const { return mldsaEncodePublic(m_pub); }
    ref const(MLDSAPublic) raw() const { return m_pub; }
    MLDSAMode mode() const { return m_pub.params.mode; }

private:
    MLDSAPublic m_pub;
}

final class MLDSAPrivateKey : PrivateKey, PublicKey
{
public:
    this(MLDSAParams p, RandomNumberGenerator rng)
    {
        m_sk = mldsaKeygen(p, rng);
    }

    this(MLDSAMode mode, RandomNumberGenerator rng)
    {
        this(mldsaParams(mode), rng);
    }

    this(in string name, RandomNumberGenerator rng)
    {
        this(mldsaParamsFromName(name), rng);
    }

    this(MLDSAParams p, const(ubyte)* xi)
    {
        m_sk = mldsaKeygenFromSeed(p, xi);
    }

    this(MLDSAMode mode, const(ubyte)* xi)
    {
        this(mldsaParams(mode), xi);
    }

    this(in string name, const(ubyte)* xi)
    {
        this(mldsaParamsFromName(name), xi);
    }

    this(MLDSAParams p, const(ubyte)* bits, size_t len)
    {
        if (len == 32)
            m_sk = mldsaKeygenFromSeed(p, bits);
        else if (p.dilithium_r3 && len == mldsaExpandedSkBytes(p))
            m_sk = mldsaDecodeExpandedSk(bits, len, p);
        else
            throw new DecodingError(p.name ~ ": unexpected private key length");
    }

    this(MLDSAMode mode, const(ubyte)* bits, size_t len)
    {
        this(mldsaParams(mode), bits, len);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        import botan.asn1.ber_dec;
        auto p = mldsaParamsFromName(OIDS.lookup(alg_id.oid));
        if (key_bits.length == 32 || (p.dilithium_r3 && key_bits.length == mldsaExpandedSkBytes(p)))
            this(p, key_bits.ptr, key_bits.length);
        else
        {
            SecureVector!ubyte bits;
            BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING).discardRemaining();
            this(p, bits.ptr, bits.length);
        }
    }

    override @property string algoName() const { return m_sk.params.name; }
    override size_t estimatedStrength() const { return m_sk.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_sk.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const { return mldsaEncodePublic(m_sk.pub); }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        if (m_sk.params.dilithium_r3)
            return mldsaEncodeExpandedSk(m_sk);
        auto v = SecureVector!ubyte(32);
        v[0 .. 32] = m_sk.xi[];
        return v.move();
    }
    ref const(MLDSASecret) raw() const { return m_sk; }
    MLDSAPublicKey publicKey() const { return new MLDSAPublicKey(m_sk.pub); }
    MLDSAMode mode() const { return m_sk.params.mode; }

private:
    MLDSASecret m_sk;
}

final class MLDSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { m_key = cast(MLDSAPrivateKey) pkey; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator rng)
    {
        auto sig = SecureVector!ubyte(mldsaSigBytes(m_key.raw().params));
        mldsaSign(m_key.raw(), msg, msg_len, rng, sig.ptr);
        return sig.move();
    }
private:
    const MLDSAPrivateKey m_key;
}

final class MLDSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { m_key = cast(MLDSAPublicKey) pkey; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return mldsaVerify(m_key.raw(), msg, msg_len, sig, sig_len);
    }
    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("ML-DSA has no message recovery");
    }
private:
    const MLDSAPublicKey m_key;
}

static if (BOTAN_HAS_TESTS && !SKIP_ML_DSA_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import botan.pubkey.pk_algs;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists, dirEntries, SpanMode;

    auto state = globalState();
    logDebug("Testing ml_dsa.d ...");
    size_t fails;

    foreach (mode; [MLDSAMode.Dsa44, MLDSAMode.Dsa65, MLDSAMode.Dsa87])
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(mode, *rng);
        Unique!MLDSAPublicKey pk = sk.publicKey();
        auto p = mldsaParams(mode);
        const ubyte[11] msg = cast(ubyte[11]) "hello world";
        auto sig = new ubyte[mldsaSigBytes(p)];
        mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
        if (!mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError(p.name, " pairwise verify failed");
            ++fails;
        }
        sig[0] ^= 0xff;
        if (mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError(p.name, " mutated signature accepted");
            ++fails;
        }
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(MLDSAMode.Dsa44, *rng);
        auto pub_bits = SecureVector!ubyte(sk.x509SubjectPublicKey()[]);
        Unique!PublicKey via_pk = makePublicKey(sk.algorithmIdentifier(), pub_bits);
        if (!via_pk || via_pk.algoName != "ML-DSA-4x4")
        {
            logError("ML-DSA factory public key");
            ++fails;
        }
        auto seed = sk.pkcs8PrivateKey();
        auto alg_id = sk.pkcs8AlgorithmIdentifier();
        Unique!PrivateKey via_sk = makePrivateKey(alg_id, seed, *rng);
        if (!via_sk || via_sk.algoName != "ML-DSA-4x4")
        {
            logError("ML-DSA factory private key");
            ++fails;
        }
        const OID oid = OIDS.lookup("ML-DSA-6x5");
        if (oid.toString() != "2.16.840.1.101.3.4.3.18")
            ++fails;
        if (OIDS.lookup(oid) != "ML-DSA-6x5")
            ++fails;
        const OID oidr3 = OIDS.lookup("Dilithium-4x4-r3");
        if (oidr3.toString() != "1.3.6.1.4.1.25258.1.9.1")
            ++fails;
        if (OIDS.lookup(oidr3) != "Dilithium-4x4-r3")
            ++fails;
        const OID oidaes = OIDS.lookup("Dilithium-4x4-AES-r3");
        if (oidaes.toString() != "1.3.6.1.4.1.25258.1.10.1")
            ++fails;
    }

    foreach (name; ["Dilithium-4x4-r3", "Dilithium-6x5-r3", "Dilithium-8x7-r3",
                    "Dilithium-4x4-AES-r3", "Dilithium-6x5-AES-r3", "Dilithium-8x7-AES-r3"])
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(name, *rng);
        Unique!MLDSAPublicKey pk = sk.publicKey();
        if (sk.algoName != name || !sk.raw().params.dilithium_r3)
        {
            logError(name, " name/flag");
            ++fails;
        }
        auto p = sk.raw().params;
        const ubyte[11] msg = cast(ubyte[11]) "hello world";
        auto sig = new ubyte[mldsaSigBytes(p)];
        mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
        if (!mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError(name, " pairwise verify failed");
            ++fails;
        }
        sig[0] ^= 0xff;
        if (mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError(name, " mutated signature accepted");
            ++fails;
        }
        auto pub_bits = SecureVector!ubyte(sk.x509SubjectPublicKey()[]);
        Unique!PublicKey via_pk = makePublicKey(sk.algorithmIdentifier(), pub_bits);
        if (!via_pk || via_pk.algoName != name)
        {
            logError(name, " factory public key");
            ++fails;
        }
        auto skbits = sk.pkcs8PrivateKey();
        auto alg_idr3 = sk.pkcs8AlgorithmIdentifier();
        Unique!PrivateKey via_sk = makePrivateKey(alg_idr3, skbits, *rng);
        if (!via_sk || via_sk.algoName != name)
        {
            logError(name, " factory private key");
            ++fails;
        }
    }

    if (exists("test_data/pubkey/ml_dsa_verify.vec"))
    {
        File vec = File("test_data/pubkey/ml_dsa_verify.vec", "r");
        fails += runTestsBb(vec, "Mode", "Valid", false,
            (ref HashMap!(string, string) m)
            {
                if (!("Key" in m) || !("Msg" in m) || !("Signature" in m) || !("Valid" in m))
                    return 0;
                const mode = mldsaModeFromName(m["Mode"]);
                auto key = hexDecode(m["Key"]);
                auto msg = hexDecode(m["Msg"]);
                auto sig = hexDecode(m["Signature"]);
                Unique!MLDSAPublicKey pk = new MLDSAPublicKey(mode, key.ptr, key.length);
                const bool ok = mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length);
                const bool want = m["Valid"] == "1";
                if (ok != want)
                {
                    logError(m["Mode"], " verify KAT want=", m["Valid"], " got=", ok);
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/dilithium_kat.vec"))
    {
        import botan.block.block_cipher;
        File vec = File("test_data/pubkey/dilithium_kat.vec", "r");
        size_t[string] seen;
        fails += runTestsBb(vec, "Instance", "HashSig", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!isDilithiumR3Name(inst) && !isDilithiumAesName(inst))
                    return 0;
                const limit = (inst == "Dilithium-4x4-r3" || inst == "Dilithium-4x4-AES-r3") ? 5 : 1;
                if (++seen[inst] > limit)
                    return 0;
                if (!("Seed" in m) || !("Msg" in m) || !("HashPk" in m) || !("HashSk" in m) || !("HashSig" in m))
                    return 0;
                auto seed = hexDecode(m["Seed"]);
                ubyte[32] xi;
                {
                    auto drbg = DilithiumKatDrbg(seed.ptr, seed.length);
                    drbg.generate(xi.ptr, 32);
                }
                auto p = mldsaParamsFromName(inst);
                Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(p, xi.ptr);
                Unique!MLDSAPublicKey pk = sk.publicKey();
                auto pkbits = mldsaEncodePublic(pk.raw());
                auto skbits = mldsaEncodeExpandedSk(sk.raw());
                auto msg = hexDecode(m["Msg"]);
                auto sig = new ubyte[mldsaSigBytes(p)];
                mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
                if (dilithiumSha3_256(pkbits.ptr, pkbits.length)[] != hexDecode(m["HashPk"])[])
                {
                    logError(inst, " KAT HashPk mismatch");
                    return 1;
                }
                if (dilithiumSha3_256(skbits.ptr, skbits.length)[] != hexDecode(m["HashSk"])[])
                {
                    logError(inst, " KAT HashSk mismatch");
                    return 1;
                }
                if (dilithiumSha3_256(sig.ptr, sig.length)[] != hexDecode(m["HashSig"])[])
                {
                    logError(inst, " KAT HashSig mismatch");
                    return 1;
                }
                if (!mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(inst, " KAT verify failed");
                    return 1;
                }
                return 0;
            });
    }

    {
        import std.file : dirEntries, SpanMode;
        foreach (string path; dirEntries("test_data/pubkey", "ml-dsa-*_Deterministic.vec", SpanMode.shallow))
        {
            File vec = File(path, "r");
            fails += runTestsBb(vec, "Instance", "HashSig", true,
                (ref HashMap!(string, string) m)
                {
                    string inst = m["Instance"];
                    if (inst.length > 14 && inst[$ - 14 .. $] == "_Deterministic")
                        inst = inst[0 .. $ - 14];
                    if (inst != "ML-DSA-4x4" && inst != "ML-DSA-6x5" && inst != "ML-DSA-8x7")
                        return 0;
                    if (!("Seed" in m) || !("Msg" in m) || !("HashPk" in m) || !("HashSk" in m) || !("HashSig" in m))
                        return 0;
                    auto seed = hexDecode(m["Seed"]);
                    ubyte[32] xi;
                    {
                        auto drbg = DilithiumKatDrbg(seed.ptr, seed.length);
                        drbg.generate(xi.ptr, 32);
                    }
                    auto p = mldsaParamsFromName(inst);
                    Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(p, xi.ptr);
                    Unique!MLDSAPublicKey pk = sk.publicKey();
                    auto pkbits = mldsaEncodePublic(pk.raw());
                    auto skbits = sk.pkcs8PrivateKey();
                    auto msg = hexDecode(m["Msg"]);
                    auto sig = new ubyte[mldsaSigBytes(p)];
                    mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
                    if (dilithiumSha3_256(pkbits.ptr, pkbits.length)[] != hexDecode(m["HashPk"])[])
                    {
                        logError(inst, " ML-DSA KAT HashPk mismatch");
                        return 1;
                    }
                    if (dilithiumSha3_256(skbits.ptr, skbits.length)[] != hexDecode(m["HashSk"])[])
                    {
                        logError(inst, " ML-DSA KAT HashSk mismatch");
                        return 1;
                    }
                    if (dilithiumSha3_256(sig.ptr, sig.length)[] != hexDecode(m["HashSig"])[])
                    {
                        logError(inst, " ML-DSA KAT HashSig mismatch");
                        return 1;
                    }
                    if (!mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
                    {
                        logError(inst, " ML-DSA KAT verify failed");
                        return 1;
                    }
                    return 0;
                });
        }
    }

    {
        import std.file : dirEntries, SpanMode;
        foreach (string path; dirEntries("test_data/pubkey", "ml-dsa-*_Randomized.vec", SpanMode.shallow))
        {
            File vec = File(path, "r");
            fails += runTestsBb(vec, "Instance", "HashSig", true,
                (ref HashMap!(string, string) m)
                {
                    string inst = normalizeMldsaKatInstance(m["Instance"]);
                    if (inst != "ML-DSA-4x4" && inst != "ML-DSA-6x5" && inst != "ML-DSA-8x7")
                        return 0;
                    return runMldsaHashedKat(m, inst, true);
                });
        }
        foreach (string path; dirEntries("test_data/pubkey", "dilithium_*_Randomized.vec", SpanMode.shallow))
        {
            File vec = File(path, "r");
            fails += runTestsBb(vec, "Instance", "HashSig", true,
                (ref HashMap!(string, string) m)
                {
                    string inst = normalizeMldsaKatInstance(m["Instance"]);
                    if (!isDilithiumR3Name(inst) && !isDilithiumAesName(inst))
                        return 0;
                    return runMldsaHashedKat(m, inst, true);
                });
        }
    }

    fails += checkMemutilsRepeat("ml_dsa", {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(MLDSAMode.Dsa44, *rng);
        const ubyte[4] msg = [1, 2, 3, 4];
        auto p44 = mldsaParams(MLDSAMode.Dsa44);
        auto sig = new ubyte[mldsaSigBytes(p44)];
        mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
    });

    if (fails)
        logError("ml_dsa failures: ", fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS)
{

import botan.block.block_cipher;
import botan.codec.hex;
import botan.test;
import memutils.hashmap;

private string normalizeMldsaKatInstance(string inst)
{
    if (inst.length > 14 && inst[$ - 14 .. $] == "_Deterministic")
        inst = inst[0 .. $ - 14];
    if (inst.length > 12 && inst[$ - 12 .. $] == "_Randomized")
        inst = inst[0 .. $ - 12];
    if (inst == "Dilithium_4x4") return "Dilithium-4x4-r3";
    if (inst == "Dilithium_6x5") return "Dilithium-6x5-r3";
    if (inst == "Dilithium_8x7") return "Dilithium-8x7-r3";
    if (inst == "Dilithium_4x4_AES") return "Dilithium-4x4-AES-r3";
    if (inst == "Dilithium_6x5_AES") return "Dilithium-6x5-AES-r3";
    if (inst == "Dilithium_8x7_AES") return "Dilithium-8x7-AES-r3";
    return inst;
}

private size_t runMldsaHashedKat(ref HashMap!(string, string) m, string inst, bool randomized)
{
    if (!("Seed" in m) || !("Msg" in m) || !("HashPk" in m) || !("HashSk" in m) || !("HashSig" in m))
        return 0;
    auto seed = hexDecode(m["Seed"]);
    ubyte[32] xi;
    ubyte[64] rnd;
    {
        auto drbg = DilithiumKatDrbg(seed.ptr, seed.length);
        drbg.generate(xi.ptr, 32);
        if (randomized)
        {
            auto ppeek = mldsaParamsFromName(inst);
            drbg.generate(rnd.ptr, ppeek.dilithium_r3 ? 64 : 32);
        }
    }
    auto p = mldsaParamsFromName(inst);
    Unique!MLDSAPrivateKey sk = new MLDSAPrivateKey(p, xi.ptr);
    Unique!MLDSAPublicKey pk = sk.publicKey();
    auto pkbits = mldsaEncodePublic(pk.raw());
    auto skbits = sk.pkcs8PrivateKey();
    auto msg = hexDecode(m["Msg"]);
    auto sig = new ubyte[mldsaSigBytes(p)];
    if (randomized)
        mldsaSign(sk.raw(), msg.ptr, msg.length, rnd.ptr, p.dilithium_r3 ? 64 : 32, sig.ptr);
    else
        mldsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
    if (dilithiumSha3_256(pkbits.ptr, pkbits.length)[] != hexDecode(m["HashPk"])[])
    {
        logError(inst, " KAT HashPk mismatch");
        return 1;
    }
    if (dilithiumSha3_256(skbits.ptr, skbits.length)[] != hexDecode(m["HashSk"])[])
    {
        logError(inst, " KAT HashSk mismatch");
        return 1;
    }
    if (dilithiumSha3_256(sig.ptr, sig.length)[] != hexDecode(m["HashSig"])[])
    {
        logError(inst, " KAT HashSig mismatch");
        return 1;
    }
    if (!mldsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
    {
        logError(inst, " KAT verify failed");
        return 1;
    }
    return 0;
}

private ubyte[32] dilithiumSha3_256(const(ubyte)* inp, size_t len)
{
    Unique!HashFunction h = retrieveHash("SHA-3(256)").clone();
    h.update(inp, len);
    auto d = h.finished();
    ubyte[32] outp;
    outp[] = d.ptr[0 .. 32];
    return outp;
}

private void dilithiumStoreBe64(ubyte* p, ulong v)
{
    p[0] = cast(ubyte)(v >> 56);
    p[1] = cast(ubyte)(v >> 48);
    p[2] = cast(ubyte)(v >> 40);
    p[3] = cast(ubyte)(v >> 32);
    p[4] = cast(ubyte)(v >> 24);
    p[5] = cast(ubyte)(v >> 16);
    p[6] = cast(ubyte)(v >> 8);
    p[7] = cast(ubyte) v;
}

private ulong dilithiumLoadBe64(const(ubyte)* p)
{
    return (cast(ulong) p[0] << 56) | (cast(ulong) p[1] << 48) |
           (cast(ulong) p[2] << 40) | (cast(ulong) p[3] << 32) |
           (cast(ulong) p[4] << 24) | (cast(ulong) p[5] << 16) |
           (cast(ulong) p[6] << 8) | cast(ulong) p[7];
}

private struct DilithiumKatDrbg
{
    Unique!BlockCipher cipher;
    ulong v0, v1;

    this(const(ubyte)* seed, size_t slen)
    {
        cipher = retrieveBlockCipher("AES-256").clone();
        if (slen != 48)
            throw new InvalidArgument("Dilithium KAT seed must be 48 bytes");
        clear();
        update(seed, slen);
    }

    void clear()
    {
        ubyte[32] z;
        cipher.setKey(z.ptr, 32);
        v0 = 0;
        v1 = 0;
    }

    void incrV(ubyte* outp)
    {
        v1 += 1;
        if (v1 == 0)
            ++v0;
        dilithiumStoreBe64(outp, v0);
        dilithiumStoreBe64(outp + 8, v1);
    }

    void update(const(ubyte)* provided, size_t plen)
    {
        ubyte[48] temp;
        foreach (i; 0 .. 3)
            incrV(temp.ptr + 16 * i);
        cipher.encryptN(temp.ptr, temp.ptr, 3);
        if (plen)
            foreach (i; 0 .. plen)
                temp[i] ^= provided[i];
        cipher.setKey(temp.ptr, 32);
        v0 = dilithiumLoadBe64(temp.ptr + 32);
        v1 = dilithiumLoadBe64(temp.ptr + 40);
    }

    void generate(ubyte* outp, size_t n)
    {
        const size_t full = n / 16;
        const size_t left = n % 16;
        foreach (i; 0 .. full)
            incrV(outp + 16 * i);
        if (full)
            cipher.encryptN(outp, outp, full);
        if (left)
        {
            ubyte[16] block;
            incrV(block.ptr);
            cipher.encrypt(block.ptr, block.ptr);
            outp[full * 16 .. full * 16 + left] = block[0 .. left];
        }
        update(null, 0);
    }
}

}
