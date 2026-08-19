/**
* ML-KEM (FIPS 203) plus Kyber Round 3 (modern and 90s)
*
* Copyright:
* (C) 2021-2024 Jack Lloyd
* (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
* (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
* (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ml_kem;

import botan.constants;
static if (BOTAN_HAS_ML_KEM):

import botan.hash.hash;
import botan.libstate.lookup;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.ct;
import botan.xof.xof;

enum short MLKEM_N = 256;
enum short MLKEM_Q = 3329;
enum size_t MLKEM_SYMBYTES = 32;
enum size_t MLKEM_SSBYTES = 32;

/// FIPS 203 parameter set (512 / 768 / 1024).
enum MLKEMMode : ubyte { Kem512 = 0, Kem768 = 1, Kem1024 = 2 }

/**
* ML-KEM / Kyber parameter block (k, eta1, du, dv, SCAN name).
*/
struct MLKEMParams
{
    MLKEMMode mode;
    ubyte k;
    ubyte eta1;
    ubyte du;
    ubyte dv;
    size_t strength;
    string name;
    bool kyber_r3;
    bool kyber_90s;
}

/**
* Params:
*  mode = 512, 768, or 1024
*  kyber_r3 = true for Round-3 Kyber (not FIPS 203)
*  kyber_90s = true for the AES-based 90s variant
* Returns: filled parameter block
*/
MLKEMParams mlkemParams(MLKEMMode mode, bool kyber_r3 = false, bool kyber_90s = false)
{
    MLKEMParams p;
    p.mode = mode;
    p.kyber_90s = kyber_90s;
    p.kyber_r3 = kyber_r3 || kyber_90s;
    final switch (mode)
    {
        case MLKEMMode.Kem512:
            p.k = 2; p.eta1 = 3; p.du = 10; p.dv = 4; p.strength = 128;
            p.name = kyber_90s ? "Kyber-512-90s-r3" : (p.kyber_r3 ? "Kyber-512-r3" : "ML-KEM-512");
            return p;
        case MLKEMMode.Kem768:
            p.k = 3; p.eta1 = 2; p.du = 10; p.dv = 4; p.strength = 192;
            p.name = kyber_90s ? "Kyber-768-90s-r3" : (p.kyber_r3 ? "Kyber-768-r3" : "ML-KEM-768");
            return p;
        case MLKEMMode.Kem1024:
            p.k = 4; p.eta1 = 2; p.du = 11; p.dv = 5; p.strength = 256;
            p.name = kyber_90s ? "Kyber-1024-90s-r3" : (p.kyber_r3 ? "Kyber-1024-r3" : "ML-KEM-1024");
            return p;
    }
}

/**
* Params:
*  name = "ML-KEM-768", "Kyber-512-r3", …
* Returns: parameter block
*/
MLKEMParams mlkemParamsFromName(in string name)
{
    if (name == "ML-KEM-512") return mlkemParams(MLKEMMode.Kem512);
    if (name == "ML-KEM-768") return mlkemParams(MLKEMMode.Kem768);
    if (name == "ML-KEM-1024") return mlkemParams(MLKEMMode.Kem1024);
    if (name == "Kyber-512-r3") return mlkemParams(MLKEMMode.Kem512, true);
    if (name == "Kyber-768-r3") return mlkemParams(MLKEMMode.Kem768, true);
    if (name == "Kyber-1024-r3") return mlkemParams(MLKEMMode.Kem1024, true);
    if (name == "Kyber-512-90s-r3") return mlkemParams(MLKEMMode.Kem512, true, true);
    if (name == "Kyber-768-90s-r3") return mlkemParams(MLKEMMode.Kem768, true, true);
    if (name == "Kyber-1024-90s-r3") return mlkemParams(MLKEMMode.Kem1024, true, true);
    throw new InvalidArgument("Unknown ML-KEM/Kyber mode: " ~ name);
}

MLKEMMode mlkemModeFromName(in string name)
{
    return mlkemParamsFromName(name).mode;
}

bool isKyberR3Name(in string n)
{
    return n == "Kyber-512-r3" || n == "Kyber-768-r3" || n == "Kyber-1024-r3";
}

bool isKyber90sName(in string n)
{
    return n == "Kyber-512-90s-r3" || n == "Kyber-768-90s-r3" || n == "Kyber-1024-90s-r3";
}

bool isMlkemOrKyberName(in string n)
{
    return n == "ML-KEM-512" || n == "ML-KEM-768" || n == "ML-KEM-1024"
        || isKyberR3Name(n) || isKyber90sName(n);
}

size_t mlkemPolyBytes() { return 384; } // 256 * 12 / 8
size_t mlkemPkBytes(const ref MLKEMParams p) { return p.k * mlkemPolyBytes() + MLKEM_SYMBYTES; }
size_t mlkemCtBytes(const ref MLKEMParams p)
{
    return p.k * (p.du * MLKEM_N / 8) + (p.dv * MLKEM_N / 8);
}

private immutable short[128] ZETAS = [
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628
];

private enum int QINV = 62209; // q^{-1} mod 2^16 (official Kyber)

private short montgomeryReduce(int a)
{
    const short t = cast(short)(cast(short)a * QINV);
    return cast(short)((a - cast(int)t * MLKEM_Q) >> 16);
}

private short fqmul(short a, short b)
{
    return montgomeryReduce(cast(int)a * b);
}

private short barrettReduce(short a)
{
    const int v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;
    const short t = cast(short)(((cast(int)v * a + (1 << 25)) >> 26) * MLKEM_Q);
    return cast(short)(a - t);
}

private void ntt(ref short[256] r)
{
    size_t k = 1;
    for (size_t len = 128; len >= 2; len >>= 1)
    {
        for (size_t start = 0, j = 0; start < 256; start = j + len)
        {
            const short zeta = ZETAS[k++];
            for (j = start; j < start + len; ++j)
            {
                const short t = fqmul(zeta, r[j + len]);
                r[j + len] = cast(short)(r[j] - t);
                r[j] = cast(short)(r[j] + t);
            }
        }
    }
}

private void invntt(ref short[256] r)
{
    size_t k = 127;
    for (size_t len = 2; len <= 128; len <<= 1)
    {
        for (size_t start = 0, j = 0; start < 256; start = j + len)
        {
            const short zeta = ZETAS[k--];
            for (j = start; j < start + len; ++j)
            {
                const short t = r[j];
                r[j] = barrettReduce(cast(short)(t + r[j + len]));
                r[j + len] = fqmul(zeta, cast(short)(r[j + len] - t));
            }
        }
    }
    foreach (j; 0 .. 256)
        r[j] = fqmul(r[j], 1441);
}

private void basemul(ref short[2] r, const ref short[2] a, const ref short[2] b, short zeta)
{
    r[0] = cast(short)(fqmul(a[0], b[0]) + fqmul(fqmul(a[1], b[1]), zeta));
    r[1] = cast(short)(fqmul(a[0], b[1]) + fqmul(a[1], b[0]));
}

private void polyBasemul(ref short[256] r, const ref short[256] a, const ref short[256] b)
{
    foreach (i; 0 .. 64)
    {
        short[2] ra, aa = [a[4 * i], a[4 * i + 1]], ba = [b[4 * i], b[4 * i + 1]];
        short[2] rb, ab = [a[4 * i + 2], a[4 * i + 3]], bb = [b[4 * i + 2], b[4 * i + 3]];
        basemul(ra, aa, ba, ZETAS[64 + i]);
        basemul(rb, ab, bb, cast(short)(-ZETAS[64 + i]));
        r[4 * i] = ra[0];
        r[4 * i + 1] = ra[1];
        r[4 * i + 2] = rb[0];
        r[4 * i + 3] = rb[1];
    }
}

private void polyReduce(ref short[256] r)
{
    foreach (i; 0 .. 256)
        r[i] = barrettReduce(r[i]);
}

/// Convert from Montgomery domain (official `poly_tomont`). Needed after A·s.
private void polyTomont(ref short[256] r)
{
    enum short f = 1353; // 2^32 % Q
    foreach (i; 0 .. 256)
        r[i] = montgomeryReduce(cast(int)r[i] * f);
}

private void polyCsubq(ref short[256] r)
{
    foreach (i; 0 .. 256)
    {
        r[i] -= MLKEM_Q;
        r[i] += (r[i] >> 15) & MLKEM_Q;
    }
}

/// Barrett can leave a negative representative; map it into [0, Q).
private void polyMakePositive(ref short[256] r)
{
    foreach (i; 0 .. 256)
        r[i] += (r[i] >> 15) & MLKEM_Q;
}

private void polyToUnsigned(ref short[256] r)
{
    polyCsubq(r);
    polyMakePositive(r);
}

private void polyAdd(ref short[256] r, const ref short[256] a)
{
    foreach (i; 0 .. 256)
        r[i] = cast(short)(r[i] + a[i]);
}

private void polySub(ref short[256] r, const ref short[256] a)
{
    foreach (i; 0 .. 256)
        r[i] = cast(short)(r[i] - a[i]);
}

private uint compressD(uint x, ubyte d)
{
    return (cast(uint)((cast(ulong)x * (1u << d) + MLKEM_Q / 2) / MLKEM_Q)) & ((1u << d) - 1);
}

private short decompressD(uint y, ubyte d)
{
    return cast(short)((cast(uint)y * MLKEM_Q + (1u << (d - 1))) >> d);
}

private void byteEncode12(ubyte* outp, const ref short[256] a)
{
    short[256] t = a;
    polyToUnsigned(t);
    foreach (i; 0 .. 128)
    {
        const ushort t0 = t[2 * i];
        const ushort t1 = t[2 * i + 1];
        outp[3 * i + 0] = cast(ubyte) t0;
        outp[3 * i + 1] = cast(ubyte)((t0 >> 8) | (t1 << 4));
        outp[3 * i + 2] = cast(ubyte)(t1 >> 4);
    }
}

private void byteDecode12(ref short[256] r, const(ubyte)* a)
{
    foreach (i; 0 .. 128)
    {
        r[2 * i] = cast(short)(a[3 * i + 0] | ((cast(ushort)a[3 * i + 1] & 0x0f) << 8));
        r[2 * i + 1] = cast(short)((a[3 * i + 1] >> 4) | (cast(ushort)a[3 * i + 2] << 4));
    }
}

private void polyCompress(ubyte* outp, const ref short[256] a, ubyte d)
{
    short[256] t = a;
    polyCsubq(t);
    polyMakePositive(t);
    if (d == 4)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            ubyte[8] u;
            foreach (j; 0 .. 8)
                u[j] = cast(ubyte) compressD(t[8 * i + j], 4);
            outp[off + 0] = cast(ubyte)(u[0] | (u[1] << 4));
            outp[off + 1] = cast(ubyte)(u[2] | (u[3] << 4));
            outp[off + 2] = cast(ubyte)(u[4] | (u[5] << 4));
            outp[off + 3] = cast(ubyte)(u[6] | (u[7] << 4));
            off += 4;
        }
    }
    else if (d == 5)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            ubyte[8] u;
            foreach (j; 0 .. 8)
                u[j] = cast(ubyte) compressD(t[8 * i + j], 5);
            outp[off + 0] = cast(ubyte)((u[0] >> 0) | (u[1] << 5));
            outp[off + 1] = cast(ubyte)((u[1] >> 3) | (u[2] << 2) | (u[3] << 7));
            outp[off + 2] = cast(ubyte)((u[3] >> 1) | (u[4] << 4));
            outp[off + 3] = cast(ubyte)((u[4] >> 4) | (u[5] << 1) | (u[6] << 6));
            outp[off + 4] = cast(ubyte)((u[6] >> 2) | (u[7] << 3));
            off += 5;
        }
    }
    else if (d == 10)
    {
        size_t off;
        foreach (i; 0 .. 64)
        {
            ushort[4] u;
            foreach (j; 0 .. 4)
                u[j] = cast(ushort) compressD(t[4 * i + j], 10);
            outp[off + 0] = cast(ubyte)(u[0] >> 0);
            outp[off + 1] = cast(ubyte)((u[0] >> 8) | (u[1] << 2));
            outp[off + 2] = cast(ubyte)((u[1] >> 6) | (u[2] << 4));
            outp[off + 3] = cast(ubyte)((u[2] >> 4) | (u[3] << 6));
            outp[off + 4] = cast(ubyte)(u[3] >> 2);
            off += 5;
        }
    }
    else if (d == 11)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            ushort[8] u;
            foreach (j; 0 .. 8)
                u[j] = cast(ushort) compressD(t[8 * i + j], 11);
            outp[off + 0] = cast(ubyte)(u[0] >> 0);
            outp[off + 1] = cast(ubyte)((u[0] >> 8) | (u[1] << 3));
            outp[off + 2] = cast(ubyte)((u[1] >> 5) | (u[2] << 6));
            outp[off + 3] = cast(ubyte)(u[2] >> 2);
            outp[off + 4] = cast(ubyte)((u[2] >> 10) | (u[3] << 1));
            outp[off + 5] = cast(ubyte)((u[3] >> 7) | (u[4] << 4));
            outp[off + 6] = cast(ubyte)((u[4] >> 4) | (u[5] << 7));
            outp[off + 7] = cast(ubyte)(u[5] >> 1);
            outp[off + 8] = cast(ubyte)((u[5] >> 9) | (u[6] << 2));
            outp[off + 9] = cast(ubyte)((u[6] >> 6) | (u[7] << 5));
            outp[off + 10] = cast(ubyte)(u[7] >> 3);
            off += 11;
        }
    }
    else
        throw new InvalidArgument("ML-KEM compress d");
}

private void polyDecompress(ref short[256] r, const(ubyte)* a, ubyte d)
{
    if (d == 4)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            r[8 * i + 0] = decompressD(a[off + 0] & 15, 4);
            r[8 * i + 1] = decompressD(a[off + 0] >> 4, 4);
            r[8 * i + 2] = decompressD(a[off + 1] & 15, 4);
            r[8 * i + 3] = decompressD(a[off + 1] >> 4, 4);
            r[8 * i + 4] = decompressD(a[off + 2] & 15, 4);
            r[8 * i + 5] = decompressD(a[off + 2] >> 4, 4);
            r[8 * i + 6] = decompressD(a[off + 3] & 15, 4);
            r[8 * i + 7] = decompressD(a[off + 3] >> 4, 4);
            off += 4;
        }
    }
    else if (d == 5)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            r[8 * i + 0] = decompressD(a[off + 0] & 31, 5);
            r[8 * i + 1] = decompressD((a[off + 0] >> 5) | ((a[off + 1] & 3) << 3), 5);
            r[8 * i + 2] = decompressD((a[off + 1] >> 2) & 31, 5);
            r[8 * i + 3] = decompressD((a[off + 1] >> 7) | ((a[off + 2] & 15) << 1), 5);
            r[8 * i + 4] = decompressD((a[off + 2] >> 4) | ((a[off + 3] & 1) << 4), 5);
            r[8 * i + 5] = decompressD((a[off + 3] >> 1) & 31, 5);
            r[8 * i + 6] = decompressD((a[off + 3] >> 6) | ((a[off + 4] & 7) << 2), 5);
            r[8 * i + 7] = decompressD(a[off + 4] >> 3, 5);
            off += 5;
        }
    }
    else if (d == 10)
    {
        size_t off;
        foreach (i; 0 .. 64)
        {
            r[4 * i + 0] = decompressD(a[off + 0] | ((cast(uint)a[off + 1] & 0x03) << 8), 10);
            r[4 * i + 1] = decompressD((a[off + 1] >> 2) | ((cast(uint)a[off + 2] & 0x0f) << 6), 10);
            r[4 * i + 2] = decompressD((a[off + 2] >> 4) | ((cast(uint)a[off + 3] & 0x3f) << 4), 10);
            r[4 * i + 3] = decompressD((a[off + 3] >> 6) | ((cast(uint)a[off + 4] & 0xff) << 2), 10);
            off += 5;
        }
    }
    else if (d == 11)
    {
        size_t off;
        foreach (i; 0 .. 32)
        {
            r[8 * i + 0] = decompressD(a[off + 0] | ((cast(uint)a[off + 1] & 0x07) << 8), 11);
            r[8 * i + 1] = decompressD((a[off + 1] >> 3) | ((cast(uint)a[off + 2] & 0x3f) << 5), 11);
            r[8 * i + 2] = decompressD((a[off + 2] >> 6) | ((cast(uint)a[off + 3] & 0xff) << 2) | ((cast(uint)a[off + 4] & 0x01) << 10), 11);
            r[8 * i + 3] = decompressD((a[off + 4] >> 1) | ((cast(uint)a[off + 5] & 0x0f) << 7), 11);
            r[8 * i + 4] = decompressD((a[off + 5] >> 4) | ((cast(uint)a[off + 6] & 0x7f) << 4), 11);
            r[8 * i + 5] = decompressD((a[off + 6] >> 7) | ((cast(uint)a[off + 7] & 0xff) << 1) | ((cast(uint)a[off + 8] & 0x03) << 9), 11);
            r[8 * i + 6] = decompressD((a[off + 8] >> 2) | ((cast(uint)a[off + 9] & 0x1f) << 6), 11);
            r[8 * i + 7] = decompressD((a[off + 9] >> 5) | ((cast(uint)a[off + 10] & 0xff) << 3), 11);
            off += 11;
        }
    }
    else
        throw new InvalidArgument("ML-KEM decompress d");
}

private void polyFromMsg(ref short[256] r, const(ubyte)* msg)
{
    foreach (i; 0 .. 32)
    {
        foreach (j; 0 .. 8)
        {
            const short mask = -cast(short)((msg[i] >> j) & 1);
            r[8 * i + j] = mask & cast(short)((MLKEM_Q + 1) / 2);
        }
    }
}

private void polyToMsg(ubyte* msg, const ref short[256] a)
{
    short[256] t = a;
    polyToUnsigned(t);
    foreach (i; 0 .. 32)
    {
        msg[i] = 0;
        foreach (j; 0 .. 8)
        {
            uint x = t[8 * i + j];
            x <<= 1;
            x += 1665;
            x *= 80635;
            x >>= 28;
            msg[i] |= cast(ubyte)((x & 1) << j);
        }
    }
}

private void samplePolyCBD(ref short[256] r, const(ubyte)* buf, ubyte eta)
{
    if (eta == 2)
    {
        foreach (i; 0 .. 32)
        {
            const uint t = buf[4 * i] | (cast(uint)buf[4 * i + 1] << 8)
                | (cast(uint)buf[4 * i + 2] << 16) | (cast(uint)buf[4 * i + 3] << 24);
            uint d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
            foreach (j; 0 .. 8)
                r[8 * i + j] = cast(short)(((d >> (4 * j)) & 0x3) - ((d >> (4 * j + 2)) & 0x3));
        }
    }
    else if (eta == 3)
    {
        foreach (i; 0 .. 64)
        {
            const uint t = buf[3 * i] | (cast(uint)buf[3 * i + 1] << 8) | (cast(uint)buf[3 * i + 2] << 16);
            uint d = (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249);
            foreach (j; 0 .. 4)
                r[4 * i + j] = cast(short)(((d >> (6 * j)) & 0x7) - ((d >> (6 * j + 3)) & 0x7));
        }
    }
    else
        throw new InvalidArgument("ML-KEM CBD eta");
}

private void sampleNTT(ref short[256] r, XOF xof)
{
    size_t ctr;
    ubyte[3] buf;
    while (ctr < 256)
    {
        xof.output(buf[]);
        const ushort d1 = buf[0] | ((cast(ushort)buf[1] & 0x0f) << 8);
        const ushort d2 = (buf[1] >> 4) | (cast(ushort)buf[2] << 4);
        if (d1 < MLKEM_Q)
            r[ctr++] = d1;
        if (ctr < 256 && d2 < MLKEM_Q)
            r[ctr++] = d2;
    }
}

private Unique!HashFunction hashNamed(in string name)
{
    auto proto = retrieveHash(name);
    if (!proto)
        throw new LookupError(name ~ " unavailable");
    return Unique!HashFunction(proto.clone());
}

private void hashG(const ref MLKEMParams p, const(ubyte)* inbuf, size_t inlen, ubyte* out64)
{
    Unique!HashFunction h = hashNamed(p.kyber_90s ? "SHA-512" : "SHA-3(512)");
    h.update(inbuf, inlen);
    auto d = h.finished();
    out64[0 .. 64] = d[];
}

private void hashH(const ref MLKEMParams p, const(ubyte)* inbuf, size_t inlen, ubyte* out32)
{
    Unique!HashFunction h = hashNamed(p.kyber_90s ? "SHA-256" : "SHA-3(256)");
    h.update(inbuf, inlen);
    auto d = h.finished();
    out32[0 .. 32] = d[];
}

private void kdfSs(const ref MLKEMParams p, const(ubyte)* inbuf, size_t inlen, ubyte* ss)
{
    if (p.kyber_90s)
    {
        Unique!HashFunction h = hashNamed("SHA-256");
        h.update(inbuf, inlen);
        auto d = h.finished();
        ss[0 .. 32] = d[];
    }
    else
        shake256(inbuf, inlen, ss, 32);
}

private Unique!XOF shakeXof(in string name)
{
    Unique!XOF x = getXof(name);
    if (!x)
        throw new LookupError(name ~ " XOF unavailable");
    return x;
}

private void shake256(const(ubyte)* inbuf, size_t inlen, ubyte* outp, size_t outlen)
{
    Unique!XOF x = shakeXof("SHAKE-256");
    x.update(inbuf, inlen);
    x.output(outp, outlen);
}

private void prf(const ref MLKEMParams p, ubyte* outp, size_t outlen, const(ubyte)* seed, ubyte nonce)
{
    if (p.kyber_90s)
    {
        static if (BOTAN_HAS_AES_CTR_XOF)
        {
            Unique!XOF x = getXof("CTR-BE(AES-256)");
            if (!x)
                throw new LookupError("CTR-BE(AES-256) XOF unavailable");
            ubyte[12] iv;
            iv[] = 0;
            iv[0] = nonce;
            x.start(iv[], seed[0 .. 32]);
            x.output(outp, outlen);
        }
        else
            throw new LookupError("Kyber-90s requires AES_CTR_XOF");
    }
    else
    {
        ubyte[33] ext;
        ext[0 .. 32] = seed[0 .. 32];
        ext[32] = nonce;
        shake256(ext.ptr, 33, outp, outlen);
    }
}

private void genMatrix(const ref MLKEMParams p, ref short[256][][] a, const(ubyte)* rho, bool transposed)
{
    const ubyte k = p.k;
    a.length = k;
    foreach (i; 0 .. k)
    {
        a[i].length = k;
        foreach (j; 0 .. k)
        {
            if (p.kyber_90s)
            {
                static if (BOTAN_HAS_AES_CTR_XOF)
                {
                    Unique!XOF x = getXof("CTR-BE(AES-256)");
                    if (!x)
                        throw new LookupError("CTR-BE(AES-256) XOF unavailable");
                    ubyte[12] iv;
                    iv[] = 0;
                    if (transposed)
                    {
                        iv[0] = cast(ubyte) i;
                        iv[1] = cast(ubyte) j;
                    }
                    else
                    {
                        iv[0] = cast(ubyte) j;
                        iv[1] = cast(ubyte) i;
                    }
                    x.start(iv[], rho[0 .. 32]);
                    sampleNTT(a[i][j], x);
                }
                else
                    throw new LookupError("Kyber-90s requires AES_CTR_XOF");
            }
            else
            {
                Unique!XOF x = shakeXof("SHAKE-128");
                ubyte[34] seed;
                seed[0 .. 32] = rho[0 .. 32];
                if (transposed)
                {
                    seed[32] = cast(ubyte) i;
                    seed[33] = cast(ubyte) j;
                }
                else
                {
                    seed[32] = cast(ubyte) j;
                    seed[33] = cast(ubyte) i;
                }
                x.update(seed.ptr, 34);
                sampleNTT(a[i][j], x);
            }
        }
    }
}

private void getNoise(const ref MLKEMParams p, ref short[256] r, const(ubyte)* seed, ubyte nonce, ubyte eta)
{
    auto buf = new ubyte[64 * eta]; // 128 for eta=2, 192 for eta=3
    prf(p, buf.ptr, buf.length, seed, nonce);
    samplePolyCBD(r, buf.ptr, eta);
}

/// Encoded public key in expanded form (t, rho, H(pk)).
struct MLKEMPublic
{
    MLKEMParams params;
    short[256][] t; // k polys, NTT
    ubyte[32] rho;
    ubyte[32] h;
}

/// Secret key plus the matching public key.
struct MLKEMSecret
{
    MLKEMParams params;
    short[256][] s; // k polys, NTT
    ubyte[32] d;
    ubyte[32] z;
    MLKEMPublic pub;
}

private void encodePk(const ref MLKEMPublic pk, ubyte* outp)
{
    foreach (i; 0 .. pk.params.k)
        byteEncode12(outp + i * 384, pk.t[i]);
    outp[pk.params.k * 384 .. pk.params.k * 384 + 32] = pk.rho[];
}

private MLKEMPublic decodePk(const(ubyte)* inp, MLKEMParams p)
{
    MLKEMPublic pk;
    pk.params = p;
    pk.t.length = p.k;
    foreach (i; 0 .. p.k)
    {
        byteDecode12(pk.t[i], inp + i * 384);
        foreach (c; pk.t[i])
            if (c < 0 || c >= MLKEM_Q)
                throw new DecodingError("Decoded polynomial coefficients out of range");
    }
    pk.rho[] = inp[p.k * 384 .. p.k * 384 + 32];
    hashH(p, inp, mlkemPkBytes(p), pk.h.ptr);
    return pk;
}

/// FIPS 203 Algorithms 13 + 16: KeyGen from seeds d, z.
/// Kyber R3 uses G(d) without the FIPS 203 domain-separation byte k.
MLKEMSecret mlkemKeygenFromSeeds(const ref MLKEMParams p, const(ubyte)* d, const(ubyte)* z)
{
    ubyte[64] gout;
    if (p.kyber_r3)
        hashG(p, d, 32, gout.ptr);
    else
    {
        ubyte[33] gin;
        gin[0 .. 32] = d[0 .. 32];
        gin[32] = p.k;
        hashG(p, gin.ptr, 33, gout.ptr);
    }
    const(ubyte)* rho = gout.ptr;
    const(ubyte)* sigma = gout.ptr + 32;

    short[256][][] A;
    genMatrix(p, A, rho, false);

    short[256][] s, e, t;
    s.length = p.k;
    e.length = p.k;
    t.length = p.k;
    ubyte nonce;
    foreach (i; 0 .. p.k)
        getNoise(p, s[i], sigma, nonce++, p.eta1);
    foreach (i; 0 .. p.k)
        getNoise(p, e[i], sigma, nonce++, p.eta1);
    foreach (i; 0 .. p.k)
        ntt(s[i]);
    foreach (i; 0 .. p.k)
        ntt(e[i]);

    foreach (i; 0 .. p.k)
    {
        t[i][] = 0;
        foreach (j; 0 .. p.k)
        {
            short[256] prod;
            polyBasemul(prod, A[i][j], s[j]);
            polyAdd(t[i], prod);
        }
        polyTomont(t[i]);
        polyAdd(t[i], e[i]);
        polyReduce(t[i]);
    }
    foreach (i; 0 .. p.k)
        polyReduce(s[i]);

    MLKEMSecret sk;
    sk.params = p;
    sk.s = s;
    sk.d[] = d[0 .. 32];
    sk.z[] = z[0 .. 32];
    sk.pub.params = p;
    sk.pub.t = t;
    sk.pub.rho[] = rho[0 .. 32];
    auto ek = new ubyte[mlkemPkBytes(p)];
    encodePk(sk.pub, ek.ptr);
    hashH(p, ek.ptr, ek.length, sk.pub.h.ptr);
    return sk;
}

MLKEMSecret mlkemKeygenFromSeeds(MLKEMMode mode, const(ubyte)* d, const(ubyte)* z)
{
    auto p = mlkemParams(mode);
    return mlkemKeygenFromSeeds(p, d, z);
}

MLKEMSecret mlkemKeygen(const ref MLKEMParams p, RandomNumberGenerator rng)
{
    ubyte[32] d, z;
    rng.randomize(d.ptr, 32);
    rng.randomize(z.ptr, 32);
    return mlkemKeygenFromSeeds(p, d.ptr, z.ptr);
}

MLKEMSecret mlkemKeygen(MLKEMMode mode, RandomNumberGenerator rng)
{
    auto p = mlkemParams(mode);
    return mlkemKeygen(p, rng);
}

private void indcpaEncrypt(const ref MLKEMPublic pk, const(ubyte)* m, const(ubyte)* coins, ubyte* ct)
{
    auto p = pk.params;
    short[256][][] At;
    genMatrix(p, At, pk.rho.ptr, true);

    short[256][] y, e1;
    y.length = p.k;
    e1.length = p.k;
    short[256] e2, mu, v;
    ubyte nonce;
    foreach (i; 0 .. p.k)
        getNoise(p, y[i], coins, nonce++, p.eta1);
    foreach (i; 0 .. p.k)
        getNoise(p, e1[i], coins, nonce++, 2);
    getNoise(p, e2, coins, nonce++, 2);
    foreach (i; 0 .. p.k)
        ntt(y[i]);

    short[256][] u;
    u.length = p.k;
    foreach (i; 0 .. p.k)
    {
        u[i][] = 0;
        foreach (j; 0 .. p.k)
        {
            short[256] prod;
            polyBasemul(prod, At[i][j], y[j]);
            polyAdd(u[i], prod);
        }
        invntt(u[i]);
        polyAdd(u[i], e1[i]);
        polyReduce(u[i]);
    }

    v[] = 0;
    foreach (j; 0 .. p.k)
    {
        short[256] prod;
        polyBasemul(prod, pk.t[j], y[j]);
        polyAdd(v, prod);
    }
    invntt(v);
    polyFromMsg(mu, m);
    polyAdd(v, e2);
    polyAdd(v, mu);
    polyReduce(v);

    const size_t u_bytes = p.k * (p.du * MLKEM_N / 8);
    foreach (i; 0 .. p.k)
        polyCompress(ct + i * (p.du * MLKEM_N / 8), u[i], p.du);
    polyCompress(ct + u_bytes, v, p.dv);
}

private void indcpaDecrypt(const ref MLKEMSecret sk, const(ubyte)* ct, ubyte* m)
{
    auto p = sk.params;
    const size_t u_bytes = p.k * (p.du * MLKEM_N / 8);
    short[256][] u;
    u.length = p.k;
    foreach (i; 0 .. p.k)
        polyDecompress(u[i], ct + i * (p.du * MLKEM_N / 8), p.du);
    short[256] v;
    polyDecompress(v, ct + u_bytes, p.dv);

    foreach (i; 0 .. p.k)
        ntt(u[i]);
    short[256] w;
    w[] = 0;
    foreach (i; 0 .. p.k)
    {
        short[256] prod;
        polyBasemul(prod, sk.s[i], u[i]);
        polyAdd(w, prod);
    }
    invntt(w);
    polySub(v, w);
    polyReduce(v);
    polyToMsg(m, v);
}

/// FIPS 203 Encaps, or Kyber R3 CCAKEM.Enc (m = H(seed), SS = KDF(K̄‖H(c))).
void mlkemEncaps(const ref MLKEMPublic pk, const(ubyte)* m_or_seed, ubyte* ss, ubyte* ct)
{
    auto p = pk.params;
    ubyte[32] m;
    if (p.kyber_r3)
        hashH(p, m_or_seed, 32, m.ptr);
    else
        m[] = m_or_seed[0 .. 32];
    ubyte[64] gh;
    ubyte[64] gin;
    gin[0 .. 32] = m[];
    gin[32 .. 64] = pk.h[];
    hashG(p, gin.ptr, 64, gh.ptr);
    indcpaEncrypt(pk, m.ptr, gh.ptr + 32, ct);
    if (p.kyber_r3)
    {
        ubyte[64] kdfin;
        kdfin[0 .. 32] = gh[0 .. 32];
        hashH(p, ct, mlkemCtBytes(p), kdfin.ptr + 32);
        kdfSs(p, kdfin.ptr, 64, ss);
    }
    else
        ss[0 .. 32] = gh[0 .. 32];
}

void mlkemEncaps(const ref MLKEMPublic pk, RandomNumberGenerator rng, ubyte* ss, ubyte* ct)
{
    ubyte[32] m;
    rng.randomize(m.ptr, 32);
    mlkemEncaps(pk, m.ptr, ss, ct);
}

/// FIPS 203 Algorithms 18/21 Decaps (implicit rejection).
void mlkemDecaps(const ref MLKEMSecret sk, const(ubyte)* ct, size_t ct_len, ubyte* ss)
{
    auto p = sk.params;
    const size_t clen = mlkemCtBytes(p);
    if (ct_len != clen)
        throw new DecodingError("ML-KEM: unexpected ciphertext length");
    ubyte[32] mp;
    indcpaDecrypt(sk, ct, mp.ptr);
    ubyte[64] gh;
    ubyte[64] gin;
    gin[0 .. 32] = mp[];
    gin[32 .. 64] = sk.pub.h[];
    hashG(p, gin.ptr, 64, gh.ptr);
    auto c2 = new ubyte[clen];
    indcpaEncrypt(sk.pub, mp.ptr, gh.ptr + 32, c2.ptr);

    ubyte fail;
    foreach (i; 0 .. clen)
        fail |= ct[i] ^ c2[i];
    const auto mask = CTMask!ubyte.isZero(fail);
    if (p.kyber_r3)
    {
        ubyte[32] k;
        foreach (i; 0 .. 32)
            k[i] = mask.select(gh[i], sk.z[i]);
        ubyte[64] kdfin;
        kdfin[0 .. 32] = k[];
        hashH(p, ct, clen, kdfin.ptr + 32);
        kdfSs(p, kdfin.ptr, 64, ss);
    }
    else
    {
        auto zc = new ubyte[32 + clen];
        zc[0 .. 32] = sk.z[];
        zc[32 .. 32 + clen] = ct[0 .. clen];
        ubyte[32] kbar;
        shake256(zc.ptr, zc.length, kbar.ptr, 32);
        foreach (i; 0 .. 32)
            ss[i] = mask.select(gh[i], kbar[i]);
    }
}

size_t kyberExpandedSkBytes(const ref MLKEMParams p)
{
    return p.k * 384 + mlkemPkBytes(p) + 32 + 32;
}

ubyte[] kyberR3EncodeSk(const ref MLKEMSecret sk)
{
    const k = sk.params.k;
    const pklen = mlkemPkBytes(sk.params);
    auto v = new ubyte[k * 384 + pklen + 32 + 32];
    foreach (i; 0 .. k)
        byteEncode12(v.ptr + i * 384, sk.s[i]);
    encodePk(sk.pub, v.ptr + k * 384);
    v[k * 384 + pklen .. k * 384 + pklen + 32] = sk.pub.h[];
    v[$ - 32 .. $] = sk.z[];
    return v;
}

MLKEMSecret kyberDecodeExpandedSk(const ref MLKEMParams p, const(ubyte)* bits, size_t len)
{
    if (len != kyberExpandedSkBytes(p))
        throw new InvalidArgument("Private key does not have the correct byte count");
    MLKEMSecret sk;
    sk.params = p;
    sk.s.length = p.k;
    foreach (i; 0 .. p.k)
        byteDecode12(sk.s[i], bits + i * 384);
    const pkoff = p.k * 384;
    sk.pub = decodePk(bits + pkoff, p);
    const hoff = pkoff + mlkemPkBytes(p);
    if (sk.pub.h[] != bits[hoff .. hoff + 32])
        throw new DecodingError("Kyber private key public-hash mismatch");
    sk.z[] = bits[hoff + 32 .. hoff + 64];
    return sk;
}

Vector!ubyte mlkemEncodePublic(const ref MLKEMPublic pk)
{
    auto v = Vector!ubyte(mlkemPkBytes(pk.params));
    encodePk(pk, v.ptr);
    return v.move();
}

Vector!ubyte mlkemEncodeSeed(const ref MLKEMSecret sk)
{
    auto v = Vector!ubyte(64);
    v[0 .. 32] = sk.d[];
    v[32 .. 64] = sk.z[];
    return v.move();
}

ubyte[16] mlkemShake16(const(ubyte)* p, size_t n)
{
    ubyte[16] outp;
    shake256(p, n, outp.ptr, 16);
    return outp;
}

ubyte[16] mlkemSha256_16(const(ubyte)* p, size_t n)
{
    Unique!HashFunction h = hashNamed("SHA-256");
    h.update(p, n);
    auto d = h.finished();
    ubyte[16] outp;
    outp[] = d.ptr[0 .. 16];
    return outp;
}

/**
* ML-KEM (FIPS 203) / Kyber public key
*/
final class MLKEMPublicKey : PublicKey
{
public:
    /**
    * Decode an encoded public key
    * Params:
    *  mode = parameter set
    *  bits = t || rho
    *  len = must be mlkemPkBytes(mode)
    */
    this(MLKEMMode mode, const(ubyte)* bits, size_t len)
    {
        auto p = mlkemParams(mode);
        this(p, bits, len);
    }

    /**
    * Params:
    *  p = parameter block
    *  bits = t || rho
    *  len = must equal mlkemPkBytes(p)
    */
    this(const ref MLKEMParams p, const(ubyte)* bits, size_t len)
    {
        if (len != mlkemPkBytes(p))
            throw new InvalidArgument("Public key does not have the correct byte count");
        m_pub = decodePk(bits, p);
    }

    /**
    * Params:
    *  name = SCAN name ("ML-KEM-768", …)
    *  bits = encoded public key
    *  len = length of bits
    */
    this(in string name, const(ubyte)* bits, size_t len)
    {
        auto p = mlkemParamsFromName(name);
        this(p, bits, len);
    }

    /// Copy from an expanded public key.
    this(const ref MLKEMPublic pub)
    {
        m_pub.params = pub.params;
        m_pub.t.length = pub.t.length;
        foreach (i; 0 .. pub.t.length)
            m_pub.t[i] = pub.t[i];
        m_pub.rho = pub.rho;
        m_pub.h = pub.h;
    }

    /**
    * Decode X.509 SubjectPublicKeyInfo
    * Params:
    *  alg_id = algorithm identifier (OID selects the set)
    *  key_bits = encoded public key
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        this(OIDS.lookup(alg_id.oid), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_pub.params.name; }
    override size_t estimatedStrength() const { return m_pub.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_pub.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        return mlkemEncodePublic(m_pub);
    }
    /// Expanded public key (polynomials, rho, H(pk)).
    ref const(MLKEMPublic) raw() const { return m_pub; }
    /// Parameter set of this key.
    MLKEMMode mode() const { return m_pub.params.mode; }

private:
    MLKEMPublic m_pub;
}

/**
* ML-KEM (FIPS 203) / Kyber private key
*/
final class MLKEMPrivateKey : PrivateKey, PublicKey
{
public:
    /**
    * Generate a random key
    * Params:
    *  mode = parameter set
    *  rng = random number generator
    */
    this(MLKEMMode mode, RandomNumberGenerator rng)
    {
        m_sk = mlkemKeygen(mode, rng);
        m_has_seed = true;
    }

    /**
    * Params:
    *  name = SCAN name ("ML-KEM-768", …)
    *  rng = random number generator
    */
    this(in string name, RandomNumberGenerator rng)
    {
        auto p = mlkemParamsFromName(name);
        m_sk = mlkemKeygen(p, rng);
        m_has_seed = true;
    }

    /**
    * KeyGen from FIPS 203 seeds (d, z), each 32 bytes
    * Params:
    *  mode = parameter set
    *  d = seed d
    *  z = implicit-rejection seed z
    */
    this(MLKEMMode mode, const(ubyte)* d, const(ubyte)* z)
    {
        m_sk = mlkemKeygenFromSeeds(mode, d, z);
        m_has_seed = true;
    }

    /// ditto
    this(const ref MLKEMParams p, const(ubyte)* d, const(ubyte)* z)
    {
        m_sk = mlkemKeygenFromSeeds(p, d, z);
        m_has_seed = true;
    }

    /// ditto
    this(in string name, const(ubyte)* d, const(ubyte)* z)
    {
        auto p = mlkemParamsFromName(name);
        m_sk = mlkemKeygenFromSeeds(p, d, z);
        m_has_seed = true;
    }

    /**
    * Decode an encoded private key
    * Params:
    *  mode = parameter set
    *  bits = seed (64 bytes) or expanded encoding
    *  len = length of bits
    */
    this(MLKEMMode mode, const(ubyte)* bits, size_t len)
    {
        auto p = mlkemParams(mode);
        loadEncoded(p, bits, len);
    }

    /// ditto
    this(in string name, const(ubyte)* bits, size_t len)
    {
        auto p = mlkemParamsFromName(name);
        loadEncoded(p, bits, len);
    }

    /**
    * Decode PKCS #8 (seed form, 64 bytes)
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = BER OCTET STRING of d || z
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        import botan.asn1.ber_dec;
        auto p = mlkemParamsFromName(OIDS.lookup(alg_id.oid));
        if (p.kyber_r3)
            throw new DecodingError("Kyber R3 private keys are not seed-encoded");
        if (key_bits.length == 64)
        {
            m_sk = mlkemKeygenFromSeeds(p, key_bits.ptr, key_bits.ptr + 32);
            m_has_seed = true;
        }
        else
        {
            SecureVector!ubyte bits;
            BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING).discardRemaining();
            if (bits.length != 64)
                throw new DecodingError("ML-KEM: only seed private keys (64 bytes) supported");
            m_sk = mlkemKeygenFromSeeds(p, bits.ptr, bits.ptr + 32);
            m_has_seed = true;
        }
    }

    override @property string algoName() const { return m_sk.params.name; }
    override size_t estimatedStrength() const { return m_sk.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_sk.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        return mlkemEncodePublic(m_sk.pub);
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        if (m_has_seed && !m_sk.params.kyber_r3)
        {
            auto v = SecureVector!ubyte(64);
            v[0 .. 32] = m_sk.d[];
            v[32 .. 64] = m_sk.z[];
            return v.move();
        }
        auto raw = kyberR3EncodeSk(m_sk);
        auto v = SecureVector!ubyte(raw.length);
        v[] = raw[];
        return v.move();
    }
    ref const(MLKEMSecret) raw() const { return m_sk; }
    MLKEMPublicKey publicKey() const { return new MLKEMPublicKey(m_sk.pub); }
    MLKEMMode mode() const { return m_sk.params.mode; }

private:
    void loadEncoded(const ref MLKEMParams p, const(ubyte)* bits, size_t len)
    {
        if (p.kyber_r3 && len == 64)
            throw new InvalidArgument("Kyber round 3 private keys do not support the seed format");
        if (!p.kyber_r3 && len == 64)
        {
            m_sk = mlkemKeygenFromSeeds(p, bits, bits + 32);
            m_has_seed = true;
        }
        else if (len == kyberExpandedSkBytes(p))
        {
            m_sk = kyberDecodeExpandedSk(p, bits, len);
            m_has_seed = false;
        }
        else
            throw new InvalidArgument("Private key does not have the correct byte count");
    }

    MLKEMSecret m_sk;
    bool m_has_seed;
}

static if (BOTAN_HAS_TESTS && !SKIP_ML_KEM_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import botan.pubkey.pk_algs;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing ml_kem.d ...");
    size_t fails;

    foreach (mode; [MLKEMMode.Kem512, MLKEMMode.Kem768, MLKEMMode.Kem1024])
    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(mode, *rng);
        Unique!MLKEMPublicKey pk = sk.publicKey();
        auto p = mlkemParams(mode);
        auto ss1 = new ubyte[32];
        auto ss2 = new ubyte[32];
        auto ct = new ubyte[mlkemCtBytes(p)];
        mlkemEncaps(pk.raw(), *rng, ss1.ptr, ct.ptr);
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
        if (ss1[0 .. 32] != ss2[0 .. 32])
        {
            logError(p.name, " pairwise mismatch K=", hexEncode(ss1.ptr, 32),
                     " K'=", hexEncode(ss2.ptr, 32));
            ++fails;
        }
        ct[0] ^= 0xff;
        auto ss3 = new ubyte[32];
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss3.ptr);
        if (ss3[0 .. 32] == ss1[0 .. 32])
        {
            logError(p.name, " implicit rejection failed");
            ++fails;
        }
    }

    if (exists("test_data/pubkey/ml_kem_acvp_keygen.vec"))
    {
        File vec = File("test_data/pubkey/ml_kem_acvp_keygen.vec", "r");
        fails += runTestsBb(vec, "ML-KEM", "DK", true,
            (ref HashMap!(string, string) m)
            {
                if (!("D" in m) || !("Z" in m) || !("EK" in m) || !("DK" in m))
                    return 0;
                const mode = mlkemModeFromName(m["ML-KEM"]);
                auto d = hexDecode(m["D"]);
                auto z = hexDecode(m["Z"]);
                Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(mode, d.ptr, z.ptr);
                auto ek = mlkemEncodePublic(sk.raw().pub);
                auto dk = mlkemEncodeSeed(sk.raw());
                auto ekh = mlkemShake16(ek.ptr, ek.length);
                auto dkh = mlkemShake16(dk.ptr, dk.length);
                auto want_ek = hexDecode(m["EK"]);
                auto want_dk = hexDecode(m["DK"]);
                if (ekh[] != want_ek[] || dkh[] != want_dk[])
                {
                    logError(m["ML-KEM"], " ACVP keygen mismatch EK=", hexEncode(ekh.ptr, 16),
                             " want=", m["EK"], " DK=", hexEncode(dkh.ptr, 16), " want=", m["DK"]);
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/ml_kem_acvp_encap.vec"))
    {
        File vec = File("test_data/pubkey/ml_kem_acvp_encap.vec", "r");
        fails += runTestsBb(vec, "ML-KEM", "C", true,
            (ref HashMap!(string, string) m)
            {
                if (!("EK" in m) || !("M" in m) || !("K" in m) || !("C" in m))
                    return 0;
                const mode = mlkemModeFromName(m["ML-KEM"]);
                auto ek = hexDecode(m["EK"]);
                auto msg = hexDecode(m["M"]);
                Unique!MLKEMPublicKey pk = new MLKEMPublicKey(mode, ek.ptr, ek.length);
                auto p = mlkemParams(mode);
                auto ss = new ubyte[32];
                auto ct = new ubyte[mlkemCtBytes(p)];
                mlkemEncaps(pk.raw(), msg.ptr, ss.ptr, ct.ptr);
                auto want_k = hexDecode(m["K"]);
                auto want_c = hexDecode(m["C"]);
                auto ch = mlkemShake16(ct.ptr, ct.length);
                if (ss[0 .. 32] != want_k[] || ch[] != want_c[])
                {
                    logError(m["ML-KEM"], " ACVP encap mismatch");
                    return 1;
                }
                return 0;
            });
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(MLKEMMode.Kem512, *rng);
        auto pub_bits = SecureVector!ubyte(sk.x509SubjectPublicKey()[]);
        Unique!PublicKey via_pk = makePublicKey(sk.algorithmIdentifier(), pub_bits);
        if (!via_pk || via_pk.algoName != "ML-KEM-512")
        {
            logError("ML-KEM factory public key");
            ++fails;
        }
        auto seed = sk.pkcs8PrivateKey();
        auto alg_id = sk.pkcs8AlgorithmIdentifier();
        Unique!PrivateKey via_sk = makePrivateKey(alg_id, seed, *rng);
        if (!via_sk || via_sk.algoName != "ML-KEM-512")
        {
            logError("ML-KEM factory private key");
            ++fails;
        }
        {
            const OID oid = OIDS.lookup("ML-KEM-768");
            if (oid.toString() != "2.16.840.1.101.3.4.4.2")
                ++fails;
            if (OIDS.lookup(oid) != "ML-KEM-768")
                ++fails;
        }
        const OID oidk = OIDS.lookup("Kyber-512-r3");
        if (oidk.toString() != "1.3.6.1.4.1.25258.1.7.1")
            ++fails;
        const OID oid90 = OIDS.lookup("Kyber-512-90s-r3");
        if (oid90.toString() != "1.3.6.1.4.1.25258.1.11.1")
            ++fails;
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey("Kyber-512-r3", *rng);
        Unique!MLKEMPublicKey pk = sk.publicKey();
        if (sk.algoName != "Kyber-512-r3" || !sk.raw().params.kyber_r3)
        {
            logError("Kyber R3 name");
            ++fails;
        }
        auto p = sk.raw().params;
        auto ss1 = new ubyte[32];
        auto ss2 = new ubyte[32];
        auto ct = new ubyte[mlkemCtBytes(p)];
        mlkemEncaps(pk.raw(), *rng, ss1.ptr, ct.ptr);
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
        if (ss1[0 .. 32] != ss2[0 .. 32])
        {
            logError("Kyber-512-r3 pairwise mismatch");
            ++fails;
        }
        ct[0] ^= 0xff;
        auto ss3 = new ubyte[32];
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss3.ptr);
        if (ss3[0 .. 32] == ss1[0 .. 32])
        {
            logError("Kyber-512-r3 implicit reject failed");
            ++fails;
        }
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey("Kyber-512-90s-r3", *rng);
        Unique!MLKEMPublicKey pk = sk.publicKey();
        if (sk.algoName != "Kyber-512-90s-r3" || !sk.raw().params.kyber_90s)
        {
            logError("Kyber-90s name");
            ++fails;
        }
        auto p = sk.raw().params;
        auto ss1 = new ubyte[32];
        auto ss2 = new ubyte[32];
        auto ct = new ubyte[mlkemCtBytes(p)];
        mlkemEncaps(pk.raw(), *rng, ss1.ptr, ct.ptr);
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
        if (ss1[0 .. 32] != ss2[0 .. 32])
        {
            logError("Kyber-512-90s-r3 pairwise mismatch");
            ++fails;
        }
        ct[0] ^= 0xff;
        auto ss3 = new ubyte[32];
        mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss3.ptr);
        if (ss3[0 .. 32] == ss1[0 .. 32])
        {
            logError("Kyber-512-90s-r3 implicit reject failed");
            ++fails;
        }
    }

    if (exists("test_data/pubkey/kyber_kat.vec"))
    {
        import botan.block.block_cipher;
        File vec = File("test_data/pubkey/kyber_kat.vec", "r");
        size_t[string] seen;
        fails += runTestsBb(vec, "Instance", "CT", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!isKyberR3Name(inst) && !isKyber90sName(inst))
                    return 0;
                if (++seen[inst] > 25)
                    return 0;
                if (!("Seed" in m) || !("SS" in m) || !("PK" in m) || !("SK" in m) || !("CT" in m))
                    return 0;
                auto seed = hexDecode(m["Seed"]);
                ubyte[32] d, z, sm;
                {
                    auto drbg = KyberKatDrbg(seed.ptr, seed.length);
                    drbg.generate(d.ptr, 32);
                    drbg.generate(z.ptr, 32);
                    drbg.generate(sm.ptr, 32);
                }
                auto p = mlkemParamsFromName(inst);
                Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(p, d.ptr, z.ptr);
                Unique!MLKEMPublicKey pk = sk.publicKey();
                auto pkbits = mlkemEncodePublic(pk.raw());
                auto skbits = kyberR3EncodeSk(sk.raw());
                auto ss = new ubyte[32];
                auto ct = new ubyte[mlkemCtBytes(p)];
                mlkemEncaps(pk.raw(), sm.ptr, ss.ptr, ct.ptr);
                auto want_ss = hexDecode(m["SS"]);
                if (ss[0 .. 32] != want_ss[])
                {
                    logError(inst, " KAT SS mismatch");
                    return 1;
                }
                auto pkh = isKyber90sName(inst)
                    ? mlkemSha256_16(pkbits.ptr, pkbits.length)
                    : mlkemShake16(pkbits.ptr, pkbits.length);
                if (pkh[] != hexDecode(m["PK"])[])
                {
                    logError(inst, " KAT PK hash mismatch");
                    return 1;
                }
                auto skh = isKyber90sName(inst)
                    ? mlkemSha256_16(skbits.ptr, skbits.length)
                    : mlkemShake16(skbits.ptr, skbits.length);
                if (skh[] != hexDecode(m["SK"])[])
                {
                    logError(inst, " KAT SK hash mismatch");
                    return 1;
                }
                auto cth = isKyber90sName(inst)
                    ? mlkemSha256_16(ct.ptr, ct.length)
                    : mlkemShake16(ct.ptr, ct.length);
                if (cth[] != hexDecode(m["CT"])[])
                {
                    logError(inst, " KAT CT hash mismatch");
                    return 1;
                }
                auto ss2 = new ubyte[32];
                mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
                if (ss2[0 .. 32] != want_ss[])
                {
                    logError(inst, " KAT decaps mismatch");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/ml_kem.vec"))
    {
        File vec = File("test_data/pubkey/ml_kem.vec", "r");
        fails += runTestsBb(vec, "ML-KEM", "SS_N", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["ML-KEM"];
                if (inst != "ML-KEM-512" && inst != "ML-KEM-768" && inst != "ML-KEM-1024")
                    return 0;
                if (!("Seed" in m) || !("SS" in m) || !("PK" in m) || !("SK" in m) || !("CT" in m))
                    return 0;
                auto seed = hexDecode(m["Seed"]);
                ubyte[32] z, d, sm;
                {
                    auto drbg = KyberKatDrbg(seed.ptr, seed.length);
                    drbg.generate(z.ptr, 32);
                    drbg.generate(d.ptr, 32);
                    drbg.generate(sm.ptr, 32);
                }
                const mode = mlkemModeFromName(inst);
                Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(mode, d.ptr, z.ptr);
                Unique!MLKEMPublicKey pk = sk.publicKey();
                auto pkbits = mlkemEncodePublic(pk.raw());
                auto skbits = mlkemEncodeSeed(sk.raw());
                auto ss = new ubyte[32];
                auto p = mlkemParams(mode);
                auto ct = new ubyte[mlkemCtBytes(p)];
                mlkemEncaps(pk.raw(), sm.ptr, ss.ptr, ct.ptr);
                auto want_ss = hexDecode(m["SS"]);
                if (ss[0 .. 32] != want_ss[])
                {
                    logError(inst, " KAT SS mismatch");
                    return 1;
                }
                if (mlkemShake16(pkbits.ptr, pkbits.length)[] != hexDecode(m["PK"])[])
                {
                    logError(inst, " KAT PK hash mismatch");
                    return 1;
                }
                if (mlkemShake16(skbits.ptr, skbits.length)[] != hexDecode(m["SK"])[])
                {
                    logError(inst, " KAT SK hash mismatch");
                    return 1;
                }
                if (mlkemShake16(ct.ptr, ct.length)[] != hexDecode(m["CT"])[])
                {
                    logError(inst, " KAT CT hash mismatch");
                    return 1;
                }
                auto ss2 = new ubyte[32];
                mlkemDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
                if (ss2[0 .. 32] != want_ss[])
                {
                    logError(inst, " KAT decaps mismatch");
                    return 1;
                }
                if (("CT_N" in m) && ("SS_N" in m))
                {
                    auto ctn = hexDecode(m["CT_N"]);
                    auto ssn = new ubyte[32];
                    mlkemDecaps(sk.raw(), ctn.ptr, ctn.length, ssn.ptr);
                    if (ssn[0 .. 32] != hexDecode(m["SS_N"])[])
                    {
                        logError(inst, " KAT SS_N mismatch");
                        return 1;
                    }
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/kyber_encodings.vec"))
    {
        File enc = File("test_data/pubkey/kyber_encodings.vec", "r");
        fails += runTestsBb(enc, "Instance", "PublicRaw", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!("PrivateRaw" in m) || !("PublicRaw" in m))
                    return 0;
                try { mlkemParamsFromName(inst); }
                catch (Exception) { return 0; }
                auto skraw = hexDecode(m["PrivateRaw"]);
                auto pkraw = hexDecode(m["PublicRaw"]);
                if ("Error" in m && m["Error"].length)
                {
                    try
                    {
                        if (skraw.length)
                            Unique!MLKEMPrivateKey badsk = new MLKEMPrivateKey(inst, skraw.ptr, skraw.length);
                        if (pkraw.length)
                            Unique!MLKEMPublicKey badpk = new MLKEMPublicKey(inst, pkraw.ptr, pkraw.length);
                        logError(inst, " encodings expected throw: ", m["Error"]);
                        return 1;
                    }
                    catch (Exception e)
                    {
                        import std.string : indexOf;
                        if (e.msg.indexOf(m["Error"]) < 0)
                        {
                            logError(inst, " encodings error want=", m["Error"], " got=", e.msg);
                            return 1;
                        }
                        return 0;
                    }
                }
                Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(inst, skraw.ptr, skraw.length);
                Unique!MLKEMPublicKey pk = new MLKEMPublicKey(inst, pkraw.ptr, pkraw.length);
                auto gotpk = mlkemEncodePublic(pk.raw());
                if (gotpk[] != pkraw[])
                {
                    logError(inst, " encodings PK mismatch");
                    return 1;
                }
                auto gotsk = sk.pkcs8PrivateKey();
                if (gotsk[] != skraw[])
                {
                    logError(inst, " encodings SK mismatch");
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("ml_kem", {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!MLKEMPrivateKey sk = new MLKEMPrivateKey(MLKEMMode.Kem512, *rng);
        auto p = mlkemParams(MLKEMMode.Kem512);
        auto ss = new ubyte[32];
        auto ct = new ubyte[mlkemCtBytes(p)];
        mlkemEncaps(sk.raw().pub, *rng, ss.ptr, ct.ptr);
    });

    if (fails)
        logError("ml_kem failures: ", fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS)
{

import botan.block.block_cipher;

private void kyberStoreBe64(ubyte* p, ulong v)
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

private ulong kyberLoadBe64(const(ubyte)* p)
{
    return (cast(ulong) p[0] << 56) | (cast(ulong) p[1] << 48) |
           (cast(ulong) p[2] << 40) | (cast(ulong) p[3] << 32) |
           (cast(ulong) p[4] << 24) | (cast(ulong) p[5] << 16) |
           (cast(ulong) p[6] << 8) | cast(ulong) p[7];
}

private struct KyberKatDrbg
{
    Unique!BlockCipher cipher;
    ulong v0, v1;

    this(const(ubyte)* seed, size_t slen)
    {
        cipher = retrieveBlockCipher("AES-256").clone();
        if (slen != 48)
            throw new InvalidArgument("Kyber KAT seed must be 48 bytes");
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
        kyberStoreBe64(outp, v0);
        kyberStoreBe64(outp + 8, v1);
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
        v0 = kyberLoadBe64(temp.ptr + 32);
        v1 = kyberLoadBe64(temp.ptr + 40);
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
            cipher.encryptN(block.ptr, block.ptr, 1);
            copyMem(outp + 16 * full, block.ptr, left);
        }
        update(null, 0);
    }
}

} // BOTAN_HAS_TESTS

