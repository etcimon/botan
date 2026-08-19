/**
* Classic McEliece (NIST Round 4 / ISO draft) — code-based KEM
*
* Based on the public domain reference implementation by the designers
* (https://classic.mceliece.org/impl.html — NISTPQC-R4, Oct 2022)
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2023-2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.classic_mceliece;

import botan.constants;
static if (BOTAN_HAS_CLASSIC_MCELIECE):

import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.libstate.lookup;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.utils.ct;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import botan.xof.xof;

enum size_t CMCE_ELL = 256;
enum size_t CMCE_SIGMA1 = 16;
enum size_t CMCE_SIGMA2 = 32;
enum size_t CMCE_MU = 32;
enum size_t CMCE_NU = 64;

struct CmceParams
{
    string name;
    uint m;
    uint n;
    uint t;
    ushort poly_f;
    uint bitsec;
    bool fast;
    bool pc;
    CmceTerm[] fterms;
}

struct CmceTerm
{
    size_t idx;
    ushort coeff;
}

private uint floorLog2(uint x)
{
    uint r;
    while (x > 1)
    {
        x >>= 1;
        ++r;
    }
    return r;
}

private uint ceilToBytes(uint bits) { return (bits + 7) / 8; }

private bool isPow2(size_t n) { return n != 0 && (n & (n - 1)) == 0; }

private ushort loadLe16(const(ubyte)* p)
{
    return cast(ushort)(p[0] | (cast(ushort) p[1] << 8));
}

private uint loadLe32(const(ubyte)* p)
{
    return p[0] | (cast(uint) p[1] << 8) | (cast(uint) p[2] << 16) | (cast(uint) p[3] << 24);
}

private void storeLe16(ushort v, ubyte* p)
{
    p[0] = cast(ubyte) v;
    p[1] = cast(ubyte)(v >> 8);
}

private ushort ctReverse16(ushort x)
{
    x = cast(ushort)(((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1));
    x = cast(ushort)(((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2));
    x = cast(ushort)(((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4));
    return cast(ushort)((x << 8) | (x >> 8));
}

private CmceParams make348864(string name, bool fast)
{
    CmceParams p;
    p.name = name;
    p.m = 12;
    p.n = 3488;
    p.t = 64;
    p.poly_f = 0b0001000000001001;
    p.bitsec = 140;
    p.fast = fast;
    p.fterms = [CmceTerm(3, 1), CmceTerm(1, 1), CmceTerm(0, 2)];
    return p;
}

private CmceParams make460896(string name, bool fast)
{
    CmceParams p;
    p.name = name;
    p.m = 13;
    p.n = 4608;
    p.t = 96;
    p.poly_f = 0b0010000000011011;
    p.bitsec = 179;
    p.fast = fast;
    p.fterms = [CmceTerm(10, 1), CmceTerm(9, 1), CmceTerm(6, 1), CmceTerm(0, 1)];
    return p;
}

private CmceParams make6688128(string name, bool fast, bool pc)
{
    CmceParams p;
    p.name = name;
    p.m = 13;
    p.n = 6688;
    p.t = 128;
    p.poly_f = 0b0010000000011011;
    p.bitsec = 246;
    p.fast = fast;
    p.pc = pc;
    p.fterms = [CmceTerm(7, 1), CmceTerm(2, 1), CmceTerm(1, 1), CmceTerm(0, 1)];
    return p;
}

private CmceParams make6960119(string name, bool fast, bool pc)
{
    CmceParams p;
    p.name = name;
    p.m = 13;
    p.n = 6960;
    p.t = 119;
    p.poly_f = 0b0010000000011011;
    p.bitsec = 245;
    p.fast = fast;
    p.pc = pc;
    p.fterms = [CmceTerm(8, 1), CmceTerm(0, 1)];
    return p;
}

private CmceParams make8192128(string name, bool fast, bool pc)
{
    CmceParams p;
    p.name = name;
    p.m = 13;
    p.n = 8192;
    p.t = 128;
    p.poly_f = 0b0010000000011011;
    p.bitsec = 256;
    p.fast = fast;
    p.pc = pc;
    p.fterms = [CmceTerm(7, 1), CmceTerm(2, 1), CmceTerm(1, 1), CmceTerm(0, 1)];
    return p;
}

CmceParams cmceParams(in string name)
{
    string core = name;
    if (name.length >= 17 && name[0 .. 16] == "ClassicMcEliece_")
        core = name[16 .. $];
    if (core == "348864") return make348864("ClassicMcEliece_348864", false);
    if (core == "348864f") return make348864("ClassicMcEliece_348864f", true);
    if (core == "460896") return make460896("ClassicMcEliece_460896", false);
    if (core == "460896f") return make460896("ClassicMcEliece_460896f", true);
    if (core == "6688128") return make6688128("ClassicMcEliece_6688128", false, false);
    if (core == "6688128f") return make6688128("ClassicMcEliece_6688128f", true, false);
    if (core == "6688128pc") return make6688128("ClassicMcEliece_6688128pc", false, true);
    if (core == "6688128pcf") return make6688128("ClassicMcEliece_6688128pcf", true, true);
    if (core == "6960119") return make6960119("ClassicMcEliece_6960119", false, false);
    if (core == "6960119f") return make6960119("ClassicMcEliece_6960119f", true, false);
    if (core == "6960119pc") return make6960119("ClassicMcEliece_6960119pc", false, true);
    if (core == "6960119pcf") return make6960119("ClassicMcEliece_6960119pcf", true, true);
    if (core == "8192128") return make8192128("ClassicMcEliece_8192128", false, false);
    if (core == "8192128f") return make8192128("ClassicMcEliece_8192128f", true, false);
    if (core == "8192128pc") return make8192128("ClassicMcEliece_8192128pc", false, true);
    if (core == "8192128pcf") return make8192128("ClassicMcEliece_8192128pcf", true, true);
    throw new InvalidArgument("Unknown Classic McEliece mode: " ~ name);
}

bool isCmceName(in string n)
{
    if (n.length >= 17 && n[0 .. 16] == "ClassicMcEliece_")
        return true;
    if (n.length >= 6 && n[0] >= '0' && n[0] <= '9')
    {
        try { cmceParams(n); return true; }
        catch (InvalidArgument) { return false; }
    }
    return false;
}

uint cmceQ(const ref CmceParams p) { return 1u << p.m; }
uint cmcePkRows(const ref CmceParams p) { return p.t * p.m; }
uint cmcePkCols(const ref CmceParams p) { return p.n - cmcePkRows(p); }
uint cmcePkRowBytes(const ref CmceParams p) { return ceilToBytes(cmcePkCols(p)); }
uint cmcePkBytes(const ref CmceParams p) { return cmcePkRows(p) * cmcePkRowBytes(p); }
uint cmceEncodeOut(const ref CmceParams p) { return ceilToBytes(p.m * p.t); }
uint cmceHashOut() { return CMCE_ELL / 8; }
uint cmceCtBytes(const ref CmceParams p)
{
    return p.pc ? cmceEncodeOut(p) + cmceHashOut() : cmceEncodeOut(p);
}
uint cmceSeedLen() { return CMCE_ELL / 8; }
uint cmceSkCBytes() { return 8; }
uint cmceSkGBytes(const ref CmceParams p) { return p.t * 2; }
uint cmceSkCtrlBytes(const ref CmceParams p) { return (2 * p.m - 1) * (1u << (p.m - 4)); }
uint cmceSkSBytes(const ref CmceParams p) { return p.n / 8; }
uint cmceSkBytes(const ref CmceParams p)
{
    return cmceSeedLen() + cmceSkCBytes() + cmceSkGBytes(p) + cmceSkCtrlBytes(p) + cmceSkSBytes(p);
}
uint cmceTau(const ref CmceParams p)
{
    return (1u << (p.m - floorLog2(p.n))) * p.t;
}

private Unique!XOF shake256()
{
    Unique!XOF x = getXof("SHAKE-256");
    if (!x)
        throw new LookupError("SHAKE-256 XOF unavailable");
    return x;
}

private void cmcePrg(const(ubyte)* seed, ubyte* outp, size_t n)
{
    Unique!XOF x = shake256();
    ubyte prefix = 64;
    x.update(&prefix, 1);
    x.update(seed, 32);
    x.output(outp, n);
}

private void cmceHash(const(ubyte)* inp, size_t n, ubyte* outp)
{
    Unique!XOF x = shake256();
    if (n)
        x.update(inp, n);
    x.output(outp, 32);
}

private ushort gfReduce(uint x, ushort mod)
{
    if (mod == 0b0010000000011011)
    {
        uint t = x & 0x1FF0000;
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        t = x & 0x000E000;
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        return cast(ushort)(x & 0x1fff);
    }
    if (mod == 0b0001000000001001)
    {
        uint t = x & 0x7FC000;
        x ^= t >> 9;
        x ^= t >> 12;
        t = x & 0x3000;
        x ^= t >> 9;
        x ^= t >> 12;
        return cast(ushort)(x & 0xfff);
    }
    throw new InternalError("Classic McEliece: unsupported GF modulus");
}

struct CmceGF
{
    ushort elem;
    ushort mod;

    uint logQ() const { return floorLog2(mod); }

    CmceGF add(CmceGF o) const { return CmceGF(cast(ushort)(elem ^ o.elem), mod); }
    void addEq(CmceGF o) { elem ^= o.elem; }

    CmceGF mul(CmceGF o) const
    {
        const uint a = elem;
        const uint b = o.elem;
        const uint lq = logQ();
        uint acc = a * (b & ctValueBarrier!uint(1));
        foreach (i; 1 .. lq)
            acc ^= a * (b & (1u << i));
        return CmceGF(gfReduce(acc, mod), mod);
    }

    void mulEq(CmceGF o) { this = mul(o); }
    CmceGF square() const { return mul(this); }

    CmceGF inv() const
    {
        size_t exp = (size_t(1) << logQ()) - 2;
        CmceGF base = this;
        CmceGF r = CmceGF(1, mod);
        while (exp)
        {
            if (exp & 1)
                r = r.mul(base);
            base = base.square();
            exp >>= 1;
        }
        return r;
    }

    bool isZero() const { return elem == 0; }
}

private CmceGF gfOf(const ref CmceParams p, ushort e) { return CmceGF(e, p.poly_f); }

private CmceGF gfMaskIf(CTMask!ushort m, CmceGF x)
{
    return CmceGF(m.ifSetReturn(x.elem), x.mod);
}

private CmceGF gfSelect(CTMask!ushort m, CmceGF x, CmceGF y)
{
    return CmceGF(m.select(x.elem, y.elem), x.mod);
}

struct CmcePoly
{
    CmceGF[] coef;

    CmceGF eval(CmceGF a) const
    {
        CmceGF r = CmceGF(0, a.mod);
        foreach_reverse (c; coef)
        {
            r.mulEq(a);
            r.addEq(c);
        }
        return r;
    }
}

private CmcePoly polyMul(const ref CmceParams p, const ref CmcePoly a, const ref CmcePoly b)
{
    auto prod = new CmceGF[p.t * 2 - 1];
    foreach (ref e; prod)
        e = CmceGF(0, p.poly_f);
    foreach (i; 0 .. p.t)
        foreach (j; 0 .. p.t)
            prod[i + j].addEq(a.coef[i].mul(b.coef[j]));
    for (size_t i = (p.t - 1) * 2; i >= p.t; --i)
    {
        foreach (term; p.fterms)
            prod[i - p.t + term.idx].addEq(CmceGF(term.coeff, p.poly_f).mul(prod[i]));
    }
    CmcePoly r;
    r.coef = prod[0 .. p.t];
    return r;
}

private CmcePoly polyFromBytes(const ref CmceParams p, const(ubyte)* bytes)
{
    const ushort mask = cast(ushort)((1u << p.m) - 1);
    CmcePoly r;
    r.coef = new CmceGF[p.t];
    foreach (i; 0 .. p.t)
        r.coef[i] = CmceGF(cast(ushort)(loadLe16(bytes + 2 * i) & mask), p.poly_f);
    return r;
}

private bool minPoly(const ref CmceParams p, const(ubyte)* seed, ref CmcePoly g)
{
    auto beta = polyFromBytes(p, seed);
    auto mat = new CmcePoly[p.t + 1];
    mat[0].coef = new CmceGF[p.t];
    mat[0].coef[0] = CmceGF(1, p.poly_f);
    foreach (i; 1 .. p.t)
        mat[0].coef[i] = CmceGF(0, p.poly_f);
    mat[1] = beta;
    foreach (j; 2 .. p.t + 1)
        mat[j] = polyMul(p, mat[j - 1], beta);
    foreach (j; 0 .. p.t)
    {
        foreach (k; j + 1 .. p.t)
        {
            auto cond = CTMask!ushort.isZero(mat[j].coef[j].elem);
            foreach (c; j .. p.t + 1)
                mat[c].coef[j].addEq(gfMaskIf(cond, mat[c].coef[k]));
        }
        if (mat[j].coef[j].isZero())
            return false;
        auto inv = mat[j].coef[j].inv();
        foreach (c; j .. p.t + 1)
            mat[c].coef[j].mulEq(inv);
        foreach (k; 0 .. p.t)
        {
            if (k == j)
                continue;
            const t = mat[j].coef[k];
            foreach (c; j .. p.t + 1)
                mat[c].coef[k].addEq(mat[c].coef[j].mul(t));
        }
    }
    g.coef = mat[p.t].coef.dup;
    g.coef ~= CmceGF(1, p.poly_f);
    return true;
}

private void serializeG(const ref CmcePoly g, ubyte* outp)
{
    foreach (i; 0 .. g.coef.length - 1)
        storeLe16(g.coef[i].elem, outp + 2 * i);
}

private CmcePoly gFromBytes(const(ubyte)* bytes, size_t nbytes, ushort poly_f)
{
    CmcePoly g;
    const n = nbytes / 2;
    g.coef = new CmceGF[n + 1];
    foreach (i; 0 .. n)
        g.coef[i] = CmceGF(loadLe16(bytes + 2 * i), poly_f);
    g.coef[n] = CmceGF(1, poly_f);
    return g;
}

private bool getBit(const(ubyte)* b, size_t i)
{
    return ((b[i >> 3] >> (i & 7)) & 1) != 0;
}

private void setBit(ubyte* b, size_t i, bool v)
{
    const ubyte m = cast(ubyte)(1 << (i & 7));
    if (v)
        b[i >> 3] |= m;
    else
        b[i >> 3] &= cast(ubyte)~m;
}

private ulong getBits64(const(ubyte)* b, size_t bitpos)
{
    ulong v;
    foreach (i; 0 .. 64)
        if (getBit(b, bitpos + i))
            v |= ulong(1) << i;
    return v;
}

private void setBits64(ubyte* b, size_t bitpos, ulong v)
{
    foreach (i; 0 .. 64)
        setBit(b, bitpos + i, ((v >> i) & 1) != 0);
}

private void xorRow(ubyte* dest, const(ubyte)* src, size_t nbytes)
{
    foreach (i; 0 .. nbytes)
        dest[i] ^= src[i];
}

private void condXorRow(ubyte* dest, const(ubyte)* src, size_t nbytes, bool cond)
{
    const ubyte m = cond ? 0xff : 0;
    foreach (i; 0 .. nbytes)
        dest[i] ^= cast(ubyte)(src[i] & m);
}

private size_t hammingBytes(const(ubyte)* b, size_t nbytes)
{
    size_t w;
    foreach (i; 0 .. nbytes)
        w += popcnt(b[i]);
    return w;
}

private ubyte popcnt(ubyte x)
{
    x = cast(ubyte)(x - ((x >> 1) & 0x55));
    x = cast(ubyte)((x & 0x33) + ((x >> 2) & 0x33));
    return cast(ubyte)((x + (x >> 4)) & 0x0f);
}

private bool oddParity(const(ubyte)* b, size_t nbytes)
{
    ubyte acc;
    foreach (i; 0 .. nbytes)
        acc ^= b[i];
    acc ^= acc >> 4;
    acc ^= acc >> 2;
    acc ^= acc >> 1;
    return (acc & 1) != 0;
}

private void swap1Bit(ref ulong val, size_t i, size_t j)
{
    const ulong bi = (val >> i) & ctValueBarrier!ulong(1);
    const ulong bj = (val >> j) & ctValueBarrier!ulong(1);
    const ulong x = bi ^ bj;
    val ^= x << i;
    val ^= x << j;
}

private size_t countLsbZeros(ulong n)
{
    size_t res;
    auto onlyz = CTMask!ulong.set();
    foreach (bit; 0 .. 64)
    {
        auto bitset = CTMask!ulong.expand((n >> bit) & 1);
        onlyz = onlyz & ~bitset;
        res += cast(size_t) onlyz.ifSetReturn(1UL);
    }
    return res;
}

private void condSwap16(ref ushort a, ref ushort b, CTMask!ushort m)
{
    const ushort t = m.ifSetReturn(cast(ushort)(a ^ b));
    a ^= t;
    b ^= t;
}

private void condSwap32(ref uint a, ref uint b, CTMask!uint m)
{
    const uint t = m.ifSetReturn(a ^ b);
    a ^= t;
    b ^= t;
}

private void condSwapSz(ref size_t a, ref size_t b, CTMask!size_t m)
{
    const size_t t = m.ifSetReturn(a ^ b);
    a ^= t;
    b ^= t;
}

private struct Pair32
{
    uint first;
    ushort second;
}

private void condSwapPair(ref Pair32 a, ref Pair32 b, CTMask!ulong m)
{
    auto m32 = CTMask!uint(cast(uint) m.value());
    auto m16 = CTMask!ushort(cast(ushort) m.value());
    condSwap32(a.first, b.first, m32);
    condSwap16(a.second, b.second, m16);
}

private void compareSwapPair32(Pair32[] a, size_t i, size_t k, size_t l)
{
    if ((i & k) == 0)
    {
        auto need = CTMask!ulong.isLt(a[l].first, a[i].first);
        condSwapPair(a[i], a[l], need);
    }
    else
    {
        auto need = CTMask!ulong.isGt(a[l].first, a[i].first);
        condSwapPair(a[i], a[l], need);
    }
}

private void bitonicSortPair32(Pair32[] a)
{
    const n = a.length;
    for (size_t k = 2; k <= n; k *= 2)
        for (size_t j = k / 2; j > 0; j /= 2)
            foreach (i; 0 .. n)
            {
                const size_t l = i ^ j;
                if (l > i)
                    compareSwapPair32(a, i, k, l);
            }
}

private struct Pair16
{
    ushort first;
    ushort second;
}

private void condSwapPair16(ref Pair16 a, ref Pair16 b, CTMask!ulong m)
{
    auto mm = CTMask!ushort(cast(ushort) m.value());
    condSwap16(a.first, b.first, mm);
    condSwap16(a.second, b.second, mm);
}

private void compareSwapPair16(Pair16[] a, size_t i, size_t k, size_t l)
{
    if ((i & k) == 0)
    {
        auto need = CTMask!ulong.isLt(a[l].first, a[i].first);
        condSwapPair16(a[i], a[l], need);
    }
    else
    {
        auto need = CTMask!ulong.isGt(a[l].first, a[i].first);
        condSwapPair16(a[i], a[l], need);
    }
}

private void bitonicSortPair16(Pair16[] a)
{
    const n = a.length;
    for (size_t k = 2; k <= n; k *= 2)
        for (size_t j = k / 2; j > 0; j /= 2)
            foreach (i; 0 .. n)
            {
                const size_t l = i ^ j;
                if (l > i)
                    compareSwapPair16(a, i, k, l);
            }
}

private ushort[] composeInv(const(ushort)[] c, const(ushort)[] pi)
{
    auto z = new Pair16[pi.length];
    foreach (i; 0 .. pi.length)
        z[i] = Pair16(pi[i], c[i]);
    bitonicSortPair16(z);
    auto outp = new ushort[c.length];
    foreach (i; 0 .. c.length)
        outp[i] = z[i].second;
    return outp;
}

private void simultaneousComposeInv(ref ushort[] p, ref ushort[] q)
{
    auto pnew = composeInv(p, q);
    q = composeInv(q, p);
    p = pnew;
}

private ushort[] genControlBits(const(ushort)[] pi)
{
    const n = pi.length;
    const size_t m = floorLog2(cast(uint) n);
    if (m == 1)
        return [pi[0]];
    auto p = new ushort[n];
    auto q = new ushort[n];
    foreach (x; 0 .. n)
    {
        p[x] = pi[x ^ 1];
        q[x] = cast(ushort)(pi[x] ^ 1);
    }
    auto range = new ushort[n];
    foreach (x; 0 .. n)
        range[x] = cast(ushort) x;
    auto piinv = composeInv(range, pi);
    simultaneousComposeInv(p, q);
    auto c = new ushort[n];
    foreach (x; 0 .. n)
        c[x] = p[x] < x ? p[x] : cast(ushort) x;
    simultaneousComposeInv(p, q);
    foreach (i; 1 .. m - 1)
    {
        auto cp = composeInv(c, q);
        simultaneousComposeInv(p, q);
        foreach (x; 0 .. n)
            if (cp[x] < c[x])
                c[x] = cp[x];
    }
    auto f = new ushort[n / 2];
    foreach (j; 0 .. n / 2)
        f[j] = c[2 * j] % 2;
    auto bigf = new ushort[n];
    foreach (x; 0 .. n)
        bigf[x] = cast(ushort)(x ^ f[x / 2]);
    auto fpi = composeInv(bigf, piinv);
    auto l = new ushort[n / 2];
    foreach (k; 0 .. n / 2)
        l[k] = fpi[2 * k] % 2;
    auto bigl = new ushort[n];
    foreach (y; 0 .. n)
        bigl[y] = cast(ushort)(y ^ l[y / 2]);
    auto bigm = composeInv(fpi, bigl);
    auto sub0 = new ushort[n / 2];
    auto sub1 = new ushort[n / 2];
    foreach (j; 0 .. n / 2)
    {
        sub0[j] = bigm[2 * j] / 2;
        sub1[j] = bigm[2 * j + 1] / 2;
    }
    auto z0 = genControlBits(sub0);
    auto z1 = genControlBits(sub1);
    auto z = new ushort[z0.length + z1.length];
    foreach (j; 0 .. z0.length)
    {
        z[2 * j] = z0[j];
        z[2 * j + 1] = z1[j];
    }
    return f ~ z ~ l;
}

private bool hasAdjDup(const(uint)[] v)
{
    foreach (i; 0 .. v.length - 1)
        if (v[i] == v[i + 1])
            return true;
    return false;
}

struct CmceOrdering
{
    ushort[] pi;
    ushort poly_f;
}

private bool createOrdering(const ref CmceParams p, const(ubyte)* bits, ref CmceOrdering ord)
{
    const q = cmceQ(p);
    auto a = new Pair32[q];
    foreach (i; 0 .. q)
        a[i] = Pair32(loadLe32(bits + 4 * i), cast(ushort) i);
    bitonicSortPair32(a);
    auto sorted = new uint[q];
    auto pi = new ushort[q];
    foreach (i; 0 .. q)
    {
        sorted[i] = a[i].first;
        pi[i] = a[i].second;
    }
    if (hasAdjDup(sorted))
        return false;
    ord.pi = pi;
    ord.poly_f = p.poly_f;
    return true;
}

private CmceGF alphaAt(const ref CmceOrdering ord, size_t i)
{
    const m = floorLog2(ord.poly_f);
    auto rev = ctReverse16(ord.pi[i]);
    rev >>= (16 - m);
    return CmceGF(rev, ord.poly_f);
}

private CmceGF[] alphasN(const ref CmceOrdering ord, size_t n)
{
    auto v = new CmceGF[n];
    foreach (i; 0 .. n)
        v[i] = alphaAt(ord, i);
    return v;
}

private ubyte[] controlBits(const ref CmceOrdering ord)
{
    auto words = genControlBits(ord.pi);
    auto bits = new ubyte[ceilToBytes(cast(uint) words.length)];
    foreach (i; 0 .. words.length)
        if (words[i])
            setBit(bits.ptr, i, true);
    return bits;
}

private CmceOrdering orderingFromControl(const ref CmceParams p, const(ubyte)* bits, size_t nbits)
{
    const uint n = 1u << p.m;
    auto pi = new ushort[n];
    foreach (i; 0 .. n)
        pi[i] = cast(ushort) i;
    foreach (i; 0 .. 2 * p.m - 1)
    {
        const size_t gap = size_t(1) << (i < (2 * p.m - 2 - i) ? i : (2 * p.m - 2 - i));
        foreach (j; 0 .. n / 2)
        {
            const size_t pos = (j % gap) + 2 * gap * (j / gap);
            if (getBit(bits, i * n / 2 + j))
            {
                const tmp = pi[pos];
                pi[pos] = pi[pos + gap];
                pi[pos + gap] = tmp;
            }
        }
    }
    return CmceOrdering(pi, p.poly_f);
}

private void permutePivots(const ref CmceParams p, ref CmceOrdering ord, const(ubyte)* pivots)
{
    const col_off = cmcePkRows(p) - CMCE_MU;
    foreach (p_idx; 1 .. CMCE_MU + 1)
    {
        size_t p_counter;
        foreach (col; 0 .. CMCE_NU)
        {
            const set = getBit(pivots, col);
            if (set)
                ++p_counter;
            if (set && p_idx == p_counter)
            {
                const tmp = ord.pi[col_off + col];
                ord.pi[col_off + col] = ord.pi[col_off + p_idx - 1];
                ord.pi[col_off + p_idx - 1] = tmp;
            }
        }
    }
}

private ubyte[][] initMatrix(const ref CmceParams p, const ref CmceOrdering ord, const ref CmcePoly g)
{
    auto al = alphasN(ord, p.n);
    auto invg = new CmceGF[p.n];
    foreach (j; 0 .. p.n)
        invg[j] = g.eval(al[j]).inv();
    const rb = ceilToBytes(p.n);
    auto mat = new ubyte[][cmcePkRows(p)];
    foreach (r; 0 .. mat.length)
        mat[r] = new ubyte[rb];
    foreach (i; 0 .. p.t)
    {
        foreach (j; 0 .. p.n)
        {
            const inv = invg[j].elem;
            foreach (bit; 0 .. p.m)
                setBit(mat[i * p.m + bit].ptr, j, ((inv >> bit) & 1) != 0);
        }
        foreach (j; 0 .. p.n)
            invg[j].mulEq(al[j]);
    }
    return mat;
}

private bool moveColumns(const ref CmceParams p, ubyte[][] mat, ubyte* pivots)
{
    const pos = cmcePkRows(p) - CMCE_MU;
    auto area = new ulong[cmcePkRows(p)];
    foreach (i; 0 .. cmcePkRows(p))
        area[i] = getBits64(mat[i].ptr, pos);
    ulong[CMCE_MU] sub;
    foreach (i; 0 .. CMCE_MU)
        sub[i] = area[pos + i];
    size_t[CMCE_MU] pividx;
    foreach (row; 0 .. CMCE_MU)
    {
        ulong acc = sub[row];
        foreach (nr; row + 1 .. CMCE_MU)
            acc |= sub[nr];
        if (acc == 0)
            return false;
        const cur = countLsbZeros(acc);
        pividx[row] = cur;
        foreach (nr; row + 1 .. CMCE_MU)
        {
            if (((sub[row] >> cur) & 1) == 0)
                sub[row] ^= sub[nr];
        }
        foreach (nr; row + 1 .. CMCE_MU)
        {
            if ((sub[nr] >> cur) & 1)
                sub[nr] ^= sub[row];
        }
    }
    foreach (i; 0 .. CMCE_NU)
        setBit(pivots, i, false);
    foreach (idx; pividx)
        setBit(pivots, idx, true);
    foreach (r; 0 .. cmcePkRows(p))
        foreach (col; 0 .. CMCE_MU)
            swap1Bit(area[r], col, pividx[col]);
    foreach (r; 0 .. cmcePkRows(p))
        setBits64(mat[r].ptr, pos, area[r]);
    return true;
}

private bool applyGauss(const ref CmceParams p, ubyte[][] mat, ubyte* pivots)
{
    pivots[0 .. 4] = 0xff;
    pivots[4 .. 8] = 0;
    const rb = ceilToBytes(p.n);
    foreach (diag; 0 .. cmcePkRows(p))
    {
        if (p.fast && diag == cmcePkRows(p) - CMCE_MU)
        {
            if (!moveColumns(p, mat, pivots))
                return false;
        }
        foreach (nr; diag + 1 .. cmcePkRows(p))
            condXorRow(mat[diag].ptr, mat[nr].ptr, rb, !getBit(mat[diag].ptr, diag));
        if (!getBit(mat[diag].ptr, diag))
            return false;
        foreach (row; 0 .. cmcePkRows(p))
            if (row != diag)
                condXorRow(mat[row].ptr, mat[diag].ptr, rb, getBit(mat[row].ptr, diag));
    }
    return true;
}

private ubyte[] extractPk(const ref CmceParams p, ubyte[][] mat)
{
    auto bigt = new ubyte[cmcePkBytes(p)];
    const rowb = cmcePkRowBytes(p);
    const start = cmcePkRows(p);
    foreach (row; 0 .. cmcePkRows(p))
    {
        auto dest = bigt.ptr + row * rowb;
        foreach (j; 0 .. cmcePkCols(p))
            setBit(dest, j, getBit(mat[row].ptr, start + j));
    }
    return bigt;
}

private bool createMatrix(const ref CmceParams p, const ref CmceOrdering ord, const ref CmcePoly g,
                          ref ubyte[] pk, ubyte* pivots)
{
    auto mat = initMatrix(p, ord, g);
    if (!applyGauss(p, mat, pivots))
        return false;
    pk = extractPk(p, mat);
    return true;
}

private void mulH(const ref CmceParams p, const(ubyte)* tbytes, const(ubyte)* e, ubyte* outp)
{
    const rows = cmcePkRows(p);
    const tbits = p.n - rows;
    const tbytes_row = cmcePkRowBytes(p);
    foreach (i; 0 .. ceilToBytes(rows))
        outp[i] = 0;
    foreach (i; 0 .. rows)
        setBit(outp, i, getBit(e, i));
    auto eT = new ubyte[tbytes_row];
    foreach (j; 0 .. tbits)
        setBit(eT.ptr, j, getBit(e, rows + j));
    foreach (i; 0 .. rows)
    {
        const row = tbytes + i * tbytes_row;
        auto acc = new ubyte[tbytes_row];
        acc[] = row[0 .. tbytes_row];
        foreach (j; 0 .. tbytes_row)
            acc[j] &= eT[j];
        if (oddParity(acc.ptr, tbytes_row))
            setBit(outp, i, !getBit(outp, i));
    }
}

struct CmcePublic
{
    CmceParams params;
    ubyte[] mat;
}

struct CmceSecret
{
    CmceParams params;
    ubyte[] delta;
    ubyte[] c;
    CmcePoly g;
    CmceOrdering alpha;
    ubyte[] s;
    CmcePublic pub;
}

private bool tryKeygen(const ref CmceParams p, const(ubyte)* seed, ubyte* next_seed, ref CmceSecret sk)
{
    const exp_len = p.n / 8 + (CMCE_SIGMA2 * cmceQ(p)) / 8 + (CMCE_SIGMA1 * p.t) / 8 + 32;
    auto big = new ubyte[exp_len];
    cmcePrg(seed, big.ptr, exp_len);
    size_t off;
    auto s = big[off .. off + p.n / 8];
    off += p.n / 8;
    auto ord_bits = big[off .. off + (CMCE_SIGMA2 * cmceQ(p)) / 8];
    off += (CMCE_SIGMA2 * cmceQ(p)) / 8;
    auto irr = big[off .. off + (CMCE_SIGMA1 * p.t) / 8];
    off += (CMCE_SIGMA1 * p.t) / 8;
    next_seed[0 .. 32] = big[off .. off + 32];
    CmceOrdering ord;
    if (!createOrdering(p, ord_bits.ptr, ord))
        return false;
    CmcePoly g;
    if (!minPoly(p, irr.ptr, g))
        return false;
    ubyte[] pk;
    auto piv = new ubyte[8];
    if (!createMatrix(p, ord, g, pk, piv.ptr))
        return false;
    if (p.fast)
        permutePivots(p, ord, piv.ptr);
    sk.params = cmceParams(p.name);
    sk.delta = seed[0 .. 32].dup;
    sk.c = piv;
    sk.g = g;
    sk.alpha = ord;
    sk.s = s.dup;
    sk.pub.params = sk.params;
    sk.pub.mat = pk;
    return true;
}

void cmceKeygenFromSeed(ref CmceSecret sk, const ref CmceParams p, const(ubyte)* seed)
{
    auto cur = seed[0 .. 32].dup;
    auto nxt = new ubyte[32];
    while (!tryKeygen(p, cur.ptr, nxt.ptr, sk))
        cur[] = nxt[];
}

void cmceKeygen(ref CmceSecret sk, const ref CmceParams p, RandomNumberGenerator rng)
{
    auto seed = new ubyte[32];
    rng.randomize(seed.ptr, 32);
    cmceKeygenFromSeed(sk, p, seed.ptr);
}

void cmceEncodePk(const ref CmcePublic pk, ubyte* outp)
{
    outp[0 .. pk.mat.length] = pk.mat[];
}

void cmceEncodeSk(const ref CmceSecret sk, ubyte* outp)
{
    auto p = sk.params;
    size_t off;
    outp[off .. off + 32] = sk.delta[];
    off += 32;
    outp[off .. off + 8] = sk.c[];
    off += 8;
    serializeG(sk.g, outp + off);
    off += cmceSkGBytes(p);
    auto cb = controlBits(sk.alpha);
    outp[off .. off + cb.length] = cb[];
    off += cb.length;
    outp[off .. off + sk.s.length] = sk.s[];
}

private bool loadSk(ref CmceSecret sk, const ref CmceParams p, const(ubyte)* bits, size_t len)
{
    if (len != cmceSkBytes(p))
        return false;
    size_t off;
    sk.params = cmceParams(p.name);
    sk.delta = bits[off .. off + 32].dup;
    off += 32;
    sk.c = bits[off .. off + 8].dup;
    off += 8;
    sk.g = gFromBytes(bits + off, cmceSkGBytes(p), p.poly_f);
    off += cmceSkGBytes(p);
    const cb = cmceSkCtrlBytes(p);
    sk.alpha = orderingFromControl(p, bits + off, cb * 8);
    off += cb;
    sk.s = bits[off .. off + cmceSkSBytes(p)].dup;
    ubyte[] pk;
    auto piv = new ubyte[8];
    if (!createMatrix(p, sk.alpha, sk.g, pk, piv.ptr))
        return false;
    sk.pub.params = sk.params;
    sk.pub.mat = pk;
    return true;
}

private bool fixedWeight(const ref CmceParams p, RandomNumberGenerator rng, ubyte* e)
{
    const tau = cmceTau(p);
    auto rnd = new ubyte[(CMCE_SIGMA1 / 8) * tau];
    rng.randomize(rnd.ptr, rnd.length);
    const ushort mask_m = cast(ushort)((1u << p.m) - 1);
    auto a = new ushort[p.t];
    size_t na;
    foreach (j; 0 .. tau)
    {
        auto d = loadLe16(rnd.ptr + 2 * j);
        d &= mask_m;
        if (d < p.n && na < p.t)
            a[na++] = d;
    }
    if (na < p.t)
        return false;
    foreach (i; 1 .. p.t)
        foreach (j; 0 .. i)
            if (a[i] == a[j])
                return false;
    foreach (i; 0 .. ceilToBytes(p.n))
        e[i] = 0;
    auto abyte = new ubyte[p.t];
    foreach (j; 0 .. p.t)
        abyte[j] = cast(ubyte)(1 << (a[j] % 8));
    foreach (i; 0 .. p.n / 8)
        foreach (j; 0 .. p.t)
            if (i == (a[j] >> 3))
                e[i] |= abyte[j];
    return true;
}

private CmcePoly goppaSyndrome(const ref CmceParams p, const ref CmcePoly g,
                               const ref CmceOrdering ord, const(ubyte)* cw)
{
    auto syn = new CmceGF[2 * p.t];
    foreach (ref s; syn)
        s = CmceGF(0, p.poly_f);
    auto al = alphasN(ord, p.n);
    foreach (i; 0 .. p.n)
    {
        auto ga = g.eval(al[i]);
        auto r = ga.mul(ga).inv();
        auto mask = CTMask!ushort.expand(cast(ushort)(getBit(cw, i) ? 1 : 0));
        foreach (j; 0 .. 2 * p.t)
        {
            syn[j].addEq(gfMaskIf(mask, r));
            r.mulEq(al[i]);
        }
    }
    CmcePoly outp;
    outp.coef = syn;
    return outp;
}

private CmcePoly berlekampMassey(const ref CmceParams p, const ref CmcePoly syn)
{
    auto bigc = new CmceGF[p.t + 1];
    auto bigb = new CmceGF[p.t + 1];
    foreach (i; 0 .. p.t + 1)
    {
        bigc[i] = CmceGF(0, p.poly_f);
        bigb[i] = CmceGF(0, p.poly_f);
    }
    auto b = CmceGF(1, p.poly_f);
    bigb[1] = CmceGF(1, p.poly_f);
    bigc[0] = CmceGF(1, p.poly_f);
    size_t bigl;
    foreach (bign; 0 .. 2 * p.t)
    {
        auto d = CmceGF(0, p.poly_f);
        const lim = bign < p.t ? bign : p.t;
        foreach (i; 0 .. lim + 1)
            d.addEq(bigc[i].mul(syn.coef[bign - i]));
        auto dnz = CTMask!ushort.expand(d.elem);
        auto adj = CTMask!ushort.isLte(cast(ushort)(2 * bigl), cast(ushort) bign) & dnz;
        auto tcopy = bigc.dup;
        auto f = d.mul(b.inv());
        foreach (i; 0 .. p.t + 1)
            bigc[i].addEq(gfMaskIf(dnz, f.mul(bigb[i])));
        bigl = adj.select(cast(ushort)((bign + 1) - bigl), cast(ushort) bigl);
        foreach (i; 0 .. p.t + 1)
            bigb[i] = gfSelect(adj, tcopy[i], bigb[i]);
        b = gfSelect(adj, d, b);
        auto last = bigb[p.t];
        foreach_reverse (i; 1 .. p.t + 1)
            bigb[i] = bigb[i - 1];
        bigb[0] = last;
    }
    CmcePoly loc;
    loc.coef = new CmceGF[p.t + 1];
    foreach (i; 0 .. p.t + 1)
        loc.coef[i] = bigc[p.t - i];
    return loc;
}

private bool decode(const ref CmceSecret sk, const(ubyte)* c0, ubyte* e)
{
    auto p = sk.params;
    auto padded = new ubyte[ceilToBytes(p.n)];
    const cbits = p.m * p.t;
    foreach (i; 0 .. ceilToBytes(cbits))
        padded[i] = 0;
    foreach (i; 0 .. cbits)
        setBit(padded.ptr, i, getBit(c0, i));
    auto syn = goppaSyndrome(p, sk.g, sk.alpha, padded.ptr);
    auto loc = berlekampMassey(p, syn);
    auto al = alphasN(sk.alpha, p.n);
    foreach (i; 0 .. ceilToBytes(p.n))
        e[i] = 0;
    size_t wt;
    foreach (i; 0 .. p.n)
    {
        if (loc.eval(al[i]).isZero())
        {
            setBit(e, i, true);
            ++wt;
        }
    }
    if (wt != p.t)
        return false;
    auto syn2 = goppaSyndrome(p, sk.g, sk.alpha, e);
    foreach (i; 0 .. syn.coef.length)
        if (syn.coef[i].elem != syn2.coef[i].elem)
            return false;
    return true;
}

void cmceEncaps(const ref CmcePublic pk, RandomNumberGenerator rng, ubyte* ss, ubyte* ct)
{
    auto p = pk.params;
    auto e = new ubyte[ceilToBytes(p.n)];
    bool ok;
    foreach (attempt; 0 .. 647)
    {
        if (fixedWeight(p, rng, e.ptr))
        {
            ok = true;
            break;
        }
    }
    if (!ok)
        throw new InternalError("Classic McEliece: cannot create fixed-weight vector (RNG broken?)");
    auto c0 = new ubyte[cmceEncodeOut(p)];
    mulH(p, pk.mat.ptr, e.ptr, c0.ptr);
    size_t clen = c0.length;
    ct[0 .. clen] = c0[];
    if (p.pc)
    {
        auto inp = new ubyte[1 + e.length];
        inp[0] = 2;
        inp[1 .. $] = e[];
        cmceHash(inp.ptr, inp.length, ct + clen);
        clen += 32;
    }
    auto hin = new ubyte[1 + e.length + clen];
    hin[0] = 1;
    hin[1 .. 1 + e.length] = e[];
    hin[1 + e.length .. $] = ct[0 .. clen];
    cmceHash(hin.ptr, hin.length, ss);
}

void cmceDecaps(const ref CmceSecret sk, const(ubyte)* ct, size_t ctlen, ubyte* ss)
{
    auto p = sk.params;
    if (ctlen != cmceCtBytes(p))
        throw new InvalidArgument("Classic McEliece ciphertext has the wrong length");
    const c0len = cmceEncodeOut(p);
    auto e = new ubyte[sk.s.length];
    ubyte b = 1;
    if (!decode(sk, ct, e.ptr))
    {
        e[] = sk.s[];
        b = 0;
    }
    if (p.pc)
    {
        auto inp = new ubyte[1 + e.length];
        inp[0] = 2;
        inp[1 .. $] = e[];
        auto c1p = new ubyte[32];
        cmceHash(inp.ptr, inp.length, c1p.ptr);
        if (!constantTimeCompare(c1p.ptr, ct + c0len, 32))
        {
            e[] = sk.s[];
            b = 0;
        }
    }
    auto hin = new ubyte[1 + e.length + ctlen];
    hin[0] = b;
    hin[1 .. 1 + e.length] = e[];
    hin[1 + e.length .. $] = ct[0 .. ctlen];
    cmceHash(hin.ptr, hin.length, ss);
}

private AlgorithmIdentifier cmceAlgId(in string name)
{
    Vector!ubyte empty;
    return AlgorithmIdentifier(OIDS.lookup(name), empty);
}

/**
* Classic McEliece public key
*/
final class ClassicMcEliecePublicKey : PublicKey
{
public:
    /**
    * Decode an encoded public key
    * Params:
    *  name = SCAN name ("ClassicMcEliece-348864", …)
    *  bits = packed public matrix T
    *  len = must equal cmcePkBytes
    */
    this(in string name, const(ubyte)* bits, size_t len)
    {
        m_pub.params = cmceParams(name);
        if (len != cmcePkBytes(m_pub.params))
            throw new DecodingError("Classic McEliece: unexpected public key length");
        m_pub.mat = bits[0 .. len].dup;
    }

    /// Copy from an expanded public key.
    this(const ref CmcePublic pub)
    {
        m_pub.params = cmceParams(pub.params.name);
        m_pub.mat = pub.mat.dup;
    }

    /**
    * Decode X.509 SubjectPublicKeyInfo
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = encoded public key
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        this(OIDS.lookup(alg_id.oid), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_pub.params.name; }
    override size_t estimatedStrength() const { return m_pub.params.bitsec; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return cmceAlgId(m_pub.params.name); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(m_pub.mat.length);
        cmceEncodePk(m_pub, v.ptr);
        return v.move();
    }
    /// Expanded public key (packed matrix T).
    ref const(CmcePublic) raw() const { return m_pub; }

private:
    CmcePublic m_pub;
}

/**
* Classic McEliece private key
*/
final class ClassicMcEliecePrivateKey : PrivateKey, PublicKey
{
public:
    /**
    * Generate a random key
    * Params:
    *  name = SCAN name ("ClassicMcEliece-348864", …)
    *  rng = random number generator
    */
    this(in string name, RandomNumberGenerator rng)
    {
        auto p = cmceParams(name);
        cmceKeygen(m_sk, p, rng);
    }

    /**
    * Decode an encoded private key
    * Params:
    *  name = SCAN name
    *  bits = encoded secret
    *  len = length of bits
    */
    this(in string name, const(ubyte)* bits, size_t len)
    {
        auto p = cmceParams(name);
        if (!loadSk(m_sk, p, bits, len))
            throw new DecodingError("Classic McEliece: unexpected or invalid private key");
    }

    /**
    * KeyGen from a 32-byte seed
    * Params:
    *  name = SCAN name
    *  seed = 32-byte seed
    *  seedlen = must be 32
    *  from_seed = must be true
    */
    this(in string name, const(ubyte)* seed, size_t seedlen, bool from_seed)
    {
        auto p = cmceParams(name);
        if (!from_seed || seedlen != 32)
            throw new DecodingError("Classic McEliece: seed must be 32 bytes");
        cmceKeygenFromSeed(m_sk, p, seed);
    }

    /**
    * Decode PKCS #8
    * Params:
    *  alg_id = algorithm identifier
    *  key_bits = encoded private key
    */
    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        this(OIDS.lookup(alg_id.oid), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_sk.params.name; }
    override size_t estimatedStrength() const { return m_sk.params.bitsec; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return cmceAlgId(m_sk.params.name); }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(m_sk.pub.mat.length);
        cmceEncodePk(m_sk.pub, v.ptr);
        return v.move();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        auto v = SecureVector!ubyte(cmceSkBytes(m_sk.params));
        cmceEncodeSk(m_sk, v.ptr);
        return v.move();
    }
    ref const(CmceSecret) raw() const { return m_sk; }
    ClassicMcEliecePublicKey publicKey() const { return new ClassicMcEliecePublicKey(m_sk.pub); }

private:
    CmceSecret m_sk;
}

static if (BOTAN_HAS_TESTS && !SKIP_CMCE_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import botan.hash.hash;
    import botan.block.block_cipher;
    import botan.pubkey.pk_algs;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing classic_mceliece.d ...");
    size_t fails;

    {
        auto p = cmceParams("ClassicMcEliece_348864");
        if (cmcePkBytes(p) != 261120)
            ++fails;
        auto v = gfOf(p, 42);
        auto inv = v.inv();
        if (v.mul(inv).elem != 1)
        {
            logError("CMCE GF inv failed");
            ++fails;
        }
        ubyte[32] seed = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
        const blen = (p.n + CMCE_SIGMA2 * cmceQ(p) + CMCE_SIGMA1 * p.t + CMCE_ELL) / 8;
        auto exp = new ubyte[blen];
        cmcePrg(seed.ptr, exp.ptr, blen);
        auto want = hexDecode("543e2791fd98dbc1d332a7c40776ca01");
        if (exp[0 .. 8] != want[0 .. 8] || exp[$ - 8 .. $] != want[8 .. 16])
        {
            logError("CMCE PRG expansion mismatch");
            ++fails;
        }
        auto irr = hexDecode(
            "d9b8bb962a3f9dac0f832d243def581e7d26f4028de1ff9cd168460e5050ab095a32a372b40d720bd5d75389a6b3f08fa1d13cec60a4b716d4d6c240f2f80cd3"
            ~ "cbc76ae0dddca164c1130da185bd04e890f2256fb9f4754864811e14ea5a43b8b3612d59cecde1b2fdb6362659a0193d2b7d4b9d79aa1801dde3ca90dc300773");
        CmcePoly g;
        if (!minPoly(p, irr.ptr, g))
        {
            logError("CMCE minpoly failed");
            ++fails;
        }
        else
        {
            auto got = new ubyte[cmceSkGBytes(p)];
            serializeG(g, got.ptr);
            auto expg = hexDecode(
                "8d00a50f520a0307b8007c06cb04b9073b0f4a0f800fb706a60f2a05910a670b460375091209fc060a09ab036c09e5085a0df90d3506b404a30fda041d09970f"
                ~ "1206d000e00aac01c00dc80f490cd80b4108330c0208cf00d602450ec00a21079806eb093f00de015f052905560917081b09270c820af002000c34094504cd03");
            if (got[] != expg[])
            {
                logError("CMCE minpoly mismatch");
                ++fails;
            }
        }
        auto va = polyFromBytes(p, hexDecode(
            "bb02d40437094c0ae4034c00b10fed090a04850f660c3b0e110eb409810a86015b0f5804ca0e78089806e20b5b03aa0bc2020b05ea03710da902340c390f630b"
            ~ "bc07a70db20b9e0ee4038905a00a09090a0521045e0a0706370b5a00050a4100480c4d0e8f00730692093701fe04650dbe0fd00702011a04910360023f04fb0a").ptr);
        auto vb = polyFromBytes(p, hexDecode(
            "060c630b170abb00020fef03e501020e89098108bf01f30dd30900000e0d3d0ca404ec01190760021f088c09b90b0a06a702d104500f0f02f00a580287010a09"
            ~ "4e01490d270c73051800bc0af303b901b202b50321002802b903ce0ab40806083f0a2d06d002df0f260811005c02a10b300e5c0ba20d14045003c50f2f02de02").ptr);
        auto wantm = polyFromBytes(p, hexDecode(
            "370d090b19008f0efb01f5011b04f9054b0d1f071d0457011e09cd0dfa093c004f08500e670abb0567090000f603770a3905bf044408b8025805930b25012201"
            ~ "8d0a560e840d960d9d0a280d1d06fc08d5078c06fe0cb406d0061e02c6090507d20eb10cb90146085c042e030c0e1a07910fcd0c5f0fda066c0cee061d01f40f").ptr);
        auto gotm = polyMul(p, va, vb);
        foreach (i; 0 .. p.t)
            if (gotm.coef[i].elem != wantm.coef[i].elem)
            {
                logError("CMCE poly mul mismatch");
                ++fails;
                break;
            }
        const OID oid = OIDS.lookup("ClassicMcEliece_348864");
        if (oid.toString() != "1.3.6.1.4.1.22554.5.1.1")
            ++fails;
    }

    if (exists("test_data/pubkey/cmce_kat_hashed.vec"))
    {
        import botan.block.block_cipher;
        File vec = File("test_data/pubkey/cmce_kat_hashed.vec", "r");
        fails += runTestsBb(vec, "Instance", "CT", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!isCmceName(inst))
                    return 0;
                if (!("Seed" in m) || !("SS" in m) || !("PK" in m) || !("SK" in m) || !("CT" in m))
                    return 0;
                auto seed = hexDecode(m["Seed"]);
                auto p = cmceParams(inst);
                auto scratch = new ubyte[32];
                const per = (CMCE_SIGMA1 / 8) * cmceTau(p);
                auto noncebuf = new ubyte[100 * per];
                {
                    auto drbg = CmceKatDrbg(seed.ptr, seed.length);
                    drbg.generate(scratch.ptr, 32);
                    // C++ pulls one CTR_DRBG generate per encaps attempt (update after each).
                    foreach (a; 0 .. 100)
                        drbg.generate(noncebuf.ptr + a * per, per);
                }
                Unique!ClassicMcEliecePrivateKey sk = new ClassicMcEliecePrivateKey(inst, scratch.ptr, 32, true);
                Unique!ClassicMcEliecePublicKey pk = sk.publicKey();
                Unique!XOF hx = getXof("SHAKE-256");
                hx.update(pk.raw().mat.ptr, pk.raw().mat.length);
                auto pkh = new ubyte[64];
                hx.output(pkh.ptr, 64);
                auto want_pk = hexDecode(m["PK"]);
                if (pkh[] != want_pk[])
                {
                    logError("CMCE hashed PK mismatch");
                    return 1;
                }
                auto skb = new ubyte[cmceSkBytes(p)];
                cmceEncodeSk(sk.raw(), skb.ptr);
                Unique!XOF hs = getXof("SHAKE-256");
                hs.update(skb.ptr, skb.length);
                auto skh = new ubyte[64];
                hs.output(skh.ptr, 64);
                auto want_sk = hexDecode(m["SK"]);
                if (skh[] != want_sk[])
                {
                    logError("CMCE hashed SK mismatch");
                    return 1;
                }
                auto ss = new ubyte[32];
                auto ct = new ubyte[cmceCtBytes(p)];
                Unique!FixedBufRng frng = new FixedBufRng(noncebuf);
                cmceEncaps(pk.raw(), *frng, ss.ptr, ct.ptr);
                auto want_ss = hexDecode(m["SS"]);
                auto want_ct = hexDecode(m["CT"]);
                if (ss[] != want_ss[])
                {
                    logError("CMCE SS mismatch");
                    return 1;
                }
                if (ct[] != want_ct[])
                {
                    logError("CMCE CT mismatch");
                    return 1;
                }
                auto ss2 = new ubyte[32];
                cmceDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
                if (ss2[] != want_ss[])
                {
                    logError("CMCE decaps mismatch");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/cmce_negative.vec"))
    {
        import botan.block.block_cipher;
        File nvec = File("test_data/pubkey/cmce_negative.vec", "r");
        fails += runTestsBb(nvec, "Instance", "ss_invalid", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!isCmceName(inst))
                    return 0;
                if (!("seed" in m) || !("ct_invalid" in m) || !("ss_invalid" in m))
                    return 0;
                auto seed = hexDecode(m["seed"]);
                ubyte[32] xi;
                {
                    auto drbg = CmceKatDrbg(seed.ptr, seed.length);
                    drbg.generate(xi.ptr, 32);
                }
                Unique!ClassicMcEliecePrivateKey sk = new ClassicMcEliecePrivateKey(inst, xi.ptr, 32, true);
                auto cti = hexDecode(m["ct_invalid"]);
                auto ssn = new ubyte[32];
                cmceDecaps(sk.raw(), cti.ptr, cti.length, ssn.ptr);
                if (ssn[] != hexDecode(m["ss_invalid"])[])
                {
                    logError(inst, " cmce_negative ss_invalid mismatch");
                    return 1;
                }
                if (("ct_invalid_c1" in m) && ("ss_invalid_c1" in m))
                {
                    auto c1 = hexDecode(m["ct_invalid_c1"]);
                    auto ss1 = new ubyte[32];
                    cmceDecaps(sk.raw(), c1.ptr, c1.length, ss1.ptr);
                    if (ss1[] != hexDecode(m["ss_invalid_c1"])[])
                    {
                        logError(inst, " cmce_negative ss_invalid_c1 mismatch");
                        return 1;
                    }
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("cmce", {
        auto p = cmceParams("ClassicMcEliece_348864");
        auto v = gfOf(p, 7);
        auto w = v.inv();
        auto z = v.mul(w);
        if (z.elem != 1)
            throw new Exception("cmce leak probe");
    });

    if (fails)
        logError("classic_mceliece failures: ", fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS)
{

import botan.block.block_cipher;

private void storeBe64(ubyte* p, ulong v)
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

private ulong loadBe64(const(ubyte)* p)
{
    return (cast(ulong) p[0] << 56) | (cast(ulong) p[1] << 48) |
           (cast(ulong) p[2] << 40) | (cast(ulong) p[3] << 32) |
           (cast(ulong) p[4] << 24) | (cast(ulong) p[5] << 16) |
           (cast(ulong) p[6] << 8) | cast(ulong) p[7];
}

private struct CmceKatDrbg
{
    Unique!BlockCipher cipher;
    ulong v0, v1;

    this(const(ubyte)* seed, size_t slen)
    {
        import botan.block.block_cipher;
        cipher = retrieveBlockCipher("AES-256").clone();
        if (slen != 48)
            throw new InvalidArgument("CMCE KAT seed must be 48 bytes");
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
        storeBe64(outp, v0);
        storeBe64(outp + 8, v1);
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
        v0 = loadBe64(temp.ptr + 32);
        v1 = loadBe64(temp.ptr + 40);
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

final class FixedBufRng : RandomNumberGenerator
{
public:
    this(ubyte[] buf) { m_buf = buf; }
    override void randomize(ubyte* outp, size_t n)
    {
        if (m_off + n > m_buf.length)
            throw new InvalidState("FixedBufRng exhausted");
        outp[0 .. n] = m_buf[m_off .. m_off + n];
        m_off += n;
    }
    override @property string name() const { return "FixedBufRng"; }
    override void clear() {}
    override bool isSeeded() const { return true; }
    override void reseed(size_t) {}
    override void addEntropy(const(ubyte)*, size_t) {}
    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }
private:
    ubyte[] m_buf;
    size_t m_off;
}

} // BOTAN_HAS_TESTS
