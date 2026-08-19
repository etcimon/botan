/**
* FrodoKEM (ISO / NIST R3) — SHAKE and AES-A parameter sets
*
* Based on the MIT licensed reference implementation by the designers
* (https://github.com/microsoft/PQCrypto-LWEKE)
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.frodo_kem;

import botan.constants;
static if (BOTAN_HAS_FRODOKEM):

import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.utils.ct;
import botan.utils.exceptn;
import botan.utils.loadstor;
import botan.utils.mem_ops;
import botan.utils.types;
import botan.xof.xof;
import botan.block.block_cipher;
import botan.libstate.lookup;

enum ubyte FRODO_DS_KEYGEN = 0x5F;
enum ubyte FRODO_DS_ENCAPS = 0x96;

struct FrodoParams
{
    string name;
    string shake;
    size_t n;
    size_t n_bar;
    size_t d;
    size_t b;
    size_t strength;
    size_t len_a;
    size_t len_se;
    size_t len_salt;
    immutable(ushort)[] cdf;
    bool aes;
}

private immutable ushort[13] CDF_640 =
    [4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767];
private immutable ushort[11] CDF_976 =
    [5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767];
private immutable ushort[7] CDF_1344 =
    [9142, 23462, 30338, 32361, 32725, 32765, 32767];

FrodoParams frodoParams(in string name)
{
    FrodoParams p;
    p.n_bar = 8;
    p.len_a = 16;
    string core = name;
    if (name.length >= 16 && name[0 .. 9] == "FrodoKEM-")
        core = name[9 .. $];
    else if (name.length >= 17 && name[0 .. 10] == "eFrodoKEM-")
        core = name[10 .. $];
    else
        throw new InvalidArgument("Unknown FrodoKEM mode: " ~ name);

    p.name = name;
    if (core == "640-SHAKE" || core == "640-AES")
    {
        p.shake = "SHAKE-128";
        p.n = 640;
        p.d = 15;
        p.b = 2;
        p.strength = 128;
        p.cdf = CDF_640;
        p.aes = (core[$-3 .. $] == "AES");
        if (name[0] == 'e')
            p.len_se = 16;
        else
        {
            p.len_se = 32;
            p.len_salt = 32;
        }
        return p;
    }
    if (core == "976-SHAKE" || core == "976-AES")
    {
        p.shake = "SHAKE-256";
        p.n = 976;
        p.d = 16;
        p.b = 3;
        p.strength = 192;
        p.cdf = CDF_976;
        p.aes = (core[$-3 .. $] == "AES");
        if (name[0] == 'e')
            p.len_se = 24;
        else
        {
            p.len_se = 48;
            p.len_salt = 48;
        }
        return p;
    }
    if (core == "1344-SHAKE" || core == "1344-AES")
    {
        p.shake = "SHAKE-256";
        p.n = 1344;
        p.d = 16;
        p.b = 4;
        p.strength = 256;
        p.cdf = CDF_1344;
        p.aes = (core[$-3 .. $] == "AES");
        if (name[0] == 'e')
            p.len_se = 32;
        else
        {
            p.len_se = 64;
            p.len_salt = 64;
        }
        return p;
    }
    throw new InvalidArgument("Unknown FrodoKEM mode: " ~ name);
}

bool isFrodoName(in string n)
{
    return (n.length >= 16 && n[0 .. 9] == "FrodoKEM-")
        || (n.length >= 17 && n[0 .. 10] == "eFrodoKEM-");
}

size_t frodoLenSec(const ref FrodoParams p) { return p.strength / 8; }
size_t frodoPackedB(const ref FrodoParams p) { return p.d * p.n * p.n_bar / 8; }
size_t frodoPackedC(const ref FrodoParams p) { return p.d * p.n_bar * p.n_bar / 8; }
size_t frodoPkBytes(const ref FrodoParams p) { return p.len_a + frodoPackedB(p); }
size_t frodoCtBytes(const ref FrodoParams p) { return frodoPackedB(p) + frodoPackedC(p) + p.len_salt; }
size_t frodoSkBytes(const ref FrodoParams p)
{
    return frodoLenSec(p) + p.len_a + frodoPackedB(p) + (p.n_bar * p.n * 2) + frodoLenSec(p);
}

private struct FrodoMat
{
    size_t r, c;
    ushort[] e;
}

private FrodoMat frodoMat(size_t r, size_t c)
{
    FrodoMat m;
    m.r = r;
    m.c = c;
    m.e = new ushort[r * c];
    return m;
}

private Unique!XOF frodoXof(in string name)
{
    Unique!XOF x = getXof(name);
    if (!x)
        throw new LookupError(name ~ " XOF unavailable");
    return x;
}

private void frodoGenARowShake(XOF x, const(ubyte)* seed_a, size_t seed_len, ushort i,
                               ubyte* outp, size_t nbytes)
{
    x.clear();
    ubyte[2] ib;
    storeLittleEndian(i, ib.ptr);
    x.update(ib.ptr, 2);
    x.update(seed_a, seed_len);
    x.output(outp, nbytes);
}

private Unique!BlockCipher frodoAes()
{
    Unique!BlockCipher aes = retrieveBlockCipher("AES-128").clone();
    if (!aes)
        throw new LookupError("AES-128 unavailable for FrodoKEM-AES");
    return aes;
}

private void frodoGenARowAes(BlockCipher aes, ushort i, ubyte* outp, size_t nbytes)
{
    size_t off;
    ushort j;
    while (off < nbytes)
    {
        outp[off + 0] = cast(ubyte) i;
        outp[off + 1] = cast(ubyte)(i >> 8);
        outp[off + 2] = cast(ubyte) j;
        outp[off + 3] = cast(ubyte)(j >> 8);
        foreach (k; 4 .. 16)
            outp[off + k] = 0;
        off += 16;
        j += 8;
    }
    aes.encryptN(outp, outp, nbytes / 16);
}

private struct FrodoAGen
{
    bool aes;
    Unique!XOF x;
    Unique!BlockCipher c;
    const(ubyte)* seed;
    size_t seed_len;

    this(const ref FrodoParams p, const(ubyte)* seed_a)
    {
        aes = p.aes;
        seed = seed_a;
        seed_len = p.len_a;
        if (aes)
        {
            c = frodoAes();
            c.setKey(seed_a, p.len_a);
        }
        else
            x = frodoXof("SHAKE-128");
    }

    void row(ushort i, ubyte* outp, size_t nbytes)
    {
        if (aes)
            frodoGenARowAes(c, i, outp, nbytes);
        else
            frodoGenARowShake(x, seed, seed_len, i, outp, nbytes);
    }
}

private FrodoMat frodoSample(const ref FrodoParams p, size_t r, size_t c, const(ubyte)* rnd)
{
    auto m = frodoMat(r, c);
    const size_t n = r * c;
    loadLittleEndian(m.e.ptr, rnd, n);
    foreach (ref elem; m.e)
    {
        const ushort prnd = cast(ushort)(elem >> 1);
        auto sign = CTMask!ushort.expand(cast(ushort)(elem & 1));
        uint sample;
        foreach (j; 0 .. p.cdf.length - 1)
            sample += CTMask!ushort.isLt(p.cdf[j], prnd).ifSetReturn(1);
        const ushort su = cast(ushort) sample;
        elem = sign.select(cast(ushort)(~su + 1), su);
    }
    return m;
}

private FrodoMat frodoSampleFrom(XOF x, const ref FrodoParams p, size_t r, size_t c)
{
    auto rnd = new ubyte[2 * r * c];
    x.output(rnd.ptr, rnd.length);
    return frodoSample(p, r, c, rnd.ptr);
}

private void frodoReduce(ref FrodoMat m, const ref FrodoParams p)
{
    if (p.d >= 16)
        return;
    const ushort mask = cast(ushort)((1 << p.d) - 1);
    foreach (ref e; m.e)
        e &= mask;
}

private bool frodoMatEq(const ref FrodoMat a, const ref FrodoMat b)
{
    if (a.e.length != b.e.length)
        return false;
    return constantTimeCompare(cast(const(ubyte)*) a.e.ptr, cast(const(ubyte)*) b.e.ptr, a.e.length * 2);
}

private void frodoPack(const ref FrodoMat m, const ref FrodoParams p, ubyte* outp, size_t outlen)
{
    clearMem(outp, outlen);
    size_t i, j;
    ushort w;
    ubyte bits;
    while (i < outlen && (j < m.e.length || (j == m.e.length && bits > 0)))
    {
        ubyte b;
        while (b < 8)
        {
            const ubyte nbits = (8 - b) < bits ? cast(ubyte)(8 - b) : bits;
            const ushort mask = cast(ushort)((1 << nbits) - 1);
            const ubyte t = cast(ubyte)((w >> (bits - nbits)) & mask);
            outp[i] = cast(ubyte)(outp[i] + (t << (8 - b - nbits)));
            b += nbits;
            bits -= nbits;
            if (bits == 0)
            {
                if (j < m.e.length)
                {
                    w = m.e[j];
                    bits = cast(ubyte) p.d;
                    ++j;
                }
                else
                    break;
            }
        }
        if (b == 8)
            ++i;
    }
}

private FrodoMat frodoUnpack(const ref FrodoParams p, size_t r, size_t c,
                             const(ubyte)* inp, size_t inlen)
{
    auto m = frodoMat(r, c);
    const ubyte lsb = cast(ubyte) p.d;
    const size_t outlen = r * c;
    size_t i, j;
    ubyte w, bits;
    while (i < outlen && (j < inlen || (j == inlen && bits > 0)))
    {
        ubyte b;
        while (b < lsb)
        {
            const ubyte nbits = (lsb - b) < bits ? cast(ubyte)(lsb - b) : bits;
            const ushort mask = cast(ushort)((1 << nbits) - 1);
            const ubyte t = (w >> (bits - nbits)) & mask;
            m.e[i] = cast(ushort)(m.e[i] + (t << (lsb - b - nbits)));
            b += nbits;
            bits -= nbits;
            w &= cast(ubyte)(~(mask << bits));
            if (bits == 0)
            {
                if (j < inlen)
                {
                    w = inp[j];
                    bits = 8;
                    ++j;
                }
                else
                    break;
            }
        }
        if (b == lsb)
            ++i;
    }
    return m;
}

private void frodoSerialize(const ref FrodoMat m, ubyte* outp)
{
    foreach (i; 0 .. m.e.length)
        storeLittleEndian(m.e[i], outp + 2 * i);
}

private FrodoMat frodoDeserialize(size_t r, size_t c, const(ubyte)* inp)
{
    auto m = frodoMat(r, c);
    loadLittleEndian(m.e.ptr, inp, m.e.length);
    return m;
}

private FrodoMat frodoEncode(const ref FrodoParams p, const(ubyte)* inp)
{
    const ulong mask = (ulong(1) << p.b) - 1;
    auto m = frodoMat(p.n_bar, p.n_bar);
    size_t pos;
    foreach (i; 0 .. (p.n_bar * p.n_bar) / 8)
    {
        ulong temp;
        foreach (j; 0 .. p.b)
            temp |= ulong(inp[i * p.b + j]) << (8 * j);
        foreach (j; 0 .. 8)
        {
            m.e[pos++] = cast(ushort)((temp & mask) << (p.d - p.b));
            temp >>= p.b;
        }
    }
    return m;
}

private void frodoDecode(const ref FrodoParams p, const ref FrodoMat m, ubyte* outp)
{
    const size_t nwords = (p.n_bar * p.n_bar) / 8;
    const ushort maskex = cast(ushort)((1 << p.b) - 1);
    const ushort maskq = cast(ushort)((1 << p.d) - 1);
    size_t index;
    foreach (i; 0 .. nwords)
    {
        ulong templong;
        foreach (j; 0 .. 8)
        {
            const ushort temp = cast(ushort)(((m.e[index] & maskq) + (1 << (p.d - p.b - 1))) >> (p.d - p.b));
            templong |= ulong(temp & maskex) << (p.b * j);
            ++index;
        }
        foreach (j; 0 .. p.b)
            outp[i * p.b + j] = (templong >> (8 * j)) & 0xFF;
    }
}

private FrodoMat frodoAdd(const ref FrodoMat a, const ref FrodoMat b)
{
    auto m = frodoMat(a.r, a.c);
    foreach (i; 0 .. a.e.length)
        m.e[i] = cast(ushort)(a.e[i] + b.e[i]);
    return m;
}

private FrodoMat frodoSub(const ref FrodoMat a, const ref FrodoMat b)
{
    auto m = frodoMat(a.r, a.c);
    foreach (i; 0 .. a.e.length)
        m.e[i] = cast(ushort)(a.e[i] - b.e[i]);
    return m;
}

private FrodoMat frodoMulAddAsPlusE(const ref FrodoParams p, const ref FrodoMat s,
                                    const ref FrodoMat e, const(ubyte)* seed_a)
{
    auto m = frodoMat(e.r, e.c);
    auto ax = FrodoAGen(p, seed_a);
    auto a_bytes = new ubyte[4 * p.n * 2];
    auto a_row = new ushort[4 * p.n];
    for (size_t i = 0; i < p.n; i += 4)
    {
        foreach (k; 0 .. 4)
            ax.row(cast(ushort)(i + k), a_bytes.ptr + k * p.n * 2, p.n * 2);
        loadLittleEndian(a_row.ptr, a_bytes.ptr, 4 * p.n);
        foreach (k; 0 .. p.n_bar)
        {
            ushort[4] sum;
            foreach (j; 0 .. p.n)
            {
                const uint sp = s.e[k * p.n + j];
                sum[0] += cast(ushort)(a_row[0 * p.n + j] * sp);
                sum[1] += cast(ushort)(a_row[1 * p.n + j] * sp);
                sum[2] += cast(ushort)(a_row[2 * p.n + j] * sp);
                sum[3] += cast(ushort)(a_row[3 * p.n + j] * sp);
            }
            m.e[(i + 0) * p.n_bar + k] = cast(ushort)(e.e[(i + 0) * p.n_bar + k] + sum[0]);
            m.e[(i + 1) * p.n_bar + k] = cast(ushort)(e.e[(i + 1) * p.n_bar + k] + sum[1]);
            m.e[(i + 2) * p.n_bar + k] = cast(ushort)(e.e[(i + 2) * p.n_bar + k] + sum[2]);
            m.e[(i + 3) * p.n_bar + k] = cast(ushort)(e.e[(i + 3) * p.n_bar + k] + sum[3]);
        }
    }
    return m;
}

private FrodoMat frodoMulAddSaPlusE(const ref FrodoParams p, const ref FrodoMat s,
                                    const ref FrodoMat e, const(ubyte)* seed_a)
{
    auto m = frodoMat(e.r, e.c);
    m.e[] = e.e[];
    auto ax = FrodoAGen(p, seed_a);
    auto a_bytes = new ubyte[8 * p.n * 2];
    auto a_row = new ushort[8 * p.n];
    for (size_t i = 0; i < p.n; i += 8)
    {
        foreach (k; 0 .. 8)
            ax.row(cast(ushort)(i + k), a_bytes.ptr + k * p.n * 2, p.n * 2);
        loadLittleEndian(a_row.ptr, a_bytes.ptr, 8 * p.n);
        foreach (j; 0 .. p.n_bar)
        {
            uint[8] sp;
            foreach (q; 0 .. 8)
                sp[q] = s.e[j * p.n + i + q];
            foreach (q; 0 .. p.n)
            {
                ushort sum = m.e[j * p.n + q];
                foreach (t; 0 .. 8)
                    sum += cast(ushort)(sp[t] * a_row[t * p.n + q]);
                m.e[j * p.n + q] = sum;
            }
        }
    }
    return m;
}

private FrodoMat frodoMulAddSbPlusE(const ref FrodoParams p, const ref FrodoMat b,
                                    const ref FrodoMat s, const ref FrodoMat e)
{
    auto m = frodoMat(p.n_bar, p.n_bar);
    foreach (k; 0 .. p.n_bar)
    {
        foreach (i; 0 .. p.n_bar)
        {
            ushort acc = e.e[k * p.n_bar + i];
            foreach (j; 0 .. p.n)
            {
                const uint sj = s.e[k * p.n + j];
                acc += cast(ushort)(sj * b.e[j * p.n_bar + i]);
            }
            m.e[k * p.n_bar + i] = acc;
        }
    }
    return m;
}

private FrodoMat frodoMulBs(const ref FrodoParams p, const ref FrodoMat b, const ref FrodoMat s)
{
    auto m = frodoMat(p.n_bar, p.n_bar);
    foreach (i; 0 .. p.n_bar)
    {
        foreach (j; 0 .. p.n_bar)
        {
            ushort acc;
            foreach (k; 0 .. p.n)
            {
                const uint bk = b.e[i * p.n + k];
                const uint sk = s.e[j * p.n + k];
                acc += cast(ushort)(bk * sk);
            }
            m.e[i * p.n_bar + j] = acc;
        }
    }
    return m;
}

struct FrodoPublic
{
    FrodoParams params;
    ubyte[] seed_a;
    FrodoMat b;
    ubyte[] pkh;
}

struct FrodoSecret
{
    FrodoParams params;
    ubyte[] s;
    FrodoMat s_trans;
    FrodoPublic pub;
}

private void frodoHashPk(ref FrodoPublic pub)
{
    auto packed = new ubyte[frodoPackedB(pub.params)];
    frodoPack(pub.b, pub.params, packed.ptr, packed.length);
    Unique!XOF x = frodoXof(pub.params.shake);
    x.update(pub.seed_a.ptr, pub.seed_a.length);
    x.update(packed.ptr, packed.length);
    pub.pkh = new ubyte[frodoLenSec(pub.params)];
    x.output(pub.pkh.ptr, pub.pkh.length);
}

void frodoEncodePk(const ref FrodoPublic pub, ubyte* outp)
{
    outp[0 .. pub.params.len_a] = pub.seed_a[];
    frodoPack(pub.b, pub.params, outp + pub.params.len_a, frodoPackedB(pub.params));
}

void frodoEncodeSk(const ref FrodoSecret sk, ubyte* outp)
{
    const auto p = sk.params;
    const size_t ls = frodoLenSec(p);
    outp[0 .. ls] = sk.s[];
    frodoEncodePk(sk.pub, outp + ls);
    frodoSerialize(sk.s_trans, outp + ls + frodoPkBytes(p));
    const size_t off = ls + frodoPkBytes(p) + p.n_bar * p.n * 2;
    outp[off .. off + ls] = sk.pub.pkh[];
}

void frodoKeygenFromSeeds(ref FrodoSecret sk, const ref FrodoParams p,
                          const(ubyte)* s, const(ubyte)* seed_se, const(ubyte)* z)
{
    sk.params = p;
    sk.s = s[0 .. frodoLenSec(p)].dup;
    Unique!XOF x = frodoXof(p.shake);
    x.update(z, p.len_a);
    sk.pub.seed_a = new ubyte[p.len_a];
    x.output(sk.pub.seed_a.ptr, p.len_a);
    x.clear();
    ubyte ds = FRODO_DS_KEYGEN;
    x.update(&ds, 1);
    x.update(seed_se, p.len_se);
    sk.s_trans = frodoSampleFrom(x, p, p.n_bar, p.n);
    auto e = frodoSampleFrom(x, p, p.n, p.n_bar);
    x.clear();
    sk.pub.params = p;
    sk.pub.b = frodoMulAddAsPlusE(p, sk.s_trans, e, sk.pub.seed_a.ptr);
    frodoHashPk(sk.pub);
}

void frodoKeygen(ref FrodoSecret sk, const ref FrodoParams p, RandomNumberGenerator rng)
{
    auto s = new ubyte[frodoLenSec(p)];
    auto seed_se = new ubyte[p.len_se];
    auto z = new ubyte[p.len_a];
    rng.randomize(s.ptr, s.length);
    rng.randomize(seed_se.ptr, seed_se.length);
    rng.randomize(z.ptr, z.length);
    frodoKeygenFromSeeds(sk, p, s.ptr, seed_se.ptr, z.ptr);
}

void frodoEncapsFrom(const ref FrodoPublic pub, const(ubyte)* u, const(ubyte)* salt,
                     ubyte* ss, ubyte* ct)
{
    const auto p = pub.params;
    const size_t ls = frodoLenSec(p);
    Unique!XOF x = frodoXof(p.shake);
    x.update(pub.pkh.ptr, pub.pkh.length);
    x.update(u, ls);
    if (p.len_salt)
        x.update(salt, p.len_salt);
    auto seed_se = new ubyte[p.len_se];
    auto k = new ubyte[ls];
    x.output(seed_se.ptr, p.len_se);
    x.output(k.ptr, ls);
    x.clear();
    ubyte ds = FRODO_DS_ENCAPS;
    x.update(&ds, 1);
    x.update(seed_se.ptr, p.len_se);
    auto s_p = frodoSampleFrom(x, p, p.n_bar, p.n);
    auto e_p = frodoSampleFrom(x, p, p.n_bar, p.n);
    auto b_p = frodoMulAddSaPlusE(p, s_p, e_p, pub.seed_a.ptr);
    auto e_pp = frodoSampleFrom(x, p, p.n_bar, p.n_bar);
    x.clear();
    auto v = frodoMulAddSbPlusE(p, pub.b, s_p, e_pp);
    auto encoded = frodoEncode(p, u);
    auto c = frodoAdd(v, encoded);
    const size_t pb = frodoPackedB(p);
    const size_t pc = frodoPackedC(p);
    frodoPack(b_p, p, ct, pb);
    frodoPack(c, p, ct + pb, pc);
    if (p.len_salt)
        ct[pb + pc .. pb + pc + p.len_salt] = salt[0 .. p.len_salt];
    x.update(ct, frodoCtBytes(p));
    x.update(k.ptr, ls);
    x.output(ss, ls);
}

void frodoEncaps(const ref FrodoPublic pub, RandomNumberGenerator rng, ubyte* ss, ubyte* ct)
{
    auto u = new ubyte[frodoLenSec(pub.params)];
    auto salt = new ubyte[pub.params.len_salt];
    rng.randomize(u.ptr, u.length);
    if (pub.params.len_salt)
        rng.randomize(salt.ptr, salt.length);
    frodoEncapsFrom(pub, u.ptr, salt.ptr, ss, ct);
}

void frodoDecaps(const ref FrodoSecret sk, const(ubyte)* ct, size_t ct_len, ubyte* ss)
{
    const auto p = sk.params;
    if (ct_len != frodoCtBytes(p))
        throw new InvalidArgument("FrodoKEM ciphertext does not have the correct byte count");
    const size_t ls = frodoLenSec(p);
    const size_t pb = frodoPackedB(p);
    const size_t pc = frodoPackedC(p);
    auto b_p = frodoUnpack(p, p.n_bar, p.n, ct, pb);
    auto c = frodoUnpack(p, p.n_bar, p.n_bar, ct + pb, pc);
    const(ubyte)* salt = ct + pb + pc;
    auto w = frodoMulBs(p, b_p, sk.s_trans);
    auto m = frodoSub(c, w);
    auto u_p = new ubyte[ls];
    frodoDecode(p, m, u_p.ptr);
    Unique!XOF x = frodoXof(p.shake);
    x.update(sk.pub.pkh.ptr, sk.pub.pkh.length);
    x.update(u_p.ptr, ls);
    if (p.len_salt)
        x.update(salt, p.len_salt);
    auto seed_se = new ubyte[p.len_se];
    auto k_p = new ubyte[ls];
    x.output(seed_se.ptr, p.len_se);
    x.output(k_p.ptr, ls);
    x.clear();
    ubyte ds = FRODO_DS_ENCAPS;
    x.update(&ds, 1);
    x.update(seed_se.ptr, p.len_se);
    auto s_p = frodoSampleFrom(x, p, p.n_bar, p.n);
    auto e_p = frodoSampleFrom(x, p, p.n_bar, p.n);
    auto b_pp = frodoMulAddSaPlusE(p, s_p, e_p, sk.pub.seed_a.ptr);
    auto e_pp = frodoSampleFrom(x, p, p.n_bar, p.n_bar);
    x.clear();
    auto v = frodoMulAddSbPlusE(p, sk.pub.b, s_p, e_pp);
    auto encoded = frodoEncode(p, u_p.ptr);
    auto c_p = frodoAdd(v, encoded);
    frodoReduce(b_pp, p);
    frodoReduce(c_p, p);
    const bool match = frodoMatEq(b_p, b_pp) & frodoMatEq(c, c_p);
    auto k_bar = new ubyte[ls];
    const ubyte mm = match ? 0xff : 0x00;
    foreach (i; 0 .. ls)
        k_bar[i] = cast(ubyte)((k_p[i] & mm) | (sk.s[i] & ~mm));
    x.update(ct, ct_len);
    x.update(k_bar.ptr, ls);
    x.output(ss, ls);
}

private AlgorithmIdentifier frodoAlgId(in string name)
{
    Vector!ubyte empty;
    return AlgorithmIdentifier(OIDS.lookup(name), empty);
}

/**
* FrodoKEM public key
*/
final class FrodoPublicKey : PublicKey
{
public:
    /**
    * Decode an encoded public key
    * Params:
    *  name = SCAN name ("FrodoKEM-640-SHAKE", …)
    *  bits = seedA || packed B
    *  len = must equal frodoPkBytes
    */
    this(in string name, const(ubyte)* bits, size_t len)
    {
        m_pub.params = frodoParams(name);
        if (len != frodoPkBytes(m_pub.params))
            throw new DecodingError("FrodoKEM: unexpected public key length");
        m_pub.seed_a = bits[0 .. m_pub.params.len_a].dup;
        m_pub.b = frodoUnpack(m_pub.params, m_pub.params.n, m_pub.params.n_bar,
                              bits + m_pub.params.len_a, frodoPackedB(m_pub.params));
        frodoHashPk(m_pub);
    }

    /// Copy from an expanded public key.
    this(const ref FrodoPublic pub)
    {
        m_pub.params = pub.params;
        m_pub.seed_a = pub.seed_a.dup;
        m_pub.b.r = pub.b.r;
        m_pub.b.c = pub.b.c;
        m_pub.b.e = pub.b.e.dup;
        m_pub.pkh = pub.pkh.dup;
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
    override size_t estimatedStrength() const { return m_pub.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return frodoAlgId(m_pub.params.name); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(frodoPkBytes(m_pub.params));
        frodoEncodePk(m_pub, v.ptr);
        return v.move();
    }
    /// Expanded public key.
    ref const(FrodoPublic) raw() const { return m_pub; }

private:
    FrodoPublic m_pub;
}

/**
* FrodoKEM private key
*/
final class FrodoPrivateKey : PrivateKey, PublicKey
{
public:
    /**
    * Generate a random key
    * Params:
    *  name = SCAN name ("FrodoKEM-640-SHAKE", …)
    *  rng = random number generator
    */
    this(in string name, RandomNumberGenerator rng)
    {
        auto p = frodoParams(name);
        frodoKeygen(m_sk, p, rng);
    }

    /**
    * Decode an encoded private key
    * Params:
    *  name = SCAN name
    *  bits = s || pk || S^T || pkh
    *  len = must equal frodoSkBytes
    */
    this(in string name, const(ubyte)* bits, size_t len)
    {
        auto p = frodoParams(name);
        if (len != frodoSkBytes(p))
            throw new DecodingError("FrodoKEM: unexpected private key length");
        const size_t ls = frodoLenSec(p);
        m_sk.params = p;
        m_sk.s = bits[0 .. ls].dup;
        m_sk.pub.params = p;
        m_sk.pub.seed_a = bits[ls .. ls + p.len_a].dup;
        m_sk.pub.b = frodoUnpack(p, p.n, p.n_bar, bits + ls + p.len_a, frodoPackedB(p));
        m_sk.s_trans = frodoDeserialize(p.n_bar, p.n, bits + ls + frodoPkBytes(p));
        const size_t off = ls + frodoPkBytes(p) + p.n_bar * p.n * 2;
        frodoHashPk(m_sk.pub);
        if (!constantTimeCompare(m_sk.pub.pkh.ptr, bits + off, ls))
            throw new DecodingError("FrodoKEM embedded public key hash did not match recomputed value");
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
    override size_t estimatedStrength() const { return m_sk.params.strength; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return frodoAlgId(m_sk.params.name); }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(frodoPkBytes(m_sk.params));
        frodoEncodePk(m_sk.pub, v.ptr);
        return v.move();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        auto v = SecureVector!ubyte(frodoSkBytes(m_sk.params));
        frodoEncodeSk(m_sk, v.ptr);
        return v.move();
    }
    ref const(FrodoSecret) raw() const { return m_sk; }
    FrodoPublicKey publicKey() const { return new FrodoPublicKey(m_sk.pub); }

private:
    FrodoSecret m_sk;
}

static if (BOTAN_HAS_TESTS && !SKIP_FRODOKEM_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import botan.pubkey.pk_algs;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing frodo_kem.d ...");
    size_t fails;

    static immutable string[12] modes = [
        "FrodoKEM-640-SHAKE", "eFrodoKEM-640-SHAKE",
        "FrodoKEM-976-SHAKE", "eFrodoKEM-976-SHAKE",
        "FrodoKEM-1344-SHAKE", "eFrodoKEM-1344-SHAKE",
        "FrodoKEM-640-AES", "eFrodoKEM-640-AES",
        "FrodoKEM-976-AES", "eFrodoKEM-976-AES",
        "FrodoKEM-1344-AES", "eFrodoKEM-1344-AES",
    ];

    Unique!AutoSeededRNG rng = new AutoSeededRNG;
    foreach (inst; modes)
    {
        Unique!FrodoPrivateKey sk = new FrodoPrivateKey(inst, *rng);
        Unique!FrodoPublicKey pk = sk.publicKey();
        const auto p = sk.raw().params;
        auto ss1 = new ubyte[frodoLenSec(p)];
        auto ss2 = new ubyte[frodoLenSec(p)];
        auto ct = new ubyte[frodoCtBytes(p)];
        frodoEncaps(pk.raw(), *rng, ss1.ptr, ct.ptr);
        frodoDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
        if (ss1[0 .. ss1.length] != ss2[0 .. ss2.length])
        {
            logError(inst, " pairwise mismatch");
            ++fails;
        }
        ct[0] ^= 0xff;
        auto ss3 = new ubyte[frodoLenSec(p)];
        frodoDecaps(sk.raw(), ct.ptr, ct.length, ss3.ptr);
        if (ss3[0 .. ss3.length] == ss1[0 .. ss1.length])
        {
            logError(inst, " mutated CT accepted");
            ++fails;
        }
        auto pub_bits = SecureVector!ubyte(sk.x509SubjectPublicKey()[]);
        Unique!PublicKey via_pk = makePublicKey(sk.algorithmIdentifier(), pub_bits);
        if (!via_pk || via_pk.algoName != inst)
        {
            logError(inst, " factory public key");
            ++fails;
        }
        auto sk_bits = sk.pkcs8PrivateKey();
        Unique!FrodoPrivateKey sk2 = new FrodoPrivateKey(inst, sk_bits.ptr, sk_bits.length);
        auto ss4 = new ubyte[frodoLenSec(p)];
        ct[0] ^= 0xff;
        frodoDecaps(sk2.raw(), ct.ptr, ct.length, ss4.ptr);
        if (ss4[0 .. ss4.length] != ss1[0 .. ss1.length])
        {
            logError(inst, " reloaded SK decaps mismatch");
            ++fails;
        }
    }

    const OID oid640 = OIDS.lookup("FrodoKEM-640-SHAKE");
    if (oid640.toString() != "1.3.6.1.4.1.25258.1.14.1")
        ++fails;
    const OID oide640 = OIDS.lookup("eFrodoKEM-640-SHAKE");
    if (oide640.toString() != "1.3.6.1.4.1.25258.1.16.1")
        ++fails;
    const OID oid640a = OIDS.lookup("FrodoKEM-640-AES");
    if (oid640a.toString() != "1.3.6.1.4.1.25258.1.15.1")
        ++fails;
    const OID oide640a = OIDS.lookup("eFrodoKEM-640-AES");
    if (oide640a.toString() != "1.3.6.1.4.1.25258.1.17.1")
        ++fails;

    if (exists("test_data/pubkey/frodokem_kat.vec"))
    {
        import memutils.hashmap;
        import std.stdio : File;
        import std.string : indexOf;

        File vec = File("test_data/pubkey/frodokem_kat.vec", "r");
        size_t[string] seen;
        fails += runTestsBb(vec, "Instance", "CT", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["Instance"];
                if (!isFrodoName(inst))
                    return 0;
                if (++seen[inst] > 25)
                    return 0;
                if (!("Seed" in m) || !("SS" in m) || !("PK" in m) || !("SK" in m) || !("CT" in m))
                    return 0;
                auto seed = hexDecode(m["Seed"]);
                auto p = frodoParams(inst);
                const kg = frodoLenSec(p) + p.len_se + p.len_a;
                const encn = frodoLenSec(p) + p.len_salt;
                auto kgbuf = new ubyte[kg];
                auto encbuf = new ubyte[encn];
                {
                    auto drbg = FrodoKatDrbg(seed.ptr, seed.length);
                    drbg.generate(kgbuf.ptr, kg);
                    drbg.generate(encbuf.ptr, encn);
                }
                Unique!FixedBufRng kgrng = new FixedBufRng(kgbuf);
                Unique!FrodoPrivateKey sk = new FrodoPrivateKey(inst, *kgrng);
                Unique!FrodoPublicKey pk = sk.publicKey();
                auto pkbits = new ubyte[frodoPkBytes(p)];
                frodoEncodePk(pk.raw(), pkbits.ptr);
                auto skbits = new ubyte[frodoSkBytes(p)];
                frodoEncodeSk(sk.raw(), skbits.ptr);
                auto ss = new ubyte[frodoLenSec(p)];
                auto ct = new ubyte[frodoCtBytes(p)];
                Unique!FixedBufRng encrng = new FixedBufRng(encbuf);
                frodoEncaps(pk.raw(), *encrng, ss.ptr, ct.ptr);
                auto want_ss = hexDecode(m["SS"]);
                if (ss[] != want_ss[])
                {
                    logError(inst, " KAT SS mismatch");
                    return 1;
                }
                if (frodoShake16(pkbits) != hexDecode(m["PK"])[])
                {
                    logError(inst, " KAT PK hash mismatch");
                    return 1;
                }
                if (frodoShake16(skbits) != hexDecode(m["SK"])[])
                {
                    logError(inst, " KAT SK hash mismatch");
                    return 1;
                }
                if (frodoShake16(ct) != hexDecode(m["CT"])[])
                {
                    logError(inst, " KAT CT hash mismatch");
                    return 1;
                }
                auto ss2 = new ubyte[frodoLenSec(p)];
                frodoDecaps(sk.raw(), ct.ptr, ct.length, ss2.ptr);
                if (ss2[] != want_ss[])
                {
                    logError(inst, " KAT decaps mismatch");
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("frodo_kem", {
        Unique!AutoSeededRNG r = new AutoSeededRNG;
        Unique!FrodoPrivateKey sk = new FrodoPrivateKey("eFrodoKEM-640-SHAKE", *r);
        Unique!FrodoPublicKey pk = sk.publicKey();
        auto ss = new ubyte[16];
        auto ct = new ubyte[frodoCtBytes(pk.raw().params)];
        frodoEncaps(pk.raw(), *r, ss.ptr, ct.ptr);
        frodoDecaps(sk.raw(), ct.ptr, ct.length, ss.ptr);
    });

    if (fails)
        logError("frodo_kem failures: ", fails);
    assert(fails == 0);
}

static if (BOTAN_HAS_TESTS)
{

import botan.block.block_cipher;

private ubyte[] frodoShake16(const(ubyte)[] inp)
{
    Unique!XOF x = getXof("SHAKE-256");
    if (inp.length)
        x.update(inp.ptr, inp.length);
    auto outp = new ubyte[16];
    x.output(outp.ptr, 16);
    return outp;
}

private void frodoStoreBe64(ubyte* p, ulong v)
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

private ulong frodoLoadBe64(const(ubyte)* p)
{
    return (cast(ulong) p[0] << 56) | (cast(ulong) p[1] << 48) |
           (cast(ulong) p[2] << 40) | (cast(ulong) p[3] << 32) |
           (cast(ulong) p[4] << 24) | (cast(ulong) p[5] << 16) |
           (cast(ulong) p[6] << 8) | cast(ulong) p[7];
}

private struct FrodoKatDrbg
{
    Unique!BlockCipher cipher;
    ulong v0, v1;

    this(const(ubyte)* seed, size_t slen)
    {
        cipher = retrieveBlockCipher("AES-256").clone();
        if (slen != 48)
            throw new InvalidArgument("FrodoKEM KAT seed must be 48 bytes");
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
        frodoStoreBe64(outp, v0);
        frodoStoreBe64(outp + 8, v1);
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
        v0 = frodoLoadBe64(temp.ptr + 32);
        v1 = frodoLoadBe64(temp.ptr + 40);
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

