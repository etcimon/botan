/**
* HSS/LMS (RFC 8554 / draft-fluhrer-lms-more-parm-sets)
* verify + keygen/sign (SECRET_METHOD 2; no BDS cache)
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.hss_lms;

import botan.constants;
static if (BOTAN_HAS_HSS_LMS):

import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.rng.rng;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;

private uint loadBe32(const(ubyte)* p)
{
    return (uint(p[0]) << 24) | (uint(p[1]) << 16) | (uint(p[2]) << 8) | p[3];
}

private void storeBe32(ubyte* p, uint v)
{
    p[0] = cast(ubyte)(v >> 24);
    p[1] = cast(ubyte)(v >> 16);
    p[2] = cast(ubyte)(v >> 8);
    p[3] = cast(ubyte) v;
}

private void storeBe16(ubyte* p, ushort v)
{
    p[0] = cast(ubyte)(v >> 8);
    p[1] = cast(ubyte) v;
}

private ulong loadBe64(const(ubyte)* p)
{
    return (ulong(loadBe32(p)) << 32) | loadBe32(p + 4);
}

private void storeBe64(ubyte* p, ulong v)
{
    storeBe32(p, cast(uint)(v >> 32));
    storeBe32(p + 4, cast(uint) v);
}

struct LmotsP
{
    uint type;
    string hash;
    size_t n;
    size_t w;
    size_t p;
    size_t ls;
}

struct LmsP
{
    uint type;
    string hash;
    size_t m;
    size_t h;
}

private LmotsP lmotsParams(uint t)
{
    LmotsP p;
    p.type = t;
    switch (t)
    {
        case 1: p.hash = "SHA-256"; p.n = 32; p.w = 1; p.p = 265; p.ls = 7; break;
        case 2: p.hash = "SHA-256"; p.n = 32; p.w = 2; p.p = 133; p.ls = 6; break;
        case 3: p.hash = "SHA-256"; p.n = 32; p.w = 4; p.p = 67; p.ls = 4; break;
        case 4: p.hash = "SHA-256"; p.n = 32; p.w = 8; p.p = 34; p.ls = 0; break;
        case 5: p.hash = "Truncated(SHA-256,192)"; p.n = 24; p.w = 1; p.p = 200; p.ls = 8; break;
        case 6: p.hash = "Truncated(SHA-256,192)"; p.n = 24; p.w = 2; p.p = 101; p.ls = 6; break;
        case 7: p.hash = "Truncated(SHA-256,192)"; p.n = 24; p.w = 4; p.p = 51; p.ls = 4; break;
        case 8: p.hash = "Truncated(SHA-256,192)"; p.n = 24; p.w = 8; p.p = 26; p.ls = 0; break;
        case 9: p.hash = "SHAKE-256(256)"; p.n = 32; p.w = 1; p.p = 265; p.ls = 7; break;
        case 10: p.hash = "SHAKE-256(256)"; p.n = 32; p.w = 2; p.p = 133; p.ls = 6; break;
        case 11: p.hash = "SHAKE-256(256)"; p.n = 32; p.w = 4; p.p = 67; p.ls = 4; break;
        case 12: p.hash = "SHAKE-256(256)"; p.n = 32; p.w = 8; p.p = 34; p.ls = 0; break;
        case 13: p.hash = "SHAKE-256(192)"; p.n = 24; p.w = 1; p.p = 200; p.ls = 8; break;
        case 14: p.hash = "SHAKE-256(192)"; p.n = 24; p.w = 2; p.p = 101; p.ls = 6; break;
        case 15: p.hash = "SHAKE-256(192)"; p.n = 24; p.w = 4; p.p = 51; p.ls = 4; break;
        case 16: p.hash = "SHAKE-256(192)"; p.n = 24; p.w = 8; p.p = 26; p.ls = 0; break;
        default: throw new InvalidArgument("Unknown LM-OTS type");
    }
    return p;
}

private LmsP lmsParams(uint t)
{
    LmsP p;
    p.type = t;
    switch (t)
    {
        case 5: p.hash = "SHA-256"; p.m = 32; p.h = 5; break;
        case 6: p.hash = "SHA-256"; p.m = 32; p.h = 10; break;
        case 7: p.hash = "SHA-256"; p.m = 32; p.h = 15; break;
        case 8: p.hash = "SHA-256"; p.m = 32; p.h = 20; break;
        case 9: p.hash = "SHA-256"; p.m = 32; p.h = 25; break;
        case 10: p.hash = "Truncated(SHA-256,192)"; p.m = 24; p.h = 5; break;
        case 11: p.hash = "Truncated(SHA-256,192)"; p.m = 24; p.h = 10; break;
        case 12: p.hash = "Truncated(SHA-256,192)"; p.m = 24; p.h = 15; break;
        case 13: p.hash = "Truncated(SHA-256,192)"; p.m = 24; p.h = 20; break;
        case 14: p.hash = "Truncated(SHA-256,192)"; p.m = 24; p.h = 25; break;
        case 15: p.hash = "SHAKE-256(256)"; p.m = 32; p.h = 5; break;
        case 16: p.hash = "SHAKE-256(256)"; p.m = 32; p.h = 10; break;
        case 17: p.hash = "SHAKE-256(256)"; p.m = 32; p.h = 15; break;
        case 18: p.hash = "SHAKE-256(256)"; p.m = 32; p.h = 20; break;
        case 19: p.hash = "SHAKE-256(256)"; p.m = 32; p.h = 25; break;
        case 20: p.hash = "SHAKE-256(192)"; p.m = 24; p.h = 5; break;
        case 21: p.hash = "SHAKE-256(192)"; p.m = 24; p.h = 10; break;
        case 22: p.hash = "SHAKE-256(192)"; p.m = 24; p.h = 15; break;
        case 23: p.hash = "SHAKE-256(192)"; p.m = 24; p.h = 20; break;
        case 24: p.hash = "SHAKE-256(192)"; p.m = 24; p.h = 25; break;
        default: throw new InvalidArgument("Unknown LMS type");
    }
    return p;
}

private uint coef(const(ubyte)* S, size_t i, size_t w)
{
    const size_t b = (i * w) / 8;
    const size_t s = 8 - (w * (i % (8 / w)) + w);
    return (S[b] >> s) & ((1 << w) - 1);
}

private void lmotsCksm(const ref LmotsP p, const(ubyte)* S, ubyte[] extra)
{
    uint sum;
    const size_t u = (8 * p.n) / p.w;
    foreach (i; 0 .. u)
        sum += (1 << p.w) - 1 - coef(S, i, p.w);
    sum <<= p.ls;
    extra[0] = cast(ubyte)(sum >> 8);
    extra[1] = cast(ubyte) sum;
}

private bool lmotsPkFromSig(HashFunction h, const ref LmotsP p,
                            const(ubyte)* I, uint q,
                            const(ubyte)* msg, size_t msglen,
                            const(ubyte)* sig, size_t siglen, ubyte* K)
{
    const size_t want = 4 + p.n * (1 + p.p);
    if (siglen != want)
        return false;
    if (loadBe32(sig) != p.type)
        return false;
    const(ubyte)* C = sig + 4;
    const(ubyte)* y = C + p.n;
    ubyte[4] qb;
    storeBe32(qb.ptr, q);
    ubyte[2] dmesg = [0x81, 0x81];
    h.clear();
    h.update(I, 16);
    h.update(qb.ptr, 4);
    h.update(dmesg.ptr, 2);
    h.update(C, p.n);
    if (msglen)
        h.update(msg, msglen);
    auto Q = h.finished();
    ubyte[2] cks;
    lmotsCksm(p, Q.ptr, cks);
    auto z = new ubyte[p.p * p.n];
    auto tmp = new ubyte[p.n];
    const uint maxj = (1 << p.w) - 1;
    foreach (i; 0 .. p.p)
    {
        uint a = (i < (8 * p.n) / p.w) ? coef(Q.ptr, i, p.w)
                                        : coef(cks.ptr, i - (8 * p.n) / p.w, p.w);
        copyMem(tmp.ptr, y + i * p.n, p.n);
        ubyte[2] ib;
        storeBe16(ib.ptr, cast(ushort) i);
        foreach (j; a .. maxj)
        {
            ubyte jb = cast(ubyte) j;
            h.clear();
            h.update(I, 16);
            h.update(qb.ptr, 4);
            h.update(ib.ptr, 2);
            h.update(&jb, 1);
            h.update(tmp.ptr, p.n);
            auto d = h.finished();
            copyMem(tmp.ptr, d.ptr, p.n);
        }
        copyMem(z.ptr + i * p.n, tmp.ptr, p.n);
    }
    ubyte[2] dpblc = [0x80, 0x80];
    h.clear();
    h.update(I, 16);
    h.update(qb.ptr, 4);
    h.update(dpblc.ptr, 2);
    h.update(z.ptr, p.p * p.n);
    auto Kd = h.finished();
    copyMem(K, Kd.ptr, p.n);
    return true;
}

private bool lmsVerify(const(ubyte)* pub, size_t publen, const(ubyte)* msg, size_t msglen,
                       const(ubyte)* sig, size_t siglen)
{
    if (publen < 24)
        return false;
    LmsP lp;
    LmotsP op;
    try
    {
        lp = lmsParams(loadBe32(pub));
        op = lmotsParams(loadBe32(pub + 4));
    }
    catch (Exception)
        return false;
    if (lp.hash != op.hash || publen != 24 + lp.m)
        return false;
    const(ubyte)* I = pub + 8;
    const(ubyte)* T1 = pub + 24;
    const size_t ots_len = 4 + op.n * (1 + op.p);
    if (siglen != 4 + ots_len + 4 + lp.h * lp.m)
        return false;
    const uint q = loadBe32(sig);
    if (q >= (uint(1) << lp.h))
        return false;
    if (loadBe32(sig + 4 + ots_len) != lp.type)
        return false;
    Unique!HashFunction h = retrieveHash(lp.hash).clone();
    auto Kc = new ubyte[op.n];
    if (!lmotsPkFromSig(h, op, I, q, msg, msglen, sig + 4, ots_len, Kc.ptr))
        return false;
    uint r = (1 << lp.h) + q;
    ubyte[4] rb;
    storeBe32(rb.ptr, r);
    ubyte[2] dleaf = [0x82, 0x82];
    h.clear();
    h.update(I, 16);
    h.update(rb.ptr, 4);
    h.update(dleaf.ptr, 2);
    h.update(Kc.ptr, op.n);
    auto node = h.finished();
    const(ubyte)* path = sig + 4 + ots_len + 4;
    ubyte[2] dintr = [0x83, 0x83];
    foreach (i; 0 .. lp.h)
    {
        r >>= 1;
        storeBe32(rb.ptr, r);
        h.clear();
        h.update(I, 16);
        h.update(rb.ptr, 4);
        h.update(dintr.ptr, 2);
        if (((q >> i) & 1) == 0)
        {
            h.update(node.ptr, lp.m);
            h.update(path + i * lp.m, lp.m);
        }
        else
        {
            h.update(path + i * lp.m, lp.m);
            h.update(node.ptr, lp.m);
        }
        node = h.finished();
    }
    return node[0 .. lp.m] == T1[0 .. lp.m];
}

private size_t lmsPubBytes(const ref LmsP lp) { return 24 + lp.m; }
private size_t lmsSigBytes(const ref LmsP lp, const ref LmotsP op)
{
    return 4 + 4 + op.n * (1 + op.p) + 4 + lp.h * lp.m;
}

bool hssLmsVerify(const(ubyte)* pub, size_t publen, const(ubyte)* msg, size_t msglen,
                  const(ubyte)* sig, size_t siglen)
{
    if (publen < 4 + 24)
        return false;
    const uint L = loadBe32(pub);
    if (L < 1 || L > 8)
        return false;
    if (siglen < 4)
        return false;
    const uint nspk = loadBe32(sig);
    if (nspk + 1 != L)
        return false;
    const(ubyte)* cur_pub = pub + 4;
    size_t cur_publen = publen - 4;
    const(ubyte)* p = sig + 4;
    size_t left = siglen - 4;
    foreach (i; 0 .. nspk)
    {
        if (cur_publen < 24)
            return false;
        LmsP lp;
        LmotsP op;
        try
        {
            lp = lmsParams(loadBe32(cur_pub));
            op = lmotsParams(loadBe32(cur_pub + 4));
        }
        catch (Exception)
            return false;
        const size_t slen = lmsSigBytes(lp, op);
        if (left < slen + 24)
            return false;
        LmsP next_lp;
        try { next_lp = lmsParams(loadBe32(p + slen)); }
        catch (Exception) return false;
        const size_t next_publen = lmsPubBytes(next_lp);
        if (left < slen + next_publen)
            return false;
        if (!lmsVerify(cur_pub, lmsPubBytes(lp), p + slen, next_publen, p, slen))
            return false;
        p += slen;
        left -= slen;
        cur_pub = p;
        cur_publen = next_publen;
        p += next_publen;
        left -= next_publen;
    }
    if (cur_publen < 24)
        return false;
    LmsP lp;
    LmotsP op;
    try
    {
        lp = lmsParams(loadBe32(cur_pub));
        op = lmotsParams(loadBe32(cur_pub + 4));
    }
    catch (Exception)
        return false;
    const size_t slen = lmsSigBytes(lp, op);
    if (left != slen)
        return false;
    return lmsVerify(cur_pub, lmsPubBytes(lp), msg, msglen, p, slen);
}

private void lmsPrf(HashFunction h, const(ubyte)* I, uint q, ushort i, ubyte j,
                    const(ubyte)* seed, size_t seedlen, ubyte* outp, size_t n)
{
    ubyte[4] qb;
    ubyte[2] ib;
    storeBe32(qb.ptr, q);
    storeBe16(ib.ptr, i);
    h.clear();
    h.update(I, 16);
    h.update(qb.ptr, 4);
    h.update(ib.ptr, 2);
    h.update(&j, 1);
    h.update(seed, seedlen);
    auto d = h.finished();
    copyMem(outp, d.ptr, n);
}

private void lmotsChain(HashFunction h, const(ubyte)* I, uint q, ushort chain,
                        ubyte start, ubyte end, ubyte* x, size_t n)
{
    ubyte[4] qb;
    ubyte[2] ib;
    storeBe32(qb.ptr, q);
    storeBe16(ib.ptr, chain);
    foreach (j; start .. end)
    {
        ubyte jb = cast(ubyte) j;
        h.clear();
        h.update(I, 16);
        h.update(qb.ptr, 4);
        h.update(ib.ptr, 2);
        h.update(&jb, 1);
        h.update(x, n);
        auto d = h.finished();
        copyMem(x, d.ptr, n);
    }
}

private void lmotsSkI(HashFunction h, const ref LmotsP p, const(ubyte)* I, uint q,
                      const(ubyte)* seed, size_t seedlen, ubyte[][] x)
{
    foreach (i; 0 .. p.p)
    {
        x[i] = new ubyte[p.n];
        lmsPrf(h, I, q, cast(ushort) i, 0xff, seed, seedlen, x[i].ptr, p.n);
    }
}

private void lmotsPkFromSk(HashFunction h, const ref LmotsP p, const(ubyte)* I, uint q,
                           ubyte[][] x, ubyte* K)
{
    const ubyte maxj = cast(ubyte)((1 << p.w) - 1);
    auto z = new ubyte[p.p * p.n];
    auto tmp = new ubyte[p.n];
    foreach (i; 0 .. p.p)
    {
        copyMem(tmp.ptr, x[i].ptr, p.n);
        lmotsChain(h, I, q, cast(ushort) i, 0, maxj, tmp.ptr, p.n);
        copyMem(z.ptr + i * p.n, tmp.ptr, p.n);
    }
    ubyte[4] qb;
    storeBe32(qb.ptr, q);
    ubyte[2] dpblc = [0x80, 0x80];
    h.clear();
    h.update(I, 16);
    h.update(qb.ptr, 4);
    h.update(dpblc.ptr, 2);
    h.update(z.ptr, p.p * p.n);
    auto Kd = h.finished();
    copyMem(K, Kd.ptr, p.n);
}

private void lmotsSign(HashFunction h, const ref LmotsP p, const(ubyte)* I, uint q,
                       const(ubyte)* seed, size_t seedlen,
                       const(ubyte)* msg, size_t msglen, ubyte* sig)
{
    storeBe32(sig, p.type);
    auto C = sig + 4;
    lmsPrf(h, I, q, 0xFFFD, 0xff, seed, seedlen, C, p.n);
    ubyte[4] qb;
    storeBe32(qb.ptr, q);
    ubyte[2] dmesg = [0x81, 0x81];
    h.clear();
    h.update(I, 16);
    h.update(qb.ptr, 4);
    h.update(dmesg.ptr, 2);
    h.update(C, p.n);
    if (msglen)
        h.update(msg, msglen);
    auto Q = h.finished();
    ubyte[2] cks;
    lmotsCksm(p, Q.ptr, cks);
    auto x = new ubyte[][p.p];
    lmotsSkI(h, p, I, q, seed, seedlen, x);
    auto y = sig + 4 + p.n;
    foreach (i; 0 .. p.p)
    {
        uint a = (i < (8 * p.n) / p.w) ? coef(Q.ptr, i, p.w)
                                        : coef(cks.ptr, i - (8 * p.n) / p.w, p.w);
        copyMem(y + i * p.n, x[i].ptr, p.n);
        lmotsChain(h, I, q, cast(ushort) i, 0, cast(ubyte) a, y + i * p.n, p.n);
    }
}

private void lmsLeafHash(HashFunction h, const(ubyte)* I, uint r, const(ubyte)* K, size_t n, ubyte* outp)
{
    ubyte[4] rb;
    storeBe32(rb.ptr, r);
    ubyte[2] dleaf = [0x82, 0x82];
    h.clear();
    h.update(I, 16);
    h.update(rb.ptr, 4);
    h.update(dleaf.ptr, 2);
    h.update(K, n);
    auto d = h.finished();
    copyMem(outp, d.ptr, n);
}

private void lmsIntrHash(HashFunction h, const(ubyte)* I, uint r,
                         const(ubyte)* left, const(ubyte)* right, size_t m, ubyte* outp)
{
    ubyte[4] rb;
    storeBe32(rb.ptr, r);
    ubyte[2] dintr = [0x83, 0x83];
    h.clear();
    h.update(I, 16);
    h.update(rb.ptr, 4);
    h.update(dintr.ptr, 2);
    h.update(left, m);
    h.update(right, m);
    auto d = h.finished();
    copyMem(outp, d.ptr, m);
}

private void lmsBuild(HashFunction h, const ref LmsP lp, const ref LmotsP op,
                      const(ubyte)* I, const(ubyte)* seed, size_t seedlen,
                      ubyte* root, ubyte* auth, uint q_auth, bool want_auth)
{
    const size_t leaves = size_t(1) << lp.h;
    auto level = new ubyte[][leaves];
    auto K = new ubyte[op.n];
    auto x = new ubyte[][op.p];
    foreach (q; 0 .. leaves)
    {
        lmotsSkI(h, op, I, cast(uint) q, seed, seedlen, x);
        lmotsPkFromSk(h, op, I, cast(uint) q, x, K.ptr);
        level[q] = new ubyte[lp.m];
        lmsLeafHash(h, I, cast(uint)(leaves + q), K.ptr, op.n, level[q].ptr);
    }
    if (want_auth)
        copyMem(auth, level[q_auth ^ 1].ptr, lp.m);
    size_t n = leaves;
    uint height;
    while (n > 1)
    {
        ++height;
        foreach (i; 0 .. n / 2)
        {
            const uint r = cast(uint)((1 << (lp.h - height + 1)) / 2 + i);
            lmsIntrHash(h, I, r, level[2 * i].ptr, level[2 * i + 1].ptr, lp.m, level[i].ptr);
        }
        n /= 2;
        if (want_auth && height < lp.h)
        {
            const uint idx = q_auth >> height;
            copyMem(auth + height * lp.m, level[idx ^ 1].ptr, lp.m);
        }
    }
    copyMem(root, level[0].ptr, lp.m);
}

private void lmsPubEncode(const ref LmsP lp, const ref LmotsP op, const(ubyte)* I,
                          const(ubyte)* root, ubyte* outp)
{
    storeBe32(outp, lp.type);
    storeBe32(outp + 4, op.type);
    copyMem(outp + 8, I, 16);
    copyMem(outp + 24, root, lp.m);
}

private void lmsSign(HashFunction h, const ref LmsP lp, const ref LmotsP op,
                     const(ubyte)* I, const(ubyte)* seed, size_t seedlen, uint q,
                     const(ubyte)* msg, size_t msglen, ubyte* sig, ubyte* pub)
{
    storeBe32(sig, q);
    lmotsSign(h, op, I, q, seed, seedlen, msg, msglen, sig + 4);
    const size_t ots_len = 4 + op.n * (1 + op.p);
    storeBe32(sig + 4 + ots_len, lp.type);
    auto root = new ubyte[lp.m];
    lmsBuild(h, lp, op, I, seed, seedlen, root.ptr, sig + 4 + ots_len + 4, q, true);
    if (pub)
        lmsPubEncode(lp, op, I, root.ptr, pub);
}

struct HssLayer
{
    LmsP lp;
    LmotsP op;
}

struct HssSecret
{
    HssLayer[] layers;
    ubyte[] seed;
    ubyte[] I;
    ulong unused;
}

private void hssDeriveChild(HashFunction h, const(ubyte)* parent_I, uint parent_q,
                            const(ubyte)* parent_seed, size_t seedlen,
                            ubyte* child_seed, ubyte* child_I)
{
    lmsPrf(h, parent_I, parent_q, 0xFFFE, 0xff, parent_seed, seedlen, child_seed, seedlen);
    auto id = new ubyte[seedlen];
    lmsPrf(h, parent_I, parent_q, 0xFFFF, 0xff, parent_seed, seedlen, id.ptr, seedlen);
    copyMem(child_I, id.ptr, 16);
}

void hssLmsSign(ref HssSecret sk, const(ubyte)* msg, size_t msglen, ubyte* sig)
{
    const uint L = cast(uint) sk.layers.length;
    if (L < 1)
        throw new InvalidState("HSS-LMS: empty private key");
    ulong maxc = 1;
    foreach (ref layer; sk.layers)
        maxc *= (ulong(1) << layer.lp.h);
    if (sk.unused >= maxc)
        throw new InvalidState("HSS-LMS private key exhausted");
    const ulong idx = sk.unused;
    ++sk.unused;

    auto q = new uint[L];
    ulong rest = idx;
    foreach_reverse (i; 0 .. L)
    {
        const ulong mask = (ulong(1) << sk.layers[i].lp.h) - 1;
        q[i] = cast(uint)(rest & mask);
        rest >>= sk.layers[i].lp.h;
    }

    Unique!HashFunction hf = retrieveHash(sk.layers[0].lp.hash).clone();
    auto seeds = new ubyte[][L];
    auto ids = new ubyte[][L];
    seeds[0] = sk.seed.dup;
    ids[0] = sk.I.dup;
    foreach (i; 1 .. L)
    {
        seeds[i] = new ubyte[sk.seed.length];
        ids[i] = new ubyte[16];
        hssDeriveChild(hf, ids[i - 1].ptr, q[i - 1], seeds[i - 1].ptr, seeds[i - 1].length,
                       seeds[i].ptr, ids[i].ptr);
    }

    storeBe32(sig, L - 1);
    ubyte* p = sig + 4;
    auto child_pk = new ubyte[][L];
    auto sigs = new ubyte[][L];
    foreach (i; 0 .. L)
    {
        sigs[i] = new ubyte[lmsSigBytes(sk.layers[i].lp, sk.layers[i].op)];
        child_pk[i] = new ubyte[lmsPubBytes(sk.layers[i].lp)];
    }
    foreach_reverse (i; 0 .. L)
    {
        const(ubyte)* mptr;
        size_t mlen;
        if (i + 1 == L)
        {
            mptr = msg;
            mlen = msglen;
        }
        else
        {
            mptr = child_pk[i + 1].ptr;
            mlen = child_pk[i + 1].length;
        }
        lmsSign(hf, sk.layers[i].lp, sk.layers[i].op, ids[i].ptr, seeds[i].ptr, seeds[i].length,
                q[i], mptr, mlen, sigs[i].ptr, child_pk[i].ptr);
    }
    foreach (i; 0 .. L)
    {
        copyMem(p, sigs[i].ptr, sigs[i].length);
        p += sigs[i].length;
        if (i + 1 < L)
        {
            copyMem(p, child_pk[i + 1].ptr, child_pk[i + 1].length);
            p += child_pk[i + 1].length;
        }
    }
}

size_t hssLmsSigBytes(const ref HssSecret sk)
{
    size_t n = 4;
    foreach (i; 0 .. sk.layers.length)
    {
        n += lmsSigBytes(sk.layers[i].lp, sk.layers[i].op);
        if (i + 1 < sk.layers.length)
            n += lmsPubBytes(sk.layers[i + 1].lp);
    }
    return n;
}

void hssParsePrivate(ref HssSecret sk, const(ubyte)* bits, size_t len)
{
    if (len < 4 + 8)
        throw new DecodingError("HSS-LMS: private key too short");
    const uint L = loadBe32(bits);
    if (L < 1 || L > 8)
        throw new DecodingError("HSS-LMS: invalid L");
    const size_t hdr = 4 + 8 + L * 8;
    if (len < hdr + 16)
        throw new DecodingError("HSS-LMS: private key truncated");
    sk.layers.length = L;
    foreach (i; 0 .. L)
    {
        sk.layers[i].lp = lmsParams(loadBe32(bits + 12 + i * 8));
        sk.layers[i].op = lmotsParams(loadBe32(bits + 16 + i * 8));
    }
    const size_t m = sk.layers[0].lp.m;
    if (len != hdr + m + 16)
        throw new DecodingError("HSS-LMS: unexpected private key length");
    sk.unused = loadBe64(bits + 4);
    sk.seed = bits[hdr .. hdr + m].dup;
    sk.I = bits[hdr + m .. hdr + m + 16].dup;
}

void hssPublicFromSecret(const ref HssSecret sk, ubyte[] outp)
{
    Unique!HashFunction hf = retrieveHash(sk.layers[0].lp.hash).clone();
    auto root = new ubyte[sk.layers[0].lp.m];
    lmsBuild(hf, sk.layers[0].lp, sk.layers[0].op, sk.I.ptr, sk.seed.ptr, sk.seed.length,
             root.ptr, null, 0, false);
    storeBe32(outp.ptr, cast(uint) sk.layers.length);
    lmsPubEncode(sk.layers[0].lp, sk.layers[0].op, sk.I.ptr, root.ptr, outp.ptr + 4);
}

private AlgorithmIdentifier hssAlgId()
{
    Vector!ubyte empty;
    return AlgorithmIdentifier(OIDS.lookup("HSS-LMS"), empty);
}

/**
* HSS/LMS public key (RFC 8554)
*/
final class HSSLMSPublicKey : PublicKey
{
public:
    /**
    * Decode an encoded public key
    * Params:
    *  bits = L || LMS public key
    *  len = length of bits
    */
    this(const(ubyte)* bits, size_t len)
    {
        if (len < 4 + 24)
            throw new DecodingError("HSS-LMS: public key too short");
        m_bits = bits[0 .. len].dup;
    }

    /**
    * Decode X.509 SubjectPublicKeyInfo
    * Params:
    *  key_bits = encoded public key
    */
    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        this(key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return "HSS-LMS"; }
    override size_t estimatedStrength() const
    {
        if (m_bits.length < 8)
            return 0;
        try
        {
            auto lp = lmsParams(loadBe32(m_bits.ptr + 4));
            return 8 * lp.m - 1;
        }
        catch (Exception)
            return 0;
    }
    override bool checkKey(RandomNumberGenerator, bool) const { return m_bits.length >= 4 + 24; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const { return hssAlgId(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(m_bits.length);
        v[] = m_bits[];
        return v.move();
    }
    /// Encoded public key bytes.
    const(ubyte)[] raw() const { return m_bits; }

private:
    ubyte[] m_bits;
}

/**
* HSS/LMS private key (RFC 8554)
*/
final class HSSLMSPrivateKey : PrivateKey, PublicKey
{
public:
    /**
    * Decode an encoded private key
    * Params:
    *  bits = encoded HSS private key
    *  len = length of bits
    */
    this(const(ubyte)* bits, size_t len)
    {
        hssParsePrivate(m_sk, bits, len);
    }

    /**
    * Generate a one-layer LMS key. C++ `HSS_LMS_PrivateKey(rng, "SHA-256,HW(5,8)")`.
    * Params:
    *  params = currently "SHA-256,HW(5,8)"
    *  rng = random number generator
    */
    this(in string params, RandomNumberGenerator rng)
    {
        // "SHA-256,HW(h,w)" → LMS height h, Winternitz w.
        uint lms_type = 5;
        uint ots_type = 4;
        if (params == "SHA-256,HW(5,8)")
        {
            lms_type = 5;
            ots_type = 4;
        }
        else
            throw new InvalidArgument("HSS-LMS: unsupported params " ~ params);
        m_sk.layers.length = 1;
        m_sk.layers[0].lp = lmsParams(lms_type);
        m_sk.layers[0].op = lmotsParams(ots_type);
        m_sk.unused = 0;
        auto seed = rng.randomVec(m_sk.layers[0].lp.m);
        auto id = rng.randomVec(16);
        m_sk.seed = seed[].dup;
        m_sk.I = id[].dup;
    }

    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        this(key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return "HSS-LMS"; }
    override size_t estimatedStrength() const
    {
        return 8 * m_sk.layers[0].lp.m - 1;
    }
    override bool checkKey(RandomNumberGenerator, bool) const { return m_sk.layers.length > 0; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const { return hssAlgId(); }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(4 + lmsPubBytes(m_sk.layers[0].lp));
        hssPublicFromSecret(m_sk, v[]);
        return v.move();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        const uint L = cast(uint) m_sk.layers.length;
        const size_t m = m_sk.layers[0].lp.m;
        auto v = SecureVector!ubyte(4 + 8 + L * 8 + m + 16);
        storeBe32(v.ptr, L);
        storeBe64(v.ptr + 4, m_sk.unused);
        foreach (i; 0 .. L)
        {
            storeBe32(v.ptr + 12 + i * 8, m_sk.layers[i].lp.type);
            storeBe32(v.ptr + 16 + i * 8, m_sk.layers[i].op.type);
        }
        const size_t hdr = 4 + 8 + L * 8;
        v[hdr .. hdr + m] = m_sk.seed[];
        v[hdr + m .. hdr + m + 16] = m_sk.I[];
        return v.move();
    }
    ref HssSecret raw() { return m_sk; }
    HSSLMSPublicKey publicKey() const
    {
        auto v = new ubyte[4 + lmsPubBytes(m_sk.layers[0].lp)];
        hssPublicFromSecret(m_sk, v);
        return new HSSLMSPublicKey(v.ptr, v.length);
    }

private:
    HssSecret m_sk;
}

final class HSSLMSSignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { m_key = cast(HSSLMSPrivateKey) pkey; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        auto sig = SecureVector!ubyte(hssLmsSigBytes(m_key.raw()));
        hssLmsSign(m_key.raw(), msg, msg_len, sig.ptr);
        return sig.move();
    }
private:
    HSSLMSPrivateKey m_key;
}

final class HSSLMSVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { m_key = cast(HSSLMSPublicKey) pkey; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return hssLmsVerify(m_key.raw().ptr, m_key.raw().length, msg, msg_len, sig, sig_len);
    }
    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("HSS-LMS has no message recovery");
    }
private:
    const HSSLMSPublicKey m_key;
}

static if (BOTAN_HAS_TESTS && !SKIP_HSS_LMS_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing hss_lms.d ...");
    size_t fails;

    const OID oid = OIDS.lookup("HSS-LMS");
    if (oid.toString() != "1.2.840.113549.1.9.16.3.17")
        ++fails;

    if (exists("test_data/pubkey/hss_lms_sig.vec"))
    {
        File vec = File("test_data/pubkey/hss_lms_sig.vec", "r");
        fails += runTestsBb(vec, "PrivateKey", "Signature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PrivateKey" in m) || !("Signature" in m))
                    return 0;
                auto skb = hexDecode(m["PrivateKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto want = hexDecode(m["Signature"]);
                Unique!HSSLMSPrivateKey sk = new HSSLMSPrivateKey(skb.ptr, skb.length);
                auto sig = new ubyte[hssLmsSigBytes(sk.raw())];
                hssLmsSign(sk.raw(), msg.ptr, msg.length, sig.ptr);
                if (sig[0 .. sig.length] != want[])
                {
                    logError("HSS-LMS sign mismatch");
                    return 1;
                }
                auto pk = sk.publicKey();
                if (!hssLmsVerify(pk.raw().ptr, pk.raw().length, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError("HSS-LMS signed verify failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/hss_lms_verify.vec"))
    {
        File vec = File("test_data/pubkey/hss_lms_verify.vec", "r");
        fails += runTestsBb(vec, "PublicKey", "Signature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PublicKey" in m) || !("Signature" in m))
                    return 0;
                auto pkb = hexDecode(m["PublicKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto sig = hexDecode(m["Signature"]);
                Unique!HSSLMSPublicKey pk = new HSSLMSPublicKey(pkb.ptr, pkb.length);
                if (!hssLmsVerify(pk.raw().ptr, pk.raw().length, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError("HSS-LMS verify failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/hss_lms_invalid.vec"))
    {
        File vec = File("test_data/pubkey/hss_lms_invalid.vec", "r");
        fails += runTestsBb(vec, "PublicKey", "InvalidSignature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PublicKey" in m) || !("InvalidSignature" in m))
                    return 0;
                auto pkb = hexDecode(m["PublicKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto sig = hexDecode(m["InvalidSignature"]);
                Unique!HSSLMSPublicKey pk = new HSSLMSPublicKey(pkb.ptr, pkb.length);
                if (hssLmsVerify(pk.raw().ptr, pk.raw().length, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError("HSS-LMS invalid signature accepted");
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("hss_lms", {
        if (!exists("test_data/pubkey/hss_lms_verify.vec"))
            return;
        auto pkb = hexDecode("00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878");
        Unique!HSSLMSPublicKey pk = new HSSLMSPublicKey(pkb.ptr, pkb.length);
        auto bits = pk.x509SubjectPublicKey();
        if (bits.length != pkb.length)
            throw new Exception("hss leftover probe failed");
    });

    if (fails)
        logError("hss_lms failures: ", fails);
    assert(fails == 0);
}
