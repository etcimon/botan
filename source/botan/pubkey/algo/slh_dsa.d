/**
* SLH-DSA (FIPS 205) — SHAKE and SHA2 parameter sets
* plus HashSLH-DSA pre-hash and SPHINCS+ Round 3.1 (empty prefix, FORS LSB-first)
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.slh_dsa;

import botan.constants;
static if (BOTAN_HAS_SLH_DSA):

import botan.libstate.lookup;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.rng.rng;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.hash.hash;
import botan.block.block_cipher;
import botan.mac.mac;
import botan.pk_pad.mgf1;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.xof.xof;

enum uint ADRS_WOTS_HASH = 0;
enum uint ADRS_WOTS_PK = 1;
enum uint ADRS_TREE = 2;
enum uint ADRS_FORS_TREE = 3;
enum uint ADRS_FORS_ROOTS = 4;
enum uint ADRS_WOTS_PRF = 5;
enum uint ADRS_FORS_PRF = 6;

struct SLHDSAParams
{
    string name;
    uint n;
    uint h;
    uint d;
    uint a;
    uint k;
    uint w;
    uint bitsec;
    uint lg_w;
    uint wots_len1;
    uint wots_len2;
    uint wots_len;
    uint xmss_h;
    uint fors_msg_bytes;
    uint tree_idx_bytes;
    uint leaf_idx_bytes;
    uint h_msg_bytes;
    uint wots_bytes;
    uint fors_sig_bytes;
    uint xmss_sig_bytes;
    uint ht_sig_bytes;
    uint sig_bytes;
    uint pk_bytes;
    uint sk_bytes;
    bool sha2;
    bool slh;
}

private uint ceilLog2(uint x)
{
    uint r;
    uint v = x - 1;
    while (v)
    {
        v >>= 1;
        ++r;
    }
    return r;
}

private uint ceilToBytes(uint bits) { return (bits + 7) / 8; }

private SLHDSAParams makeParams(string name, uint n, uint h, uint d, uint a, uint k, uint w, uint bitsec,
                                bool sha2 = false, bool slh = true)
{
    SLHDSAParams p;
    p.name = name;
    p.sha2 = sha2;
    p.slh = slh;
    p.n = n;
    p.h = h;
    p.d = d;
    p.a = a;
    p.k = k;
    p.w = w;
    p.bitsec = bitsec;
    p.lg_w = ceilLog2(w);
    p.xmss_h = h / d;
    p.wots_len1 = (n * 8) / p.lg_w;
    p.wots_len2 = ceilLog2(p.wots_len1 * (w - 1)) / p.lg_w + 1;
    p.wots_len = p.wots_len1 + p.wots_len2;
    p.wots_bytes = p.wots_len * n;
    p.fors_msg_bytes = ceilToBytes(k * a);
    p.fors_sig_bytes = (a + 1) * k * n;
    p.xmss_sig_bytes = p.wots_bytes + p.xmss_h * n;
    p.ht_sig_bytes = d * p.xmss_sig_bytes;
    p.sig_bytes = n + p.fors_sig_bytes + p.ht_sig_bytes;
    p.pk_bytes = 2 * n;
    p.sk_bytes = 4 * n;
    p.tree_idx_bytes = ceilToBytes(h - p.xmss_h);
    p.leaf_idx_bytes = ceilToBytes(p.xmss_h);
    p.h_msg_bytes = p.fors_msg_bytes + p.tree_idx_bytes + p.leaf_idx_bytes;
    return p;
}

SLHDSAParams slhdsaParams(in string name)
{
    if (name == "SLH-DSA-SHAKE-128s") return makeParams(name, 16, 63, 7, 12, 14, 16, 133);
    if (name == "SLH-DSA-SHAKE-128f") return makeParams(name, 16, 66, 22, 6, 33, 16, 128);
    if (name == "SLH-DSA-SHAKE-192s") return makeParams(name, 24, 63, 7, 14, 17, 16, 193);
    if (name == "SLH-DSA-SHAKE-192f") return makeParams(name, 24, 66, 22, 8, 33, 16, 194);
    if (name == "SLH-DSA-SHAKE-256s") return makeParams(name, 32, 64, 8, 14, 22, 16, 255);
    if (name == "SLH-DSA-SHAKE-256f") return makeParams(name, 32, 68, 17, 9, 35, 16, 255);
    if (name == "SLH-DSA-SHA2-128s") return makeParams(name, 16, 63, 7, 12, 14, 16, 133, true);
    if (name == "SLH-DSA-SHA2-128f") return makeParams(name, 16, 66, 22, 6, 33, 16, 128, true);
    if (name == "SLH-DSA-SHA2-192s") return makeParams(name, 24, 63, 7, 14, 17, 16, 193, true);
    if (name == "SLH-DSA-SHA2-192f") return makeParams(name, 24, 66, 22, 8, 33, 16, 194, true);
    if (name == "SLH-DSA-SHA2-256s") return makeParams(name, 32, 64, 8, 14, 22, 16, 255, true);
    if (name == "SLH-DSA-SHA2-256f") return makeParams(name, 32, 68, 17, 9, 35, 16, 255, true);
    if (name == "SphincsPlus-shake-128s-r3.1") return makeParams(name, 16, 63, 7, 12, 14, 16, 133, false, false);
    if (name == "SphincsPlus-shake-128f-r3.1") return makeParams(name, 16, 66, 22, 6, 33, 16, 128, false, false);
    if (name == "SphincsPlus-shake-192s-r3.1") return makeParams(name, 24, 63, 7, 14, 17, 16, 193, false, false);
    if (name == "SphincsPlus-shake-192f-r3.1") return makeParams(name, 24, 66, 22, 8, 33, 16, 194, false, false);
    if (name == "SphincsPlus-shake-256s-r3.1") return makeParams(name, 32, 64, 8, 14, 22, 16, 255, false, false);
    if (name == "SphincsPlus-shake-256f-r3.1") return makeParams(name, 32, 68, 17, 9, 35, 16, 255, false, false);
    if (name == "SphincsPlus-sha2-128s-r3.1") return makeParams(name, 16, 63, 7, 12, 14, 16, 133, true, false);
    if (name == "SphincsPlus-sha2-128f-r3.1") return makeParams(name, 16, 66, 22, 6, 33, 16, 128, true, false);
    if (name == "SphincsPlus-sha2-192s-r3.1") return makeParams(name, 24, 63, 7, 14, 17, 16, 193, true, false);
    if (name == "SphincsPlus-sha2-192f-r3.1") return makeParams(name, 24, 66, 22, 8, 33, 16, 194, true, false);
    if (name == "SphincsPlus-sha2-256s-r3.1") return makeParams(name, 32, 64, 8, 14, 22, 16, 255, true, false);
    if (name == "SphincsPlus-sha2-256f-r3.1") return makeParams(name, 32, 68, 17, 9, 35, 16, 255, true, false);
    throw new InvalidArgument("Unknown SLH-DSA/SPHINCS+ mode: " ~ name);
}

private Unique!XOF shakeOf()
{
    Unique!XOF x = getXof("SHAKE-256");
    if (!x)
        throw new LookupError("SHAKE-256 XOF unavailable");
    return x;
}

private void storeBe32(ubyte* p, uint v)
{
    p[0] = cast(ubyte)(v >> 24);
    p[1] = cast(ubyte)(v >> 16);
    p[2] = cast(ubyte)(v >> 8);
    p[3] = cast(ubyte) v;
}

private void adrsBytes(const ref uint[8] adrs, ubyte* outp)
{
    foreach (i; 0 .. 8)
        storeBe32(outp + 4 * i, adrs[i]);
}

private void adrsCompressed(const ref uint[8] adrs, ubyte* outp)
{
    outp[0] = cast(ubyte) adrs[0];
    storeBe32(outp + 1, adrs[2]);
    storeBe32(outp + 5, adrs[3]);
    outp[9] = cast(ubyte) adrs[4];
    storeBe32(outp + 10, adrs[5]);
    storeBe32(outp + 14, adrs[6]);
    storeBe32(outp + 18, adrs[7]);
}

private void slhT(ubyte* outp, uint n, const(ubyte)* pkseed, const ref uint[8] adrs,
                  const(ubyte)* m, size_t mlen, bool sha2)
{
    if (!sha2)
    {
        Unique!XOF x = shakeOf();
        x.update(pkseed, n);
        ubyte[32] ab;
        adrsBytes(adrs, ab.ptr);
        x.update(ab.ptr, 32);
        if (mlen)
            x.update(m, mlen);
        x.output(outp, n);
        return;
    }
    const bool use_x = mlen > n;
    const string hname = (use_x && n > 16) ? "SHA-512" : "SHA-256";
    const size_t pad = (use_x && n > 16) ? 128 : 64;
    Unique!HashFunction h = retrieveHash(hname).clone();
    ubyte[128] padded;
    padded[] = 0;
    padded[0 .. n] = pkseed[0 .. n];
    h.update(padded.ptr, pad);
    ubyte[22] ac;
    adrsCompressed(adrs, ac.ptr);
    h.update(ac.ptr, 22);
    if (mlen)
        h.update(m, mlen);
    auto d = h.finished();
    copyMem(outp, d.ptr, n);
}

private void slhT2(ubyte* outp, uint n, const(ubyte)* pkseed, const ref uint[8] adrs,
                   const(ubyte)* m1, const(ubyte)* m2, bool sha2)
{
    if (!sha2)
    {
        Unique!XOF x = shakeOf();
        x.update(pkseed, n);
        ubyte[32] ab;
        adrsBytes(adrs, ab.ptr);
        x.update(ab.ptr, 32);
        x.update(m1, n);
        x.update(m2, n);
        x.output(outp, n);
        return;
    }
    ubyte[64] buf;
    copyMem(buf.ptr, m1, n);
    copyMem(buf.ptr + n, m2, n);
    slhT(outp, n, pkseed, adrs, buf.ptr, 2 * n, true);
}

struct SLHAdrs
{
    uint[8] w;

    void setType(uint t) { w[4] = t; }
    void setLayer(uint layer) { w[0] = layer; }
    void setTree(ulong tree)
    {
        w[1] = 0;
        w[2] = cast(uint)(tree >> 32);
        w[3] = cast(uint) tree;
    }
    void setKeypair(uint kp) { w[5] = kp; }
    void setChain(uint c) { w[6] = c; }
    void setHash(uint h) { w[7] = h; }
    void setHeight(uint h) { w[6] = h; }
    void setIndex(uint i) { w[7] = i; }

    SLHAdrs subtree() const
    {
        SLHAdrs r;
        r.w[0] = w[0];
        r.w[1] = w[1];
        r.w[2] = w[2];
        r.w[3] = w[3];
        return r;
    }

    SLHAdrs keypair() const
    {
        auto r = subtree();
        r.w[5] = w[5];
        return r;
    }
}

private void base2b(uint[] outp, const(ubyte)* inp, uint lg_w, uint wmask)
{
    size_t off;
    uint cur;
    uint bits;
    foreach (ref o; outp)
    {
        if (bits == 0)
        {
            cur = inp[off++];
            bits = 8;
        }
        bits -= lg_w;
        o = (cur >> bits) & wmask;
    }
}

private void chainLengths(uint[] lengths, const(ubyte)* msg, const ref SLHDSAParams p)
{
    base2b(lengths[0 .. p.wots_len1], msg, p.lg_w, p.w - 1);
    uint csum;
    foreach (i; 0 .. p.wots_len1)
        csum += p.w - 1 - lengths[i];
    const uint shift = (8 - ((p.wots_len2 * p.lg_w) % 8)) % 8;
    csum <<= shift;
    ubyte[4] cb;
    storeBe32(cb.ptr, csum);
    const uint csz = ceilToBytes(p.wots_len2 * p.lg_w);
    base2b(lengths[p.wots_len1 .. p.wots_len], cb.ptr + (4 - csz), p.lg_w, p.w - 1);
}

private void wotsChain(ubyte* outp, const(ubyte)* startv, uint start, uint steps,
                       ref SLHAdrs addr, const(ubyte)* pkseed, uint n, uint w, bool sha2)
{
    copyMem(outp, startv, n);
    foreach (i; start .. start + steps)
    {
        if (i >= w)
            break;
        addr.setHash(i);
        slhT(outp, n, pkseed, addr.w, outp, n, sha2);
    }
}

private void wotsPkFromSig(ubyte* leaf, const(ubyte)* msg, const(ubyte)* sig,
                           ref SLHAdrs addr, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    auto lengths = new uint[p.wots_len];
    chainLengths(lengths, msg, p);
    auto pkbuf = new ubyte[p.wots_bytes];
    foreach (i; 0 .. p.wots_len)
    {
        addr.setChain(i);
        const uint start = lengths[i];
        wotsChain(pkbuf.ptr + i * p.n, sig + i * p.n, start, (p.w - 1) - start, addr, pkseed, p.n, p.w, p.sha2);
    }
    SLHAdrs pkaddr = addr.subtree();
    pkaddr.setType(ADRS_WOTS_PK);
    pkaddr.setKeypair(addr.w[5]);
    slhT(leaf, p.n, pkseed, pkaddr.w, pkbuf.ptr, p.wots_bytes, p.sha2);
}

private void wotsSignAndPkgen(ubyte* sig_or_null, ubyte* leaf, const(ubyte)* skseed,
                              uint leaf_idx, bool do_sig, const uint[] steps,
                              ref SLHAdrs leaf_addr, ref SLHAdrs pk_addr,
                              const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    leaf_addr.setKeypair(leaf_idx);
    pk_addr.setKeypair(leaf_idx);
    auto pkbuf = new ubyte[p.wots_bytes];
    size_t sigoff;
    foreach (i; 0 .. p.wots_len)
    {
        leaf_addr.setChain(i);
        leaf_addr.setHash(0);
        leaf_addr.setType(ADRS_WOTS_PRF);
        slhT(pkbuf.ptr + i * p.n, p.n, pkseed, leaf_addr.w, skseed, p.n, p.sha2);
        leaf_addr.setType(ADRS_WOTS_HASH);
        const bool want = do_sig;
        const uint stop_at = want ? steps[i] : uint.max;
        foreach (k; 0 .. p.w)
        {
            if (want && k == stop_at)
            {
                copyMem(sig_or_null + sigoff, pkbuf.ptr + i * p.n, p.n);
                sigoff += p.n;
            }
            if (k == p.w - 1)
                break;
            leaf_addr.setHash(k);
            slhT(pkbuf.ptr + i * p.n, p.n, pkseed, leaf_addr.w, pkbuf.ptr + i * p.n, p.n, p.sha2);
        }
    }
    slhT(leaf, p.n, pkseed, pk_addr.w, pkbuf.ptr, p.wots_bytes, p.sha2);
}

private void treehash(ubyte* root, ubyte* auth, bool want_auth, uint leaf_idx,
                      uint idx_offset, uint height,
                      void delegate(ubyte* outn, uint idx) genLeaf,
                      ref SLHAdrs tree_addr, const(ubyte)* pkseed, uint n, bool sha2)
{
    const uint max_idx = (1u << height) - 1;
    auto stack = new ubyte[height * n];
    auto cur = new ubyte[n];
    for (uint idx = 0; ; ++idx)
    {
        tree_addr.setHeight(0);
        genLeaf(cur.ptr, idx + idx_offset);
        uint ioff = idx_offset;
        uint iidx = idx;
        uint ileaf = leaf_idx;
        for (uint hgt = 0; ; ++hgt)
        {
            if (hgt == height)
            {
                copyMem(root, cur.ptr, n);
                return;
            }
            if (want_auth && ((iidx ^ ileaf) == 1))
                copyMem(auth + hgt * n, cur.ptr, n);
            auto slot = stack.ptr + hgt * n;
            if ((iidx & 1) == 0 && idx < max_idx)
            {
                copyMem(slot, cur.ptr, n);
                break;
            }
            ioff /= 2;
            tree_addr.setHeight(hgt + 1);
            tree_addr.setIndex(iidx / 2 + ioff);
            slhT2(cur.ptr, n, pkseed, tree_addr.w, slot, cur.ptr, sha2);
            iidx /= 2;
            ileaf /= 2;
        }
    }
}

private void computeRoot(ubyte* outn, const(ubyte)* leaf, uint leaf_idx, uint idx_offset,
                         const(ubyte)* auth, uint height, ref SLHAdrs tree_addr,
                         const(ubyte)* pkseed, uint n, bool sha2)
{
    auto node = new ubyte[n];
    copyMem(node.ptr, leaf, n);
    auto tmp = new ubyte[n];
    foreach (i; 0 .. height)
    {
        const(ubyte)* left;
        const(ubyte)* right;
        if (leaf_idx & 1)
        {
            left = auth + i * n;
            right = node.ptr;
        }
        else
        {
            left = node.ptr;
            right = auth + i * n;
        }
        leaf_idx /= 2;
        idx_offset /= 2;
        tree_addr.setHeight(i + 1);
        tree_addr.setIndex(leaf_idx + idx_offset);
        slhT2(tmp.ptr, n, pkseed, tree_addr.w, left, right, sha2);
        copyMem(node.ptr, tmp.ptr, n);
    }
    copyMem(outn, node.ptr, n);
}

private void xmssSign(ubyte* sig, ubyte* root, const(ubyte)* msg, const(ubyte)* skseed,
                      ref SLHAdrs wots_addr, ref SLHAdrs tree_addr, uint idx_leaf,
                      bool do_sig, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    uint[] steps;
    if (do_sig)
    {
        steps = new uint[p.wots_len];
        chainLengths(steps, msg, p);
    }
    SLHAdrs leaf_addr = wots_addr.subtree();
    SLHAdrs pk_addr = wots_addr.subtree();
    pk_addr.setType(ADRS_WOTS_PK);
    treehash(root, do_sig ? (sig + p.wots_bytes) : null, do_sig, idx_leaf, 0, p.xmss_h,
        (ubyte* outn, uint address_index) {
            wotsSignAndPkgen(do_sig && address_index == idx_leaf ? sig : null,
                             outn, skseed, address_index,
                             do_sig && address_index == idx_leaf, steps,
                             leaf_addr, pk_addr, pkseed, p);
        }, tree_addr, pkseed, p.n, p.sha2);
}

private void xmssGenRoot(ubyte* root, const(ubyte)* skseed, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    SLHAdrs tree_addr;
    tree_addr.setType(ADRS_TREE);
    tree_addr.setLayer(p.d - 1);
    SLHAdrs wots_addr;
    wots_addr.setType(ADRS_WOTS_PK);
    wots_addr.setLayer(p.d - 1);
    xmssSign(null, root, null, skseed, wots_addr, tree_addr, 0, false, pkseed, p);
}

private void forsIndices(uint[] idx, const(ubyte)* msg, const ref SLHDSAParams p)
{
    uint offset;
    foreach (t; 0 .. p.k)
    {
        uint v;
        foreach (i; 0 .. p.a)
        {
            if (p.slh)
            {
                const uint bit = (msg[offset >> 3] >> (~offset & 7)) & 1;
                v ^= bit << (p.a - 1 - i);
            }
            else
            {
                const uint bit = (msg[offset >> 3] >> (offset & 7)) & 1;
                v ^= bit << i;
            }
            ++offset;
        }
        idx[t] = v;
    }
}

private void forsSign(ubyte* sig, ubyte* pk, const(ubyte)* mhash, const(ubyte)* skseed,
                      ref SLHAdrs address, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    auto indices = new uint[p.k];
    forsIndices(indices, mhash, p);
    SLHAdrs tree = address.keypair();
    SLHAdrs pkaddr = address.keypair();
    pkaddr.setType(ADRS_FORS_ROOTS);
    auto roots = new ubyte[p.k * p.n];
    size_t soff;
    foreach (i; 0 .. p.k)
    {
        const uint idx_off = i * (1u << p.a);
        tree.setType(ADRS_FORS_PRF);
        tree.setHeight(0);
        tree.setIndex(indices[i] + idx_off);
        slhT(sig + soff, p.n, pkseed, tree.w, skseed, p.n, p.sha2);
        soff += p.n;
        tree.setType(ADRS_FORS_TREE);
        treehash(roots.ptr + i * p.n, sig + soff, true, indices[i], idx_off, p.a,
            (ubyte* outn, uint address_index) {
                SLHAdrs fa = tree;
                fa.setIndex(address_index);
                fa.setType(ADRS_FORS_PRF);
                auto sec = new ubyte[p.n];
                slhT(sec.ptr, p.n, pkseed, fa.w, skseed, p.n, p.sha2);
                fa.setType(ADRS_FORS_TREE);
                slhT(outn, p.n, pkseed, fa.w, sec.ptr, p.n, p.sha2);
            }, tree, pkseed, p.n, p.sha2);
        soff += p.a * p.n;
    }
    slhT(pk, p.n, pkseed, pkaddr.w, roots.ptr, p.k * p.n, p.sha2);
}

private void forsPkFromSig(ubyte* pk, const(ubyte)* mhash, const(ubyte)* sig,
                           ref SLHAdrs address, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    auto indices = new uint[p.k];
    forsIndices(indices, mhash, p);
    SLHAdrs tree = address.keypair();
    tree.setType(ADRS_FORS_TREE);
    SLHAdrs pkaddr = address.keypair();
    pkaddr.setType(ADRS_FORS_ROOTS);
    auto roots = new ubyte[p.k * p.n];
    size_t soff;
    foreach (i; 0 .. p.k)
    {
        const uint idx_off = i * (1u << p.a);
        tree.setHeight(0);
        tree.setIndex(indices[i] + idx_off);
        auto leaf = new ubyte[p.n];
        slhT(leaf.ptr, p.n, pkseed, tree.w, sig + soff, p.n, p.sha2);
        soff += p.n;
        computeRoot(roots.ptr + i * p.n, leaf.ptr, indices[i], idx_off,
                    sig + soff, p.a, tree, pkseed, p.n, p.sha2);
        soff += p.a * p.n;
    }
    slhT(pk, p.n, pkseed, pkaddr.w, roots.ptr, p.k * p.n, p.sha2);
}

private void htSign(ubyte* sig, const(ubyte)* msg, const(ubyte)* skseed,
                    ulong tree_idx, uint leaf_idx, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    size_t off;
    auto node = new ubyte[p.n];
    copyMem(node.ptr, msg, p.n);
    foreach (layer; 0 .. p.d)
    {
        SLHAdrs wots;
        wots.setType(ADRS_WOTS_HASH);
        wots.setTree(tree_idx);
        wots.setKeypair(leaf_idx);
        SLHAdrs treea;
        treea.setType(ADRS_TREE);
        treea.setLayer(layer);
        treea.setTree(tree_idx);
        wots.setLayer(layer);
        wots.setTree(tree_idx);
        auto next = new ubyte[p.n];
        xmssSign(sig + off, next.ptr, node.ptr, skseed, wots, treea, leaf_idx, true, pkseed, p);
        copyMem(node.ptr, next.ptr, p.n);
        off += p.xmss_sig_bytes;
        leaf_idx = cast(uint)(tree_idx & ((1u << p.xmss_h) - 1));
        tree_idx >>= p.xmss_h;
    }
}

private bool htVerify(const(ubyte)* msg, const(ubyte)* htsig, const(ubyte)* pkroot,
                      ulong tree_idx, uint leaf_idx, const(ubyte)* pkseed, const ref SLHDSAParams p)
{
    size_t off;
    auto node = new ubyte[p.n];
    copyMem(node.ptr, msg, p.n);
    foreach (layer; 0 .. p.d)
    {
        SLHAdrs wots;
        wots.setType(ADRS_WOTS_HASH);
        wots.setLayer(layer);
        wots.setTree(tree_idx);
        wots.setKeypair(leaf_idx);
        SLHAdrs treea;
        treea.setType(ADRS_TREE);
        treea.setLayer(layer);
        treea.setTree(tree_idx);
        auto leaf = new ubyte[p.n];
        wotsPkFromSig(leaf.ptr, node.ptr, htsig + off, wots, pkseed, p);
        off += p.wots_bytes;
        computeRoot(node.ptr, leaf.ptr, leaf_idx, 0, htsig + off, p.xmss_h, treea, pkseed, p.n, p.sha2);
        off += p.xmss_h * p.n;
        leaf_idx = cast(uint)(tree_idx & ((1u << p.xmss_h) - 1));
        tree_idx >>= p.xmss_h;
    }
    return node[0 .. p.n] == pkroot[0 .. p.n];
}

private ulong fromBits(const(ubyte)* p, size_t nbytes, uint nbits)
{
    ulong v;
    foreach (i; 0 .. nbytes)
        v = (v << 8) | p[i];
    if (nbits < 64)
        v &= (ulong.max >> (64 - nbits));
    return v;
}

private void preparePrefix(ubyte[] pre)
{
    pre[0] = 0;
    pre[1] = 0;
}

private void hMsg(const(ubyte)* r, const(ubyte)* pkseed, const(ubyte)* root,
                  const(ubyte)* pre, size_t prelen, const(ubyte)* msg, size_t msglen,
                  ubyte* digest, const ref SLHDSAParams p)
{
    if (!p.sha2)
    {
        Unique!XOF x = shakeOf();
        x.update(r, p.n);
        x.update(pkseed, p.n);
        x.update(root, p.n);
        x.update(pre, prelen);
        x.update(msg, msglen);
        x.output(digest, p.h_msg_bytes);
        return;
    }
    const string hx = (p.n == 16) ? "SHA-256" : "SHA-512";
    Unique!HashFunction h = retrieveHash(hx).clone();
    h.update(r, p.n);
    h.update(pkseed, p.n);
    h.update(root, p.n);
    h.update(pre, prelen);
    h.update(msg, msglen);
    auto rpk = h.finished();
    auto inp = new ubyte[2 * p.n + rpk.length];
    inp[0 .. p.n] = r[0 .. p.n];
    inp[p.n .. 2 * p.n] = pkseed[0 .. p.n];
    inp[2 * p.n .. $] = rpk[];
    foreach (i; 0 .. p.h_msg_bytes)
        digest[i] = 0;
    mgf1Mask(*h, inp.ptr, inp.length, digest, p.h_msg_bytes);
}

private void prfMsg(ubyte* outp, const(ubyte)* skprf, const(ubyte)* optrand,
                    const(ubyte)* pre, size_t prelen, const(ubyte)* msg, size_t msglen,
                    uint n, bool sha2)
{
    if (!sha2)
    {
        Unique!XOF x = shakeOf();
        x.update(skprf, n);
        x.update(optrand, n);
        x.update(pre, prelen);
        x.update(msg, msglen);
        x.output(outp, n);
        return;
    }
    const string macn = (n == 16) ? "HMAC(SHA-256)" : "HMAC(SHA-512)";
    Unique!MessageAuthenticationCode hmac = retrieveMac(macn).clone();
    hmac.setKey(skprf, n);
    hmac.update(optrand, n);
    hmac.update(pre, prelen);
    hmac.update(msg, msglen);
    auto d = hmac.finished();
    copyMem(outp, d.ptr, n);
}

struct SLHDSAPublic
{
    SLHDSAParams params;
    ubyte[] pkseed;
    ubyte[] root;
}

struct SLHDSASecret
{
    SLHDSAParams params;
    ubyte[] skseed;
    ubyte[] skprf;
    SLHDSAPublic pub;
}

void slhdsaKeygenFromSeeds(ref SLHDSASecret sk, const ref SLHDSAParams p,
                           const(ubyte)* skseed, const(ubyte)* skprf, const(ubyte)* pkseed)
{
    sk.params = p;
    sk.skseed = skseed[0 .. p.n].dup;
    sk.skprf = skprf[0 .. p.n].dup;
    sk.pub.params = p;
    sk.pub.pkseed = pkseed[0 .. p.n].dup;
    sk.pub.root = new ubyte[p.n];
    xmssGenRoot(sk.pub.root.ptr, sk.skseed.ptr, sk.pub.pkseed.ptr, p);
}

void slhdsaKeygen(ref SLHDSASecret sk, const ref SLHDSAParams p, RandomNumberGenerator rng)
{
    auto a = new ubyte[p.n];
    auto b = new ubyte[p.n];
    auto c = new ubyte[p.n];
    rng.randomize(a.ptr, p.n);
    rng.randomize(b.ptr, p.n);
    rng.randomize(c.ptr, p.n);
    slhdsaKeygenFromSeeds(sk, p, a.ptr, b.ptr, c.ptr);
}

void slhdsaEncodePk(const ref SLHDSAPublic pk, ubyte* outp)
{
    outp[0 .. pk.params.n] = pk.pkseed[];
    outp[pk.params.n .. 2 * pk.params.n] = pk.root[];
}

void slhdsaEncodeSk(const ref SLHDSASecret sk, ubyte* outp)
{
    const n = sk.params.n;
    outp[0 .. n] = sk.skseed[];
    outp[n .. 2 * n] = sk.skprf[];
    slhdsaEncodePk(sk.pub, outp + 2 * n);
}

void slhdsaSignPrefixed(const ref SLHDSASecret sk, const(ubyte)* pre, size_t prelen,
                        const(ubyte)* msg, size_t msglen, const(ubyte)* optrand, ubyte* sig)
{
    auto p = sk.params;
    prfMsg(sig, sk.skprf.ptr, optrand, pre, prelen, msg, msglen, p.n, p.sha2);
    auto digest = new ubyte[p.h_msg_bytes];
    hMsg(sig, sk.pub.pkseed.ptr, sk.pub.root.ptr, pre, prelen, msg, msglen, digest.ptr, p);
    const ulong tree_idx = fromBits(digest.ptr + p.fors_msg_bytes, p.tree_idx_bytes, p.h - p.xmss_h);
    const uint leaf_idx = cast(uint) fromBits(digest.ptr + p.fors_msg_bytes + p.tree_idx_bytes,
                                              p.leaf_idx_bytes, p.xmss_h);
    SLHAdrs fors;
    fors.setType(ADRS_FORS_TREE);
    fors.setTree(tree_idx);
    fors.setKeypair(leaf_idx);
    auto froots = new ubyte[p.n];
    forsSign(sig + p.n, froots.ptr, digest.ptr, sk.skseed.ptr, fors, sk.pub.pkseed.ptr, p);
    htSign(sig + p.n + p.fors_sig_bytes, froots.ptr, sk.skseed.ptr, tree_idx, leaf_idx,
           sk.pub.pkseed.ptr, p);
}

void slhdsaSign(const ref SLHDSASecret sk, const(ubyte)* msg, size_t msglen,
                const(ubyte)* optrand, ubyte* sig)
{
    if (sk.params.slh)
    {
        ubyte[2] pre;
        preparePrefix(pre);
        slhdsaSignPrefixed(sk, pre.ptr, 2, msg, msglen, optrand, sig);
    }
    else
        slhdsaSignPrefixed(sk, null, 0, msg, msglen, optrand, sig);
}

void slhdsaSignDeterministic(const ref SLHDSASecret sk, const(ubyte)* msg, size_t msglen, ubyte* sig)
{
    slhdsaSign(sk, msg, msglen, sk.pub.pkseed.ptr, sig);
}

void slhdsaSign(const ref SLHDSASecret sk, const(ubyte)* msg, size_t msglen,
                RandomNumberGenerator rng, ubyte* sig)
{
    auto rnd = new ubyte[sk.params.n];
    rng.randomize(rnd.ptr, sk.params.n);
    slhdsaSign(sk, msg, msglen, rnd.ptr, sig);
}

bool slhdsaVerifyPrefixed(const ref SLHDSAPublic pk, const(ubyte)* pre, size_t prelen,
                          const(ubyte)* msg, size_t msglen, const(ubyte)* sig, size_t siglen)
{
    auto p = pk.params;
    if (siglen != p.sig_bytes)
        return false;
    auto digest = new ubyte[p.h_msg_bytes];
    hMsg(sig, pk.pkseed.ptr, pk.root.ptr, pre, prelen, msg, msglen, digest.ptr, p);
    const ulong tree_idx = fromBits(digest.ptr + p.fors_msg_bytes, p.tree_idx_bytes, p.h - p.xmss_h);
    const uint leaf_idx = cast(uint) fromBits(digest.ptr + p.fors_msg_bytes + p.tree_idx_bytes,
                                              p.leaf_idx_bytes, p.xmss_h);
    SLHAdrs fors;
    fors.setType(ADRS_FORS_TREE);
    fors.setTree(tree_idx);
    fors.setKeypair(leaf_idx);
    auto froots = new ubyte[p.n];
    forsPkFromSig(froots.ptr, digest.ptr, sig + p.n, fors, pk.pkseed.ptr, p);
    return htVerify(froots.ptr, sig + p.n + p.fors_sig_bytes, pk.root.ptr,
                    tree_idx, leaf_idx, pk.pkseed.ptr, p);
}

bool slhdsaVerify(const ref SLHDSAPublic pk, const(ubyte)* msg, size_t msglen,
                  const(ubyte)* sig, size_t siglen)
{
    if (pk.params.slh)
    {
        ubyte[2] pre;
        preparePrefix(pre);
        return slhdsaVerifyPrefixed(pk, pre.ptr, 2, msg, msglen, sig, siglen);
    }
    return slhdsaVerifyPrefixed(pk, null, 0, msg, msglen, sig, siglen);
}

private immutable ubyte[11] HASH_OID_SHA256 =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
private immutable ubyte[11] HASH_OID_SHA512 =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
private immutable ubyte[11] HASH_OID_SHAKE128 =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b];
private immutable ubyte[11] HASH_OID_SHAKE256 =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c];

private const(ubyte)[] hashSlhOid(in string ph)
{
    if (ph == "SHA-256") return HASH_OID_SHA256;
    if (ph == "SHA-512") return HASH_OID_SHA512;
    if (ph == "SHAKE-128") return HASH_OID_SHAKE128;
    if (ph == "SHAKE-256") return HASH_OID_SHAKE256;
    throw new InvalidArgument("HashSLH-DSA: unknown pre-hash " ~ ph);
}

private ubyte[] hashSlhDigest(in string ph, const(ubyte)* msg, size_t msglen)
{
    if (ph == "SHAKE-128" || ph == "SHAKE-256")
    {
        Unique!XOF x = getXof(ph);
        if (msglen)
            x.update(msg, msglen);
        auto outp = new ubyte[(ph == "SHAKE-128") ? 32 : 64];
        x.output(outp.ptr, outp.length);
        return outp;
    }
    Unique!HashFunction h = retrieveHash(ph).clone();
    if (msglen)
        h.update(msg, msglen);
    auto d = h.finished();
    return d[].dup;
}

ubyte[] hashSlhMPrime(in string ph, const(ubyte)* ctx, size_t ctxlen,
                      const(ubyte)* msg, size_t msglen)
{
    if (ctxlen > 255)
        throw new InvalidArgument("HashSLH-DSA: ctx too long");
    auto oid = hashSlhOid(ph);
    auto digest = hashSlhDigest(ph, msg, msglen);
    auto pre = new ubyte[2 + ctxlen + oid.length];
    pre[0] = 0x01;
    pre[1] = cast(ubyte) ctxlen;
    if (ctxlen)
        pre[2 .. 2 + ctxlen] = ctx[0 .. ctxlen];
    pre[2 + ctxlen .. $] = oid[];
    return pre ~ digest;
}

void slhdsaHashSign(const ref SLHDSASecret sk, in string ph,
                    const(ubyte)* ctx, size_t ctxlen,
                    const(ubyte)* msg, size_t msglen, const(ubyte)* optrand, ubyte* sig)
{
    auto mprime = hashSlhMPrime(ph, ctx, ctxlen, msg, msglen);
    slhdsaSignPrefixed(sk, mprime.ptr, mprime.length, null, 0, optrand, sig);
}

void slhdsaHashSignDeterministic(const ref SLHDSASecret sk, in string ph,
                                 const(ubyte)* ctx, size_t ctxlen,
                                 const(ubyte)* msg, size_t msglen, ubyte* sig)
{
    slhdsaHashSign(sk, ph, ctx, ctxlen, msg, msglen, sk.pub.pkseed.ptr, sig);
}

bool slhdsaHashVerify(const ref SLHDSAPublic pk, in string ph,
                      const(ubyte)* ctx, size_t ctxlen,
                      const(ubyte)* msg, size_t msglen, const(ubyte)* sig, size_t siglen)
{
    auto mprime = hashSlhMPrime(ph, ctx, ctxlen, msg, msglen);
    return slhdsaVerifyPrefixed(pk, mprime.ptr, mprime.length, null, 0, sig, siglen);
}

final class SLHDSAPublicKey : PublicKey
{
public:
    this(in string name, const(ubyte)* bits, size_t len)
    {
        m_pub.params = slhdsaParams(name);
        if (len != m_pub.params.pk_bytes)
            throw new DecodingError("SLH-DSA: unexpected public key length");
        m_pub.pkseed = bits[0 .. m_pub.params.n].dup;
        m_pub.root = bits[m_pub.params.n .. 2 * m_pub.params.n].dup;
    }

    this(const ref SLHDSAPublic pub)
    {
        m_pub.params = pub.params;
        m_pub.pkseed = pub.pkseed.dup;
        m_pub.root = pub.root.dup;
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits)
    {
        this(OIDS.lookup(alg_id.oid), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_pub.params.name; }
    override size_t estimatedStrength() const { return m_pub.params.bitsec; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_pub.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(m_pub.params.pk_bytes);
        slhdsaEncodePk(m_pub, v.ptr);
        return v.move();
    }
    ref const(SLHDSAPublic) raw() const { return m_pub; }

private:
    SLHDSAPublic m_pub;
}

final class SLHDSAPrivateKey : PrivateKey, PublicKey
{
public:
    this(in string name, RandomNumberGenerator rng)
    {
        auto p = slhdsaParams(name);
        slhdsaKeygen(m_sk, p, rng);
    }

    this(in string name, const(ubyte)* bits, size_t len)
    {
        auto p = slhdsaParams(name);
        if (len == p.sk_bytes)
        {
            m_sk.params = p;
            m_sk.skseed = bits[0 .. p.n].dup;
            m_sk.skprf = bits[p.n .. 2 * p.n].dup;
            m_sk.pub.params = p;
            m_sk.pub.pkseed = bits[2 * p.n .. 3 * p.n].dup;
            m_sk.pub.root = bits[3 * p.n .. 4 * p.n].dup;
        }
        else if (len == 3 * p.n)
            slhdsaKeygenFromSeeds(m_sk, p, bits, bits + p.n, bits + 2 * p.n);
        else
            throw new DecodingError("SLH-DSA: unexpected private key length");
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        this(OIDS.lookup(alg_id.oid), key_bits.ptr, key_bits.length);
    }

    override @property string algoName() const { return m_sk.params.name; }
    override size_t estimatedStrength() const { return m_sk.params.bitsec; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(OIDS.lookup(m_sk.params.name), AlgorithmIdentifier.USE_NULL_PARAM);
    }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(m_sk.params.pk_bytes);
        slhdsaEncodePk(m_sk.pub, v.ptr);
        return v.move();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        auto v = SecureVector!ubyte(m_sk.params.sk_bytes);
        slhdsaEncodeSk(m_sk, v.ptr);
        return v.move();
    }
    ref const(SLHDSASecret) raw() const { return m_sk; }
    SLHDSAPublicKey publicKey() const { return new SLHDSAPublicKey(m_sk.pub); }

private:
    SLHDSASecret m_sk;
}

final class SLHDSASignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { m_key = cast(SLHDSAPrivateKey) pkey; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        auto sig = SecureVector!ubyte(m_key.raw().params.sig_bytes);
        slhdsaSignDeterministic(m_key.raw(), msg, msg_len, sig.ptr);
        return sig.move();
    }
private:
    const SLHDSAPrivateKey m_key;
}

final class SLHDSAVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { m_key = cast(SLHDSAPublicKey) pkey; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return slhdsaVerify(m_key.raw(), msg, msg_len, sig, sig_len);
    }
    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("SLH-DSA has no message recovery");
    }
private:
    const SLHDSAPublicKey m_key;
}

bool isSlhOrSphincsName(in string n)
{
    if (n.length >= 14 && n[0 .. 8] == "SLH-DSA-")
        return true;
    return n.length >= 22 && n[0 .. 12] == "SphincsPlus-";
}

static if (BOTAN_HAS_TESTS)
{

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

private struct SphincsKatDrbg
{
    Unique!BlockCipher cipher;
    ulong v0, v1;

    this(const(ubyte)* seed, size_t slen)
    {
        cipher = retrieveBlockCipher("AES-256").clone();
        if (slen != 48)
            throw new InvalidArgument("SPHINCS+ KAT seed must be 48 bytes");
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
        {
            foreach (i; 0 .. plen)
                temp[i] ^= provided[i];
        }
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

} // static if (BOTAN_HAS_TESTS)

static if (BOTAN_HAS_TESTS && !SKIP_SLH_DSA_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import botan.pubkey.pk_algs;
    import botan.hash.hash;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing slh_dsa.d ...");
    size_t fails;

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        foreach (inst; ["SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-128f"])
        {
            Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey(inst, *rng);
            Unique!SLHDSAPublicKey pk = sk.publicKey();
            const ubyte[11] msg = cast(ubyte[11]) "hello world";
            auto sig = new ubyte[sk.raw().params.sig_bytes];
            slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
            if (!slhdsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
            {
                logError(inst, " pairwise verify failed");
                ++fails;
            }
            sig[0] ^= 0xff;
            if (slhdsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
            {
                logError(inst, " mutated signature accepted");
                ++fails;
            }
            auto pub_bits = SecureVector!ubyte(sk.x509SubjectPublicKey()[]);
            Unique!PublicKey via_pk = makePublicKey(sk.algorithmIdentifier(), pub_bits);
            if (!via_pk || via_pk.algoName != inst)
            {
                logError(inst, " factory public key");
                ++fails;
            }
        }
        const OID oid_shake = OIDS.lookup("SLH-DSA-SHAKE-128s");
        if (oid_shake.toString() != "2.16.840.1.101.3.4.3.26")
            ++fails;
        const OID oid_sha2 = OIDS.lookup("SLH-DSA-SHA2-128s");
        if (oid_sha2.toString() != "2.16.840.1.101.3.4.3.20")
            ++fails;
    }

    if (exists("test_data/pubkey/slh_dsa_generic.vec"))
    {
        File vec = File("test_data/pubkey/slh_dsa_generic.vec", "r");
        fails += runTestsBb(vec, "Instance", "Signature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PrivateKey" in m) || !("Msg" in m) || !("Signature" in m))
                    return 0;
                if (m["Instance"].length < 13 || m["Instance"][0 .. 13] != "SLH-DSA-SHAKE")
                    return 0;
                auto skbits = hexDecode(m["PrivateKey"]);
                auto msg = hexDecode(m["Msg"]);
                auto want = hexDecode(m["Signature"]);
                Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey(m["Instance"], skbits.ptr, skbits.length);
                auto sig = new ubyte[sk.raw().params.sig_bytes];
                if ("Nonce" in m && m["Nonce"].length)
                {
                    auto nonce = hexDecode(m["Nonce"]);
                    slhdsaSign(sk.raw(), msg.ptr, msg.length, nonce.ptr, sig.ptr);
                }
                else
                    slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
                if (sig[0 .. sig.length] != want[])
                {
                    logError(m["Instance"], " generic sign mismatch");
                    return 1;
                }
                if (!slhdsaVerify(sk.raw().pub, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(m["Instance"], " generic verify failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/slh_dsa.vec"))
    {
        File vec = File("test_data/pubkey/slh_dsa.vec", "r");
        fails += runTestsBb(vec, "SphincsParameterSet", "HashSigDet", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["SphincsParameterSet"];
                if (inst != "SLH-DSA-SHAKE-128f" && inst != "SLH-DSA-SHA2-128f")
                    return 0;
                if (!("sk" in m) || !("msg" in m) || !("HashSigDet" in m))
                    return 0;
                auto skbits = hexDecode(m["sk"]);
                auto msg = hexDecode(m["msg"]);
                Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey(inst, skbits.ptr, skbits.length);
                auto sig = new ubyte[sk.raw().params.sig_bytes];
                slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
                const string hn = (inst.length >= 13 && inst[8 .. 13] == "SHA2-") ? "SHA-256" : "SHA-3(256)";
                Unique!HashFunction h = retrieveHash(hn).clone();
                h.update(sig.ptr, sig.length);
                auto dig = h.finished();
                auto want = hexDecode(m["HashSigDet"]);
                if (dig[] != want[])
                {
                    logError(inst, " HashSigDet mismatch");
                    return 1;
                }
                return 0;
            });
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey("SLH-DSA-SHAKE-128f", *rng);
        const ubyte[8] msg = [9, 8, 7, 6, 5, 4, 3, 2];
        auto sig = new ubyte[sk.raw().params.sig_bytes];
        slhdsaHashSignDeterministic(sk.raw(), "SHA-256", null, 0, msg.ptr, msg.length, sig.ptr);
        if (!slhdsaHashVerify(sk.raw().pub, "SHA-256", null, 0, msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError("HashSLH-DSA SHA-256 pairwise failed");
            ++fails;
        }
        if (slhdsaVerify(sk.raw().pub, msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError("HashSLH-DSA accepted as pure SLH-DSA");
            ++fails;
        }
        slhdsaHashSignDeterministic(sk.raw(), "SHAKE-256", null, 0, msg.ptr, msg.length, sig.ptr);
        if (!slhdsaHashVerify(sk.raw().pub, "SHAKE-256", null, 0, msg.ptr, msg.length, sig.ptr, sig.length))
        {
            logError("HashSLH-DSA SHAKE-256 pairwise failed");
            ++fails;
        }
    }

    {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        foreach (inst; ["SphincsPlus-shake-128f-r3.1", "SphincsPlus-sha2-128f-r3.1"])
        {
            Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey(inst, *rng);
            Unique!SLHDSAPublicKey pk = sk.publicKey();
            const ubyte[11] msg = cast(ubyte[11]) "hello world";
            auto sig = new ubyte[sk.raw().params.sig_bytes];
            slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
            if (!slhdsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
            {
                logError(inst, " pairwise verify failed");
                ++fails;
            }
            sig[0] ^= 0xff;
            if (slhdsaVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
            {
                logError(inst, " mutated signature accepted");
                ++fails;
            }
            slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
            ubyte[2] slhpre = [0, 0];
            if (slhdsaVerifyPrefixed(pk.raw(), slhpre.ptr, 2,
                                     msg.ptr, msg.length, sig.ptr, sig.length))
            {
                logError(inst, " accepted SLH prefix");
                ++fails;
            }
        }
        const OID oid_sp = OIDS.lookup("SphincsPlus-shake-128f-r3.1");
        if (oid_sp.toString() != "1.3.6.1.4.1.25258.1.12.1.2")
            ++fails;
    }

    if (exists("test_data/pubkey/sphincsplus.vec"))
    {
        File vec = File("test_data/pubkey/sphincsplus.vec", "r");
        fails += runTestsBb(vec, "SphincsParameterSet", "HashSigRand", true,
            (ref HashMap!(string, string) m)
            {
                const inst = m["SphincsParameterSet"];
                if (inst != "SphincsPlus-shake-128f-r3.1" && inst != "SphincsPlus-sha2-128f-r3.1")
                    return 0;
                if (!("sk" in m) || !("msg" in m) || !("seed" in m) || !("HashSigRand" in m))
                    return 0;
                auto skbits = hexDecode(m["sk"]);
                auto msg = hexDecode(m["msg"]);
                auto seed = hexDecode(m["seed"]);
                Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey(inst, skbits.ptr, skbits.length);
                if ("pk" in m)
                {
                    auto want_pk = hexDecode(m["pk"]);
                    auto got_pk = new ubyte[sk.raw().params.pk_bytes];
                    slhdsaEncodePk(sk.raw().pub, got_pk.ptr);
                    if (got_pk[] != want_pk[])
                    {
                        logError(inst, " pk mismatch");
                        return 1;
                    }
                }
                const uint n = sk.raw().params.n;
                auto scratch = new ubyte[3 * n];
                auto nonce = new ubyte[n];
                auto drbg = SphincsKatDrbg(seed.ptr, seed.length);
                drbg.generate(scratch.ptr, scratch.length);
                drbg.generate(nonce.ptr, nonce.length);
                auto sig = new ubyte[sk.raw().params.sig_bytes];
                slhdsaSign(sk.raw(), msg.ptr, msg.length, nonce.ptr, sig.ptr);
                const string hn = (inst.length >= 16 && inst[12 .. 16] == "sha2") ? "SHA-256" : "SHA-3(256)";
                Unique!HashFunction h = retrieveHash(hn).clone();
                h.update(sig.ptr, sig.length);
                auto dig = h.finished();
                auto want = hexDecode(m["HashSigRand"]);
                if (dig[] != want[])
                {
                    logError(inst, " HashSigRand mismatch");
                    return 1;
                }
                if (!slhdsaVerify(sk.raw().pub, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(inst, " HashSigRand verify failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/sphincsplus_fors.vec"))
    {
        import botan.utils.loadstor;
        File vec = File("test_data/pubkey/sphincsplus_fors.vec", "r");
        fails += runTestsBb(vec, "SphincsParameterSet", "HashSig", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Address" in m) || !("SecretSeed" in m) || !("PublicSeed" in m) ||
                    !("PublicKey" in m) || !("Msg" in m) || !("HashSig" in m))
                    return 0;
                const inst = m["SphincsParameterSet"];
                auto p = slhdsaParams(inst);
                auto addr_b = hexDecode(m["Address"]);
                if (addr_b.length != 32)
                    return 1;
                SLHAdrs addr;
                foreach (i; 0 .. 8)
                    addr.w[i] = loadBigEndian!uint(addr_b.ptr, i);
                auto skseed = hexDecode(m["SecretSeed"]);
                auto pkseed = hexDecode(m["PublicSeed"]);
                auto msg = hexDecode(m["Msg"]);
                auto want_pk = hexDecode(m["PublicKey"]);
                auto want_hs = hexDecode(m["HashSig"]);
                auto sig = new ubyte[p.fors_sig_bytes];
                auto pk = new ubyte[p.n];
                forsSign(sig.ptr, pk.ptr, msg.ptr, skseed.ptr, addr, pkseed.ptr, p);
                if (pk[0 .. p.n] != want_pk[])
                {
                    logError(inst, " FORS pk mismatch");
                    return 1;
                }
                const string hn = p.sha2 ? "SHA-256" : "SHA-3(256)";
                Unique!HashFunction h = retrieveHash(hn).clone();
                h.update(sig.ptr, sig.length);
                auto dig = h.finished();
                if (dig[] != want_hs[])
                {
                    logError(inst, " FORS HashSig mismatch");
                    return 1;
                }
                auto pk2 = new ubyte[p.n];
                forsPkFromSig(pk2.ptr, msg.ptr, sig.ptr, addr, pkseed.ptr, p);
                if (pk2[0 .. p.n] != pk[0 .. p.n])
                {
                    logError(inst, " FORS pk from sig mismatch");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/sphincsplus_wots.vec"))
    {
        import botan.utils.loadstor;
        File vec = File("test_data/pubkey/sphincsplus_wots.vec", "r");
        fails += runTestsBb(vec, "SphincsParameterSet", "HashedWotsSig", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Address" in m) || !("SecretSeed" in m) || !("PublicSeed" in m) ||
                    !("HashedWotsPk" in m) || !("Msg" in m) || !("HashedWotsSig" in m))
                    return 0;
                const inst = m["SphincsParameterSet"];
                auto p = slhdsaParams(inst);
                auto addr_b = hexDecode(m["Address"]);
                if (addr_b.length != 32)
                    return 1;
                SLHAdrs addr;
                foreach (i; 0 .. 8)
                    addr.w[i] = loadBigEndian!uint(addr_b.ptr, i);
                const uint leaf_idx = addr.w[5];
                auto skseed = hexDecode(m["SecretSeed"]);
                auto pkseed = hexDecode(m["PublicSeed"]);
                auto msg = hexDecode(m["Msg"]);
                auto want_pk = hexDecode(m["HashedWotsPk"]);
                auto want_hs = hexDecode(m["HashedWotsSig"]);
                auto steps = new uint[p.wots_len];
                chainLengths(steps, msg.ptr, p);
                SLHAdrs leaf_addr = addr.subtree();
                SLHAdrs pk_addr = addr.subtree();
                pk_addr.setType(ADRS_WOTS_PK);
                auto sig = new ubyte[p.wots_bytes];
                auto hashed_pk = new ubyte[p.n];
                wotsSignAndPkgen(sig.ptr, hashed_pk.ptr, skseed.ptr, leaf_idx, true,
                                 steps, leaf_addr, pk_addr, pkseed.ptr, p);
                if (hashed_pk[0 .. p.n] != want_pk[])
                {
                    logError(inst, " WOTS hashed pk mismatch");
                    return 1;
                }
                const string hn = p.sha2 ? "SHA-256" : "SHA-3(256)";
                Unique!HashFunction h = retrieveHash(hn).clone();
                h.update(sig.ptr, sig.length);
                auto dig = h.finished();
                if (dig[] != want_hs[])
                {
                    logError(inst, " WOTS HashSig mismatch");
                    return 1;
                }
                auto hashed_pk2 = new ubyte[p.n];
                wotsPkFromSig(hashed_pk2.ptr, msg.ptr, sig.ptr, addr, pkseed.ptr, p);
                if (hashed_pk2[0 .. p.n] != want_pk[])
                {
                    logError(inst, " WOTS pk from sig mismatch");
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("slh_dsa", {
        Unique!AutoSeededRNG rng = new AutoSeededRNG;
        Unique!SLHDSAPrivateKey sk = new SLHDSAPrivateKey("SLH-DSA-SHAKE-128f", *rng);
        const ubyte[4] msg = [1, 2, 3, 4];
        auto sig = new ubyte[sk.raw().params.sig_bytes];
        slhdsaSignDeterministic(sk.raw(), msg.ptr, msg.length, sig.ptr);
    });

    if (fails)
        logError("slh_dsa failures: ", fails);
    assert(fails == 0);
}
