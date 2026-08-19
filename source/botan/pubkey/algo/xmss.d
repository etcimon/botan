/**
* XMSS (RFC 8391 / NIST SP 800-208) — verify, keygen, and sign
* (no BDS state; auth path is recomputed. HSS-LMS is separate.)
*
* Copyright:
* (C) 2016,2017 Matthias Gierlings
* (C) 2019 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.xmss;

import botan.constants;
static if (BOTAN_HAS_XMSS):

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
import botan.utils.xor_buf;

struct XMSSParams
{
    uint oid;
    string name;
    string hash_name;
    size_t n;
    size_t hash_id_size;
    size_t h;
    size_t len;
    size_t len_1;
    size_t len_2;
    size_t w;
    size_t lg_w;
}

private XMSSParams makeXmss(uint oid, string name, string hash_name,
                            size_t n, size_t hash_id_size, size_t h, size_t len)
{
    XMSSParams p;
    p.oid = oid;
    p.name = name;
    p.hash_name = hash_name;
    p.n = n;
    p.hash_id_size = hash_id_size;
    p.h = h;
    p.len = len;
    p.w = 16;
    p.lg_w = 4;
    p.len_1 = (n * 8) / p.lg_w;
    p.len_2 = len - p.len_1;
    return p;
}

XMSSParams xmssParamsFromOid(uint oid)
{
    switch (oid)
    {
        case 0x00000001: return makeXmss(oid, "XMSS-SHA2_10_256", "SHA-256", 32, 32, 10, 67);
        case 0x00000002: return makeXmss(oid, "XMSS-SHA2_16_256", "SHA-256", 32, 32, 16, 67);
        case 0x00000003: return makeXmss(oid, "XMSS-SHA2_20_256", "SHA-256", 32, 32, 20, 67);
        case 0x00000004: return makeXmss(oid, "XMSS-SHA2_10_512", "SHA-512", 64, 64, 10, 131);
        case 0x00000005: return makeXmss(oid, "XMSS-SHA2_16_512", "SHA-512", 64, 64, 16, 131);
        case 0x00000006: return makeXmss(oid, "XMSS-SHA2_20_512", "SHA-512", 64, 64, 20, 131);
        case 0x00000007: return makeXmss(oid, "XMSS-SHAKE_10_256", "SHAKE-128(256)", 32, 32, 10, 67);
        case 0x00000008: return makeXmss(oid, "XMSS-SHAKE_16_256", "SHAKE-128(256)", 32, 32, 16, 67);
        case 0x00000009: return makeXmss(oid, "XMSS-SHAKE_20_256", "SHAKE-128(256)", 32, 32, 20, 67);
        case 0x0000000a: return makeXmss(oid, "XMSS-SHAKE_10_512", "SHAKE-256(512)", 64, 64, 10, 131);
        case 0x0000000b: return makeXmss(oid, "XMSS-SHAKE_16_512", "SHAKE-256(512)", 64, 64, 16, 131);
        case 0x0000000c: return makeXmss(oid, "XMSS-SHAKE_20_512", "SHAKE-256(512)", 64, 64, 20, 131);
        case 0x0000000d: return makeXmss(oid, "XMSS-SHA2_10_192", "Truncated(SHA-256,192)", 24, 4, 10, 51);
        case 0x0000000e: return makeXmss(oid, "XMSS-SHA2_16_192", "Truncated(SHA-256,192)", 24, 4, 16, 51);
        case 0x0000000f: return makeXmss(oid, "XMSS-SHA2_20_192", "Truncated(SHA-256,192)", 24, 4, 20, 51);
        case 0x00000010: return makeXmss(oid, "XMSS-SHAKE256_10_256", "SHAKE-256(256)", 32, 32, 10, 67);
        case 0x00000011: return makeXmss(oid, "XMSS-SHAKE256_16_256", "SHAKE-256(256)", 32, 32, 16, 67);
        case 0x00000012: return makeXmss(oid, "XMSS-SHAKE256_20_256", "SHAKE-256(256)", 32, 32, 20, 67);
        case 0x00000013: return makeXmss(oid, "XMSS-SHAKE256_10_192", "SHAKE-256(192)", 24, 4, 10, 51);
        case 0x00000014: return makeXmss(oid, "XMSS-SHAKE256_16_192", "SHAKE-256(192)", 24, 4, 16, 51);
        case 0x00000015: return makeXmss(oid, "XMSS-SHAKE256_20_192", "SHAKE-256(192)", 24, 4, 20, 51);
        default: throw new InvalidArgument("Unknown XMSS algorithm id");
    }
}

XMSSParams xmssParamsFromName(in string name)
{
    string n = name;
    if (n.length >= 5 && n[0 .. 5] == "XMSS-")
        n = n[5 .. $];
    if (n == "SHA2_10_256") return xmssParamsFromOid(1);
    if (n == "SHA2_16_256") return xmssParamsFromOid(2);
    if (n == "SHA2_20_256") return xmssParamsFromOid(3);
    if (n == "SHA2_10_512") return xmssParamsFromOid(4);
    if (n == "SHA2_16_512") return xmssParamsFromOid(5);
    if (n == "SHA2_20_512") return xmssParamsFromOid(6);
    if (n == "SHAKE_10_256") return xmssParamsFromOid(7);
    if (n == "SHAKE_16_256") return xmssParamsFromOid(8);
    if (n == "SHAKE_20_256") return xmssParamsFromOid(9);
    if (n == "SHAKE_10_512") return xmssParamsFromOid(10);
    if (n == "SHAKE_16_512") return xmssParamsFromOid(11);
    if (n == "SHAKE_20_512") return xmssParamsFromOid(12);
    if (n == "SHA2_10_192") return xmssParamsFromOid(13);
    if (n == "SHA2_16_192") return xmssParamsFromOid(14);
    if (n == "SHA2_20_192") return xmssParamsFromOid(15);
    if (n == "SHAKE256_10_256") return xmssParamsFromOid(16);
    if (n == "SHAKE256_16_256") return xmssParamsFromOid(17);
    if (n == "SHAKE256_20_256") return xmssParamsFromOid(18);
    if (n == "SHAKE256_10_192") return xmssParamsFromOid(19);
    if (n == "SHAKE256_16_192") return xmssParamsFromOid(20);
    if (n == "SHAKE256_20_192") return xmssParamsFromOid(21);
    throw new InvalidArgument("Unknown XMSS algorithm param '" ~ name ~ "'");
}

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

struct XMSSAdrs
{
    ubyte[32] d;

    void setType(uint t)
    {
        d[15] = cast(ubyte) t;
        d[16 .. 32] = 0;
    }

    void setKeyMode(ubyte mode) { d[31] = mode; }
    void setOts(uint v) { storeBe32(d.ptr + 16, v); }
    void setLtree(uint v) { storeBe32(d.ptr + 16, v); }
    void setChain(uint v) { storeBe32(d.ptr + 20, v); }
    void setHeight(uint v) { storeBe32(d.ptr + 20, v); }
    uint getHeight() const { return loadBe32(d.ptr + 20); }
    void setHash(uint v) { storeBe32(d.ptr + 24, v); }
    void setIndex(uint v) { storeBe32(d.ptr + 24, v); }
    uint getIndex() const { return loadBe32(d.ptr + 24); }
}

private void xmssKeyedHash(HashFunction h, const(ubyte)* pad, size_t padlen, ubyte id,
                           const(ubyte)* key, size_t klen,
                           const(ubyte)* data, size_t dlen,
                           ubyte* outp, size_t n)
{
    h.clear();
    if (padlen)
        h.update(pad, padlen);
    h.update(&id, 1);
    h.update(key, klen);
    h.update(data, dlen);
    auto dig = h.finished();
    copyMem(outp, dig.ptr, n);
}

private void xmssPrf(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                     const(ubyte)* seed, const ref XMSSAdrs adrs, ubyte* outp)
{
    xmssKeyedHash(h, pad, padlen, 0x03, seed, p.n, adrs.d.ptr, 32, outp, p.n);
}

private void xmssF(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                   const(ubyte)* key, const(ubyte)* data, ubyte* outp)
{
    xmssKeyedHash(h, pad, padlen, 0x00, key, p.n, data, p.n, outp, p.n);
}

private void xmssH(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                   const(ubyte)* key, const(ubyte)* data, size_t dlen, ubyte* outp)
{
    xmssKeyedHash(h, pad, padlen, 0x01, key, p.n, data, dlen, outp, p.n);
}

private void xmssHMsg(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                      const(ubyte)* r, const(ubyte)* root,
                      const(ubyte)* idx_bytes, const(ubyte)* msg, size_t msglen, ubyte* outp)
{
    h.clear();
    if (padlen)
        h.update(pad, padlen);
    ubyte id = 0x02;
    h.update(&id, 1);
    h.update(r, p.n);
    h.update(root, p.n);
    h.update(idx_bytes, p.n);
    if (msglen)
        h.update(msg, msglen);
    auto dig = h.finished();
    copyMem(outp, dig.ptr, p.n);
}

private void xmssChain(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                       ubyte* x, ubyte* tmp, ubyte* prf, size_t start, size_t steps,
                       XMSSAdrs adrs, const(ubyte)* seed)
{
    copyMem(tmp, x, p.n);
    foreach (i; start .. start + steps)
    {
        if (i >= p.w)
            break;
        adrs.setHash(cast(uint) i);
        adrs.setKeyMode(1);
        xmssPrf(h, p, pad, padlen, seed, adrs, prf);
        xorBuf(tmp, prf, p.n);
        adrs.setKeyMode(0);
        xmssPrf(h, p, pad, padlen, seed, adrs, prf);
        xmssF(h, p, pad, padlen, prf, tmp, tmp);
    }
    copyMem(x, tmp, p.n);
}

private void xmssBaseW(const ref XMSSParams p, const(ubyte)* msg, ubyte[] outp)
{
    size_t inp;
    size_t total;
    size_t bits;
    const ubyte mask = cast(ubyte)(p.w - 1);
    foreach (i; 0 .. p.len_1)
    {
        if (bits == 0)
        {
            total = msg[inp++];
            bits = 8;
        }
        bits -= p.lg_w;
        outp[i] = cast(ubyte)((total >> bits) & mask);
    }
    size_t csum;
    foreach (i; 0 .. p.len_1)
        csum += p.w - 1 - outp[i];
    foreach (i; 0 .. p.len_2)
    {
        const size_t shift = p.lg_w * (p.len_2 - 1 - i);
        outp[p.len_1 + i] = cast(ubyte)((csum >> shift) & mask);
    }
}

private void xmssRandTreeHash(HashFunction h, const ref XMSSParams p,
                              const(ubyte)* pad, size_t padlen,
                              ubyte* outp, const(ubyte)* left, const(ubyte)* right,
                              XMSSAdrs adrs, const(ubyte)* seed,
                              ubyte* key, ubyte* bl, ubyte* br, ubyte* concat)
{
    adrs.setKeyMode(0);
    xmssPrf(h, p, pad, padlen, seed, adrs, key);
    adrs.setKeyMode(1);
    xmssPrf(h, p, pad, padlen, seed, adrs, bl);
    adrs.setKeyMode(2);
    xmssPrf(h, p, pad, padlen, seed, adrs, br);
    foreach (i; 0 .. p.n)
    {
        concat[i] = left[i] ^ bl[i];
        concat[i + p.n] = right[i] ^ br[i];
    }
    xmssH(h, p, pad, padlen, key, concat, 2 * p.n, outp);
}

private void xmssLTree(HashFunction h, const ref XMSSParams p,
                       const(ubyte)* pad, size_t padlen,
                       ubyte* outp, ubyte[][] pk,
                       XMSSAdrs adrs, const(ubyte)* seed,
                       ubyte* key, ubyte* bl, ubyte* br, ubyte* concat)
{
    size_t l = p.len;
    adrs.setHeight(0);
    while (l > 1)
    {
        foreach (i; 0 .. (l >> 1))
        {
            adrs.setIndex(cast(uint) i);
            xmssRandTreeHash(h, p, pad, padlen, pk[i].ptr, pk[2 * i].ptr, pk[2 * i + 1].ptr,
                             adrs, seed, key, bl, br, concat);
        }
        if (l & 1)
            pk[l >> 1][] = pk[l - 1][];
        l = (l >> 1) + (l & 1);
        adrs.setHeight(adrs.getHeight() + 1);
    }
    copyMem(outp, pk[0].ptr, p.n);
}

struct XMSSPublic
{
    XMSSParams params;
    ubyte[] root;
    ubyte[] seed;
}

bool xmssVerify(const ref XMSSPublic pk, const(ubyte)* msg, size_t msglen,
                const(ubyte)* sig, size_t siglen)
{
    const auto p = pk.params;
    const size_t want = 4 + (p.len + p.h + 1) * p.n;
    if (siglen != want)
        return false;
    uint idx = loadBe32(sig);
    if (idx >= (uint(1) << p.h))
        return false;
    const(ubyte)* r = sig + 4;
    const(ubyte)* ots = r + p.n;
    const(ubyte)* auth = ots + p.len * p.n;

    Unique!HashFunction hf = retrieveHash(p.hash_name).clone();
    auto pad = new ubyte[p.hash_id_size - 1];
    auto tmp = new ubyte[p.n];
    auto prf = new ubyte[p.n];
    auto key = new ubyte[p.n];
    auto bl = new ubyte[p.n];
    auto br = new ubyte[p.n];
    auto concat = new ubyte[2 * p.n];

    auto idx_bytes = new ubyte[p.n];
    storeBe32(idx_bytes.ptr + p.n - 4, idx);

    auto digest = new ubyte[p.n];
    xmssHMsg(hf, p, pad.ptr, pad.length, r, pk.root.ptr, idx_bytes.ptr, msg, msglen, digest.ptr);

    auto digits = new ubyte[p.len];
    xmssBaseW(p, digest.ptr, digits);

    auto wots_pk = new ubyte[][p.len];
    XMSSAdrs ots_adrs;
    ots_adrs.setType(0);
    ots_adrs.setOts(idx);
    foreach (i; 0 .. p.len)
    {
        wots_pk[i] = ots[i * p.n .. (i + 1) * p.n].dup;
        ots_adrs.setChain(cast(uint) i);
        const size_t start = digits[i];
        xmssChain(hf, p, pad.ptr, pad.length, wots_pk[i].ptr, tmp.ptr, prf.ptr,
                  start, p.w - 1 - start, ots_adrs, pk.seed.ptr);
    }

    XMSSAdrs ltree;
    ltree.setType(1);
    ltree.setLtree(idx);
    auto leaf = new ubyte[p.n];
    xmssLTree(hf, p, pad.ptr, pad.length, leaf.ptr, wots_pk, ltree, pk.seed.ptr,
              key.ptr, bl.ptr, br.ptr, concat.ptr);

    XMSSAdrs tree;
    tree.setType(2);
    tree.setIndex(idx);
    auto node = leaf.dup;
    auto next = new ubyte[p.n];
    foreach (k; 0 .. p.h)
    {
        tree.setHeight(cast(uint) k);
        const(ubyte)* path = auth + k * p.n;
        if (((idx / (uint(1) << k)) & 1) == 0)
        {
            tree.setIndex(tree.getIndex() >> 1);
            xmssRandTreeHash(hf, p, pad.ptr, pad.length, next.ptr, node.ptr, path,
                             tree, pk.seed.ptr, key.ptr, bl.ptr, br.ptr, concat.ptr);
        }
        else
        {
            tree.setIndex((tree.getIndex() - 1) >> 1);
            xmssRandTreeHash(hf, p, pad.ptr, pad.length, next.ptr, path, node.ptr,
                             tree, pk.seed.ptr, key.ptr, bl.ptr, br.ptr, concat.ptr);
        }
        node[] = next[];
    }
    return node[] == pk.root[];
}

private AlgorithmIdentifier xmssAlgId()
{
    Vector!ubyte empty;
    return AlgorithmIdentifier(OIDS.lookup("XMSS"), empty);
}

/**
* XMSS public key (RFC 8391)
*/
final class XMSSPublicKey : PublicKey
{
public:
    /**
    * Decode an encoded public key (OID || root || SEED)
    * Params:
    *  bits = encoded public key
    *  len = length of bits
    */
    this(const(ubyte)* bits, size_t len)
    {
        if (len < 4)
            throw new DecodingError("XMSS: public key too short");
        const uint oid = loadBe32(bits);
        m_pub.params = xmssParamsFromOid(oid);
        if (len != 4 + 2 * m_pub.params.n)
            throw new DecodingError("XMSS: unexpected public key length");
        m_pub.root = bits[4 .. 4 + m_pub.params.n].dup;
        m_pub.seed = bits[4 + m_pub.params.n .. 4 + 2 * m_pub.params.n].dup;
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

    /// Copy from an expanded public key.
    this(const ref XMSSPublic pub)
    {
        m_pub.params = pub.params;
        m_pub.root = pub.root.dup;
        m_pub.seed = pub.seed.dup;
    }

    override @property string algoName() const { return "XMSS"; }
    override size_t estimatedStrength() const { return 8 * m_pub.params.n; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const { return xmssAlgId(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto v = Vector!ubyte(4 + 2 * m_pub.params.n);
        storeBe32(v.ptr, m_pub.params.oid);
        v[4 .. 4 + m_pub.params.n] = m_pub.root[];
        v[4 + m_pub.params.n .. 4 + 2 * m_pub.params.n] = m_pub.seed[];
        return v.move();
    }
    /// Expanded public key (root, SEED).
    ref const(XMSSPublic) raw() const { return m_pub; }

private:
    XMSSPublic m_pub;
}

enum ubyte XMSS_WOTS_BOTAN2X = 1;
enum ubyte XMSS_WOTS_NIST = 2;

struct XMSSSecret
{
    XMSSPublic pub;
    ubyte[] prf;
    ubyte[] sk_seed;
    uint unused;
    ubyte wots_method = XMSS_WOTS_NIST;
}

private void xmssWotsSk(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                        const(ubyte)* pub_seed, const(ubyte)* sk_seed, XMSSAdrs adrs,
                        ubyte wots_method, ubyte[][] sk)
{
    if (wots_method == XMSS_WOTS_NIST)
    {
        auto data = new ubyte[p.n + 32];
        copyMem(data.ptr, pub_seed, p.n);
        foreach (i; 0 .. p.len)
        {
            adrs.setChain(cast(uint) i);
            copyMem(data.ptr + p.n, adrs.d.ptr, 32);
            sk[i] = new ubyte[p.n];
            xmssKeyedHash(h, pad, padlen, 0x04, sk_seed, p.n, data.ptr, p.n + 32, sk[i].ptr, p.n);
        }
    }
    else
    {
        auto r = new ubyte[p.n];
        xmssPrf(h, p, pad, padlen, sk_seed, adrs, r.ptr);
        auto idxb = new ubyte[32];
        foreach (i; 0 .. p.len)
        {
            storeBe32(idxb.ptr + 28, cast(uint) i);
            sk[i] = new ubyte[p.n];
            xmssKeyedHash(h, pad, padlen, 0x03, r.ptr, p.n, idxb.ptr, 32, sk[i].ptr, p.n);
        }
    }
}

private void xmssWotsPkFromSk(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                              ubyte[][] sk, XMSSAdrs adrs, const(ubyte)* pub_seed,
                              ubyte* tmp, ubyte* prf)
{
    foreach (i; 0 .. p.len)
    {
        adrs.setChain(cast(uint) i);
        xmssChain(h, p, pad, padlen, sk[i].ptr, tmp, prf, 0, p.w - 1, adrs, pub_seed);
    }
}

private void xmssWotsSign(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                          ubyte[][] sk, const(ubyte)* digest, XMSSAdrs adrs, const(ubyte)* pub_seed,
                          ubyte* tmp, ubyte* prf)
{
    auto digits = new ubyte[p.len];
    xmssBaseW(p, digest, digits);
    foreach (i; 0 .. p.len)
    {
        adrs.setChain(cast(uint) i);
        xmssChain(h, p, pad, padlen, sk[i].ptr, tmp, prf, 0, digits[i], adrs, pub_seed);
    }
}

private void xmssTreeHash(HashFunction h, const ref XMSSParams p, const(ubyte)* pad, size_t padlen,
                          ubyte* outp, size_t start_idx, size_t height,
                          const(ubyte)* pub_seed, const(ubyte)* sk_seed, ubyte wots_method)
{
    auto tmp = new ubyte[p.n];
    auto prf = new ubyte[p.n];
    auto key = new ubyte[p.n];
    auto bl = new ubyte[p.n];
    auto br = new ubyte[p.n];
    auto concat = new ubyte[2 * p.n];
    auto leaf = new ubyte[p.n];
    auto nodes = new ubyte[][height + 1];
    auto levels = new ubyte[height + 1];
    foreach (i; 0 .. height + 1)
        nodes[i] = new ubyte[p.n];
    ubyte level;
    const size_t last = start_idx + (size_t(1) << height);
    foreach (i; start_idx .. last)
    {
        XMSSAdrs ots;
        ots.setType(0);
        ots.setOts(cast(uint) i);
        auto wots = new ubyte[][p.len];
        xmssWotsSk(h, p, pad, padlen, pub_seed, sk_seed, ots, wots_method, wots);
        xmssWotsPkFromSk(h, p, pad, padlen, wots, ots, pub_seed, tmp.ptr, prf.ptr);
        XMSSAdrs ltree;
        ltree.setType(1);
        ltree.setLtree(cast(uint) i);
        xmssLTree(h, p, pad, padlen, leaf.ptr, wots, ltree, pub_seed, key.ptr, bl.ptr, br.ptr, concat.ptr);
        nodes[level][] = leaf[];
        levels[level] = 0;
        XMSSAdrs tree;
        tree.setType(2);
        tree.setHeight(0);
        tree.setIndex(cast(uint) i);
        while (level > 0 && levels[level] == levels[level - 1])
        {
            tree.setIndex((tree.getIndex() - 1) >> 1);
            xmssRandTreeHash(h, p, pad, padlen, nodes[level - 1].ptr, nodes[level - 1].ptr, nodes[level].ptr,
                             tree, pub_seed, key.ptr, bl.ptr, br.ptr, concat.ptr);
            levels[level - 1]++;
            --level;
            tree.setHeight(tree.getHeight() + 1);
        }
        ++level;
    }
    copyMem(outp, nodes[level - 1].ptr, p.n);
}

void xmssKeygenFromSeeds(ref XMSSSecret sk, const ref XMSSParams p,
                         const(ubyte)* sk_seed, const(ubyte)* prf, const(ubyte)* pub_seed)
{
    sk.pub.params = p;
    sk.pub.seed = pub_seed[0 .. p.n].dup;
    sk.sk_seed = sk_seed[0 .. p.n].dup;
    sk.prf = prf[0 .. p.n].dup;
    sk.unused = 0;
    sk.wots_method = XMSS_WOTS_NIST;
    Unique!HashFunction hf = retrieveHash(p.hash_name).clone();
    auto pad = new ubyte[p.hash_id_size - 1];
    sk.pub.root = new ubyte[p.n];
    xmssTreeHash(hf, p, pad.ptr, pad.length, sk.pub.root.ptr, 0, p.h,
                 sk.pub.seed.ptr, sk.sk_seed.ptr, sk.wots_method);
}

void xmssKeygen(ref XMSSSecret sk, const ref XMSSParams p, RandomNumberGenerator rng)
{
    auto a = new ubyte[p.n];
    auto b = new ubyte[p.n];
    auto c = new ubyte[p.n];
    rng.randomize(c.ptr, p.n);
    rng.randomize(b.ptr, p.n);
    rng.randomize(a.ptr, p.n);
    xmssKeygenFromSeeds(sk, p, a.ptr, b.ptr, c.ptr);
}

size_t xmssSigBytes(const ref XMSSParams p) { return 4 + (p.len + p.h + 1) * p.n; }
size_t xmssRawSkBytes(const ref XMSSParams p) { return 4 + 2 * p.n + 4 + 2 * p.n + 1; }

void xmssSign(ref XMSSSecret sk, const(ubyte)* msg, size_t msglen, ubyte* sig)
{
    const auto p = sk.pub.params;
    if (sk.unused >= (uint(1) << p.h))
        throw new InvalidState("XMSS private key exhausted");
    const uint idx = sk.unused;
    ++sk.unused;

    Unique!HashFunction hf = retrieveHash(p.hash_name).clone();
    auto pad = new ubyte[p.hash_id_size - 1];
    auto tmp = new ubyte[p.n];
    auto prf = new ubyte[p.n];

    auto idx32 = new ubyte[32];
    storeBe32(idx32.ptr + 28, idx);
    xmssKeyedHash(hf, pad.ptr, pad.length, 0x03, sk.prf.ptr, p.n, idx32.ptr, 32, sig + 4, p.n);

    auto idx_n = new ubyte[p.n];
    storeBe32(idx_n.ptr + p.n - 4, idx);
    auto digest = new ubyte[p.n];
    xmssHMsg(hf, p, pad.ptr, pad.length, sig + 4, sk.pub.root.ptr, idx_n.ptr, msg, msglen, digest.ptr);

    storeBe32(sig, idx);
    auto wots = new ubyte[][p.len];
    XMSSAdrs ots;
    ots.setType(0);
    ots.setOts(idx);
    xmssWotsSk(hf, p, pad.ptr, pad.length, sk.pub.seed.ptr, sk.sk_seed.ptr, ots, sk.wots_method, wots);
    xmssWotsSign(hf, p, pad.ptr, pad.length, wots, digest.ptr, ots, sk.pub.seed.ptr, tmp.ptr, prf.ptr);
    foreach (i; 0 .. p.len)
        copyMem(sig + 4 + p.n + i * p.n, wots[i].ptr, p.n);

    ubyte* auth = sig + 4 + p.n + p.len * p.n;
    foreach (j; 0 .. p.h)
    {
        const size_t k = (idx / (size_t(1) << j)) ^ 1;
        xmssTreeHash(hf, p, pad.ptr, pad.length, auth + j * p.n, k * (size_t(1) << j), j,
                     sk.pub.seed.ptr, sk.sk_seed.ptr, sk.wots_method);
    }
}

/**
* XMSS private key (RFC 8391)
*/
final class XMSSPrivateKey : PrivateKey, PublicKey
{
public:
    /**
    * Generate a random key
    * Params:
    *  name = parameter set ("XMSS-SHA2_10_256", …)
    *  rng = random number generator
    */
    this(in string name, RandomNumberGenerator rng)
    {
        auto p = xmssParamsFromName(name);
        xmssKeygen(m_sk, p, rng);
    }

    /**
    * Decode an encoded private key
    * Params:
    *  bits = OID || public || unused || PRF || SK_SEED
    *  len = length of bits
    */
    this(const(ubyte)* bits, size_t len)
    {
        if (len < 4)
            throw new DecodingError("XMSS: private key too short");
        const uint oid = loadBe32(bits);
        auto p = xmssParamsFromOid(oid);
        const size_t pub_len = 4 + 2 * p.n;
        const size_t min_len = pub_len + 4 + 2 * p.n;
        if (len != min_len && len != min_len + 1)
            throw new DecodingError("XMSS: unexpected private key length");
        m_sk.pub.params = p;
        m_sk.pub.root = bits[4 .. 4 + p.n].dup;
        m_sk.pub.seed = bits[4 + p.n .. pub_len].dup;
        m_sk.unused = loadBe32(bits + pub_len);
        m_sk.prf = bits[pub_len + 4 .. pub_len + 4 + p.n].dup;
        m_sk.sk_seed = bits[pub_len + 4 + p.n .. pub_len + 4 + 2 * p.n].dup;
        if (len == min_len + 1)
            m_sk.wots_method = bits[min_len];
        else
            m_sk.wots_method = XMSS_WOTS_BOTAN2X;
    }

    /**
    * Decode PKCS #8
    * Params:
    *  key_bits = encoded private key
    */
    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits, RandomNumberGenerator)
    {
        this(key_bits.ptr, key_bits.length);
    }

    /// Copy from an expanded secret key.
    this(const ref XMSSSecret sk)
    {
        m_sk.pub.params = sk.pub.params;
        m_sk.pub.root = sk.pub.root.dup;
        m_sk.pub.seed = sk.pub.seed.dup;
        m_sk.prf = sk.prf.dup;
        m_sk.sk_seed = sk.sk_seed.dup;
        m_sk.unused = sk.unused;
        m_sk.wots_method = sk.wots_method;
    }

    override @property string algoName() const { return "XMSS"; }
    override size_t estimatedStrength() const { return 8 * m_sk.pub.params.n; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override AlgorithmIdentifier algorithmIdentifier() const { return xmssAlgId(); }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        Unique!XMSSPublicKey pk = new XMSSPublicKey(m_sk.pub);
        return pk.x509SubjectPublicKey();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        const auto p = m_sk.pub.params;
        auto v = SecureVector!ubyte(xmssRawSkBytes(p));
        storeBe32(v.ptr, p.oid);
        v[4 .. 4 + p.n] = m_sk.pub.root[];
        v[4 + p.n .. 4 + 2 * p.n] = m_sk.pub.seed[];
        storeBe32(v.ptr + 4 + 2 * p.n, m_sk.unused);
        v[4 + 2 * p.n + 4 .. 4 + 3 * p.n + 4] = m_sk.prf[];
        v[4 + 3 * p.n + 4 .. 4 + 4 * p.n + 4] = m_sk.sk_seed[];
        v[4 + 4 * p.n + 4] = m_sk.wots_method;
        return v.move();
    }
    ref XMSSSecret raw() { return m_sk; }
    ref const(XMSSSecret) raw() const { return m_sk; }
    XMSSPublicKey publicKey() const { return new XMSSPublicKey(m_sk.pub); }

private:
    XMSSSecret m_sk;
}

final class XMSSSignatureOperation : Signature
{
public:
    this(in PrivateKey pkey) { m_key = cast(XMSSPrivateKey) pkey; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override SecureVector!ubyte sign(const(ubyte)* msg, size_t msg_len, RandomNumberGenerator)
    {
        auto sig = SecureVector!ubyte(xmssSigBytes(m_key.raw().pub.params));
        xmssSign(m_key.raw(), msg, msg_len, sig.ptr);
        return sig.move();
    }
private:
    XMSSPrivateKey m_key;
}

final class XMSSVerificationOperation : Verification
{
public:
    this(in PublicKey pkey) { m_key = cast(XMSSPublicKey) pkey; }
    override size_t maxInputBits() const { return size_t.max / 2; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override bool withRecovery() const { return false; }
    override bool verify(const(ubyte)* msg, size_t msg_len, const(ubyte)* sig, size_t sig_len)
    {
        return xmssVerify(m_key.raw(), msg, msg_len, sig, sig_len);
    }
    override SecureVector!ubyte verifyMr(const(ubyte)*, size_t)
    {
        throw new InvalidState("XMSS has no message recovery");
    }
private:
    const XMSSPublicKey m_key;
}

static if (BOTAN_HAS_TESTS && !SKIP_XMSS_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.pubkey.pk_algs;
    import botan.pubkey.pubkey;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;

    auto state = globalState();
    logDebug("Testing xmss.d ...");
    size_t fails;

    const OID oid = OIDS.lookup("XMSS");
    if (oid.toString() != "0.4.0.127.0.15.1.1.13.0")
        ++fails;

    if (exists("test_data/pubkey/xmss_verify.vec"))
    {
        File vec = File("test_data/pubkey/xmss_verify.vec", "r");
        fails += runTestsBb(vec, "Params", "Signature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PublicKey" in m) || !("Signature" in m))
                    return 0;
                auto pkb = hexDecode(m["PublicKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto sig = hexDecode(m["Signature"]);
                Unique!XMSSPublicKey pk = new XMSSPublicKey(pkb.ptr, pkb.length);
                if (!xmssVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(m["Params"], " verify failed");
                    return 1;
                }
                auto pub_bits = SecureVector!ubyte(pk.x509SubjectPublicKey()[]);
                Unique!PublicKey via_pk = makePublicKey(pk.algorithmIdentifier(), pub_bits);
                if (!via_pk || via_pk.algoName != "XMSS")
                {
                    logError(m["Params"], " factory public key");
                    return 1;
                }
                auto v = PKVerifier(via_pk, "Raw");
                if (!v.verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(m["Params"], " PKVerifier failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/xmss_invalid.vec"))
    {
        File vec = File("test_data/pubkey/xmss_invalid.vec", "r");
        fails += runTestsBb(vec, "Params", "InvalidSignature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PublicKey" in m) || !("InvalidSignature" in m))
                    return 0;
                auto pkb = hexDecode(m["PublicKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto sig = hexDecode(m["InvalidSignature"]);
                Unique!XMSSPublicKey pk = new XMSSPublicKey(pkb.ptr, pkb.length);
                if (xmssVerify(pk.raw(), msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(m["Params"], " invalid signature accepted");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/xmss_sig.vec"))
    {
        File vec = File("test_data/pubkey/xmss_sig.vec", "r");
        fails += runTestsBb(vec, "Params", "Signature", true,
            (ref HashMap!(string, string) m)
            {
                if (!("PrivateKey" in m) || !("Signature" in m))
                    return 0;
                if (m["Params"] != "SHA2_10_256")
                    return 0;
                auto skb = hexDecode(m["PrivateKey"]);
                auto msg = ("Msg" in m) ? hexDecode(m["Msg"]) : hexDecode("");
                auto want = hexDecode(m["Signature"]);
                Unique!XMSSPrivateKey sk = new XMSSPrivateKey(skb.ptr, skb.length);
                auto sig = new ubyte[xmssSigBytes(sk.raw().pub.params)];
                xmssSign(sk.raw(), msg.ptr, msg.length, sig.ptr);
                if (sig[0 .. sig.length] != want[])
                {
                    logError(m["Params"], " sign mismatch");
                    return 1;
                }
                if (!xmssVerify(sk.raw().pub, msg.ptr, msg.length, sig.ptr, sig.length))
                {
                    logError(m["Params"], " signed verify failed");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/xmss_keygen_reference.vec"))
    {
        File vec = File("test_data/pubkey/xmss_keygen_reference.vec", "r");
        fails += runTestsBb(vec, "Params", "PublicKey", true,
            (ref HashMap!(string, string) m)
            {
                if (!("SecretSeed" in m) || !("PublicSeed" in m) || !("SecretPrf" in m) || !("PublicKey" in m))
                    return 0;
                if (m["Params"] != "XMSS-SHA2_10_256" && m["Params"] != "SHA2_10_256")
                    return 0;
                auto p = xmssParamsFromName(m["Params"]);
                auto sks = hexDecode(m["SecretSeed"]);
                auto pubs = hexDecode(m["PublicSeed"]);
                auto prf = hexDecode(m["SecretPrf"]);
                XMSSSecret sk;
                xmssKeygenFromSeeds(sk, p, sks.ptr, prf.ptr, pubs.ptr);
                Unique!XMSSPublicKey pk = new XMSSPublicKey(sk.pub);
                auto got = pk.x509SubjectPublicKey();
                auto want = hexDecode(m["PublicKey"]);
                if (got[] != want[])
                {
                    logError(m["Params"], " keygen root mismatch");
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("xmss", {
        auto pkb = hexDecode("00000001128da06431c474d9740fb8bc401da6c3a6ed07d9e6be4304737e2df2cdb3ccc018cccf27ac6fbcb6900d2547f49c39f60adbbd79b4746a7d0d5232655d9f11a9");
        Unique!XMSSPublicKey pk = new XMSSPublicKey(pkb.ptr, pkb.length);
        auto bits = pk.x509SubjectPublicKey();
        if (bits.length != 4 + 2 * 32)
            throw new Exception("xmss leftover probe failed");
    });

    if (fails)
        logError("xmss failures: ", fails);
    assert(fails == 0);
}
