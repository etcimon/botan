/**
* Hybrid KEM — ML-KEM-768 concatenated with X25519
* Shared secret is SHA-3-256(ss_mlkem || ss_x25519).
*
* Copyright:
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.hybrid_kem;

import botan.constants;
static if (BOTAN_HAS_HYBRID_KEM):

import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.pubkey.algo.curve25519;
import botan.pubkey.algo.ml_kem;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;

enum string HYBRID_NAME = "Hybrid-ML-KEM-768-X25519";
enum size_t X25519_LEN = 32;
enum size_t HYBRID_SS = 32;

private size_t mlkem768Pk() { auto p = mlkemParams(MLKEMMode.Kem768); return mlkemPkBytes(p); }
private size_t mlkem768Ct() { auto p = mlkemParams(MLKEMMode.Kem768); return mlkemCtBytes(p); }
size_t hybridCtBytes() { return mlkem768Ct() + X25519_LEN; }

private void hybridCombine(const(ubyte)* a, const(ubyte)* b, ubyte* outp)
{
    Unique!HashFunction h = retrieveHash("SHA-3(256)").clone();
    h.update(a, 32);
    h.update(b, 32);
    auto d = h.finished();
    copyMem(outp, d.ptr, HYBRID_SS);
}

private AlgorithmIdentifier hybridAlgId()
{
    Vector!ubyte empty;
    return AlgorithmIdentifier(OIDS.lookup(HYBRID_NAME), empty);
}

final class HybridPublicKey : PublicKey
{
public:
    this(MLKEMPublicKey ml, Vector!ubyte x)
    {
        m_mlkem = ml;
        m_x25519 = x.move();
    }

    this(in AlgorithmIdentifier, const ref SecureVector!ubyte key_bits)
    {
        const size_t mlen = mlkem768Pk();
        if (key_bits.length != mlen + X25519_LEN)
            throw new DecodingError("Hybrid KEM: unexpected public key length");
        m_mlkem = new MLKEMPublicKey(MLKEMMode.Kem768, key_bits.ptr, mlen);
        m_x25519 = Vector!ubyte(key_bits[mlen .. $]);
    }

    override @property string algoName() const { return HYBRID_NAME; }
    override size_t estimatedStrength() const { return 192; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return hybridAlgId(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        auto mk = m_mlkem.x509SubjectPublicKey();
        auto v = Vector!ubyte(mk.length + X25519_LEN);
        v[0 .. mk.length] = mk[];
        v[mk.length .. $] = m_x25519[];
        return v.move();
    }

    void encaps(RandomNumberGenerator rng, ubyte* ss, ubyte* ct)
    {
        auto ss1 = new ubyte[32];
        mlkemEncaps(m_mlkem.raw(), rng, ss1.ptr, ct);
        auto eph = Curve25519PrivateKey(rng);
        auto eph_pub = eph.publicValue();
        copyMem(ct + mlkem768Ct(), eph_pub.ptr, X25519_LEN);
        auto ss2 = eph.agree(m_x25519.ptr, m_x25519.length);
        hybridCombine(ss1.ptr, ss2.ptr, ss);
    }

private:
    MLKEMPublicKey m_mlkem;
    Vector!ubyte m_x25519;
}

final class HybridPrivateKey : PrivateKey, PublicKey
{
public:
    this(RandomNumberGenerator rng)
    {
        m_mlkem = new MLKEMPrivateKey(MLKEMMode.Kem768, rng);
        m_x25519 = Curve25519PrivateKey(rng);
    }

    override @property string algoName() const { return HYBRID_NAME; }
    override size_t estimatedStrength() const { return 192; }
    override bool checkKey(RandomNumberGenerator, bool) const { return true; }
    override size_t messageParts() const { return 1; }
    override size_t messagePartSize() const { return 0; }
    override size_t maxInputBits() const { return 0; }
    override AlgorithmIdentifier algorithmIdentifier() const { return hybridAlgId(); }
    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return algorithmIdentifier(); }
    override Vector!ubyte x509SubjectPublicKey() const
    {
        return publicKey().x509SubjectPublicKey();
    }
    override SecureVector!ubyte pkcs8PrivateKey() const
    {
        return m_mlkem.pkcs8PrivateKey();
    }

    HybridPublicKey publicKey() const
    {
        return new HybridPublicKey(m_mlkem.publicKey(), m_x25519.publicValue());
    }

    void decaps(const(ubyte)* ct, size_t ctlen, ubyte* ss)
    {
        if (ctlen != hybridCtBytes())
            throw new DecodingError("Hybrid KEM: unexpected ciphertext length");
        auto ss1 = new ubyte[32];
        mlkemDecaps(m_mlkem.raw(), ct, mlkem768Ct(), ss1.ptr);
        auto ss2 = m_x25519.agree(ct + mlkem768Ct(), X25519_LEN);
        hybridCombine(ss1.ptr, ss2.ptr, ss);
    }

private:
    MLKEMPrivateKey m_mlkem;
    Curve25519PrivateKey m_x25519;
}

static if (BOTAN_HAS_TESTS && !SKIP_HYBRID_KEM_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.rng.auto_rng;
    import botan.pubkey.pk_algs;

    auto state = globalState();
    logDebug("Testing hybrid_kem.d ...");
    size_t fails;

    const OID oid = OIDS.lookup(HYBRID_NAME);
    if (oid.toString() != "1.3.6.1.4.1.25258.1.21")
        ++fails;

    Unique!AutoSeededRNG rng = new AutoSeededRNG;
    Unique!HybridPrivateKey sk = new HybridPrivateKey(*rng);
    Unique!HybridPublicKey pk = sk.publicKey();
    auto ss1 = new ubyte[HYBRID_SS];
    auto ss2 = new ubyte[HYBRID_SS];
    auto ct = new ubyte[hybridCtBytes()];
    pk.encaps(*rng, ss1.ptr, ct.ptr);
    sk.decaps(ct.ptr, ct.length, ss2.ptr);
    if (ss1[0 .. HYBRID_SS] != ss2[0 .. HYBRID_SS])
    {
        logError("hybrid pairwise mismatch");
        ++fails;
    }
    ct[0] ^= 0xff;
    auto ss3 = new ubyte[HYBRID_SS];
    sk.decaps(ct.ptr, ct.length, ss3.ptr);
    if (ss3[0 .. HYBRID_SS] == ss1[0 .. HYBRID_SS])
    {
        logError("hybrid mutated CT accepted");
        ++fails;
    }

    auto pub_bits = SecureVector!ubyte(pk.x509SubjectPublicKey()[]);
    Unique!PublicKey via = makePublicKey(pk.algorithmIdentifier(), pub_bits);
    if (!via || via.algoName != HYBRID_NAME)
        ++fails;

    fails += checkMemutilsRepeat("hybrid_kem", {
        Unique!AutoSeededRNG r = new AutoSeededRNG;
        Unique!HybridPrivateKey s = new HybridPrivateKey(*r);
        Unique!HybridPublicKey p = s.publicKey();
        auto ss = new ubyte[HYBRID_SS];
        auto c = new ubyte[hybridCtBytes()];
        p.encaps(*r, ss.ptr, c.ptr);
        s.decaps(c.ptr, c.length, ss.ptr);
    });

    if (fails)
        logError("hybrid_kem failures: ", fails);
    assert(fails == 0);
}
