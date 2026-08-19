/**
* SPAKE2+ (RFC 9383)
*
* Copyright:
* (C) 2024,2025,2026 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.spake2p;

import botan.constants;
static if (BOTAN_HAS_SPAKE2P):

static assert(BOTAN_HAS_PUBLIC_KEY_CRYPTO, "SPAKE2P requires PUBKEY");
static assert(BOTAN_HAS_HKDF, "SPAKE2P requires HKDF");
static assert(BOTAN_HAS_HMAC, "SPAKE2P requires HMAC");

import botan.pubkey.algo.ec_group;
import botan.math.ec_gfp.point_gfp;
import botan.math.bigint.bigint;
import botan.hash.hash;
import botan.mac.mac;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.codec.hex;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;


// RFC 9383 §4 M/N (compressed)
private enum string SPAKE2P_P256_M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
private enum string SPAKE2P_P256_N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
private enum string SPAKE2P_P384_M =
    "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853";
private enum string SPAKE2P_P384_N =
    "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10";
private enum string SPAKE2P_P521_M =
    "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa";
private enum string SPAKE2P_P521_N =
    "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25";

private void hashLe64(HashFunction hash, const(ubyte)* data, size_t len)
{
    ubyte[8] nlen;
    storeLittleEndian(cast(ulong) len, nlen.ptr);
    hash.update(nlen.ptr, 8);
    if (len)
        hash.update(data, len);
}

private void hashLe64()(HashFunction hash, const auto ref Vector!ubyte data)
{
    hashLe64(hash, data.ptr, data.length);
}

private void hashLe64()(HashFunction hash, const auto ref SecureVector!ubyte data)
{
    hashLe64(hash, data.ptr, data.length);
}

private Vector!ubyte encodeUncompressed()(const auto ref PointGFp pt)
{
    return unlock(EC2OSP(pt, PointGFp.UNCOMPRESSED));
}

private PointGFp applyCofactor()(const auto ref PointGFp pt, const auto ref ECGroup group)
{
    const BigInt* h = &group.getCofactor();
    if (*h == 1)
        return pt.clone;
    return pt * h;
}

private PointGFp mulAdd()(const auto ref PointGFp p, const auto ref BigInt a,
                          const auto ref PointGFp q, const auto ref BigInt b)
{
    auto pa = p * &a;
    auto qb = q * &b;
    return pa + qb;
}

/// RFC 9383 §3.4 session keys from the transcript.
private struct SPAKE2pSessionKeys
{
    SecureVector!ubyte shared_key;
    Vector!ubyte confirm_p;
    Vector!ubyte confirm_v;
}

private SPAKE2pSessionKeys spake2pKeySchedule(SPAKE2pSystemParameters params,
                                              const(ubyte)* context, size_t context_len,
                                              const(ubyte)* prover_id, size_t prover_id_len,
                                              const(ubyte)* verifier_id, size_t verifier_id_len,
                                              const(ubyte)* share_p, size_t share_p_len,
                                              const(ubyte)* share_v, size_t share_v_len,
                                              const ref PointGFp z,
                                              const ref PointGFp v,
                                              const ref BigInt w0)
{
    Unique!HashFunction hash = retrieveHash(params.hashFunction()).clone();
    hashLe64(hash, context, context_len);
    hashLe64(hash, prover_id, prover_id_len);
    hashLe64(hash, verifier_id, verifier_id_len);

    auto m_enc = encodeUncompressed(params.spake2pM());
    auto n_enc = encodeUncompressed(params.spake2pN());
    auto z_enc = encodeUncompressed(z);
    auto v_enc = encodeUncompressed(v);
    auto w0_enc = BigInt.encode1363(w0, params.group().getOrder().bytes());

    hashLe64(hash, m_enc);
    hashLe64(hash, n_enc);
    hashLe64(hash, share_p, share_p_len);
    hashLe64(hash, share_v, share_v_len);
    hashLe64(hash, z_enc);
    hashLe64(hash, v_enc);
    hashLe64(hash, w0_enc);

    auto k_main = hash.finished();

    Unique!KDF kdf = getKdf("HKDF(" ~ params.hashFunction() ~ ")");
    const size_t mac_key_len = hash.outputLength;
    immutable confirm_info = "ConfirmationKeys";
    auto confirm_keys = kdf.deriveKey(2 * mac_key_len, k_main.ptr, k_main.length,
                                      null, 0,
                                      cast(const(ubyte)*) confirm_info.ptr, confirm_info.length);

    immutable shared_info = "SharedKey";
    SPAKE2pSessionKeys keys;
    keys.shared_key = kdf.deriveKey(mac_key_len, k_main.ptr, k_main.length,
                                    null, 0,
                                    cast(const(ubyte)*) shared_info.ptr, shared_info.length);

    Unique!MessageAuthenticationCode mac = retrieveMac("HMAC(" ~ params.hashFunction() ~ ")").clone();
    mac.setKey(confirm_keys.ptr, mac_key_len);
    mac.update(share_v, share_v_len);
    keys.confirm_p = unlock(mac.finished());

    mac.setKey(confirm_keys.ptr + mac_key_len, mac_key_len);
    mac.update(share_p, share_p_len);
    keys.confirm_v = unlock(mac.finished());
    return keys;
}

private BigInt randomScalar(SPAKE2pSystemParameters params, RandomNumberGenerator rng)
{
    const size_t n_bytes = params.group().getOrder().bytes();
    auto bytes = rng.randomVec(n_bytes);
    auto x = BigInt(bytes.ptr, bytes.length);
    auto order = &params.group().getOrder();
    if (x >= *order)
        x = x % order;
    if (x.isZero())
        throw new InternalError("SPAKE2+ random scalar was zero");
    return x.move();
}

/**
* RFC 9383 system parameters: group, M/N, and hash (which fixes HKDF/HMAC).
*/
final class SPAKE2pSystemParameters
{
public:
    /**
    * Params:
    *  group = elliptic-curve group
    *  m = SPAKE2+ M generator
    *  n = SPAKE2+ N generator
    *  hash_fn = hash name (fixes HKDF/HMAC)
    */
    this()(const auto ref ECGroup group, const auto ref PointGFp m, const auto ref PointGFp n, string hash_fn)
    {
        m_group = group.clone;
        m_m = m.clone;
        m_n = n.clone;
        m_hash_fn = hash_fn.idup;
    }

    /// RFC 9383 P-256 / SHA-256.
    static SPAKE2pSystemParameters rfc9383P256Sha256()
    { return fromNamed("secp256r1", SPAKE2P_P256_M, SPAKE2P_P256_N, "SHA-256"); }

    /// RFC 9383 P-256 / SHA-512.
    static SPAKE2pSystemParameters rfc9383P256Sha512()
    { return fromNamed("secp256r1", SPAKE2P_P256_M, SPAKE2P_P256_N, "SHA-512"); }

    /// RFC 9383 P-384 / SHA-256.
    static SPAKE2pSystemParameters rfc9383P384Sha256()
    { return fromNamed("secp384r1", SPAKE2P_P384_M, SPAKE2P_P384_N, "SHA-256"); }

    /// RFC 9383 P-384 / SHA-512.
    static SPAKE2pSystemParameters rfc9383P384Sha512()
    { return fromNamed("secp384r1", SPAKE2P_P384_M, SPAKE2P_P384_N, "SHA-512"); }

    /// RFC 9383 P-521 / SHA-512.
    static SPAKE2pSystemParameters rfc9383P521Sha512()
    { return fromNamed("secp521r1", SPAKE2P_P521_M, SPAKE2P_P521_N, "SHA-512"); }

    /**
    * Custom M/N (C++ `SystemParameters::custom`); used by `spake2p_custom.vec`.
    * Params:
    *  group_name = named curve
    *  m_hex = uncompressed M point
    *  n_hex = uncompressed N point
    *  hash_fn = hash name
    */
    static SPAKE2pSystemParameters custom(string group_name, string m_hex, string n_hex, string hash_fn)
    {
        return fromNamed(group_name, m_hex, n_hex, hash_fn);
    }

    /**
    * Params:
    *  group_name = secp256r1, secp384r1, or secp521r1
    *  hash_fn = SHA-256 or SHA-512 (P-521 is SHA-512 only)
    */
    static SPAKE2pSystemParameters fromRfc9383(string group_name, string hash_fn)
    {
        if (group_name == "secp256r1" && hash_fn == "SHA-256")
            return rfc9383P256Sha256();
        if (group_name == "secp256r1" && hash_fn == "SHA-512")
            return rfc9383P256Sha512();
        if (group_name == "secp384r1" && hash_fn == "SHA-256")
            return rfc9383P384Sha256();
        if (group_name == "secp384r1" && hash_fn == "SHA-512")
            return rfc9383P384Sha512();
        if (group_name == "secp521r1" && hash_fn == "SHA-512")
            return rfc9383P521Sha512();
        throw new InvalidArgument("SPAKE2+: unsupported Group/Hash " ~ group_name ~ "/" ~ hash_fn);
    }

    ref const(ECGroup) group() const return { return m_group; }
    ref const(PointGFp) spake2pM() const return { return m_m; }
    ref const(PointGFp) spake2pN() const return { return m_n; }
    string hashFunction() const { return m_hash_fn; }

    size_t shareSize() const { return 1 + 2 * m_group.getCurve().getP().bytes(); }

    size_t confirmationSize() const
    {
        Unique!HashFunction hash = retrieveHash(m_hash_fn).clone();
        return hash.outputLength;
    }

private:
    static SPAKE2pSystemParameters fromNamed(string group_name, string m_hex, string n_hex, string hash_fn)
    {
        auto group = ECGroup(group_name);
        auto m_bin = hexDecode(m_hex);
        auto n_bin = hexDecode(n_hex);
        auto m = OS2ECP(m_bin, group.getCurve());
        auto n = OS2ECP(n_bin, group.getCurve());
        return new SPAKE2pSystemParameters(group, m, n, hash_fn);
    }

    ECGroup m_group;
    PointGFp m_m;
    PointGFp m_n;
    string m_hash_fn;
}

/**
* Verifier registration record: (w0, L = w1·G).
*/
final class SPAKE2pRegistrationRecord
{
public:
    /**
    * Params:
    *  params = SPAKE2+ system parameters
    *  rec = serialized (w0 || L)
    *  rec_len = length in bytes
    */
    static SPAKE2pRegistrationRecord deserialize(SPAKE2pSystemParameters params, const(ubyte)* rec, size_t rec_len)
    {
        const size_t scalar_len = params.group().getOrder().bytes();
        const size_t point_len = params.shareSize();
        if (rec_len != scalar_len + point_len)
            throw new DecodingError("Invalid length for SPAKE2+ registration record");
        auto w0 = BigInt(rec, scalar_len);
        auto l = OS2ECP(rec + scalar_len, point_len, params.group().getCurve());
        if (w0.isZero() || w0 >= params.group().getOrder() || l.isZero())
            throw new DecodingError("Invalid SPAKE2+ registration record");
        return new SPAKE2pRegistrationRecord(w0, l);
    }

    /// ditto
    static SPAKE2pRegistrationRecord deserialize()(SPAKE2pSystemParameters params, const auto ref Vector!ubyte rec)
    {
        return deserialize(params, rec.ptr, rec.length);
    }

    /**
    * Params:
    *  params = SPAKE2+ system parameters
    * Returns: serialized (w0 || L)
    */
    SecureVector!ubyte serialize(SPAKE2pSystemParameters params) const
    {
        auto rec = BigInt.encode1363(m_w0, params.group().getOrder().bytes());
        auto l_enc = EC2OSP(m_l, PointGFp.UNCOMPRESSED);
        rec ~= l_enc[];
        return rec.move();
    }

    ref const(BigInt) w0() const return { return m_w0; }
    ref const(PointGFp) l() const return { return m_l; }

package:
    this()(const auto ref BigInt w0, const auto ref PointGFp l)
    {
        m_w0 = w0.clone;
        m_l = l.clone;
    }

    BigInt m_w0;
    PointGFp m_l;
}

/**
* Prover secret: (w0, w1). Password hashing is a later increment; KATs use fromPrehashed.
*/
final class SPAKE2pProverSecret
{
public:
    /**
    * Params:
    *  w0 = prehashed w0 scalar
    *  w1 = prehashed w1 scalar
    */
    static SPAKE2pProverSecret fromPrehashed()(const auto ref BigInt w0, const auto ref BigInt w1)
    {
        return new SPAKE2pProverSecret(w0, w1);
    }

    /**
    * Params:
    *  params = SPAKE2+ system parameters
    *  sec = serialized (w0 || w1)
    *  sec_len = length in bytes
    */
    static SPAKE2pProverSecret deserialize(SPAKE2pSystemParameters params, const(ubyte)* sec, size_t sec_len)
    {
        const size_t scalar_len = params.group().getOrder().bytes();
        if (sec_len != 2 * scalar_len)
            throw new DecodingError("Invalid SPAKE2+ prover secret");
        auto w0 = BigInt(sec, scalar_len);
        auto w1 = BigInt(sec + scalar_len, scalar_len);
        if (w0.isZero() || w1.isZero() || w0 >= params.group().getOrder() || w1 >= params.group().getOrder())
            throw new DecodingError("Invalid SPAKE2+ prover secret");
        return new SPAKE2pProverSecret(w0, w1);
    }

    /**
    * Params:
    *  params = SPAKE2+ system parameters
    * Returns: serialized (w0 || w1)
    */
    SecureVector!ubyte serialize(SPAKE2pSystemParameters params) const
    {
        auto rec = BigInt.encode1363(m_w0, params.group().getOrder().bytes());
        auto w1enc = BigInt.encode1363(m_w1, params.group().getOrder().bytes());
        rec ~= w1enc[];
        return rec.move();
    }

    /**
    * Params:
    *  params = SPAKE2+ system parameters
    * Returns: verifier record (w0, L = w1·G)
    */
    SPAKE2pRegistrationRecord registrationRecord(SPAKE2pSystemParameters params) const
    {
        auto l = params.group().getBasePoint() * &m_w1;
        if (l.isZero())
            throw new InternalError("SPAKE2+ L was the identity");
        return new SPAKE2pRegistrationRecord(m_w0, l);
    }

    ref const(BigInt) w0() const return { return m_w0; }
    ref const(BigInt) w1() const return { return m_w1; }

private:
    this()(const auto ref BigInt w0, const auto ref BigInt w1)
    {
        m_w0 = w0.clone;
        m_w1 = w1.clone;
    }

    BigInt m_w0;
    BigInt m_w1;
}

/**
* SPAKE2+ prover (knows w0, w1).
*/
final class SPAKE2pProverContext
{
public:
    /**
    * Params:
    *  params = SPAKE2+ system parameters
    *  secret = prover (w0, w1)
    *  prover_id = prover identity
    *  prover_id_len = length of prover_id
    *  verifier_id = verifier identity
    *  verifier_id_len = length of verifier_id
    *  context = optional transcript context
    *  context_len = length of context
    */
    this(SPAKE2pSystemParameters params, SPAKE2pProverSecret secret,
         const(ubyte)* prover_id, size_t prover_id_len,
         const(ubyte)* verifier_id, size_t verifier_id_len,
         const(ubyte)* context = null, size_t context_len = 0)
    {
        m_params = params;
        m_secret = secret;
        m_prover_id = Vector!ubyte(prover_id[0 .. prover_id_len]);
        m_verifier_id = Vector!ubyte(verifier_id[0 .. verifier_id_len]);
        if (context_len)
            m_context = Vector!ubyte(context[0 .. context_len]);
        m_state = State.Initial;
    }

    /// ditto
    this()(SPAKE2pSystemParameters params, SPAKE2pProverSecret secret,
           const auto ref Vector!ubyte prover_id,
           const auto ref Vector!ubyte verifier_id,
           const auto ref Vector!ubyte context)
    {
        this(params, secret, prover_id.ptr, prover_id.length,
             verifier_id.ptr, verifier_id.length, context.ptr, context.length);
    }

    /**
    * Params:
    *  rng = RNG for the prover scalar
    * Returns: prover share
    */
    Vector!ubyte generateMessage(RandomNumberGenerator rng)
    {
        if (m_state != State.Initial)
            throw new InvalidState("SPAKE2+ prover generateMessage called twice");

        auto x = randomScalar(m_params, rng);
        auto share_pt = mulAdd(m_params.group().getBasePoint(), x,
                               m_params.spake2pM(), m_secret.w0());
        if (share_pt.isZero())
            throw new InternalError("Computed the identity element during SPAKE2+ key exchange");

        m_our_share = encodeUncompressed(share_pt);
        m_x = x.move();
        m_state = State.ShareGenerated;
        return m_our_share.clone;
    }

    /**
    * Params:
    *  peer = verifier share || confirmation
    *  peer_len = length of peer
    * Returns: prover confirmation
    */
    Vector!ubyte processMessage(const(ubyte)* peer, size_t peer_len, RandomNumberGenerator)
    {
        if (m_state != State.ShareGenerated)
            throw new InvalidState("SPAKE2+ prover processMessage in wrong state");

        const size_t share_size = m_params.shareSize();
        const size_t confirm_size = m_params.confirmationSize();
        if (peer_len != share_size + confirm_size)
            throw new DecodingError("Invalid length for SPAKE2+ verifier message");

        const(ubyte)* share_v = peer;
        const(ubyte)* confirm_v = peer + share_size;

        auto y = OS2ECP(share_v, share_size, m_params.group().getCurve());
        if (y.isZero())
            throw new DecodingError("Invalid SPAKE2+ key share");

        auto xw0 = (m_x * &m_secret.m_w0) % &m_params.group().getOrder();
        xw0.flipSign();
        auto z_raw = mulAdd(y, m_x, m_params.spake2pN(), xw0);
        auto z = applyCofactor(z_raw, m_params.group());

        auto w1w0 = (m_secret.m_w1 * &m_secret.m_w0) % &m_params.group().getOrder();
        w1w0.flipSign();
        auto v_raw = mulAdd(y, m_secret.m_w1, m_params.spake2pN(), w1w0);
        auto v = applyCofactor(v_raw, m_params.group());

        if (z.isZero() || v.isZero())
            throw new DecodingError("Invalid SPAKE2+ key share");

        auto keys = spake2pKeySchedule(m_params,
                                       m_context.ptr, m_context.length,
                                       m_prover_id.ptr, m_prover_id.length,
                                       m_verifier_id.ptr, m_verifier_id.length,
                                       m_our_share.ptr, m_our_share.length,
                                       share_v, share_size,
                                       z, v, m_secret.m_w0);

        if (keys.confirm_v.length != confirm_size ||
            !sameMem(keys.confirm_v.ptr, confirm_v, confirm_size))
        {
            m_state = State.Failed;
            throw new IntegrityFailure("SPAKE2+ key confirmation failed");
        }

        m_shared = keys.shared_key.move();
        m_state = State.Complete;
        return keys.confirm_p.move();
    }

    /// ditto
    Vector!ubyte processMessage()(const auto ref Vector!ubyte peer, RandomNumberGenerator rng)
    {
        return processMessage(peer.ptr, peer.length, rng);
    }

    /**
    * Returns: shared secret after successful confirmation
    */
    ref const(SecureVector!ubyte) sharedSecret() const return
    {
        if (m_state != State.Complete)
            throw new InvalidState("SPAKE2+ shared secret not ready");
        return m_shared;
    }

    /// Returns: the system parameters used by this context
    SPAKE2pSystemParameters parameters() { return m_params; }

private:
    enum State : ubyte { Initial, ShareGenerated, Complete, Failed }

    SPAKE2pSystemParameters m_params;
    SPAKE2pProverSecret m_secret;
    Vector!ubyte m_prover_id;
    Vector!ubyte m_verifier_id;
    Vector!ubyte m_context;
    Vector!ubyte m_our_share;
    BigInt m_x;
    SecureVector!ubyte m_shared;
    State m_state;
}

/**
* SPAKE2+ verifier (stores only the registration record).
*/
final class SPAKE2pVerifierContext
{
public:
    /**
    * Params:
    *  params = SPAKE2+ system parameters
    *  record = verifier registration record
    *  prover_id = prover identity
    *  prover_id_len = length of prover_id
    *  verifier_id = verifier identity
    *  verifier_id_len = length of verifier_id
    *  context = optional transcript context
    *  context_len = length of context
    */
    this(SPAKE2pSystemParameters params, SPAKE2pRegistrationRecord record,
         const(ubyte)* prover_id, size_t prover_id_len,
         const(ubyte)* verifier_id, size_t verifier_id_len,
         const(ubyte)* context = null, size_t context_len = 0)
    {
        m_params = params;
        m_record = record;
        m_prover_id = Vector!ubyte(prover_id[0 .. prover_id_len]);
        m_verifier_id = Vector!ubyte(verifier_id[0 .. verifier_id_len]);
        if (context_len)
            m_context = Vector!ubyte(context[0 .. context_len]);
        m_state = State.Initial;
    }

    /// ditto
    this()(SPAKE2pSystemParameters params, SPAKE2pRegistrationRecord record,
           const auto ref Vector!ubyte prover_id,
           const auto ref Vector!ubyte verifier_id,
           const auto ref Vector!ubyte context)
    {
        this(params, record, prover_id.ptr, prover_id.length,
             verifier_id.ptr, verifier_id.length, context.ptr, context.length);
    }

    /**
    * Params:
    *  peer = prover share
    *  peer_len = length of peer
    *  rng = RNG for the verifier scalar
    * Returns: verifier share || confirmation
    */
    Vector!ubyte processMessage(const(ubyte)* peer, size_t peer_len, RandomNumberGenerator rng)
    {
        if (m_state != State.Initial)
            throw new InvalidState("SPAKE2+ verifier processMessage called twice");

        auto x = OS2ECP(peer, peer_len, m_params.group().getCurve());
        if (x.isZero())
            throw new DecodingError("Invalid SPAKE2+ key share");

        auto y = randomScalar(m_params, rng);
        auto share_v_pt = mulAdd(m_params.group().getBasePoint(), y,
                                 m_params.spake2pN(), m_record.w0());
        if (share_v_pt.isZero())
            throw new InternalError("Computed the identity element during SPAKE2+ key exchange");
        auto share_v = encodeUncompressed(share_v_pt);

        auto yw0 = (y * &m_record.m_w0) % &m_params.group().getOrder();
        yw0.flipSign();
        auto z_raw = mulAdd(x, y, m_params.spake2pM(), yw0);
        auto z = applyCofactor(z_raw, m_params.group());
        if (z.isZero())
            throw new DecodingError("Invalid SPAKE2+ key share");

        auto v_raw = m_record.m_l * &y;
        auto v = applyCofactor(v_raw, m_params.group());

        auto keys = spake2pKeySchedule(m_params,
                                       m_context.ptr, m_context.length,
                                       m_prover_id.ptr, m_prover_id.length,
                                       m_verifier_id.ptr, m_verifier_id.length,
                                       peer, peer_len,
                                       share_v.ptr, share_v.length,
                                       z, v, m_record.m_w0);

        m_shared = keys.shared_key.move();
        m_expected_confirm = keys.confirm_p.move();
        m_state = State.Responded;

        Vector!ubyte outbuf;
        outbuf ~= share_v[];
        outbuf ~= keys.confirm_v[];
        return outbuf.move();
    }

    /// ditto
    Vector!ubyte processMessage()(const auto ref Vector!ubyte peer, RandomNumberGenerator rng)
    {
        return processMessage(peer.ptr, peer.length, rng);
    }

    /**
    * Params:
    *  confirmation = prover confirmation
    *  confirmation_len = length of confirmation
    */
    void verifyConfirmation(const(ubyte)* confirmation, size_t confirmation_len)
    {
        if (m_state != State.Responded)
            throw new InvalidState("SPAKE2+ verifier verifyConfirmation in wrong state");
        if (confirmation_len != m_expected_confirm.length ||
            !sameMem(m_expected_confirm.ptr, confirmation, confirmation_len))
        {
            m_expected_confirm.clear();
            m_shared.clear();
            m_state = State.Failed;
            throw new IntegrityFailure("SPAKE2+ key confirmation failed");
        }
        m_expected_confirm.clear();
        m_state = State.Complete;
    }

    /// ditto
    void verifyConfirmation()(const auto ref Vector!ubyte confirmation)
    {
        verifyConfirmation(confirmation.ptr, confirmation.length);
    }

    /// Complete without checking the prover confirmation (KATs only).
    void skipConfirmation()
    {
        if (m_state != State.Responded)
            throw new InvalidState("SPAKE2+ verifier skipConfirmation in wrong state");
        m_expected_confirm.clear();
        m_state = State.Complete;
    }

    /**
    * Returns: shared secret after successful confirmation
    */
    ref const(SecureVector!ubyte) sharedSecret() const return
    {
        if (m_state != State.Complete)
            throw new InvalidState("SPAKE2+ shared secret not ready");
        return m_shared;
    }

    /// Returns: the system parameters used by this context
    SPAKE2pSystemParameters parameters() { return m_params; }

private:
    enum State : ubyte { Initial, Responded, Complete, Failed }

    SPAKE2pSystemParameters m_params;
    SPAKE2pRegistrationRecord m_record;
    Vector!ubyte m_prover_id;
    Vector!ubyte m_verifier_id;
    Vector!ubyte m_context;
    Vector!ubyte m_expected_confirm;
    SecureVector!ubyte m_shared;
    State m_state;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.global_state;
import botan.rng.test;
import memutils.hashmap;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_SPAKE2P_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing spake2p.d ...");
    size_t fails = 0;

    size_t runSpake(string path)
    {
        File vec = File(path, "r");
        return runTestsBb(vec, "SPAKE2+", "Shared", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Shared" in m) || !("W0" in m) || !("W1" in m) || !("Group" in m))
                return 0;

            Unique!SPAKE2pSystemParameters params;
            try
            {
                if (("M" in m) && ("N" in m) && m["M"].length && m["N"].length)
                    params = SPAKE2pSystemParameters.custom(m["Group"], m["M"], m["N"], m["Hash"]);
                else
                    params = SPAKE2pSystemParameters.fromRfc9383(m["Group"], m["Hash"]);
            }
            catch (Exception e)
            {
                logTrace("SPAKE2+ skip group ", m["Group"], ": ", e.msg);
                return 0;
            }
            auto context = hexDecode(m["Context"]);
            auto prover_id = hexDecode(m["ProverId"]);
            auto verifier_id = hexDecode(m["VerifierId"]);
            auto w0b = hexDecode(m["W0"]);
            auto w1b = hexDecode(m["W1"]);
            auto w0 = BigInt(w0b.ptr, w0b.length);
            auto w1 = BigInt(w1b.ptr, w1b.length);

            Unique!SPAKE2pProverSecret secret = SPAKE2pProverSecret.fromPrehashed(w0, w1);
            auto exp_secret = w0b.clone;
            exp_secret ~= w1b[];
            if (secret.serialize(*params)[] != exp_secret[])
                return 7;

            Unique!SPAKE2pRegistrationRecord record = secret.registrationRecord(*params);
            auto l_bin = hexDecode(m["L"]);
            auto exp_record = w0b.clone;
            exp_record ~= l_bin[];
            if (record.serialize(*params)[] != exp_record[])
                return 8;

            Unique!SPAKE2pRegistrationRecord record2 = SPAKE2pRegistrationRecord.deserialize(*params, exp_record);
            if (record2.serialize(*params)[] != exp_record[])
                return 9;

            Unique!SPAKE2pProverContext prover = new SPAKE2pProverContext(*params, *secret, prover_id, verifier_id, context);
            Unique!SPAKE2pVerifierContext verifier = new SPAKE2pVerifierContext(*params, *record2, prover_id, verifier_id, context);

            auto x_bytes = hexDecode(m["X"]);
            Unique!FixedOutputRNG x_rng = new FixedOutputRNG(x_bytes);
            auto share_p = prover.generateMessage(x_rng);
            auto exp_share_p = hexDecode(m["ShareP"]);
            if (share_p[] != exp_share_p[])
                return 1;
            if (share_p.length != params.shareSize())
                return 10;

            auto y_bytes = hexDecode(m["Y"]);
            Unique!FixedOutputRNG y_rng = new FixedOutputRNG(y_bytes);
            auto verifier_msg = verifier.processMessage(share_p, y_rng);
            auto exp_share_v = hexDecode(m["ShareV"]);
            auto exp_confirm_v = hexDecode(m["ConfirmV"]);
            auto exp_vmsg = exp_share_v.clone;
            exp_vmsg ~= exp_confirm_v[];
            if (verifier_msg[] != exp_vmsg[])
                return 2;

            Unique!FixedOutputRNG dummy = new FixedOutputRNG;
            auto confirm_p = prover.processMessage(verifier_msg, dummy);
            auto exp_confirm_p = hexDecode(m["ConfirmP"]);
            if (confirm_p[] != exp_confirm_p[])
                return 3;
            if (confirm_p.length != params.confirmationSize())
                return 11;

            auto exp_shared = hexDecode(m["Shared"]);
            if (prover.sharedSecret()[] != exp_shared[])
                return 4;

            verifier.verifyConfirmation(confirm_p);
            if (verifier.sharedSecret()[] != exp_shared[])
                return 5;
            return 0;
        });
    }

    fails += runSpake("test_data/pake/spake2p.vec");
    fails += runSpake("test_data/pake/spake2p_custom.vec");

    fails += checkMemutilsRepeat("spake2p rfc", {
        Unique!SPAKE2pSystemParameters params = SPAKE2pSystemParameters.rfc9383P256Sha256();
        auto w0b = hexDecode("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3");
        auto w1b = hexDecode("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
        Unique!SPAKE2pProverSecret secret = SPAKE2pProverSecret.fromPrehashed(
            BigInt(w0b.ptr, w0b.length), BigInt(w1b.ptr, w1b.length));
        Unique!SPAKE2pRegistrationRecord record = secret.registrationRecord(*params);
        auto context = hexDecode("5350414b45322b2d503235362d5348413235362d484b44462d5348413235362d484d41432d534841323536205465737420566563746f7273");
        auto prover_id = hexDecode("636c69656e74");
        auto verifier_id = hexDecode("736572766572");
        Unique!SPAKE2pProverContext prover = new SPAKE2pProverContext(*params, *secret, prover_id, verifier_id, context);
        Unique!SPAKE2pVerifierContext verifier = new SPAKE2pVerifierContext(*params, *record, prover_id, verifier_id, context);
        Unique!FixedOutputRNG x_rng = new FixedOutputRNG(hexDecode("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"));
        auto share_p = prover.generateMessage(x_rng);
        Unique!FixedOutputRNG y_rng = new FixedOutputRNG(hexDecode("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"));
        auto vmsg = verifier.processMessage(share_p, y_rng);
        Unique!FixedOutputRNG dummy = new FixedOutputRNG;
        auto confirm_p = prover.processMessage(vmsg, dummy);
        verifier.verifyConfirmation(confirm_p);
        if (!prover.sharedSecret().length)
            throw new Exception("spake2p leak probe");
    });

    if (fails)
        logError("spake2p failures: ", fails);
    assert(fails == 0);
}
