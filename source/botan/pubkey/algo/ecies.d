/**
* ECIES (ISO 18033-2)
*
* Copyright:
* (C) 2016 Philipp Weber
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.ecies;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_ECIES && BOTAN_HAS_ECDH):

public import botan.pubkey.pubkey;
import botan.pubkey.algo.ecdh;
import botan.pubkey.algo.ecc_key;
import botan.math.ec_gfp.point_gfp;
import botan.math.bigint.bigint;
import botan.kdf.kdf;
import botan.mac.mac;
import botan.libstate.lookup;
import botan.filters.filters;
import botan.algo_base.symkey;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.math.numbertheory.numthry;

enum : ubyte {
    ECIES_UNCOMPRESSED = PointGFp.UNCOMPRESSED,
    ECIES_COMPRESSED   = PointGFp.COMPRESSED,
    ECIES_HYBRID       = PointGFp.HYBRID
}

/**
* ECIES system parameters (group, KDF, DEM cipher, MAC, point format).
*/
final class ECIESSystemParams
{
    ECGroup group;
    string kdf;
    string dem;
    size_t dem_key_len;
    string mac;
    size_t mac_key_len;
    ubyte point_format = ECIES_UNCOMPRESSED;
    bool single_hash_mode = false;
    bool cofactor_mode = false;
    bool old_cofactor_mode = false;
    bool check_mode = false;
    // 0 => dem_key_len + mac_key_len (ECIES-DEM). ISO 18033-2 KEM KATs set this.
    size_t kdf_out_len = 0;

    /**
    * Params:
    *  g = EC domain
    *  kdf_spec = KDF SCAN name
    *  dem_spec = DEM cipher SCAN name
    *  dem_len = DEM key length
    *  mac_spec = MAC SCAN name
    *  mac_len = MAC key length
    *  format = point encoding (uncompressed / compressed / hybrid)
    *  single_hash = ISO 18033-2 single-hash mode
    *  cofactor = BSI TR-03111 cofactor mode
    *  old_cofactor = ISO 18033 old-cofactor (scale the peer point)
    *  check = check mode (mutually exclusive with the cofactor flags)
    */
    this()(const auto ref ECGroup g, string kdf_spec, string dem_spec, size_t dem_len,
           string mac_spec, size_t mac_len, ubyte format = ECIES_UNCOMPRESSED,
           bool single_hash = false, bool cofactor = false,
           bool old_cofactor = false, bool check = false)
    {
        if (cast(size_t) cofactor + cast(size_t) old_cofactor + cast(size_t) check > 1)
            throw new InvalidArgument("ECIES: only one of cofactor_mode, old_cofactor_mode and check_mode can be set");
        group = g.clone;
        kdf = kdf_spec;
        dem = dem_spec;
        dem_key_len = dem_len;
        mac = mac_spec;
        mac_key_len = mac_len;
        point_format = format;
        single_hash_mode = single_hash;
        cofactor_mode = cofactor;
        old_cofactor_mode = old_cofactor;
        check_mode = check;
    }

    /// KDF output length (DEM key + MAC key, unless kdf_out_len is set).
    size_t secretLength() const { return kdf_out_len ? kdf_out_len : dem_key_len + mac_key_len; }
}

size_t eciesPointSize(const ref ECGroup group, ubyte format)
{
    const size_t p_bytes = group.getCurve().getP().bytes();
    if (format == ECIES_COMPRESSED)
        return 1 + p_bytes;
    return 1 + 2 * p_bytes;
}

ubyte eciesFormatFromName(string format)
{
    if (format == "uncompressed")
        return ECIES_UNCOMPRESSED;
    if (format == "compressed")
        return ECIES_COMPRESSED;
    if (format == "hybrid")
        return ECIES_HYBRID;
    throw new InvalidArgument("ECIES: invalid point format " ~ format);
}

SecureVector!ubyte eciesEcdhX(const ref ECGroup group, const ref BigInt priv,
                              const(ubyte)* pub, size_t pub_len,
                              bool old_cofactor, bool cofactor)
{
    PointGFp Q = OS2ECP(pub, pub_len, group.getCurve());
    if (Q.isZero())
        throw new InvalidArgument("ECIES: peer public key is the identity");
    const BigInt* h = &group.getCofactor();
    // ISO 18033 old-cofactor: scale the peer point before the agreement.
    if (old_cofactor && *h != 1)
        Q = Q * h;
    PointGFp S;
    if (cofactor && *h != 1)
    {
        // Decrypt-only cofactor mode uses BSI TR-03111 ECKAEG (same as
        // ECDHKAOperation): (h·Q)·(x·h^{-1}). For prime-order subgroup
        // points this equals Q·x, matching the encrypt-side raw ECDH.
        auto order = &group.getOrder();
        auto l = inverseMod(h, order) * &priv;
        auto tmp = Q * h;
        S = tmp * &l;
    }
    else
        S = Q * &priv;
    if (S.isZero())
        throw new DecodingError("ECIES agreed point is zero");
    auto x = S.getAffineX();
    return BigInt.encode1363(&x, group.getCurve().getP().bytes());
}

SecureVector!ubyte eciesDeriveSecret(const ECIESSystemParams params,
                                     const ref BigInt priv,
                                     const(ubyte)[] eph_public,
                                     const(ubyte)[] other_public,
                                     bool for_encryption)
{
    Unique!KDF kdf = getKdf(params.kdf);
    if (!kdf)
        throw new LookupError("ECIES unknown KDF " ~ params.kdf);

    const bool use_cofactor = params.cofactor_mode && !for_encryption;
    auto peh = eciesEcdhX(params.group, priv, other_public.ptr, other_public.length,
                          params.old_cofactor_mode, use_cofactor);

    SecureVector!ubyte kdf_in;
    if (!params.single_hash_mode)
    {
        kdf_in ~= eph_public;
    }
    kdf_in ~= peh[];
    return kdf.deriveKey(params.secretLength(), kdf_in.ptr, kdf_in.length);
}

/**
* ECIES encryptor (ISO 18033-2 / IEEE 1363a)
*/
class ECIESEncryptor : PKEncryptor
{
public:
    /**
    * Params:
    *  eph = ephemeral ECDH key (its public point is prepended to the ciphertext)
    *  params = system parameters
    */
    this(in ECDHPrivateKey eph, ECIESSystemParams params)
    {
        m_params = params;
        m_priv = eph.privateValue().clone;
        m_eph_public = unlock(EC2OSP(eph.publicPoint(), params.point_format));
    }

    /**
    * Params:
    *  pt = peer public point
    */
    void setOtherKey(const ref PointGFp pt)
    {
        m_other = unlock(EC2OSP(pt, m_params.point_format));
        m_other_set = true;
    }

    /**
    * Params:
    *  iv = DEM IV; required fresh for each message
    */
    void setInitializationVector(const(ubyte)[] iv)
    {
        m_iv = Vector!ubyte(iv);
        m_iv_set = true;
    }

    /**
    * Optional MAC label (ISO 18033-2)
    * Params:
    *  label = associated data for the MAC
    */
    void setLabel(string label)
    {
        m_label = Vector!ubyte(cast(const(ubyte)[]) label);
    }

    override size_t maximumInputSize() const { return 64; }

protected:
    override Vector!ubyte enc(const(ubyte)* data, size_t length, RandomNumberGenerator) const
    {
        if (!m_other_set)
            throw new InvalidState("ECIES_Encryptor: peer key invalid or not set");
        if (!m_iv_set)
            throw new InvalidState("ECIES requires a fresh IV be provided for each message");

        auto secret = eciesDeriveSecret(m_params, m_priv, m_eph_public[], m_other[], true);
        if (secret.length != m_params.secretLength())
            throw new EncodingError("ECIES: KDF did not provide sufficient output");

        auto dem_key = SymmetricKey(secret.ptr, m_params.dem_key_len);
        auto iv_bytes = m_iv.length ? m_iv.clone() : Vector!ubyte(16);
        auto iv = InitializationVector(iv_bytes);
        Pipe pipe = Pipe(getCipher(m_params.dem, dem_key, iv, ENCRYPTION));
        pipe.processMsg(data, length);
        auto encrypted = pipe.readAll();

        Unique!MessageAuthenticationCode mac = retrieveMac(m_params.mac).clone();
        mac.setKey(secret.ptr + m_params.dem_key_len, m_params.mac_key_len);
        mac.update(encrypted.ptr, encrypted.length);
        if (m_label.length)
            mac.update(m_label.ptr, m_label.length);
        auto tag = mac.finished();

        Vector!ubyte outbuf;
        outbuf ~= m_eph_public[];
        outbuf ~= encrypted[];
        outbuf ~= tag[];
        return outbuf.move();
    }

private:
    ECIESSystemParams m_params;
    BigInt m_priv;
    Vector!ubyte m_eph_public;
    Vector!ubyte m_other;
    Vector!ubyte m_iv;
    Vector!ubyte m_label;
    bool m_other_set;
    bool m_iv_set;
}

/**
* ECIES decryptor
*/
class ECIESDecryptor : PKDecryptor
{
public:
    /**
    * Params:
    *  key = static ECDH private key
    *  params = system parameters (must match the encryptor)
    */
    this(in ECDHPrivateKey key, ECIESSystemParams params)
    {
        m_params = params;
        m_priv = key.privateValue().clone;
    }

    void setInitializationVector(const(ubyte)[] iv)
    {
        m_iv = Vector!ubyte(iv);
        m_iv_set = true;
    }

    void setLabel(string label)
    {
        m_label = Vector!ubyte(cast(const(ubyte)[]) label);
    }

protected:
    override SecureVector!ubyte dec(const(ubyte)* input, size_t length) const
    {
        Unique!MessageAuthenticationCode mac = retrieveMac(m_params.mac).clone();
        const size_t point_size = eciesPointSize(m_params.group, m_params.point_format);
        if (length < point_size + mac.outputLength)
            throw new DecodingError("ECIES decryption: ciphertext is too short");
        if (!m_iv_set)
            throw new InvalidState("ECIES requires a fresh IV be provided for each message");

        const(ubyte)[] eph = input[0 .. point_size];
        const size_t enc_len = length - point_size - mac.outputLength;
        const(ubyte)[] encrypted = input[point_size .. point_size + enc_len];
        const(ubyte)[] tag = input[point_size + enc_len .. length];

        auto secret = eciesDeriveSecret(m_params, m_priv, eph, eph, false);
        if (secret.length != m_params.secretLength())
            throw new EncodingError("ECIES: KDF did not provide sufficient output");

        mac.setKey(secret.ptr + m_params.dem_key_len, m_params.mac_key_len);
        mac.update(encrypted.ptr, encrypted.length);
        if (m_label.length)
            mac.update(m_label.ptr, m_label.length);
        auto expect = mac.finished();
        if (expect[] != tag[])
            throw new DecodingError("ECIES: message authentication failed");

        auto dem_key = SymmetricKey(secret.ptr, m_params.dem_key_len);
        auto iv_bytes = m_iv.length ? m_iv.clone() : Vector!ubyte(16);
        auto iv = InitializationVector(iv_bytes);
        Pipe pipe = Pipe(getCipher(m_params.dem, dem_key, iv, DECRYPTION));
        pipe.processMsg(encrypted.ptr, encrypted.length);
        return pipe.readAll();
    }

private:
    ECIESSystemParams m_params;
    BigInt m_priv;
    Vector!ubyte m_iv;
    Vector!ubyte m_label;
    bool m_iv_set;
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.codec.hex;
import botan.libstate.global_state;
import memutils.hashmap;
import std.conv : to;
import std.stdio : File;

static if (BOTAN_HAS_TESTS && !SKIP_ECIES_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing ecies.d ...");
    size_t fails = 0;

    File iso = File("test_data/pubkey/ecies-18033.vec", "r");
    fails += runTestsBb(iso, "ECIES-ISO", "K", false,
        (ref HashMap!(string, string) m)
        {
            if (!("K" in m) || !("C0" in m) || !("r" in m))
                return 0;
            auto group = ECGroup("secp192r1");
            auto r = BigInt(m["r"]);
            const ubyte fmt = eciesFormatFromName(m["format"]);
            PointGFp eph_pt = group.getBasePoint() * &r;
            auto eph_bin = unlock(EC2OSP(eph_pt, fmt));
            auto c0 = hexDecode(m["C0"]);
            if (eph_bin[] != c0[])
                return 2;
            auto hx = BigInt(m["hx"]);
            auto hy = BigInt(m["hy"]);
            auto other = PointGFp(group.getCurve(), &hx, &hy);
            auto other_bin = unlock(EC2OSP(other, fmt));
            auto params = new ECIESSystemParams(group, "KDF1-18033(SHA-1)", "AES-256/CBC", 32,
                                                "HMAC(SHA-1)", 20, fmt, false);
            // ISO 18033-2 annex C KEM: KDF1-18033(SHA-1) of C0||peh, 128 bytes.
            params.kdf_out_len = 128;
            auto secret = eciesDeriveSecret(params, r, eph_bin[], other_bin[], true);
            auto exp = hexDecode(m["K"]);
            if (secret[] != exp[])
                return 3;
            return 0;
        });

    File vec = File("test_data/pubkey/ecies.vec", "r");
    fails += runTestsBb(vec, "ECIES", "Ciphertext", false,
        (ref HashMap!(string, string) m)
        {
            if (!("Ciphertext" in m) || !("Curve" in m) || !("PrivateKey" in m))
                return 0;
            auto group = ECGroup(m["Curve"]);
            Unique!AutoSeededRNG rng = new AutoSeededRNG;
            auto x = BigInt(m["PrivateKey"]);
            auto y = BigInt(m["OtherPrivateKey"]);
            auto eph = ECDHPrivateKey(*rng, group, x.move());
            auto other = ECDHPrivateKey(*rng, group, y.move());
            const ubyte fmt = eciesFormatFromName(m["Format"]);
            const bool single_hash = m["SingleHashMode"] != "0";
            const bool cofactor = m["CofactorMode"] != "0";
            const bool old_cofactor = m["OldCofactorMode"] != "0";
            const bool check = m["CheckMode"] != "0";
            const size_t dem_len = to!size_t(m["DemKeyLen"]);
            const size_t mac_len = to!size_t(m["MacKeyLen"]);
            string label;
            if (auto lp = "Label" in m)
                label = *lp;
            Vector!ubyte iv;
            if (auto ip = "Iv" in m)
                if ((*ip).length)
                    iv = hexDecode(*ip);
            auto pt = hexDecode(m["Plaintext"]);
            auto exp = hexDecode(m["Ciphertext"]);
            ECIESSystemParams params;
            try
            {
                params = new ECIESSystemParams(group, m["Kdf"], m["Dem"], dem_len, m["Mac"], mac_len,
                                               fmt, single_hash, cofactor, old_cofactor, check);
            }
            catch (InvalidArgument)
            {
                return 1;
            }
            auto enc = scoped!ECIESEncryptor(eph, params);
            enc.setOtherKey(other.publicPoint());
            enc.setInitializationVector(iv[]);
            if (label.length)
                enc.setLabel(label);
            auto got = enc.encrypt(pt, *rng);
            if (got[] != exp[])
                return 1;
            auto dec = scoped!ECIESDecryptor(other, params);
            dec.setInitializationVector(iv[]);
            if (label.length)
                dec.setLabel(label);
            auto back = dec.decrypt(got);
            if (back[] != pt[])
                return 1;
            return 0;
        });

    testReport("ecies", 0, fails);
    assert(fails == 0);
}
