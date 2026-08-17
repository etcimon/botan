/**
* RFC 9380 hash-to-scalar / hash-to-curve (XMD + SSWU)
*
* Copyright:
* (C) 2019,2020,2021,2024 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.hash_to_curve;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_XMD):

import botan.pubkey.algo.ec_group;
import botan.math.ec_gfp.curve_gfp;
import botan.math.ec_gfp.point_gfp;
import botan.math.bigint.bigint;
import botan.math.numbertheory.numthry;
import botan.hash.hash;
import botan.kdf.xmd;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import botan.utils.types;
import std.algorithm : min;
import std.conv : to;

/// C++ HashFunction::security_level default 4*output_length; SHA-1=61, MD5/MD4=0.
size_t hashSecurityLevel(HashFunction hash)
{
    const string n = hash.name;
    if (n == "MD5" || n == "MD4" || n == "MD2")
        return 0;
    if (n == "SHA-160" || n == "SHA-1")
        return 61;
    return 4 * hash.outputLength();
}

/**
* RFC 9380 expand_message wrapper used by hash-to-field / hash-to-scalar.
* `order_bits` is the group order length (hash-strength k = min((n+1)/2, 256)).
*/
void expandH2cMessage(string hash_fn, size_t order_bits,
                      ubyte* output, size_t output_len,
                      const(ubyte)* input, size_t input_len,
                      const(ubyte)* domain, size_t domain_len)
{
    if (hash_fn.length >= 5 && hash_fn[0 .. 5] == "SHAKE")
        throw new Exception("Hash to curve currently does not support expand_message_xof");

    Unique!HashFunction hash = retrieveHash(hash_fn).clone();
    const size_t k = min((order_bits + 1) / 2, 256);
    if (hashSecurityLevel(hash) < k)
        throw new InvalidArgument("Hash " ~ hash.name ~ " is too weak for use with a "
                                  ~ to!string(order_bits) ~ " bit group");
    expandMessageXmd(hash, output, output_len, input, input_len, domain, domain_len);
}

/**
* RFC 9380 §5.2 hash_to_field onto the group order (C++ `EC_Scalar::hash`).
* L = ceil((ceil(log2(n)) + k) / 8), k = min((nbits+1)/2, 256).
*/
BigInt ecHashToScalar(const ref ECGroup group, string hash_fn,
                      const(ubyte)* input, size_t input_len,
                      const(ubyte)* domain, size_t domain_len)
{
    const size_t scalar_bits = group.getOrder().bits();
    const size_t security_level = min((scalar_bits + 1) / 2, 256);
    const size_t L = (scalar_bits + security_level + 7) / 8;
    auto uniform = SecureVector!ubyte(L);
    expandH2cMessage(hash_fn, scalar_bits, uniform.ptr, uniform.length,
                     input, input_len, domain, domain_len);
    auto wide = BigInt.decode(uniform.ptr, uniform.length);
    return wide % group.getOrder();
}

SecureVector!ubyte ecHashToScalarBytes(const ref ECGroup group, string hash_fn,
                                       const(ubyte)* input, size_t input_len,
                                       const(ubyte)* domain, size_t domain_len)
{
    auto s = ecHashToScalar(group, hash_fn, input, input_len, domain, domain_len);
    return BigInt.encode1363(s, group.getOrder().bytes());
}

/// RFC 9380 SSWU Z for named groups (C++ pcurves `EllipticCurveParameters` last arg).
int sswuZForGroup(string name)
{
    if (name == "secp256r1") return -10;
    if (name == "secp384r1") return -12;
    if (name == "secp521r1") return -4;
    if (name == "brainpool256r1") return -2;
    if (name == "brainpool384r1") return -5;
    if (name == "brainpool512r1") return 7;
    if (name == "numsp512d1") return -4;
    return 0;
}

bool hashToCurveSupported(const ref ECGroup group, string hash_fn, string group_name)
{
    if (sswuZForGroup(group_name) == 0)
        return false;
    if ((group.getCurve().getP() % 4) != 3)
        return false;
    if (group.getCurve().getA().isZero() || group.getCurve().getB().isZero())
        return false;
    if (hash_fn.length >= 5 && hash_fn[0 .. 5] == "SHAKE")
        return false;
    try
    {
        Unique!HashFunction hash = retrieveHash(hash_fn).clone();
        const size_t k = min((group.getOrder().bits() + 1) / 2, 256);
        if (hashSecurityLevel(hash) < k)
            return false;
        return hash.hashBlockSize() > 0 && hash.outputLength() <= hash.hashBlockSize();
    }
    catch (Exception)
    {
        return false;
    }
}

private BigInt fieldMul(const ref BigInt x, const ref BigInt y, const ref BigInt p)
{
    auto t = x * y;
    return t % p;
}

private BigInt fieldAdd(const ref BigInt x, const ref BigInt y, const ref BigInt p)
{
    auto t = x + y;
    if (t >= p)
        t -= p;
    return t.move();
}

private BigInt curveGx(const ref BigInt x, const ref BigInt a, const ref BigInt b, const ref BigInt p)
{
    auto x2 = fieldMul(x, x, p);
    auto x3 = fieldMul(x2, x, p);
    auto ax = fieldMul(a, x, p);
    auto t = fieldAdd(x3, ax, p);
    return fieldAdd(t, b, p);
}

private PointGFp mapToCurveSswu(const ref CurveGFp curve, const ref BigInt u, int z_i)
{
    auto p = curve.getP().clone;
    auto a = curve.getA().clone;
    auto b = curve.getB().clone;
    auto zabs = BigInt(z_i < 0 ? -z_i : z_i);
    BigInt z;
    if (z_i < 0)
        z = p - zabs;
    else
        z = zabs.move();

    auto inv_a = inverseMod(&a, &p);
    auto c1 = fieldMul(b, inv_a, p);
    c1 = p - c1;
    auto za = fieldMul(z, a, p);
    auto inv_za = inverseMod(&za, &p);
    auto c2 = fieldMul(b, inv_za, p);

    auto u2 = fieldMul(u, u, p);
    auto z_u2 = fieldMul(z, u2, p);
    auto z2_u4 = fieldMul(z_u2, z_u2, p);
    auto den = fieldAdd(z2_u4, z_u2, p);

    BigInt x1;
    if (den.isZero())
        x1 = c2.clone;
    else
    {
        auto tv1 = inverseMod(&den, &p);
        auto one = BigInt(1);
        auto one_tv1 = fieldAdd(one, tv1, p);
        x1 = fieldMul(c1, one_tv1, p);
    }
    auto x2 = fieldMul(z_u2, x1, p);

    auto gx1 = curveGx(x1, a, b, p);
    auto gx2 = curveGx(x2, a, b, p);
    auto y1 = ressol(&gx1, &p);
    auto y2 = ressol(&gx2, &p);
    const bool use_y1 = !y1.isNegative();
    if (!use_y1 && y2.isNegative())
        throw new InternalError("SSWU: neither candidate is a quadratic residue");

    auto x = use_y1 ? x1.move() : x2.move();
    auto y = use_y1 ? y1.move() : y2.move();
    if (y.getBit(0) != u.getBit(0))
        y = p - y;
    return PointGFp(curve, &x, &y);
}

private BigInt fieldFromWide(const(ubyte)* bytes, size_t len, const ref BigInt p)
{
    auto w = BigInt.decode(bytes, len);
    return w % p;
}

private void hashToField(ubyte* outp, size_t nbytes, const ref ECGroup group, string hash_fn,
                         const(ubyte)* input, size_t input_len,
                         const(ubyte)* domain, size_t domain_len)
{
    const size_t order_bits = group.getOrder().bits();
    expandH2cMessage(hash_fn, order_bits, outp, nbytes, input, input_len, domain, domain_len);
}

private size_t h2cFieldL(const ref ECGroup group)
{
    const size_t field_bits = group.getCurve().getP().bits();
    const size_t security_level = (group.getOrder().bits() + 1) / 2;
    return (field_bits + security_level + 7) / 8;
}

private PointGFp clearCofactor(const ref PointGFp pt, const ref ECGroup group)
{
    auto h = group.getCofactor().clone;
    if (h == BigInt(1))
        return pt.clone;
    return pt * &h;
}

/**
* RFC 9380 hash_to_curve (RO = two SSWU maps + add). C++ `hash_to_curve_ro`.
*/
PointGFp hashToCurveRo(const ref ECGroup group, string group_name, string hash_fn,
                       const(ubyte)* input, size_t input_len,
                       const(ubyte)* domain, size_t domain_len)
{
    const int z = sswuZForGroup(group_name);
    if (z == 0)
        throw new Exception("Hash to curve is not implemented for this curve");
    const size_t L = h2cFieldL(group);
    auto uniform = SecureVector!ubyte(2 * L);
    hashToField(uniform.ptr, uniform.length, group, hash_fn, input, input_len, domain, domain_len);
    auto p = group.getCurve().getP().clone;
    auto u0 = fieldFromWide(uniform.ptr, L, p);
    auto u1 = fieldFromWide(uniform.ptr + L, L, p);
    auto q0 = mapToCurveSswu(group.getCurve(), u0, z);
    auto q1 = mapToCurveSswu(group.getCurve(), u1, z);
    auto r = q0 + q1;
    return clearCofactor(r, group);
}

/**
* RFC 9380 encode_to_curve (NU = one SSWU map). C++ `hash_to_curve_nu`.
*/
PointGFp hashToCurveNu(const ref ECGroup group, string group_name, string hash_fn,
                       const(ubyte)* input, size_t input_len,
                       const(ubyte)* domain, size_t domain_len)
{
    const int z = sswuZForGroup(group_name);
    if (z == 0)
        throw new Exception("Hash to curve is not implemented for this curve");
    const size_t L = h2cFieldL(group);
    auto uniform = SecureVector!ubyte(L);
    hashToField(uniform.ptr, uniform.length, group, hash_fn, input, input_len, domain, domain_len);
    auto p = group.getCurve().getP().clone;
    auto u = fieldFromWide(uniform.ptr, L, p);
    auto q = mapToCurveSswu(group.getCurve(), u, z);
    return clearCofactor(q, group);
}

static if (BOTAN_HAS_TESTS && !SKIP_ECDSA_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;
    import std.string : indexOf;

    auto state = globalState();
    logDebug("Testing hash_to_curve.d ...");
    size_t fails;

    if (exists("test_data/pubkey/ec_h2s.vec"))
    {
        File vec = File("test_data/pubkey/ec_h2s.vec", "r");
        fails += runTestsBb(vec, "Group", "Output", false,
            (ref HashMap!(string, string) m)
            {
                if (!("Hash" in m) || !("Output" in m))
                    return 0;
                const string group_id = m["Group"];
                ECGroup group;
                try
                    group = ECGroup(group_id);
                catch (Exception e)
                    return 0;
                string domain;
                if (auto p = "Domain" in m)
                    domain = *p;
                string msg;
                if (auto p = "Input" in m)
                    msg = *p;
                auto want = hexDecode(m["Output"]);
                auto got = ecHashToScalarBytes(group, m["Hash"],
                                               cast(const(ubyte)*) msg.ptr, msg.length,
                                               cast(const(ubyte)*) domain.ptr, domain.length);
                if (got.length != want.length || !sameMem(got.ptr, want.ptr, want.length))
                {
                    logError("h2s ", group_id, " got ", hexEncode(got), " != ", hexEncode(want));
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/pubkey/ec_h2c.vec"))
    {
        File vec = File("test_data/pubkey/ec_h2c.vec", "r");
        fails += runTestsBb(vec, "H2C", "Point", false,
            (ref HashMap!(string, string) m)
            {
                if (!("Group" in m) || !("Hash" in m) || !("Point" in m))
                    return 0;
                const string method = m["H2C"];
                const string group_id = m["Group"];
                if (sswuZForGroup(group_id) == 0)
                    return 0;
                ECGroup group;
                try
                    group = ECGroup(group_id);
                catch (Exception e)
                    return 0;
                string domain;
                if (auto p = "Domain" in m)
                    domain = *p;
                auto input = hexDecode(m.get("Input", ""));
                auto want = hexDecode(m["Point"]);
                const bool ro = method.indexOf("-RO") >= 0;
                PointGFp pt;
                if (ro)
                    pt = hashToCurveRo(group, group_id, m["Hash"],
                                       input.ptr, input.length,
                                       cast(const(ubyte)*) domain.ptr, domain.length);
                else
                    pt = hashToCurveNu(group, group_id, m["Hash"],
                                       input.ptr, input.length,
                                       cast(const(ubyte)*) domain.ptr, domain.length);
                auto got = unlock(EC2OSP(pt, PointGFp.UNCOMPRESSED));
                if (got.length != want.length || !sameMem(got.ptr, want.ptr, want.length))
                {
                    logError("h2c ", method, " ", group_id, " got ", hexEncode(got),
                             " != ", hexEncode(want));
                    return 1;
                }
                return 0;
            });
    }

    fails += checkMemutilsRepeat("h2s", {
        ECGroup group = ECGroup("secp256r1");
        const ubyte[3] msg = [109, 115, 103];
        const ubyte[3] dst = [100, 115, 116];
        auto got = ecHashToScalarBytes(group, "SHA-256", msg.ptr, msg.length, dst.ptr, dst.length);
        if (got.length != 32)
            throw new Exception("h2s leak probe");
    });

    if (fails)
        logError("hash_to_curve failures: ", fails);
    assert(fails == 0);
}
