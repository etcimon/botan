/**
* TLS 1.3 ClientHello key_share generation (RFC 8446 4.2.8)
*
* Copyright:
* (C) 2011,2012,2015,2016 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2021 Elektrobit Automotive GmbH
* (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.key_share_gen;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.tls.tls13.hello_ext;
import botan.rng.rng;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.get_byte;
import botan.math.bigint.bigint;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
static if (BOTAN_HAS_CURVE25519) import botan.pubkey.algo.curve25519;
static if (BOTAN_HAS_ECDH) import botan.pubkey.algo.ecdh;
static if (BOTAN_HAS_DIFFIE_HELLMAN) import botan.pubkey.algo.dh;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO) import botan.pubkey.algo.dl_group;
import std.algorithm : canFind, splitter;
import std.array : array;
import std.string : strip;

private string[] splitGroups(string s)
{
    string[] outp;
    foreach (part; splitter(s, ' '))
    {
        auto t = part.strip;
        if (t.length)
            outp ~= t.idup;
    }
    return outp;
}

private ushort tls13NamedGroup(string name)
{
    if (name == "x25519") return TLS13_GROUP_X25519;
    if (name == "secp256r1") return TLS13_GROUP_SECP256R1;
    if (name == "ffdhe/ietf/2048") return TLS13_GROUP_FFDHE_2048;
    return 0;
}

private Vector!ubyte tls13OfferShare(string name, RandomNumberGenerator rng)
{
    static if (BOTAN_HAS_CURVE25519)
    {
        if (name == "x25519")
        {
            auto sk = Curve25519PrivateKey(rng);
            return sk.publicValue();
        }
    }
    static if (BOTAN_HAS_ECDH)
    {
        if (name == "secp256r1")
        {
            auto group = ECGroup("secp256r1");
            auto sk = ECDHPrivateKey(rng, group);
            return sk.publicValue();
        }
    }
    static if (BOTAN_HAS_DIFFIE_HELLMAN && BOTAN_HAS_PUBLIC_KEY_CRYPTO)
    {
        if (name == "ffdhe/ietf/2048")
        {
            auto grp = DLGroup(name);
            // C++ 3 `BigInt(rng, exponent_bits())` = dl_exponent_size(p bits), high bit set.
            auto x = BigInt();
            x.randomize(rng, dlExponentSize(grp.getP().bits()), true);
            auto y = powerMod(&grp.getG(), &x, &grp.getP());
            return unlock(BigInt.encode1363(y, grp.getP().bytes()));
        }
    }
    return Vector!ubyte();
}

/**
* C++ `Key_Share(policy, cb, rng)` ClientHello emit.
* Walk `groups` in order and offer those also listed in `offered`.
* `offered == "none"` emits an empty client_shares (length 0).
* `offered` empty means offer every supported group.
* Unknown / unsupported offered names are ignored.
*/
Vector!ubyte generateTls13ClientHelloKeyShare(string groups, string offered, RandomNumberGenerator rng)
{
    auto supported = splitGroups(groups);
    string[] want;
    if (offered == "none")
        want = [];
    else if (!offered.length)
        want = supported;
    else
        want = splitGroups(offered);

    Vector!TLS13KeyShareEntry ents;
    foreach (g; supported)
    {
        if (!canFind(want, g))
            continue;
        const ushort id = tls13NamedGroup(g);
        if (!id)
            continue;
        auto pub = tls13OfferShare(g, rng);
        if (pub.empty)
            continue;
        auto e = new TLS13KeyShareEntry;
        e.group = id;
        e.key_exchange = pub.move();
        ents.pushBack(e);
    }
    Unique!TLS13KeyShare ks = new TLS13KeyShare(TLS13KeyShare.Kind.Client, ents.move());
    return ks.serialize();
}
