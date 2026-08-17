/**
* Roughtime
*
* Copyright:
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.roughtime;

import botan.constants;
static if (BOTAN_HAS_ROUGHTIME):

import botan.pubkey.algo.ed25519;
import botan.hash.hash;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.codec.base64;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import std.string : indexOf, splitLines;

/// C++ `Roughtime::request_min_size`
enum size_t ROUGHTIME_REQUEST_MIN_SIZE = 1024;

/// C++ `Roughtime::Roughtime_Error` (`Decoding_Error("Roughtime", s)`).
final class RoughtimeError : DecodingError
{
    this(string s, string file = __FILE__, int line = __LINE__)
    {
        super("Roughtime: " ~ s, null, file, line);
    }
}

/// 64-byte Roughtime nonce (C++ `Roughtime::Nonce`).
struct RoughtimeNonce
{
    this(const(ubyte)[] nonce)
    {
        if (nonce.length != 64)
            throw new InvalidArgument("Roughtime nonce must be 64 bytes long");
        m_nonce[] = nonce[0 .. 64];
    }

    this(RandomNumberGenerator rng)
    {
        rng.randomize(m_nonce.ptr, 64);
    }

    this(in ubyte[64] nonce)
    {
        m_nonce = nonce;
    }

    bool opEquals(const ref RoughtimeNonce rhs) const
    {
        return sameMem(m_nonce.ptr, rhs.m_nonce.ptr, 64);
    }

    ref const(ubyte[64]) getNonce() const { return m_nonce; }

private:
    ubyte[64] m_nonce;
}

/// C++ `encode_request`: LE num_tags=2, first-end=64, tags NONC / PAD\xff, 64-byte nonce, zero-pad to 1024.
Vector!ubyte encodeRequest(const ref RoughtimeNonce nonce)
{
    auto buf = Vector!ubyte(ROUGHTIME_REQUEST_MIN_SIZE);
    buf[0] = 2;
    buf[4] = 64;
    buf[8] = 'N';
    buf[9] = 'O';
    buf[10] = 'N';
    buf[11] = 'C';
    buf[12] = 'P';
    buf[13] = 'A';
    buf[14] = 'D';
    buf[15] = 0xff;
    buf[16 .. 80] = nonce.getNonce()[];
    return buf;
}

/// C++ `RoughTime v1 response signature\0` (32) and `RoughTime v1 delegation signature--\0` (36).
private enum string ROUGHTIME_RESPONSE_CONTEXT = "RoughTime v1 response signature\0";
private enum string ROUGHTIME_DELEGATION_CONTEXT = "RoughTime v1 delegation signature--\0";
static assert(ROUGHTIME_RESPONSE_CONTEXT.length == 32);
static assert(ROUGHTIME_DELEGATION_CONTEXT.length == 36);

private string roughtimeLabel(const(ubyte)* p)
{
    char[5] tmp = 0;
    foreach (i; 0 .. 4)
    {
        tmp[i] = cast(char) p[i];
        if (p[i] == 0)
            break;
    }
    import std.string : fromStringz;
    return fromStringz(tmp.ptr).idup;
}

/// C++ `unpack_roughtime_packet`. `num_tags` is only `buf[0]` (not the full LE u32).
private Vector!ubyte[string] unpackRoughtimePacket(const(ubyte)[] bytes)
{
    if (bytes.length < 8)
        throw new RoughtimeError("Map length is under minimum of 8 bytes");
    const(ubyte)* buf = bytes.ptr;
    const uint num_tags = buf[0];
    const uint start_content = num_tags * 8;
    if (start_content > bytes.length)
        throw new RoughtimeError("Map length too small to contain all tags");
    uint start = start_content;
    Vector!ubyte[string] tags;
    foreach (uint i; 0 .. num_tags)
    {
        size_t end = bytes.length;
        if ((i + 1) != num_tags)
        {
            const ulong tag_end = cast(ulong) start_content
                + loadLittleEndian!uint(buf + 4 + i * 4, 0);
            if (tag_end > size_t.max)
                throw new RoughtimeError("Tag end index out of bounds");
            end = cast(size_t) tag_end;
        }
        if (end > bytes.length)
            throw new RoughtimeError("Tag end index out of bounds");
        if (end < start)
            throw new RoughtimeError("Tag offset must be more than previous tag offset");
        const string label = roughtimeLabel(buf + (num_tags + i) * 4);
        if (label in tags)
            throw new RoughtimeError("Map has duplicated tag: " ~ label);
        tags[label] = Vector!ubyte(buf[start .. end]);
        start = cast(uint) end;
    }
    return tags;
}

private const(Vector!ubyte)* getTag(const ref Vector!ubyte[string] map, string label)
{
    auto p = label in map;
    if (!p)
        throw new RoughtimeError("Tag " ~ label ~ " not found");
    return p;
}

private void getExact(size_t N)(const ref Vector!ubyte[string] map, string label, ubyte* dest)
{
    auto tag = getTag(map, label);
    if (tag.length != N)
        throw new RoughtimeError("Tag " ~ label ~ " has unexpected size");
    dest[0 .. N] = (*tag)[0 .. N];
}

private uint getU32(const ref Vector!ubyte[string] map, string label)
{
    ubyte[4] raw;
    getExact!4(map, label, raw.ptr);
    return loadLittleEndian!uint(raw.ptr, 0);
}

private ulong getU64(const ref Vector!ubyte[string] map, string label)
{
    ubyte[8] raw;
    getExact!8(map, label, raw.ptr);
    return loadLittleEndian!ulong(raw.ptr, 0);
}

private bool verifyRoughtimeSignature(const(ubyte)* pk, const(ubyte)* payload, size_t payload_len,
                                      const(ubyte)* signature, const(ubyte)* context, size_t context_len)
{
    auto msg = Vector!ubyte();
    if (context_len)
        msg ~= context[0 .. context_len];
    if (payload_len)
        msg ~= payload[0 .. payload_len];
    return ed25519Verify(msg.ptr, msg.length, signature, pk, null, 0);
}

private ubyte[64] hashLeaf(const ref ubyte[64] leaf)
{
    Unique!HashFunction hash = retrieveHash("SHA-512").clone();
    ubyte z = 0;
    hash.update(&z, 1);
    hash.update(leaf.ptr, 64);
    auto dig = hash.finished();
    ubyte[64] ret;
    ret[] = dig[0 .. 64];
    return ret;
}

private void hashNode(ref ubyte[64] hash, const(ubyte)* node, bool reverse)
{
    Unique!HashFunction h = retrieveHash("SHA-512").clone();
    ubyte one = 1;
    h.update(&one, 1);
    if (reverse)
    {
        h.update(node, 64);
        h.update(hash.ptr, 64);
    }
    else
    {
        h.update(hash.ptr, 64);
        h.update(node, 64);
    }
    auto dig = h.finished();
    hash[] = dig[0 .. 64];
}

/// Parsed Roughtime response (C++ `Roughtime::Response`).
struct RoughtimeResponse
{
    static RoughtimeResponse fromBits(const(ubyte)[] response, const ref RoughtimeNonce nonce)
    {
        auto response_v = unpackRoughtimePacket(response);
        auto cert = unpackRoughtimePacket((*getTag(response_v, "CERT"))[]);
        ubyte[72] cert_dele;
        ubyte[64] cert_sig;
        getExact!72(cert, "DELE", cert_dele.ptr);
        getExact!64(cert, "SIG", cert_sig.ptr);
        auto cert_dele_v = unpackRoughtimePacket(cert_dele[]);
        auto srep = getTag(response_v, "SREP");
        auto srep_v = unpackRoughtimePacket((*srep)[]);

        ubyte[32] cert_dele_pubk;
        getExact!32(cert_dele_v, "PUBK", cert_dele_pubk.ptr);
        ubyte[64] sig;
        getExact!64(response_v, "SIG", sig.ptr);
        if (!verifyRoughtimeSignature(cert_dele_pubk.ptr, srep.ptr, srep.length, sig.ptr,
                                     cast(const(ubyte)*) ROUGHTIME_RESPONSE_CONTEXT.ptr,
                                     ROUGHTIME_RESPONSE_CONTEXT.length))
            throw new RoughtimeError("Response signature invalid");

        const uint indx = getU32(response_v, "INDX");
        auto path = getTag(response_v, "PATH");
        ubyte[64] srep_root;
        getExact!64(srep_v, "ROOT", srep_root.ptr);
        const size_t size = path.length;
        const size_t levels = size / 64;
        if (size % 64 != 0)
            throw new RoughtimeError("Merkle tree path size must be multiple of 64 bytes");
        if (levels >= 32 || indx >= (cast(uint) 1 << levels))
            throw new RoughtimeError("Merkle tree path is too short");

        auto hash = hashLeaf(nonce.getNonce());
        uint index = indx;
        foreach (level; 0 .. levels)
        {
            hashNode(hash, path.ptr + level * 64, (index % 2) == 1);
            index >>= 1;
        }
        if (!sameMem(srep_root.ptr, hash.ptr, 64))
            throw new RoughtimeError("Nonce verification failed");

        const ulong cert_dele_maxt = getU64(cert_dele_v, "MAXT");
        const ulong cert_dele_mint = getU64(cert_dele_v, "MINT");
        const ulong srep_midp = getU64(srep_v, "MIDP");
        const uint srep_radi = getU32(srep_v, "RADI");
        if (srep_midp < cert_dele_mint)
            throw new RoughtimeError("Midpoint earlier than delegation start");
        if (srep_midp > cert_dele_maxt)
            throw new RoughtimeError("Midpoint later than delegation end");

        RoughtimeResponse r;
        r.m_cert_dele = cert_dele;
        r.m_cert_sig = cert_sig;
        r.m_utc_midpoint = srep_midp;
        r.m_utc_radius = srep_radi;
        return r;
    }

    bool validate(const ref Ed25519PublicKey pk) const
    {
        auto pub = pk.publicValue();
        if (pub.length != 32)
            return false;
        return validate(pub.ptr);
    }

    bool validate(const(ubyte)* pk) const
    {
        return verifyRoughtimeSignature(pk, m_cert_dele.ptr, 72, m_cert_sig.ptr,
                                        cast(const(ubyte)*) ROUGHTIME_DELEGATION_CONTEXT.ptr,
                                        ROUGHTIME_DELEGATION_CONTEXT.length);
    }

    ulong utcMidpoint() const { return m_utc_midpoint; }
    uint utcRadius() const { return m_utc_radius; }

private:
    ubyte[72] m_cert_dele;
    ubyte[64] m_cert_sig;
    ulong m_utc_midpoint;
    uint m_utc_radius;
}

/// C++ `nonce_from_blind`: SHA-512(SHA-512(prev) ‖ blind). `finished()` resets like C++ `final()`.
RoughtimeNonce nonceFromBlind(const(ubyte)[] previous_response, const ref RoughtimeNonce blind)
{
    Unique!HashFunction hash = retrieveHash("SHA-512").clone();
    if (previous_response.length)
        hash.update(previous_response.ptr, previous_response.length);
    auto inner = hash.finished();
    hash.update(inner.ptr, inner.length);
    hash.update(blind.getNonce().ptr, 64);
    auto dig = hash.finished();
    ubyte[64] ret;
    ret[] = dig[0 .. 64];
    return RoughtimeNonce(ret);
}

/// One response in a Roughtime chain (C++ `Roughtime::Link`).
struct RoughtimeLink
{
    this(const(ubyte)[] response, const(ubyte)[] public_key, const ref RoughtimeNonce nonce_or_blind)
    {
        m_response = response.dup;
        m_public_key = public_key.dup;
        m_nonce_or_blind = nonce_or_blind;
    }

    const(ubyte)[] response() const { return m_response; }
    const(ubyte)[] publicKey() const { return m_public_key; }
    ref const(RoughtimeNonce) nonceOrBlind() const { return m_nonce_or_blind; }
    ref RoughtimeNonce nonceOrBlind() { return m_nonce_or_blind; }

private:
    ubyte[] m_response;
    ubyte[] m_public_key;
    RoughtimeNonce m_nonce_or_blind;
}

/// C++ `Roughtime::Chain`.
struct RoughtimeChain
{
    this(string str)
    {
        enum err4 = "Line does not have 4 space separated fields";
        foreach (s; str.splitLines())
        {
            if (!s.length)
                throw new DecodingError(err4);
            size_t start = 0;
            auto end = s.indexOf(' ', start);
            if (end < 0)
                throw new DecodingError(err4);
            const string publicKeyType = s[start .. end];
            if (publicKeyType != "ed25519")
                throw new InvalidArgument("Only ed25519 publicKeyType is implemented");

            start = end + 1;
            end = s.indexOf(' ', start);
            if (end < 0)
                throw new DecodingError(err4);
            auto pk_raw = base64Decode(s[start .. end]);
            auto serverPublicKey = Vector!ubyte(pk_raw[]);

            start = end + 1;
            end = s.indexOf(' ', start);
            if (end < 0)
                throw new DecodingError(err4);
            if ((end - start) != 88)
                throw new DecodingError("Nonce has invalid length");
            auto nonce_raw = base64Decode(s[start .. end]);
            if (nonce_raw.length != 64)
                throw new DecodingError("Nonce has invalid length");
            auto nonceOrBlind = RoughtimeNonce(nonce_raw[]);

            start = end + 1;
            end = s.indexOf(' ', start);
            if (end >= 0)
                throw new DecodingError(err4);
            auto resp_raw = base64Decode(s[start .. $]);
            m_links ~= RoughtimeLink(resp_raw[], serverPublicKey[], nonceOrBlind);
        }
    }

    const(RoughtimeLink[]) links() const { return m_links; }

    RoughtimeResponse[] responses() const
    {
        RoughtimeResponse[] outp;
        foreach (i, ref l; m_links)
        {
            RoughtimeNonce nonce;
            if (i > 0)
                nonce = nonceFromBlind(m_links[i - 1].response(), l.nonceOrBlind());
            else
                nonce = l.nonceOrBlind();
            auto response = RoughtimeResponse.fromBits(l.response(), nonce);
            auto pub = Vector!ubyte(l.publicKey());
            auto ekey = Ed25519PublicKey(pub);
            if (!response.validate(ekey))
                throw new RoughtimeError("Invalid signature or public key");
            outp ~= response;
        }
        return outp;
    }

    RoughtimeNonce nextNonce(const ref RoughtimeNonce blind) const
    {
        if (!m_links.length)
            return blind;
        return nonceFromBlind(m_links[$ - 1].response(), blind);
    }

    void append(const ref RoughtimeLink new_link, size_t max_chain_size)
    {
        if (max_chain_size == 0)
            throw new InvalidArgument("Max chain size must be positive");
        auto stored = RoughtimeLink(new_link.response(), new_link.publicKey(), new_link.nonceOrBlind());
        while (m_links.length >= max_chain_size)
        {
            if (m_links.length == 1)
            {
                stored.nonceOrBlind() = nonceFromBlind(m_links[0].response(), stored.nonceOrBlind());
                m_links.length = 0;
                m_links ~= stored;
                return;
            }
            if (m_links.length >= 2)
            {
                m_links[1].nonceOrBlind() = nonceFromBlind(m_links[0].response(), m_links[1].nonceOrBlind());
            }
            m_links = m_links[1 .. $];
        }
        m_links ~= stored;
    }

    string toString() const
    {
        string s;
        foreach (ref link; m_links)
        {
            s ~= "ed25519";
            s ~= ' ';
            s ~= base64Encode(link.publicKey().ptr, link.publicKey().length);
            s ~= ' ';
            s ~= base64Encode(link.nonceOrBlind().getNonce().ptr, 64);
            s ~= ' ';
            s ~= base64Encode(link.response().ptr, link.response().length);
            s ~= '\n';
        }
        return s;
    }

private:
    RoughtimeLink[] m_links;
}

/// C++ `Roughtime::Server_Information`.
struct RoughtimeServerInformation
{
    this(string name, const(ubyte)[] public_key, string[] addresses)
    {
        m_name = name.idup;
        m_public_key = public_key.dup;
        m_addresses = addresses.dup;
    }

    string name() const { return m_name; }
    const(ubyte)[] publicKey() const { return m_public_key; }
    const(string[]) addresses() const { return m_addresses; }

private:
    string m_name;
    ubyte[] m_public_key;
    string[] m_addresses;
}

/// C++ `servers_from_str`. Online UDP is not implemented.
RoughtimeServerInformation[] serversFromStr(string str)
{
    enum err5 = "Line does not have at least 5 space separated fields";
    RoughtimeServerInformation[] servers;
    foreach (s; str.splitLines())
    {
        if (!s.length)
            throw new DecodingError(err5);
        size_t start = 0;
        auto end = s.indexOf(' ', start);
        if (end < 0)
            throw new DecodingError(err5);
        const string name = s[start .. end];

        start = end + 1;
        end = s.indexOf(' ', start);
        if (end < 0)
            throw new DecodingError(err5);
        const string publicKeyType = s[start .. end];
        if (publicKeyType != "ed25519")
            throw new InvalidArgument("Only ed25519 publicKeyType is implemented");

        start = end + 1;
        end = s.indexOf(' ', start);
        if (end < 0)
            throw new DecodingError(err5);
        auto pk_raw = base64Decode(s[start .. end]);
        auto publicKey = Vector!ubyte(pk_raw[]);
        auto ekey = Ed25519PublicKey(publicKey);
        if (ekey.publicValue().length != 32)
            throw new DecodingError("Invalid size for Ed25519 public key");

        start = end + 1;
        end = s.indexOf(' ', start);
        if (end < 0)
            throw new DecodingError(err5);
        const string protocol = s[start .. end];
        if (protocol != "udp")
            throw new InvalidArgument("Only UDP protocol is implemented");

        string[] addr;
        for (;;)
        {
            start = end + 1;
            end = s.indexOf(' ', start);
            const string address = (end < 0) ? s[start .. $] : s[start .. end];
            if (!address.length)
                break;
            addr ~= address;
            if (end < 0)
                break;
        }
        if (!addr.length)
            throw new DecodingError(err5);
        servers ~= RoughtimeServerInformation(name, publicKey[], addr);
    }
    return servers;
}

static if (BOTAN_HAS_TESTS && !SKIP_ROUGHTIME_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.rng.auto_rng;
    import memutils.hashmap;
    import std.stdio : File;
    import std.file : exists;
    import std.conv : to;

    auto state = globalState();
    logDebug("Testing constructs/roughtime ...");
    size_t fails;

    void expectThrow(string label, void delegate() body)
    {
        bool threw;
        try { body(); }
        catch (Exception) { threw = true; }
        if (!threw)
        {
            logError("roughtime expected throw: ", label);
            ++fails;
        }
    }

    if (exists("test_data/roughtime/roughtime_request.vec"))
    {
        File vec = File("test_data/roughtime/roughtime_request.vec", "r");
        fails += runTestsBb(vec, "Kind", "Request", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Nonce" in m) || !("Request" in m))
                    return 0;
                auto nonce = RoughtimeNonce(hexDecode(m["Nonce"])[]);
                auto want = hexDecode(m["Request"]);
                auto got = encodeRequest(nonce);
                const bool eq = got.length == want.length && sameMem(got.ptr, want.ptr, got.length);
                const bool valid = m["Kind"] == "Valid";
                if (valid != eq)
                {
                    logError("roughtime request ", m["Kind"], " mismatch");
                    return 1;
                }
                return 0;
            });
    }

    if (exists("test_data/roughtime/roughtime_response.vec"))
    {
        File vec = File("test_data/roughtime/roughtime_response.vec", "r");
        fails += runTestsBb(vec, "Kind", "Response", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Response" in m))
                    return 0;
                auto response_v = hexDecode(m["Response"]);
                Vector!ubyte nonce_bits;
                if ("Nonce" in m)
                    nonce_bits = hexDecode(m["Nonce"]);
                else
                    nonce_bits = Vector!ubyte(64);
                const bool valid = m["Kind"] == "Valid";
                try
                {
                    auto nonce = RoughtimeNonce(nonce_bits[]);
                    auto response = RoughtimeResponse.fromBits(response_v[], nonce);
                    if (!("Pubkey" in m))
                    {
                        logError("roughtime response missing Pubkey after from_bits");
                        return valid ? 1 : 0;
                    }
                    auto pubkey = hexDecode(m["Pubkey"]);
                    if (pubkey.length != 32)
                        throw new Exception("Unexpected Roughtime Ed25519 pubkey size");
                    auto ekey = Ed25519PublicKey(pubkey);
                    if (!response.validate(ekey))
                        return valid ? 1 : 0;
                    if (!valid)
                    {
                        logError("roughtime response Invalid accepted");
                        return 1;
                    }
                    if (!("MidpointMicroSeconds" in m) || !("RadiusMicroSeconds" in m))
                    {
                        logError("roughtime response Valid missing midpoint/radius");
                        return 1;
                    }
                    const ulong mid = to!ulong(m["MidpointMicroSeconds"]);
                    const uint rad = to!uint(m["RadiusMicroSeconds"]);
                    if (response.utcMidpoint() != mid || response.utcRadius() != rad)
                    {
                        logError("roughtime response midpoint/radius mismatch");
                        return 1;
                    }
                    return 0;
                }
                catch (RoughtimeError)
                {
                    return valid ? 1 : 0;
                }
            });
    }

    if (exists("test_data/roughtime/roughtime_nonce_from_blind.vec"))
    {
        File vec = File("test_data/roughtime/roughtime_nonce_from_blind.vec", "r");
        fails += runTestsBb(vec, "Kind", "Nonce", true,
            (ref HashMap!(string, string) m)
            {
                if (!("Response" in m) || !("Blind" in m) || !("Nonce" in m))
                    return 0;
                auto response = hexDecode(m["Response"]);
                auto blind = RoughtimeNonce(hexDecode(m["Blind"])[]);
                auto nonce = RoughtimeNonce(hexDecode(m["Nonce"])[]);
                auto from_blind = nonceFromBlind(response[], blind);
                const bool eq = nonce == from_blind;
                const bool valid = m["Kind"] == "Valid";
                if (valid != eq)
                {
                    logError("roughtime nonce_from_blind ", m["Kind"], " mismatch");
                    return 1;
                }
                return 0;
            });
    }

    {
        Unique!AutoSeededRNG arng = new AutoSeededRNG;
        ubyte[64] rand64;
        arng.randomize(rand64.ptr, 64);
        auto nonce_v = RoughtimeNonce(rand64[]);
        if (nonce_v.getNonce() != rand64)
            ++fails;
        ubyte[65] over = 0;
        over[0 .. 64] = rand64[];
        expectThrow("vector oversize", { auto n = RoughtimeNonce(over[]); });
        expectThrow("vector undersize", { auto n = RoughtimeNonce(rand64[0 .. 63]); });

        RoughtimeChain c1;
        if (c1.links().length != 0 || c1.responses().length != 0)
            ++fails;
        auto next = c1.nextNonce(nonce_v);
        if (next.getNonce() != rand64)
            ++fails;

        const string chain_str =
            "ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA\n" ~
            "ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= uLeTON9D+2HqJMzK6sYWLNDEdtBl9t/9yw1cVAOm0/sONH5Oqdq9dVPkC9syjuWbglCiCPVF+FbOtcxCkrgMmA== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWOw1jl0uSiBEH9HE8/6r7zxoSc01f48vw+UzH8+VJoPelnvVJBj4lnH8uRLh5Aw0i4Du7XM1dp2u0r/I5PzhMQoDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AUBo+tEqPBQC47l77to7ESFTVhlw1SC74P5ssx6gpuJ6eP+1916GuUiySGE/x3Fp0c3otUGAdsRQou5p9PDTeane/YEeVq4/8AgAAAEAAAABTSUcAREVMRe5T1ml8wHyWAcEtHP/U5Rg/jFXTEXOSglngSa4aI/CECVdy4ZNWeP6vv+2//ZW7lQsrWo7ZkXpvm9BdBONRSQIDAAAAIAAAACgAAABQVUJLTUlOVE1BWFQpXlenV0OfVisvp9jDHXLw8vymZVK9Pgw9k6Edf8ZEhUgSGEc5jwUASHLvZE2PBQAAAAAA\n";

        auto c2 = RoughtimeChain(chain_str);
        if (c2.links().length != 2)
            ++fails;
        auto c2resp = c2.responses();
        if (c2resp.length != 2)
            ++fails;
        if (c2.toString() != chain_str)
        {
            logError("roughtime chain serialize loopback failed");
            ++fails;
        }

        c1.append(c2.links()[0], 1);
        if (c1.links().length != 1 || c1.responses().length != 1)
            ++fails;
        c1.append(c2.links()[1], 1);
        if (c1.links().length != 1 || c1.responses().length != 1)
            ++fails;
        expectThrow("non-positive max chain size", { c1.append(c2.links()[1], 0); });
        expectThrow("1 field", { auto a = RoughtimeChain("ed25519"); });
        expectThrow("2 fields", { auto a = RoughtimeChain("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE="); });
        expectThrow("3 fields", {
            auto a = RoughtimeChain("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw==");
        });
        expectThrow("5 fields", {
            auto a = RoughtimeChain("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA abc");
        });
        expectThrow("invalid key type", {
            auto a = RoughtimeChain("rsa bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");
        });
        expectThrow("invalid key", {
            auto a = RoughtimeChain("ed25519 bbT+RPS7zKX6wssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");
        });
        expectThrow("invalid nonce", {
            auto a = RoughtimeChain("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2UByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");
        });
    }

    {
        const auto servers = serversFromStr(
            "Chainpoint-Roughtime ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002\n" ~
            "Cloudflare-Roughtime ed25519 0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg= udp roughtime.cloudflare.com:2003\n" ~
            "Google-Sandbox-Roughtime ed25519 etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ= udp roughtime.sandbox.google.com:2002\n" ~
            "int08h-Roughtime ed25519 AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE= udp roughtime.int08h.com:2002\n" ~
            "ticktock ed25519 cj8GsiNlRkqiDElAeNMSBBMwrAl15hYPgX50+GWX/lA= udp ticktock.mixmin.net:5333\n");
        if (servers.length != 5)
            ++fails;
        if (servers[0].name() != "Chainpoint-Roughtime" || servers[4].name() != "ticktock")
            ++fails;
        auto want_pk = base64Decode("bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE=");
        if (servers[0].publicKey().length != want_pk.length
            || !sameMem(servers[0].publicKey().ptr, want_pk.ptr, want_pk.length))
            ++fails;
        if (servers[0].addresses().length != 1
            || servers[0].addresses()[0] != "roughtime.chainpoint.org:2002")
            ++fails;

        expectThrow("1 field", { serversFromStr("A"); });
        expectThrow("2 fields", { serversFromStr("A ed25519"); });
        expectThrow("3 fields", { serversFromStr("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE="); });
        expectThrow("4 fields", { serversFromStr("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp"); });
        expectThrow("invalid address", { serversFromStr("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp "); });
        expectThrow("invalid key type", {
            serversFromStr("A rsa bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002");
        });
        expectThrow("invalid key", {
            serversFromStr("A ed25519 bbT+RP7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002");
        });
        expectThrow("invalid protocol", {
            serversFromStr("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= tcp roughtime.chainpoint.org:2002");
        });
    }

    fails += checkMemutilsRepeat("roughtime", {
        ubyte[64] n = 0x41;
        auto nonce = RoughtimeNonce(n[]);
        auto req = encodeRequest(nonce);
        if (req.length != ROUGHTIME_REQUEST_MIN_SIZE)
            throw new Exception("roughtime encode leak probe");
        auto nb = nonceFromBlind(req[], nonce);
        if (nb.getNonce().length != 64)
            throw new Exception("roughtime nonce leak probe");
    });

    testReport("roughtime", 0, fails);
    if (fails)
        logError("roughtime failures: ", fails);
    assert(fails == 0);
}
