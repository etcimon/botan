/**
* TLS 1.3 ClientHello / ServerHello extensions (RFC 8446 4.2)
*
* Copyright:
* (C) 2011,2012,2015,2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.hello_ext;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.tls.extensions;
import botan.tls.version_;
import botan.tls.magic;
import botan.tls.reader;
import botan.tls.exceptn;
import botan.tls.alert;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.get_byte;

/// IANA NamedGroup / key_share identifiers used by TLS 1.3 emit/agree.
enum ushort TLS13_GROUP_SECP256R1 = 0x0017;
enum ushort TLS13_GROUP_X25519 = 0x001d;
enum ushort TLS13_GROUP_FFDHE_2048 = 0x0100;
/// draft-kwiatkowski-tls-ecdhe-mlkem (IANA).
enum ushort TLS13_GROUP_SECP256R1_MLKEM768 = 0x11EB;
enum ushort TLS13_GROUP_X25519_MLKEM768 = 0x11EC;
enum ushort TLS13_GROUP_SECP384R1_MLKEM1024 = 0x11ED;
/// draft-connolly-tls-mlkem-key-agreement
enum ushort TLS13_GROUP_MLKEM512 = 0x0200;
enum ushort TLS13_GROUP_MLKEM768 = 0x0201;
enum ushort TLS13_GROUP_MLKEM1024 = 0x0202;
enum size_t TLS13_X25519_SHARE_LEN = 32;
enum size_t TLS13_SECP256R1_PUB_LEN = 65;
enum size_t TLS13_SECP384R1_PUB_LEN = 97;
enum size_t TLS13_SECP256R1_SS_LEN = 32;
enum size_t TLS13_SECP384R1_SS_LEN = 48;
enum size_t TLS13_MLKEM512_PK_LEN = 800;
enum size_t TLS13_MLKEM512_CT_LEN = 768;
enum size_t TLS13_MLKEM768_PK_LEN = 1184;
enum size_t TLS13_MLKEM768_CT_LEN = 1088;
enum size_t TLS13_MLKEM1024_PK_LEN = 1568;
enum size_t TLS13_MLKEM1024_CT_LEN = 1568;
enum size_t TLS13_HYBRID_CH_SHARE_LEN = TLS13_MLKEM768_PK_LEN + TLS13_X25519_SHARE_LEN; // 1216
enum size_t TLS13_HYBRID_SH_SHARE_LEN = TLS13_MLKEM768_CT_LEN + TLS13_X25519_SHARE_LEN; // 1120
enum size_t TLS13_HYBRID_SS_LEN = 32 + TLS13_X25519_SHARE_LEN; // concat, not SHA-3-256
enum size_t TLS13_P256_HYBRID_CH_LEN = TLS13_SECP256R1_PUB_LEN + TLS13_MLKEM768_PK_LEN; // 1249
enum size_t TLS13_P256_HYBRID_SH_LEN = TLS13_SECP256R1_PUB_LEN + TLS13_MLKEM768_CT_LEN; // 1153
enum size_t TLS13_P256_HYBRID_SS_LEN = TLS13_SECP256R1_SS_LEN + 32; // ECDH first
enum size_t TLS13_P384_HYBRID_CH_LEN = TLS13_SECP384R1_PUB_LEN + TLS13_MLKEM1024_PK_LEN; // 1665
enum size_t TLS13_P384_HYBRID_SH_LEN = TLS13_SECP384R1_PUB_LEN + TLS13_MLKEM1024_CT_LEN; // 1665
enum size_t TLS13_P384_HYBRID_SS_LEN = TLS13_SECP384R1_SS_LEN + 32; // ECDH first
enum string TLS13_GROUP_X25519_MLKEM768_NAME = "x25519/ML-KEM-768";
enum string TLS13_GROUP_SECP256R1_MLKEM768_NAME = "secp256r1/ML-KEM-768";
enum string TLS13_GROUP_SECP384R1_MLKEM1024_NAME = "secp384r1/ML-KEM-1024";
enum string TLS13_GROUP_MLKEM512_NAME = "ML-KEM-512";
enum string TLS13_GROUP_MLKEM768_NAME = "ML-KEM-768";
enum string TLS13_GROUP_MLKEM1024_NAME = "ML-KEM-1024";

/// libOQS NamedGroup codes (C++ tls_algos.h). Classical first, then eFrodo.
enum ushort TLS13_GROUP_EFRODO_640_AES = 0xFE00;
enum ushort TLS13_GROUP_SECP256_EFRODO_640_AES = 0xFE01;
enum ushort TLS13_GROUP_X25519_EFRODO_640_AES = 0xFE02;
enum ushort TLS13_GROUP_EFRODO_640_SHAKE = 0xFE03;
enum ushort TLS13_GROUP_SECP256_EFRODO_640_SHAKE = 0xFE04;
enum ushort TLS13_GROUP_X25519_EFRODO_640_SHAKE = 0xFE05;
enum ushort TLS13_GROUP_EFRODO_976_AES = 0xFE06;
enum ushort TLS13_GROUP_SECP384_EFRODO_976_AES = 0xFE07;
enum ushort TLS13_GROUP_X448_EFRODO_976_AES = 0xFE08;
enum ushort TLS13_GROUP_EFRODO_976_SHAKE = 0xFE09;
enum ushort TLS13_GROUP_SECP384_EFRODO_976_SHAKE = 0xFE0A;
enum ushort TLS13_GROUP_X448_EFRODO_976_SHAKE = 0xFE0B;
enum ushort TLS13_GROUP_EFRODO_1344_AES = 0xFE0C;
enum ushort TLS13_GROUP_SECP521_EFRODO_1344_AES = 0xFE0D;
enum ushort TLS13_GROUP_EFRODO_1344_SHAKE = 0xFE0E;
enum ushort TLS13_GROUP_SECP521_EFRODO_1344_SHAKE = 0xFE0F;
enum size_t TLS13_X448_SHARE_LEN = 56;
enum size_t TLS13_SECP521R1_PUB_LEN = 133;
enum size_t TLS13_SECP521R1_SS_LEN = 66;
enum size_t TLS13_EFRODO_640_PK_LEN = 9616;
enum size_t TLS13_EFRODO_640_CT_LEN = 9720;
enum size_t TLS13_EFRODO_640_SS_LEN = 16;
enum size_t TLS13_EFRODO_976_PK_LEN = 15632;
enum size_t TLS13_EFRODO_976_CT_LEN = 15744;
enum size_t TLS13_EFRODO_976_SS_LEN = 24;
enum size_t TLS13_EFRODO_1344_PK_LEN = 21520;
enum size_t TLS13_EFRODO_1344_CT_LEN = 21632;
enum size_t TLS13_EFRODO_1344_SS_LEN = 32;
enum string TLS13_GROUP_EFRODO_640_SHAKE_NAME = "eFrodoKEM-640-SHAKE";
enum string TLS13_GROUP_EFRODO_640_AES_NAME = "eFrodoKEM-640-AES";
enum string TLS13_GROUP_EFRODO_976_SHAKE_NAME = "eFrodoKEM-976-SHAKE";
enum string TLS13_GROUP_EFRODO_976_AES_NAME = "eFrodoKEM-976-AES";
enum string TLS13_GROUP_EFRODO_1344_SHAKE_NAME = "eFrodoKEM-1344-SHAKE";
enum string TLS13_GROUP_EFRODO_1344_AES_NAME = "eFrodoKEM-1344-AES";
enum string TLS13_GROUP_X25519_EFRODO_640_SHAKE_NAME = "x25519/eFrodoKEM-640-SHAKE";
enum string TLS13_GROUP_X25519_EFRODO_640_AES_NAME = "x25519/eFrodoKEM-640-AES";
enum string TLS13_GROUP_X448_EFRODO_976_SHAKE_NAME = "x448/eFrodoKEM-976-SHAKE";
enum string TLS13_GROUP_X448_EFRODO_976_AES_NAME = "x448/eFrodoKEM-976-AES";
enum string TLS13_GROUP_SECP256_EFRODO_640_SHAKE_NAME = "secp256r1/eFrodoKEM-640-SHAKE";
enum string TLS13_GROUP_SECP256_EFRODO_640_AES_NAME = "secp256r1/eFrodoKEM-640-AES";
enum string TLS13_GROUP_SECP384_EFRODO_976_SHAKE_NAME = "secp384r1/eFrodoKEM-976-SHAKE";
enum string TLS13_GROUP_SECP384_EFRODO_976_AES_NAME = "secp384r1/eFrodoKEM-976-AES";
enum string TLS13_GROUP_SECP521_EFRODO_1344_SHAKE_NAME = "secp521r1/eFrodoKEM-1344-SHAKE";
enum string TLS13_GROUP_SECP521_EFRODO_1344_AES_NAME = "secp521r1/eFrodoKEM-1344-AES";

/// Classical component of an OQS Frodo hybrid (`""` = pure eFrodo).
enum string TLS13_FRODO_CLASSICAL_NONE = "";
enum string TLS13_FRODO_CLASSICAL_X25519 = "x25519";
enum string TLS13_FRODO_CLASSICAL_X448 = "x448";
enum string TLS13_FRODO_CLASSICAL_P256 = "secp256r1";
enum string TLS13_FRODO_CLASSICAL_P384 = "secp384r1";
enum string TLS13_FRODO_CLASSICAL_P521 = "secp521r1";

struct Tls13FrodoOqsGroup
{
    ushort id;
    string name;
    string frodo;
    string classical;
    size_t frodo_pk;
    size_t frodo_ct;
    size_t frodo_ss;
    size_t classical_pub;
    size_t classical_ss;

    size_t chLen() const { return classical_pub + frodo_pk; }
    size_t shLen() const { return classical_pub + frodo_ct; }
    size_t ssLen() const { return classical_ss + frodo_ss; }
    bool isPure() const { return classical.length == 0; }
}

immutable Tls13FrodoOqsGroup[16] TLS13_FRODO_OQS_GROUPS = [
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_640_AES, TLS13_GROUP_EFRODO_640_AES_NAME,
        "eFrodoKEM-640-AES", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP256_EFRODO_640_AES, TLS13_GROUP_SECP256_EFRODO_640_AES_NAME,
        "eFrodoKEM-640-AES", TLS13_FRODO_CLASSICAL_P256,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN,
        TLS13_SECP256R1_PUB_LEN, TLS13_SECP256R1_SS_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_X25519_EFRODO_640_AES, TLS13_GROUP_X25519_EFRODO_640_AES_NAME,
        "eFrodoKEM-640-AES", TLS13_FRODO_CLASSICAL_X25519,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN,
        TLS13_X25519_SHARE_LEN, TLS13_X25519_SHARE_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_640_SHAKE, TLS13_GROUP_EFRODO_640_SHAKE_NAME,
        "eFrodoKEM-640-SHAKE", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP256_EFRODO_640_SHAKE, TLS13_GROUP_SECP256_EFRODO_640_SHAKE_NAME,
        "eFrodoKEM-640-SHAKE", TLS13_FRODO_CLASSICAL_P256,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN,
        TLS13_SECP256R1_PUB_LEN, TLS13_SECP256R1_SS_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_X25519_EFRODO_640_SHAKE, TLS13_GROUP_X25519_EFRODO_640_SHAKE_NAME,
        "eFrodoKEM-640-SHAKE", TLS13_FRODO_CLASSICAL_X25519,
        TLS13_EFRODO_640_PK_LEN, TLS13_EFRODO_640_CT_LEN, TLS13_EFRODO_640_SS_LEN,
        TLS13_X25519_SHARE_LEN, TLS13_X25519_SHARE_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_976_AES, TLS13_GROUP_EFRODO_976_AES_NAME,
        "eFrodoKEM-976-AES", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP384_EFRODO_976_AES, TLS13_GROUP_SECP384_EFRODO_976_AES_NAME,
        "eFrodoKEM-976-AES", TLS13_FRODO_CLASSICAL_P384,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN,
        TLS13_SECP384R1_PUB_LEN, TLS13_SECP384R1_SS_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_X448_EFRODO_976_AES, TLS13_GROUP_X448_EFRODO_976_AES_NAME,
        "eFrodoKEM-976-AES", TLS13_FRODO_CLASSICAL_X448,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN,
        TLS13_X448_SHARE_LEN, TLS13_X448_SHARE_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_976_SHAKE, TLS13_GROUP_EFRODO_976_SHAKE_NAME,
        "eFrodoKEM-976-SHAKE", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP384_EFRODO_976_SHAKE, TLS13_GROUP_SECP384_EFRODO_976_SHAKE_NAME,
        "eFrodoKEM-976-SHAKE", TLS13_FRODO_CLASSICAL_P384,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN,
        TLS13_SECP384R1_PUB_LEN, TLS13_SECP384R1_SS_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_X448_EFRODO_976_SHAKE, TLS13_GROUP_X448_EFRODO_976_SHAKE_NAME,
        "eFrodoKEM-976-SHAKE", TLS13_FRODO_CLASSICAL_X448,
        TLS13_EFRODO_976_PK_LEN, TLS13_EFRODO_976_CT_LEN, TLS13_EFRODO_976_SS_LEN,
        TLS13_X448_SHARE_LEN, TLS13_X448_SHARE_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_1344_AES, TLS13_GROUP_EFRODO_1344_AES_NAME,
        "eFrodoKEM-1344-AES", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_1344_PK_LEN, TLS13_EFRODO_1344_CT_LEN, TLS13_EFRODO_1344_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP521_EFRODO_1344_AES, TLS13_GROUP_SECP521_EFRODO_1344_AES_NAME,
        "eFrodoKEM-1344-AES", TLS13_FRODO_CLASSICAL_P521,
        TLS13_EFRODO_1344_PK_LEN, TLS13_EFRODO_1344_CT_LEN, TLS13_EFRODO_1344_SS_LEN,
        TLS13_SECP521R1_PUB_LEN, TLS13_SECP521R1_SS_LEN),
    Tls13FrodoOqsGroup(TLS13_GROUP_EFRODO_1344_SHAKE, TLS13_GROUP_EFRODO_1344_SHAKE_NAME,
        "eFrodoKEM-1344-SHAKE", TLS13_FRODO_CLASSICAL_NONE,
        TLS13_EFRODO_1344_PK_LEN, TLS13_EFRODO_1344_CT_LEN, TLS13_EFRODO_1344_SS_LEN, 0, 0),
    Tls13FrodoOqsGroup(TLS13_GROUP_SECP521_EFRODO_1344_SHAKE, TLS13_GROUP_SECP521_EFRODO_1344_SHAKE_NAME,
        "eFrodoKEM-1344-SHAKE", TLS13_FRODO_CLASSICAL_P521,
        TLS13_EFRODO_1344_PK_LEN, TLS13_EFRODO_1344_CT_LEN, TLS13_EFRODO_1344_SS_LEN,
        TLS13_SECP521R1_PUB_LEN, TLS13_SECP521R1_SS_LEN),
];

bool tls13IsFrodoOqsName(in string n)
{
    foreach (g; TLS13_FRODO_OQS_GROUPS)
        if (g.name == n)
            return true;
    return false;
}

const(Tls13FrodoOqsGroup)* tls13FrodoOqsByName(in string n)
{
    foreach (i, ref g; TLS13_FRODO_OQS_GROUPS)
        if (g.name == n)
            return &TLS13_FRODO_OQS_GROUPS[i];
    return null;
}

const(Tls13FrodoOqsGroup)* tls13FrodoOqsById(ushort id)
{
    foreach (i, ref g; TLS13_FRODO_OQS_GROUPS)
        if (g.id == id)
            return &TLS13_FRODO_OQS_GROUPS[i];
    return null;
}

/// RFC 8446 4.2.1
final class TLS13SupportedVersions : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SUPPORTED_VERSIONS; }
    override HandshakeExtensionType type() const { return staticType(); }

    this(TLSProtocolVersion selected)
    {
        m_versions.pushBack(selected);
        m_from_server = true;
    }

    this(Vector!TLSProtocolVersion versions)
    {
        m_versions = versions.move();
        m_from_server = false;
    }

    this(ref TLSDataReader reader, ushort extension_size, bool from_server)
    {
        if (from_server || extension_size == 2)
        {
            if (extension_size != 2)
                throw new DecodingError("Server sent invalid supported_versions extension");
            auto code = reader.get_ushort();
            m_versions.pushBack(TLSProtocolVersion(cast(ubyte)(code >> 8), cast(ubyte) code));
            m_from_server = true;
        }
        else
        {
            auto vers = reader.getRange!ushort(1, 1, 127);
            foreach (v; vers[])
                m_versions.pushBack(TLSProtocolVersion(cast(ubyte)(v >> 8), cast(ubyte) v));
            if (extension_size != 1 + 2 * vers.length)
                throw new DecodingError("Client sent invalid supported_versions extension");
            m_from_server = false;
        }
    }

    bool supports(TLSProtocolVersion v) const
    {
        foreach (ver; m_versions[])
            if (ver == v)
                return true;
        return false;
    }

    ref const(Vector!TLSProtocolVersion) versions() const { return m_versions; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        if (m_from_server)
        {
            buf.pushBack(m_versions[0].majorVersion());
            buf.pushBack(m_versions[0].minorVersion());
        }
        else
        {
            buf.pushBack(cast(ubyte)(m_versions.length * 2));
            foreach (ver; m_versions[])
            {
                buf.pushBack(ver.majorVersion());
                buf.pushBack(ver.minorVersion());
            }
        }
        return buf.move();
    }

    override @property bool empty() const { return m_versions.empty; }

private:
    Vector!TLSProtocolVersion m_versions;
    bool m_from_server;
}

/// Heap object so Vector!TLS13KeyShareEntry stores references (Vector!ubyte is not copyable).
final class TLS13KeyShareEntry
{
    ushort group;
    Vector!ubyte key_exchange;
}

/// RFC 8446 4.2.8
final class TLS13KeyShare : Extension
{
public:
    enum Kind : ubyte { Client, Server, HelloRetry }

    static HandshakeExtensionType staticType() { return TLSEXT_KEY_SHARE; }
    override HandshakeExtensionType type() const { return staticType(); }

    /// Emit constructor (Client offers, Server selected share, or HRR group).
    this(Kind kind, Vector!TLS13KeyShareEntry entries)
    {
        m_kind = kind;
        m_entries = entries.move();
    }

    this(ref TLSDataReader reader, ushort extension_size, bool from_server)
    {
        Kind kind = Kind.Client;
        if (from_server)
            kind = (extension_size == 2) ? Kind.HelloRetry : Kind.Server;
        this(reader, extension_size, kind);
    }

    this(ref TLSDataReader reader, ushort extension_size, Kind kind)
    {
        m_kind = kind;
        if (kind == Kind.HelloRetry)
        {
            if (extension_size != 2)
                throw new DecodingError("Size of KeyShare extension in HelloRetryRequest must be 2 bytes");
            auto e = new TLS13KeyShareEntry;
            e.group = reader.get_ushort();
            m_entries.pushBack(e);
        }
        else if (kind == Kind.Server)
        {
            auto e = new TLS13KeyShareEntry;
            e.group = reader.get_ushort();
            e.key_exchange = reader.getRange!ubyte(2, 1, 65535);
            m_entries.pushBack(e);
        }
        else
        {
            const auto list_len = reader.get_ushort();
            if (reader.remainingBytes() < list_len)
                throw new TLSException(TLSAlert.DECODE_ERROR, "Inconsistent length in client KeyShare extension");
            const size_t end = reader.remainingBytes() - list_len;
            while (reader.remainingBytes() > end)
            {
                if (reader.remainingBytes() - end < 4)
                    throw new TLSException(TLSAlert.DECODE_ERROR, "Not enough data to read another KeyShareEntry");
                auto e = new TLS13KeyShareEntry;
                e.group = reader.get_ushort();
                e.key_exchange = reader.getRange!ubyte(2, 1, 65535);
                m_entries.pushBack(e);
            }
            if (reader.remainingBytes() != end)
                throw new TLSException(TLSAlert.DECODE_ERROR, "Inconsistent length in client KeyShare extension");
        }
    }

    Kind kind() const { return m_kind; }
    ref const(Vector!TLS13KeyShareEntry) entries() const { return m_entries; }

    Vector!ushort offeredGroups() const
    {
        Vector!ushort g;
        foreach (e; m_entries[])
            g.pushBack(e.group);
        return g.move();
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        if (m_kind == Kind.HelloRetry)
        {
            buf.pushBack(get_byte(0, m_entries[0].group));
            buf.pushBack(get_byte(1, m_entries[0].group));
            return buf.move();
        }
        Vector!ubyte body;
        foreach (e; m_entries[])
        {
            body.pushBack(get_byte(0, e.group));
            body.pushBack(get_byte(1, e.group));
            body.pushBack(get_byte(0, cast(ushort) e.key_exchange.length));
            body.pushBack(get_byte(1, cast(ushort) e.key_exchange.length));
            body ~= e.key_exchange[];
        }
        if (m_kind == Kind.Client)
        {
            buf.pushBack(get_byte(0, cast(ushort) body.length));
            buf.pushBack(get_byte(1, cast(ushort) body.length));
        }
        buf ~= body[];
        return buf.move();
    }

    override @property bool empty() const { return m_entries.empty; }

    ~this()
    {
        // Unique/stack destroy: free KeyShareEntry Vectors now.
        // GC finalizer: leave entries for the collector (Unique!(T,void) rule).
        if (botanInGcFinalizer())
            return;
        foreach (e; m_entries[])
            botanDestroyIfLive(e);
        m_entries.clear();
    }

private:
    Kind m_kind;
    Vector!TLS13KeyShareEntry m_entries;
}

/// RFC 8446 4.2.2
final class TLS13Cookie : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_COOKIE; }
    override HandshakeExtensionType type() const { return staticType(); }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        // RFC 8446 4.2.2: opaque cookie<1..2^16-1> → min 3 bytes on the wire.
        if (extension_size < 3)
            throw new DecodingError("Empty cookie extension is illegal");
        const ushort len = reader.get_ushort();
        if (cast(size_t)len + 2 != extension_size)
            throw new DecodingError("Inconsistent length in cookie extension");
        m_cookie = reader.getFixed!ubyte(len);
    }

    ref const(Vector!ubyte) cookie() const { return m_cookie; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.pushBack(get_byte(0, cast(ushort) m_cookie.length));
        buf.pushBack(get_byte(1, cast(ushort) m_cookie.length));
        buf ~= m_cookie[];
        return buf.move();
    }

    override @property bool empty() const { return m_cookie.empty; }

private:
    Vector!ubyte m_cookie;
}

/// RFC 8446 4.2.9
final class TLS13PskKeyExchangeModes : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_PSK_KEY_EXCHANGE_MODES; }
    override HandshakeExtensionType type() const { return staticType(); }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        m_modes = reader.getRange!ubyte(1, 1, 255);
        if (m_modes.length + 1 != extension_size)
            throw new DecodingError("Bad encoding for psk_key_exchange_modes");
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.pushBack(cast(ubyte) m_modes.length);
        buf ~= m_modes[];
        return buf.move();
    }

    override @property bool empty() const { return m_modes.empty; }

private:
    Vector!ubyte m_modes;
}

/// RFC 8449
final class TLS13RecordSizeLimit : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_RECORD_SIZE_LIMIT; }
    override HandshakeExtensionType type() const { return staticType(); }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        if (extension_size != 2)
            throw new DecodingError("Bad record_size_limit extension");
        m_limit = reader.get_ushort();
    }

    ushort limit() const { return m_limit; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.pushBack(get_byte(0, m_limit));
        buf.pushBack(get_byte(1, m_limit));
        return buf.move();
    }

    override @property bool empty() const { return false; }

private:
    ushort m_limit;
}

Extension makeTls13Extension(ref TLSDataReader reader, ushort code, ushort size, bool from_server)
{
    switch (code)
    {
        case TLSEXT_SUPPORTED_VERSIONS:
            return new TLS13SupportedVersions(reader, size, from_server);
        case TLSEXT_KEY_SHARE:
            return new TLS13KeyShare(reader, size, from_server);
        case TLSEXT_COOKIE:
            return new TLS13Cookie(reader, size);
        case TLSEXT_PSK_KEY_EXCHANGE_MODES:
            return new TLS13PskKeyExchangeModes(reader, size);
        case TLSEXT_RECORD_SIZE_LIMIT:
            return new TLS13RecordSizeLimit(reader, size);
        default:
            return null;
    }
}
