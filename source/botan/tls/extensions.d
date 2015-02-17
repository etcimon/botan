/**
* TLS Extensions
* 
* Copyright:
* (C) 2011-2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.extensions;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import memutils.vector;
import botan.tls.magic;
import botan.utils.types;
import memutils.hashmap;
import botan.tls.reader;
import botan.tls.exceptn;
import botan.tls.alert;
import botan.utils.types : Unique;
import botan.utils.get_byte;
import std.conv : to;
import std.array : Appender;

alias ushort HandshakeExtensionType;
enum : HandshakeExtensionType {
    TLSEXT_SERVER_NAME_INDICATION    = 0,
    TLSEXT_MAX_FRAGMENT_LENGTH       = 1,
    TLSEXT_CLIENT_CERT_URL           = 2,
    TLSEXT_TRUSTED_CA_KEYS           = 3,
    TLSEXT_TRUNCATED_HMAC            = 4,

    TLSEXT_CERTIFICATE_TYPES         = 9,
    TLSEXT_USABLE_ELLIPTIC_CURVES    = 10,
    TLSEXT_EC_POINT_FORMATS          = 11,
    TLSEXT_SRP_IDENTIFIER            = 12,
    TLSEXT_SIGNATURE_ALGORITHMS      = 13,
    TLSEXT_HEARTBEAT_SUPPORT         = 15,

    TLSEXT_SESSION_TICKET            = 35,

    TLSEXT_NEXT_PROTOCOL             = 13172,

    TLSEXT_SAFE_RENEGOTIATION        = 65281,
}

/**
* Base class representing a TLS extension of some kind
*/
interface Extension
{
public:
    /**
    * Returns: code number of the extension
    */
    abstract HandshakeExtensionType type() const;

    /**
    * Returns: serialized binary for the extension
    */
    abstract Vector!ubyte serialize() const;

    /**
    * Returns: if we should encode this extension or not
    */
    abstract @property bool empty() const;
}

/**
* TLS Server Name Indicator extension (RFC 3546)
*/
class ServerNameIndicator : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SERVER_NAME_INDICATION; }

    override HandshakeExtensionType type() const { return staticType(); }

    this(in string host_name) 
    {
        m_sni_host_name = host_name;
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        /*
        * This is used by the server to confirm that it knew the name
        */
        if (extension_size == 0)
            return;
        
        ushort name_bytes = reader.get_ushort();
        
        if (name_bytes + 2 != extension_size)
            throw new DecodingError("Bad encoding of SNI extension");
        
        while (name_bytes)
        {
            ubyte name_type = reader.get_byte();
            name_bytes--;
            
            if (name_type == 0) // DNS
            {
                m_sni_host_name = reader.getString(2, 1, 65535);
                name_bytes -= (2 + m_sni_host_name.length);
            }
            else // some other unknown name type
            {
                reader.discardNext(name_bytes);
                name_bytes = 0;
            }
        }
    }

    string hostName() const { return m_sni_host_name; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        size_t name_len = m_sni_host_name.length;
        
        buf.pushBack(get_byte(0, cast(ushort) (name_len+3)));
        buf.pushBack(get_byte(1, cast(ushort) (name_len+3)));
        buf.pushBack(0); // DNS
        
        buf.pushBack(get_byte(0, cast(ushort) name_len));
        buf.pushBack(get_byte(1, cast(ushort) name_len));
        
        buf ~= (cast(const(ubyte)*)m_sni_host_name.ptr)[0 .. m_sni_host_name.length];
        
        return buf.move();
    }

    override @property bool empty() const { return m_sni_host_name == ""; }
private:
    string m_sni_host_name;
}

/**
* SRP identifier extension (RFC 5054)
*/
class SRPIdentifier : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SRP_IDENTIFIER; }

    override HandshakeExtensionType type() const { return staticType(); }

    this(in string identifier) 
    {
        m_srp_identifier = identifier;
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        m_srp_identifier = reader.getString(1, 1, 255);
        
        if (m_srp_identifier.length + 1 != extension_size)
            throw new DecodingError("Bad encoding for SRP identifier extension");
    }

    this(ref TLSDataReader reader, ushort extension_size);

    string identifier() const { return m_srp_identifier; }


    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;

        const(ubyte)* srp_bytes = cast(const(ubyte)*) m_srp_identifier.ptr;
        
        appendTlsLengthValue(buf, srp_bytes, m_srp_identifier.length, 1);
        
        return buf.move();
    }

    override @property bool empty() const { return m_srp_identifier == ""; }
private:
    string m_srp_identifier;
}

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class RenegotiationExtension : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SAFE_RENEGOTIATION; }

    override HandshakeExtensionType type() const { return staticType(); }

    this() {}

    this(Vector!ubyte bits)
    {
        m_reneg_data = bits.move();
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        m_reneg_data = reader.getRange!ubyte(1, 0, 255);
        
        if (m_reneg_data.length + 1 != extension_size)
            throw new DecodingError("Bad encoding for secure renegotiation extn");
    }

    ref const(Vector!ubyte) renegotiationInfo() const { return m_reneg_data; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        appendTlsLengthValue(buf, m_reneg_data, 1);
        return buf.move();
    }

    override @property bool empty() const { return false; } // always send this

private:
    Vector!ubyte m_reneg_data;
}

/**
* Maximum Fragment Length Negotiation Extension (RFC 4366 sec 3.2)
*/
class MaximumFragmentLength : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_MAX_FRAGMENT_LENGTH; }

    override HandshakeExtensionType type() const { return staticType(); }

    override @property bool empty() const { return false; }

    size_t fragmentSize() const { return m_max_fragment; }

    override Vector!ubyte serialize() const
    {
        static ubyte[size_t] fragment_to_code;
        if (fragment_to_code.length == 0)
            fragment_to_code = [ 512: 1, 1024: 2, 2048: 3, 4096: 4 ];
        
        auto i = fragment_to_code.get(m_max_fragment, 0);
        
        if (i == 0)
            throw new InvalidArgument("Bad setting " ~ to!string(m_max_fragment) ~ " for maximum fragment size");
        
        return Vector!ubyte([i]);
    }

    /**
    * Params:
    *  max_fragment = specifies what maximum fragment size to
    *          advertise. Currently must be one of 512, 1024, 2048, or
    *          4096.
    */
    this(size_t max_fragment) 
    {
        m_max_fragment = max_fragment;
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        __gshared immutable size_t[] code_to_fragment = [ 0, 512, 1024, 2048, 4096 ];
        if (extension_size != 1)
            throw new DecodingError("Bad size for maximum fragment extension");
        ubyte val = reader.get_byte();

        if (val < code_to_fragment.length) {

            auto i = code_to_fragment[val];
            
            m_max_fragment = i;
        }
        else
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Bad value in maximum fragment extension");

    }

private:
    size_t m_max_fragment;
}

/**
* Next Protocol Negotiation
* http://technotes.googlecode.com/git/nextprotoneg.html
*
* This implementation requires the semantics defined in the Google
* spec (implemented in Chromium); the internet draft leaves the format
* unspecified.
*/
class NextProtocolNotification : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_NEXT_PROTOCOL; }

    override HandshakeExtensionType type() const { return staticType(); }

    ref const(Vector!string) protocols() const { return m_protocols; }

    /**
    * Empty extension, used by client
    */
    this() {}

    /**
    * List of protocols, used by server
    */
    this(Vector!string protocols) 
    {
        m_protocols = protocols.move(); 
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        if (extension_size == 0)
            return; // empty extension
        
        size_t bytes_remaining = extension_size;
        
        while (bytes_remaining)
        {
            const string p = reader.getString(1, 0, 255);
            
            if (bytes_remaining < p.length + 1)
                throw new DecodingError("Bad encoding for next protocol extension");
            
            bytes_remaining -= (p.length + 1);
            
            m_protocols.pushBack(p);
        }
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        for (size_t i = 0; i != m_protocols.length; ++i)
        {
            const string p = m_protocols[i];
            
            if (p != "")
                appendTlsLengthValue(buf, cast(const(ubyte)*) p.ptr, p.length, 1);
        }
        
        return buf.move();
    }

    override @property bool empty() const { return false; }
private:
    Vector!string m_protocols;
}

/**
* TLSSession Ticket Extension (RFC 5077)
*/
class SessionTicket : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SESSION_TICKET; }

    override HandshakeExtensionType type() const { return staticType(); }

    /**
    * Returns: contents of the session ticket
    */
    ref const(Vector!ubyte) contents() const { return m_ticket; }

    /**
    * Create empty extension, used by both client and server
    */
    this() {}

    /**
    * Extension with ticket, used by client
    */
    this(Vector!ubyte session_ticket)
    {
        m_ticket = session_ticket.move();
    }

    /**
    * Deserialize a session ticket
    */
    this(ref TLSDataReader reader, ushort extension_size)
    {
        m_ticket = reader.getElem!(ubyte, Vector!ubyte)(extension_size);
    }

    override Vector!ubyte serialize() const { return m_ticket.dup; }

    override @property bool empty() const { return false; }
private:
    Vector!ubyte m_ticket;
}

/**
* Supported Elliptic Curves Extension (RFC 4492)
*/
class SupportedEllipticCurves : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_USABLE_ELLIPTIC_CURVES; }

    override HandshakeExtensionType type() const { return staticType(); }

    static string curveIdToName(ushort id)
    {
        switch(id)
        {
            case 15:
                return "secp160k1";
            case 16:
                return "secp160r1";
            case 17:
                return "secp160r2";
            case 18:
                return "secp192k1";
            case 19:
                return "secp192r1";
            case 20:
                return "secp224k1";
            case 21:
                return "secp224r1";
            case 22:
                return "secp256k1";
            case 23:
                return "secp256r1";
            case 24:
                return "secp384r1";
            case 25:
                return "secp521r1";
            case 26:
                return "brainpool256r1";
            case 27:
                return "brainpool384r1";
            case 28:
                return "brainpool512r1";
            default:
                return ""; // something we don't know or support
        }
    }

    static ushort nameToCurveId(in string name)
    {
        if (name == "secp160k1")
            return 15;
        if (name == "secp160r1")
            return 16;
        if (name == "secp160r2")
            return 17;
        if (name == "secp192k1")
            return 18;
        if (name == "secp192r1")
            return 19;
        if (name == "secp224k1")
            return 20;
        if (name == "secp224r1")
            return 21;
        if (name == "secp256k1")
            return 22;
        if (name == "secp256r1")
            return 23;
        if (name == "secp384r1")
            return 24;
        if (name == "secp521r1")
            return 25;
        if (name == "brainpool256r1")
            return 26;
        if (name == "brainpool384r1")
            return 27;
        if (name == "brainpool512r1")
            return 28;
        
        throw new InvalidArgument("name_to_curve_id unknown name " ~ name);
    }

    ref const(Vector!string) curves() const { return m_curves; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(2);
        
        for (size_t i = 0; i != m_curves.length; ++i)
        {
            const ushort id = nameToCurveId(m_curves[i]);
            buf.pushBack(get_byte(0, id));
            buf.pushBack(get_byte(1, id));
        }
        
        buf[0] = get_byte(0, cast(ushort) (buf.length-2));
        buf[1] = get_byte(1, cast(ushort) (buf.length-2));
        
        return buf.move();
    }

    this(Vector!string curves) 
    {
        m_curves = curves.move();
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        ushort len = reader.get_ushort();
        
        if (len + 2 != extension_size)
            throw new DecodingError("Inconsistent length field in elliptic curve list");
        
        if (len % 2 == 1)
            throw new DecodingError("Elliptic curve list of strange size");
        
        len /= 2;
        
        foreach (size_t i; 0 .. len)
        {
            const ushort id = reader.get_ushort();
            const string name = curveIdToName(id);
            
            if (name != "")
                m_curves.pushBack(name);
        }
    }

    override @property bool empty() const { return m_curves.empty; }
private:
    Vector!string m_curves;
}

/**
* Signature Algorithms Extension for TLS 1.2 (RFC 5246)
*/
class SignatureAlgorithms : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_SIGNATURE_ALGORITHMS; }

    override HandshakeExtensionType type() const { return staticType(); }

    static string hashAlgoName(ubyte code)
    {
        switch(code)
        {
            case 1:
                return "MD5";
                // code 1 is MD5 - ignore it
                
            case 2:
                return "SHA-1";
            case 3:
                return "SHA-224";
            case 4:
                return "SHA-256";
            case 5:
                return "SHA-384";
            case 6:
                return "SHA-512";
            default:
                return "";
        }
    }

    static ubyte hashAlgoCode(in string name)
    {
        if (name == "MD5")
            return 1;
        
        if (name == "SHA-1")
            return 2;
        
        if (name == "SHA-224")
            return 3;
        
        if (name == "SHA-256")
            return 4;
        
        if (name == "SHA-384")
            return 5;
        
        if (name == "SHA-512")
            return 6;
        
        throw new InternalError("Unknown hash ID " ~ name ~ " for signature_algorithms");
    }

    static string sigAlgoName(ubyte code)
    {
        switch(code)
        {
            case 1:
                return "RSA";
            case 2:
                return "DSA";
            case 3:
                return "ECDSA";
            default:
                return "";
        }
    }

    static ubyte sigAlgoCode(in string name)
    {
        if (name == "RSA")
            return 1;
        
        if (name == "DSA")
            return 2;
        
        if (name == "ECDSA")
            return 3;
        
        throw new InternalError("Unknown sig ID " ~ name ~ " for signature_algorithms");
    }

    ref const(Vector!( Pair!(string, string)  )) supportedSignatureAlgorthms() const
    {
        return m_supported_algos;
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(2);
        
        for (size_t i = 0; i != m_supported_algos.length; ++i)
        {
            try
            {
                const ubyte hash_code = hashAlgoCode(m_supported_algos[i].first);
                const ubyte sig_code = sigAlgoCode(m_supported_algos[i].second);
                
                buf.pushBack(hash_code);
                buf.pushBack(sig_code);
            }
            catch (Throwable)
            {}
        }
        
        buf[0] = get_byte(0, cast(ushort) (buf.length-2));
        buf[1] = get_byte(1, cast(ushort) (buf.length-2));
        
        return buf.move();
    }

    override @property bool empty() const { return false; }

    this()(auto const ref Vector!string hashes, auto const ref Vector!string sigs)
    {
        for (size_t i = 0; i != hashes.length; ++i)
            for (size_t j = 0; j != sigs.length; ++j)
                m_supported_algos.pushBack(makePair(hashes[i], sigs[j]));
    }
    
    this(ref TLSDataReader reader,
         ushort extension_size)
    {
        ushort len = reader.get_ushort();
        
        if (len + 2 != extension_size)
            throw new DecodingError("Bad encoding on signature algorithms extension");
        
        while (len)
        {
            const string hash_code = hashAlgoName(reader.get_byte());
            const string sig_code = sigAlgoName(reader.get_byte());
            
            len -= 2;
            
            // If not something we know, ignore it completely
            if (hash_code == "" || sig_code == "")
                continue;
            
            m_supported_algos.pushBack(makePair(hash_code, sig_code));
        }
    }

    this(Vector!( Pair!(string, string)  ) algos) 
    {
        m_supported_algos = algos.move();
    }

private:
    Vector!( Pair!(string, string) ) m_supported_algos;
}

/**
* Heartbeat Extension (RFC 6520)
*/
class HeartbeatSupportIndicator : Extension
{
public:
    static HandshakeExtensionType staticType() { return TLSEXT_HEARTBEAT_SUPPORT; }

    override HandshakeExtensionType type() const { return staticType(); }

    bool peerAllowedToSend() const { return m_peer_allowed_to_send; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte heartbeat = Vector!ubyte(1);
        heartbeat[0] = (m_peer_allowed_to_send ? 1 : 2);
        return heartbeat.move();
    }

    override @property bool empty() const { return false; }

    this(bool peer_allowed_to_send) 
    {
        m_peer_allowed_to_send = peer_allowed_to_send; 
    }

    this(ref TLSDataReader reader, ushort extension_size)
    {
        if (extension_size != 1)
            throw new DecodingError("Strange size for heartbeat extension");
        
        const ubyte code = reader.get_byte();
        
        if (code != 1 && code != 2)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Unknown heartbeat code " ~ to!string(code));
        
        m_peer_allowed_to_send = (code == 1);
    }

private:
    bool m_peer_allowed_to_send;
}

/**
* Represents a block of extensions in a hello message
*/
struct TLSExtensions
{
public:
    Vector!HandshakeExtensionType extensionTypes() const
    {
        Vector!HandshakeExtensionType offers;
        foreach (const ref HandshakeExtensionType t, const ref Extension ext; extensions)
            offers ~= t;
        return offers;
    }


    T get(T)() const
    {
        HandshakeExtensionType type = T.staticType();

        return cast(T)extensions.get(type, T.init);
    }

    void add(Extension extn)
    {
        assert(extn);

        auto val = extensions.get(extn.type(), null);
        if (val)
            destroy(val);
        extensions[extn.type()] = extn;
    }

    Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(2); // 2 bytes for length field
        
        foreach (const ref Extension extn; extensions)
        {
            if (!extn)
                continue;
            
            const ushort extn_code = extn.type();
            
            const Vector!ubyte extn_val = extn.serialize();
            
            buf.pushBack(get_byte(0, extn_code));
            buf.pushBack(get_byte(1, extn_code));
            
            buf.pushBack(get_byte(0, cast(ushort) extn_val.length));
            buf.pushBack(get_byte(1, cast(ushort) extn_val.length));
            
            buf ~= extn_val[];
        }
        
        const ushort extn_size = cast(ushort) (buf.length - 2);
        
        buf[0] = get_byte(0, extn_size);
        buf[1] = get_byte(1, extn_size);
        
        // avoid sending a completely empty extensions block
        if (buf.length == 2)
            return Vector!ubyte();
        
        return buf.move();
    }

    void deserialize(ref TLSDataReader reader)
    {
        if (reader.hasRemaining())
        {
            const ushort all_extn_size = reader.get_ushort();
            
            if (reader.remainingBytes() != all_extn_size)
                throw new DecodingError("Bad extension size");
            
            while (reader.hasRemaining())
            {
                const ushort extension_code = reader.get_ushort();
                const ushort extension_size = reader.get_ushort();
                
                Extension extn = makeExtension(reader, extension_code, extension_size);
                
                if (extn)
                    this.add(extn);
                else // unknown/unhandled extension
                    reader.discardNext(extension_size);
            }
        }
    }

    this(ref TLSDataReader reader) { deserialize(reader); }

private:
    HashMapRef!(HandshakeExtensionType, Extension) extensions;
}


private:

Extension makeExtension(ref TLSDataReader reader, ushort code, ushort size)
{
    switch(code)
    {
        case TLSEXT_SERVER_NAME_INDICATION:
            return new ServerNameIndicator(reader, size);
            
        case TLSEXT_MAX_FRAGMENT_LENGTH:
            return new MaximumFragmentLength(reader, size);
            
        case TLSEXT_SRP_IDENTIFIER:
            return new SRPIdentifier(reader, size);
            
        case TLSEXT_USABLE_ELLIPTIC_CURVES:
            return new SupportedEllipticCurves(reader, size);
            
        case TLSEXT_SAFE_RENEGOTIATION:
            return new RenegotiationExtension(reader, size);
            
        case TLSEXT_SIGNATURE_ALGORITHMS:
            return new SignatureAlgorithms(reader, size);
            
        case TLSEXT_NEXT_PROTOCOL:
            return new NextProtocolNotification(reader, size);
            
        case TLSEXT_HEARTBEAT_SUPPORT:
            return new HeartbeatSupportIndicator(reader, size);
            
        case TLSEXT_SESSION_TICKET:
            return new SessionTicket(reader, size);
            
        default:
            return null; // not known
    }
}
