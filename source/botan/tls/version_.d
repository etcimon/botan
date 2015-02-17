/**
* TLS Protocol Version Management
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.version_;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.get_byte;
import botan.tls.exceptn;
import botan.tls.alert;
import botan.utils.parsing;
import botan.utils.types;
import std.conv : to;

/**
* TLS Protocol Version
*/
struct TLSProtocolVersion
{
public:
    alias ushort VersionCode;
    enum : VersionCode {
        SSL_V3              = 0x0300,
        TLS_V10             = 0x0301,
        TLS_V11             = 0x0302,
        TLS_V12             = 0x0303,

        DTLS_V10            = 0xFEFF,
        DTLS_V12            = 0xFEFD
    }

    static TLSProtocolVersion latestTlsVersion()
    {
        return TLSProtocolVersion(TLS_V12);
    }

    static TLSProtocolVersion latestDtlsVersion()
    {
        return TLSProtocolVersion(DTLS_V12);
    }

    /**
    * Params:
    *  named_version = a specific named version of the protocol
    */
    this(VersionCode named_version = 0)
    {
        m_version = cast(ushort) named_version;
    }

    /**
    * Params:
    *  major = the major version
    *  minor = the minor version
    */
    this(ubyte major, ubyte minor)
    {
        m_version = (cast(ushort)(major) << 8) | minor; 
    }

    /**
    * Returns: true if this is a valid protocol version
    */
    bool valid() const { return (m_version != 0); }

    /**
    * Returns: true if this is a protocol version we know about
    */
    bool knownVersion() const
    {
        return (m_version == TLSProtocolVersion.SSL_V3 ||
                m_version == TLSProtocolVersion.TLS_V10 ||
                m_version == TLSProtocolVersion.TLS_V11 ||
                m_version == TLSProtocolVersion.TLS_V12 ||
                m_version == TLSProtocolVersion.DTLS_V10 ||
                m_version == TLSProtocolVersion.DTLS_V12);
    }

    /**
    * Returns: major version of the protocol version
    */
    ubyte majorVersion() const { return get_byte(0, m_version); }

    /**
    * Returns: minor version of the protocol version
    */
    ubyte minorVersion() const { return get_byte(1, m_version); }

    /**
    * Returns: human-readable description of this version
    */
    string toString() const
    {
        const ubyte maj = majorVersion();
        const ubyte min = minorVersion();
        
        if (maj == 3 && min == 0)
            return "SSL v3";
        
        if (maj == 3 && min >= 1) // TLS v1.x
            return "TLS v1." ~ to!string(min-1);
        
        if (maj == 254) // DTLS 1.x
            return "DTLS v1." ~ to!string(255 - min);
        
        // Some very new or very old protocol (or bogus data)
        return "Unknown " ~ to!string(maj) ~ "." ~ to!string(min);
    }

    /**
    * If this version is known, return that. Otherwise return the
    * best (most recent) version we know of.
    * Returns: best matching protocol version
    */
    TLSProtocolVersion bestKnownMatch() const
    {
        if (knownVersion())
            return this; // known version is its own best match
        
        if (isDatagramProtocol())
            return cast(TLSProtocolVersion) TLSProtocolVersion.DTLS_V12;
        else
            return cast(TLSProtocolVersion) TLSProtocolVersion.TLS_V12;
    }

    /**
    * Returns: true iff this is a DTLS version
    */
    bool isDatagramProtocol() const
    {
        return majorVersion() == 254;
    }

    /**
    * Returns: true if this version supports negotiable signature algorithms
    */
    bool supportsNegotiableSignatureAlgorithms() const
    {
        return (m_version == TLSProtocolVersion.TLS_V12 ||
                m_version == TLSProtocolVersion.DTLS_V12);
    }

    /**
    * Returns: true if this version uses explicit IVs for block ciphers
    */
    bool supportsExplicitCbcIvs() const
    {
        return (m_version == TLSProtocolVersion.TLS_V11 ||
                m_version == TLSProtocolVersion.TLS_V12 ||
                m_version == TLSProtocolVersion.DTLS_V10 ||
                m_version == TLSProtocolVersion.DTLS_V12);
    }

    /**
    * Returns: true if this version uses a ciphersuite specific PRF
    */
    bool supportsCiphersuiteSpecificPrf() const
    {
        return (m_version == TLSProtocolVersion.TLS_V12 ||
                m_version == TLSProtocolVersion.DTLS_V12);
    }

    bool supportsAeadModes() const
    {
        return (m_version == TLSProtocolVersion.TLS_V12 ||
                m_version == TLSProtocolVersion.DTLS_V12);
    }

    /**
    * Returns: if this version is equal to other
    */
    bool opEquals(in TLSProtocolVersion other) const
    {
        return (m_version == other.m_version);
    }
    
    /**
    * Returns: if this version is not equal to other
    */
    int opCmp(in TLSProtocolVersion other) const
    {
        if (m_version == other.m_version) return 0;
        else if (isGreaterThan(other)) return 1;
        else return -1;
    }

    /**
    * Returns: if this version is equal to other
    */
    bool opEquals(in ushort other) const
    {
        return (m_version == other);
    }
    
    /**
    * Returns: if this version is not equal to other
    */
    int opCmp(in ushort other) const
    {
        if (m_version == other) return 0;
        else if (isGreaterThan(TLSProtocolVersion(other))) return 1;
        else return -1;
    }

    /**
    * Returns: if this version is later than other
    */
    bool isGreaterThan(in TLSProtocolVersion other) const
    {
        if (this.isDatagramProtocol() != other.isDatagramProtocol())
            throw new TLSException(TLSAlert.PROTOCOL_VERSION,
                                   "Version comparing " ~ toString() ~ " with " ~ other.toString());
        
        if (this.isDatagramProtocol())
            return m_version < other.m_version; // goes backwards
        
        return m_version > other.m_version;
    }
private:
    ushort m_version;
}
