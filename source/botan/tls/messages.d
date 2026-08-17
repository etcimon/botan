/**
* TLS Messages
* 
* Copyright:
* (C) 2021-2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.messages;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.tls.handshake_state;
import botan.tls.session_key;
import std.algorithm : canFind;
import botan.tls.alert : TLSAlert;
import memutils.dictionarylist;

public import botan.algo_base.sym_algo;
public import botan.tls.session;
public import botan.tls.policy;
public import botan.tls.ciphersuite;
public import botan.tls.reader;
public import botan.tls.extensions;
public import botan.tls.handshake_io;
public import botan.tls.version_;
public import botan.tls.handshake_hash;
public import botan.tls.magic;
public import botan.tls.credentials_manager;
static if (BOTAN_HAS_TLS_13) import botan.tls.tls13.hello_ext;
static if (BOTAN_HAS_TLS_13 && BOTAN_HAS_CURVE25519) import botan.pubkey.algo.curve25519;
static if (BOTAN_HAS_TLS_13_PQC) import botan.pubkey.algo.ml_kem;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_FRODOKEM) import botan.pubkey.algo.frodo_kem;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_X448) import botan.pubkey.algo.x448;
static if (BOTAN_HAS_TLS_13_PQC && BOTAN_HAS_ECDH)
{
    import botan.pubkey.algo.ecdh;
    import botan.pubkey.algo.ec_group;
}
import botan.constructs.srp6;
import botan.utils.loadstor;
import botan.constructs.srp6;
import botan.math.bigint.bigint;
import botan.pubkey.algo.ec_group;
import botan.math.ec_gfp.point_gfp;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.pubkey.algo.dh;
import botan.pubkey.algo.ecdh;
import botan.pubkey.algo.rsa;
import botan.cert.x509.x509cert;
import botan.asn1.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.loadstor;
import botan.utils.types;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.utils.types : Unique;
import std.datetime;
import botan.utils.types;

// import string;

enum {
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV  = 0x00FF,
    TLS_FALLBACK_SCSV                  = 0x5600
}

/**
* TLS Handshake Message Base Class
*/
interface HandshakeMessage
{
public:
    abstract HandshakeType type() const;
    
    abstract Vector!ubyte serialize() const;
}

/**
* DTLS Hello Verify Request
*/
final class HelloVerifyRequest : HandshakeMessage
{
public:
    override Vector!ubyte serialize() const
    {
        /* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
            regardless of the version of TLS that is expected to be
            negotiated (RFC 6347, section 4.2.1)
        */
            
        TLSProtocolVersion format_version = TLSProtocolVersion(TLSProtocolVersion.DTLS_V10);
        
        Vector!ubyte bits;
        bits.pushBack(format_version.majorVersion());
        bits.pushBack(format_version.minorVersion());
        bits.pushBack(cast(ubyte) m_cookie.length);
        bits ~= m_cookie[];
        return bits.move();
    }

    override HandshakeType type() const { return HELLO_VERIFY_REQUEST; }

    ref const(Vector!ubyte) cookie() const { return m_cookie; }

    this(const ref Vector!ubyte buf)
    {
        if (buf.length < 3)
            throw new DecodingError("Hello verify request too small");
        
        TLSProtocolVersion version_ = TLSProtocolVersion(buf[0], buf[1]);
        
        if (version_ != TLSProtocolVersion.DTLS_V10 &&
            version_ != TLSProtocolVersion.DTLS_V12)
        {
            throw new DecodingError("Unknown version from server in hello verify request");
        }

        if ((cast(size_t) buf[2]) + 3 != buf.length)
            throw new DecodingError("Bad length in hello verify request");
        
        m_cookie[] = buf.ptr[3 .. buf.length];
    }

    this(const ref Vector!ubyte client_hello_bits, in string client_identity, in SymmetricKey secret_key)
    {
        Unique!MessageAuthenticationCode hmac = retrieveMac("HMAC(SHA-256)").clone();
        hmac.setKey(secret_key);
        
        hmac.updateBigEndian(client_hello_bits.length);
        hmac.update(client_hello_bits);
        hmac.updateBigEndian(client_identity.length);
        hmac.update(client_identity);
        
        m_cookie = unlock(hmac.finished());
    }
private:
    Vector!ubyte m_cookie;
}

enum GreaseType : size_t {
	CIPHER = 0,
	ELLIPTIC_CURVE,
	EXTENSION_FIRST,
	EXTENSION_LAST
};

/**
* TLSClient Hello Message
*/
/// Named groups for ClientHello supported_groups. Prepends policy PQC/hybrid
/// names when offering TLS 1.3.
Vector!string tls13OfferedGroups(in TLSPolicy policy, TLSProtocolVersion offered)
{
    auto curves = policy.allowedEccCurves();
    static if (BOTAN_HAS_TLS_13_PQC)
    {
        if (offered == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
        {
            auto extra = policy.tls13PqcKeyShareGroups();
            if (!extra.empty)
            {
                Vector!string g;
                foreach (n; extra[])
                    g.pushBack(n);
                foreach (c; curves[])
                    g.pushBack(c);
                return g.move();
            }
        }
    }
    return curves.move();
}

final class ClientHello : HandshakeMessage
{
public:
    override HandshakeType type() const { return CLIENT_HELLO; }

    const(TLSProtocolVersion) Version() const { return m_version; }

    ref const(Vector!ubyte) random() const { return m_random; }

	const(ubyte[]) randomBytes() const { return m_random[]; }

	private const(ushort) grease(GreaseType idx) const {
		if (!m_grease) return 0;
		ushort ret = *cast(ushort*) m_random[idx*2 .. (idx+1)*2].ptr;
		ret = (ret & 0xf0) | 0x0a;
		ret |= ret << 8;
		return ret;
	}

	ref const(Vector!ubyte) sessionId() const { return m_session_id; }
	
	const(ubyte[]) sessionIdBytes() const { return m_session_id[]; }

	ref const(Vector!ushort) ciphersuites() const { return m_suites; }

	const(ushort[]) ciphersuitesData() const { return m_suites[]; }

    ref const(Vector!ubyte) compressionMethods() const { return m_comp_methods; }

    /*
    * Check if we offered this ciphersuite
    */
    bool offeredSuite(ushort ciphersuite) const
    {
        for (size_t i = 0; i != m_suites.length; ++i)
            if (m_suites[i] == ciphersuite)
                return true;
        return false;
    }

    Vector!( Pair!(string, string) ) supportedAlgos() const
    {
        if (SignatureAlgorithms sigs = m_extensions.get!SignatureAlgorithms())
            return sigs.supportedSignatureAlgorthms().clone();
        return Vector!( Pair!(string, string) )();
    }

    Vector!string supportedEccCurves() const
    {
        if (SupportedEllipticCurves ecc = m_extensions.get!SupportedEllipticCurves())
            return ecc.curves().clone();
        return Vector!string();
    }

    string sniHostname() const
    {
        if (ServerNameIndicator sni = m_extensions.get!ServerNameIndicator())
            return sni.hostName();
        return "";
    }

    string srpIdentifier() const
    {
        if (SRPIdentifier srp = m_extensions.get!SRPIdentifier())
            return srp.identifier();
        return "";
    }

    bool sentFallbackSCSV() const
    {
        return offeredSuite(cast(ushort) TLS_FALLBACK_SCSV);
    }

    bool supportsStatusRequest() const
    {
        return m_extensions.get!StatusRequest() !is null;
    }

    bool secureRenegotiation() const
    {
        return m_extensions.get!RenegotiationExtension() !is null;
    }

    Vector!ubyte renegotiationInfo() const
    {
        if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            return reneg.renegotiationInfo().clone();
        return Vector!ubyte();
    }

    size_t fragmentSize() const
    {
        if (MaximumFragmentLength frag = m_extensions.get!MaximumFragmentLength())
            return frag.fragmentSize();
        return 0;
    }

    bool supportsSessionTicket() const
    {
        return m_extensions.get!SessionTicket() !is null;
    }

    Vector!ubyte sessionTicket() const
    {
        if (SessionTicket ticket = m_extensions.get!SessionTicket())
            return ticket.contents().clone();
        return Vector!ubyte();
    }

	bool supportsAlpn() const
	{
		return m_extensions.get!ApplicationLayerProtocolNotification() !is null;
	}

	bool supportsExtendedMasterSecret() const
	{
		return m_extensions.get!ExtendedMasterSecret() !is null;
	}

    const(Vector!string) nextProtocols() const
    {
        if (auto alpn = m_extensions.get!ApplicationLayerProtocolNotification())
            return alpn.protocols().clone;
        return Vector!string();
    }

    bool supportsHeartbeats() const
    {
        return m_extensions.get!HeartbeatSupportIndicator() !is null;
    }

    bool peerCanSendHeartbeats() const
    {
        if (HeartbeatSupportIndicator hb = m_extensions.get!HeartbeatSupportIndicator())
            return hb.peerAllowedToSend();
        return false;
    }

    bool supportsChannelID() const
    {
        return m_extensions.get!ChannelIDSupport() !is null;
    }

    void updateHelloCookie(in HelloVerifyRequest hello_verify)
    {
        if (!m_version.isDatagramProtocol())
            throw new Exception("Cannot use hello cookie with stream protocol");
        
        m_hello_cookie = hello_verify.cookie().clone;
    }

    const(Vector!HandshakeExtensionType) extensionTypes() const
    { return m_extensions.extensionTypes(); }

    static if (BOTAN_HAS_TLS_13)
    {
        TLS13KeyShare tls13KeyShare() const { return m_extensions.get!TLS13KeyShare(); }
        static if (BOTAN_HAS_CURVE25519)
        {
            bool hasTls13X25519() const { return m_has_tls13_x25519; }
            ref const(Curve25519PrivateKey) tls13X25519() const { return m_tls13_x25519; }
        }
        static if (BOTAN_HAS_TLS_13_PQC)
        {
            bool hasTls13Mlkem() const { return !m_tls13_mlkem.isEmpty; }
            const(MLKEMPrivateKey) tls13Mlkem() const { return m_tls13_mlkem; }
            bool hasTls13Mlkem512() const { return !m_tls13_mlkem512.isEmpty; }
            const(MLKEMPrivateKey) tls13Mlkem512() const { return m_tls13_mlkem512; }
            bool hasTls13Mlkem1024() const { return !m_tls13_mlkem1024.isEmpty; }
            const(MLKEMPrivateKey) tls13Mlkem1024() const { return m_tls13_mlkem1024; }
            static if (BOTAN_HAS_ECDH)
            {
                bool hasTls13P256() const { return m_has_tls13_p256; }
                ref const(ECDHPrivateKey) tls13P256() const { return m_tls13_p256; }
                bool hasTls13P384() const { return m_has_tls13_p384; }
                ref const(ECDHPrivateKey) tls13P384() const { return m_tls13_p384; }
                bool hasTls13P521() const { return m_has_tls13_p521; }
                ref const(ECDHPrivateKey) tls13P521() const { return m_tls13_p521; }
            }
            static if (BOTAN_HAS_X448)
            {
                bool hasTls13X448() const { return m_has_tls13_x448; }
                ref const(X448PrivateKey) tls13X448() const { return m_tls13_x448; }
            }
            static if (BOTAN_HAS_FRODOKEM)
            {
                bool hasTls13Frodo(in string fname) const
                {
                    auto p = tls13FrodoSlot(fname);
                    return p !is null && !(*p).isEmpty;
                }
                const(FrodoPrivateKey) tls13Frodo(in string fname) const
                {
                    auto p = tls13FrodoSlot(fname);
                    if (p is null || (*p).isEmpty)
                        return null;
                    return cast(const(FrodoPrivateKey))(*p);
                }
            }
        }
    }

    /*
    * Create a new TLSClient Hello message
    */
    this(HandshakeIO io,
         ref HandshakeHash hash,
         TLSProtocolVersion _version,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         Vector!ubyte reneg_info,
         Vector!string next_protocols,
         in string hostname,
         in string srp_identifier) 
    {
		//logDebug("ClientHello with hostname: ", hostname);

        bool reneg_empty = reneg_info.empty;
        m_version = _version;

		assert(policy.acceptableProtocolVersion(_version), "Our policy accepts the version we are offering");

        m_random = makeHelloRandom(rng, policy);
		m_suites.reserve(16);
		m_grease = policy.allowClientHelloGrease();
		if (m_grease) {
			m_suites ~= grease(GreaseType.CIPHER);
			m_extensions.grease(grease(GreaseType.EXTENSION_FIRST), grease(GreaseType.EXTENSION_LAST));
		}
        auto suite_ver = m_version;
        static if (BOTAN_HAS_TLS_13)
        {
            if (_version == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                suite_ver = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
        }
		m_suites ~= policy.ciphersuiteList(suite_ver, (srp_identifier != ""));
        m_comp_methods = policy.compression();

		Vector!ubyte fmts = policy.ecPointFormats();
        bool has_safe_reneg;
		foreach (extension_; policy.enabledExtensions()) {
			switch (extension_) {
				case TLSEXT_SAFE_RENEGOTIATION:
                    has_safe_reneg = true;
					m_extensions.add(new RenegotiationExtension(reneg_info.move()));
					break;
				case TLSEXT_SERVER_NAME_INDICATION:
					m_extensions.add(new ServerNameIndicator(hostname));
					break;
				case TLSEXT_EC_POINT_FORMATS:
					m_extensions.add(new SupportedPointFormats(fmts.move()));
					break;
				case TLSEXT_USABLE_ELLIPTIC_CURVES:
					m_extensions.add(new SupportedEllipticCurves(tls13OfferedGroups(policy, _version), grease(GreaseType.ELLIPTIC_CURVE)));
					break;
				case TLSEXT_EXTENDED_MASTER_SECRET:
					m_extensions.add(new ExtendedMasterSecret);
					break;
				case TLSEXT_SESSION_TICKET:
					m_extensions.add(new SessionTicket());
					break;
				case TLSEXT_SIGNATURE_ALGORITHMS:
					if (m_version.supportsNegotiableSignatureAlgorithms())
						m_extensions.add(new SignatureAlgorithms(policy.allowedSignatureHashes(),
							policy.allowedSignatureMethods(), policy.signatureAlgorithms()));
					break;
				case TLSEXT_STATUS_REQUEST: //todo: Complete support
					m_extensions.add(new StatusRequest);
					break;
				case TLSEXT_NPN:
					m_extensions.add(new NPN);
					break;
				case TLSEXT_SIGNED_CERT_TIMESTAMP:
					m_extensions.add(new SignedCertificateTimestamp);
					break;
				case TLSEXT_ALPN:
					if (reneg_empty && !next_protocols.empty)
						m_extensions.add(new ApplicationLayerProtocolNotification(next_protocols.move));
					break;
				case TLSEXT_CHANNEL_ID:
                    m_extensions.add(new ChannelIDSupport);
					break;
				case TLSEXT_SRP_IDENTIFIER:
					m_extensions.add(new SRPIdentifier(srp_identifier));
					break;
				case TLSEXT_HEARTBEAT_SUPPORT:
					if (policy.negotiateHeartbeatSupport())
	            		m_extensions.add(new HeartbeatSupportIndicator(true));
					break;
				case TLSEXT_PADDING:
					m_has_padding = true;
					break;
                default:
                    break;
			}

		}

        if (policy.sendFallbackSCSV(_version))
            m_suites.pushBack(TLS_FALLBACK_SCSV);
        else if (has_safe_reneg)
            m_suites.pushBack(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        static if (BOTAN_HAS_TLS_13)
        {
            if (_version == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
            {
                // RFC 8446 4.1.2: legacy_version is 0x0303; 1.3 is in supported_versions.
                m_version = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
                Vector!TLSProtocolVersion offer;
                offer.pushBack(TLSProtocolVersion(TLSProtocolVersion.TLS_V13));
                offer.pushBack(TLSProtocolVersion(TLSProtocolVersion.TLS_V12));
                m_extensions.add(new TLS13SupportedVersions(offer.move()));
                Vector!TLS13KeyShareEntry ents;
                static if (BOTAN_HAS_CURVE25519)
                {
                    m_tls13_x25519 = Curve25519PrivateKey(rng);
                    m_has_tls13_x25519 = true;
                }
                static if (BOTAN_HAS_TLS_13_PQC)
                {
                    auto extra = policy.tls13PqcKeyShareGroups();
                    foreach (n; extra[])
                        tls13EmitPqcShare(ents, n, rng);
                }
                static if (BOTAN_HAS_CURVE25519)
                {
                    auto e = new TLS13KeyShareEntry;
                    e.group = TLS13_GROUP_X25519;
                    auto pub = m_tls13_x25519.publicValue();
                    foreach (b; pub[])
                        e.key_exchange.pushBack(b);
                    ents.pushBack(e);
                }
                if (!ents.empty)
                    m_extensions.add(new TLS13KeyShare(TLS13KeyShare.Kind.Client, ents.move()));
                Vector!ushort with13;
                with13.pushBack(0x1301);
                with13.pushBack(0x1302);
                with13.pushBack(0x1303);
                foreach (s; m_suites[])
                    with13.pushBack(s);
                m_suites = with13.move();
            }
        }

        hash.update(io.send(this));
        static if (BOTAN_HAS_TLS_13)
        {
            if (_version == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                m_version = TLSProtocolVersion(TLSProtocolVersion.TLS_V13);
        }
    }


    /*
    * Create a new TLSClient Hello message (session resumption case)
    */
    this(HandshakeIO io,
         ref HandshakeHash hash,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         Vector!ubyte reneg_info,
         in TLSSession session,
         Vector!string next_protocols)
    { 
        bool reneg_empty = reneg_info.empty;

        m_version = session.Version();
        m_session_id = session.sessionId().clone;
        m_random = makeHelloRandom(rng, policy);
		m_suites.reserve(16);
		m_grease = policy.allowClientHelloGrease();
		if (m_grease) {
			m_suites ~= grease(GreaseType.CIPHER);
			m_extensions.grease(grease(GreaseType.EXTENSION_FIRST), grease(GreaseType.EXTENSION_LAST));
		}
        m_suites ~= policy.ciphersuiteList(m_version, (session.srpIdentifier() != ""));
		m_comp_methods = policy.compression();
		Vector!ubyte fmts = policy.ecPointFormats();
        if (!valueExists(m_suites, session.ciphersuiteCode()))
            m_suites.pushBack(session.ciphersuiteCode());
        
        if (!valueExists(m_comp_methods, session.compressionMethod()))
            m_comp_methods.pushBack(session.compressionMethod());
        bool has_safe_reneg;
		foreach (extension_; policy.enabledExtensions()) {
			switch (extension_) {
				case TLSEXT_SAFE_RENEGOTIATION:
                    has_safe_reneg = true;
					m_extensions.add(new RenegotiationExtension(reneg_info.move()));
					break;
				case TLSEXT_SERVER_NAME_INDICATION:
					m_extensions.add(new ServerNameIndicator(session.serverInfo().hostname()));
					break;
				case TLSEXT_EC_POINT_FORMATS:
					m_extensions.add(new SupportedPointFormats(fmts.move()));
					break;
				case TLSEXT_USABLE_ELLIPTIC_CURVES:
					m_extensions.add(new SupportedEllipticCurves(policy.allowedEccCurves(), grease(GreaseType.ELLIPTIC_CURVE)));
					break;
				case TLSEXT_EXTENDED_MASTER_SECRET:
					m_extensions.add(new ExtendedMasterSecret);
					break;
				case TLSEXT_SESSION_TICKET:
					m_extensions.add(new SessionTicket(session.sessionTicket().clone));
					break;
				case TLSEXT_SIGNATURE_ALGORITHMS:
					if (m_version.supportsNegotiableSignatureAlgorithms())
						m_extensions.add(new SignatureAlgorithms(policy.allowedSignatureHashes(),
								policy.allowedSignatureMethods(), policy.signatureAlgorithms()));
					break;
				case TLSEXT_STATUS_REQUEST: //todo: Complete support
					m_extensions.add(new StatusRequest);
					break;
				case TLSEXT_NPN:
					m_extensions.add(new NPN);
					break;
				case TLSEXT_SIGNED_CERT_TIMESTAMP:
					m_extensions.add(new SignedCertificateTimestamp);
					break;
				case TLSEXT_ALPN:
					if (reneg_empty && !next_protocols.empty)
						m_extensions.add(new ApplicationLayerProtocolNotification(next_protocols.move));
					break;
				case TLSEXT_CHANNEL_ID:
                    m_extensions.add(new ChannelIDSupport);
					break;
				case TLSEXT_SRP_IDENTIFIER:
					m_extensions.add(new SRPIdentifier(session.srpIdentifier()));
					break;
				case TLSEXT_HEARTBEAT_SUPPORT:
					if (policy.negotiateHeartbeatSupport())
						m_extensions.add(new HeartbeatSupportIndicator(true));
					break;
				case TLSEXT_MAX_FRAGMENT_LENGTH:
					if (session.fragmentSize() != 0)
						m_extensions.add(new MaximumFragmentLength(session.fragmentSize()));
					break;
				case TLSEXT_PADDING:
					m_has_padding = true;
					break;
                default:
                    break;
			}
		}

        
        if (policy.sendFallbackSCSV(m_version))
            m_suites.pushBack(TLS_FALLBACK_SCSV);
        else if (has_safe_reneg)
            m_suites.pushBack(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        hash.update(io.send(this));
    }
	bool deserialized;
    /*
    * Read a counterparty client hello
    */
    this(const ref Vector!ubyte buf, HandshakeType type)
    {
		deserialized = true;
        if (type == CLIENT_HELLO)
            deserialize(buf);
    }

protected:
    /*
    * Serialize a TLSClient Hello message
    */
    override Vector!ubyte serialize() const
    {

		/*logDebug("Ciphersuites: ", ciphersuites()[]);
		logDebug("Supported ECC curves: ", supportedEccCurves()[]);
		logDebug("SupportedAlgos: ", supportedAlgos()[]);
		logDebug("Session ID: ", sessionId[]);
		logDebug("Random: ", random()[]);
		logDebug("sni Hostname: ", sniHostname);
		logDebug("sentFallback SCSV: ", sentFallbackSCSV());
		logDebug("Secure renegotiation: ", secureRenegotiation());
		logDebug("NextProtocol: ", nextProtocols[]);
		*/
        Vector!ubyte buf;
		buf.reserve(512);

        TLSProtocolVersion wire_ver = m_version;
        static if (BOTAN_HAS_TLS_13)
        {
            // RFC 8446 4.1.2: legacy_version is 0x0303 even when offering 1.3.
            if (m_version == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                wire_ver = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
        }
        buf.pushBack(wire_ver.majorVersion());
        buf.pushBack(wire_ver.minorVersion());
        buf ~= m_random[];
        
        appendTlsLengthValue(buf, m_session_id, 1);
        
        if (m_version.isDatagramProtocol())
            appendTlsLengthValue(buf, m_hello_cookie, 1);
        
        appendTlsLengthValue(buf, m_suites, 2);
        appendTlsLengthValue(buf, m_comp_methods, 1);
        
        /*
        * May not want to send extensions at all in some cases. If so,
        * should include SCSV value (if reneg info is empty, if not we are
        * renegotiating with a modern server)
        */
        
        auto vec = m_extensions.serialize();
        // pad when between 256 and 511 (inclusive) bytes long
		if (m_has_padding && (buf.length+4) + vec.length <= 511 &&  (buf.length+4) + vec.length >= 256)
        {
            long pad = 512L - cast(long)vec.length - (cast(long)buf.length+4L) - 4L;
            if (pad <= 0)
                pad = 1;
            ushort extn_size = cast(ushort)(vec.length+pad+4-2);
            vec[0] = get_byte(0, extn_size);
            vec[1] = get_byte(1, extn_size);
            vec.pushBack(get_byte(0, cast(ushort) 21));
            vec.pushBack(get_byte(1, cast(ushort) 21)); // padding extension identifier
            vec.pushBack(get_byte(0, cast(ushort) pad));
            vec.pushBack(get_byte(1, cast(ushort) pad));
            foreach (i; 0 .. pad)
                vec ~= cast(ubyte)0x00;
        }
        buf ~= vec[];

        return buf.move();
    }

    /*
    * Deserialize a TLSClient Hello message
    */
    void deserialize(const ref Vector!ubyte buf)
    {
		if (buf.length == 0)
            throw new DecodingError("ClientHello: Packet corrupted");
        
        if (buf.length < 41)
            throw new DecodingError("ClientHello: Packet corrupted");
        
        TLSDataReader reader = TLSDataReader("ClientHello", buf);
        
        const ubyte major_version = reader.get_byte();
        const ubyte minor_version = reader.get_byte();
        
        m_version = TLSProtocolVersion(major_version, minor_version);
        m_random = reader.getFixed!ubyte(32);
        
        if (m_version.isDatagramProtocol())
            m_hello_cookie = reader.getRange!ubyte(1, 0, 255);
        
        m_session_id = reader.getRange!ubyte(1, 0, 32);
        
        m_suites = reader.getRangeVector!ushort(2, 1, 32767);
        
        m_comp_methods = reader.getRangeVector!ubyte(1, 1, 255);
        
		m_extensions.reserve(8);
        m_extensions.deserialize(reader, CLIENT_HELLO);

        static if (BOTAN_HAS_TLS_13) {
            import botan.tls.tls13.hello_ext;
            if (auto sv = m_extensions.get!TLS13SupportedVersions())
            {
                if (sv.supports(TLSProtocolVersion(TLSProtocolVersion.TLS_V13)))
                {
                    if (m_version.majorVersion() == 3 && m_version.minorVersion() >= 4)
                        throw new TLSException(TLSAlert.DECODE_ERROR,
                                               "TLS 1.3 Client Hello has invalid legacy_version");
                    if (m_comp_methods.length != 1 || m_comp_methods[0] != 0)
                        throw new TLSException(TLSAlert.ILLEGAL_PARAMETER,
                                               "Client did not offer NULL compression");
                    m_version = TLSProtocolVersion(TLSProtocolVersion.TLS_V13);
                }
            }
        }
        
        if (offeredSuite(cast(ushort)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
        {
            if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            {
                if (!reneg.renegotiationInfo().empty)
                    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                            "Client sent renegotiation SCSV and non-empty extension");
            }
            else
            {
                // add fake extension
                m_extensions.add(new RenegotiationExtension());
            }
        }
		/*logDebug("Ciphersuites: ", ciphersuites()[]);
		logDebug("Session ID: ", sessionId[]);
		logDebug("Random: ", random()[]);
		logDebug("sni Hostname: ", sniHostname);
		logDebug("sentFallback SCSV: ", sentFallbackSCSV());
		logDebug("Secure renegotiation: ", secureRenegotiation());*/
		//logDebug("NextProtocol: ", nextProtocols[]);
    }

private:
	bool m_grease;
	bool m_has_padding;
    static if (BOTAN_HAS_TLS_13 && BOTAN_HAS_CURVE25519)
    {
        Curve25519PrivateKey m_tls13_x25519;
        bool m_has_tls13_x25519;
    }
    static if (BOTAN_HAS_TLS_13_PQC)
    {
        Unique!MLKEMPrivateKey m_tls13_mlkem;
        Unique!MLKEMPrivateKey m_tls13_mlkem512;
        Unique!MLKEMPrivateKey m_tls13_mlkem1024;
        static if (BOTAN_HAS_ECDH)
        {
            ECDHPrivateKey m_tls13_p256;
            bool m_has_tls13_p256;
            ECDHPrivateKey m_tls13_p384;
            bool m_has_tls13_p384;
            ECDHPrivateKey m_tls13_p521;
            bool m_has_tls13_p521;
        }
        static if (BOTAN_HAS_X448)
        {
            X448PrivateKey m_tls13_x448;
            bool m_has_tls13_x448;
        }
        static if (BOTAN_HAS_FRODOKEM)
        {
            Unique!FrodoPrivateKey m_tls13_f640s;
            Unique!FrodoPrivateKey m_tls13_f640a;
            Unique!FrodoPrivateKey m_tls13_f976s;
            Unique!FrodoPrivateKey m_tls13_f976a;
            Unique!FrodoPrivateKey m_tls13_f1344s;
            Unique!FrodoPrivateKey m_tls13_f1344a;

            const(Unique!FrodoPrivateKey)* tls13FrodoSlot(in string fname) const
            {
                if (fname == "eFrodoKEM-640-SHAKE") return &m_tls13_f640s;
                if (fname == "eFrodoKEM-640-AES") return &m_tls13_f640a;
                if (fname == "eFrodoKEM-976-SHAKE") return &m_tls13_f976s;
                if (fname == "eFrodoKEM-976-AES") return &m_tls13_f976a;
                if (fname == "eFrodoKEM-1344-SHAKE") return &m_tls13_f1344s;
                if (fname == "eFrodoKEM-1344-AES") return &m_tls13_f1344a;
                return null;
            }

            Unique!FrodoPrivateKey* tls13FrodoSlot(in string fname)
            {
                if (fname == "eFrodoKEM-640-SHAKE") return &m_tls13_f640s;
                if (fname == "eFrodoKEM-640-AES") return &m_tls13_f640a;
                if (fname == "eFrodoKEM-976-SHAKE") return &m_tls13_f976s;
                if (fname == "eFrodoKEM-976-AES") return &m_tls13_f976a;
                if (fname == "eFrodoKEM-1344-SHAKE") return &m_tls13_f1344s;
                if (fname == "eFrodoKEM-1344-AES") return &m_tls13_f1344a;
                return null;
            }

            FrodoPrivateKey tls13EnsureFrodo(in string fname, RandomNumberGenerator rng)
            {
                auto slot = tls13FrodoSlot(fname);
                if (slot is null)
                    throw new TLSException(TLSAlert.INTERNAL_ERROR, "Unknown eFrodo mode");
                if ((*slot).isEmpty)
                    *slot = new FrodoPrivateKey(fname, rng);
                return cast(FrodoPrivateKey)(*slot);
            }
        }

        void tls13EnsureMlkem768(RandomNumberGenerator rng)
        {
            if (m_tls13_mlkem.isEmpty)
                m_tls13_mlkem = new MLKEMPrivateKey(MLKEMMode.Kem768, rng);
        }

        void tls13PushBytes(TLS13KeyShareEntry e, const(ubyte)* p, size_t n)
        {
            foreach (i; 0 .. n)
                e.key_exchange.pushBack(p[i]);
        }

        void tls13EmitPqcShare(ref Vector!TLS13KeyShareEntry ents, in string n, RandomNumberGenerator rng)
        {
            if (n == TLS13_GROUP_X25519_MLKEM768_NAME)
            {
                tls13EnsureMlkem768(rng);
                auto hy = new TLS13KeyShareEntry;
                hy.group = TLS13_GROUP_X25519_MLKEM768;
                auto mk = m_tls13_mlkem.x509SubjectPublicKey();
                auto xv = m_tls13_x25519.publicValue();
                tls13PushBytes(hy, mk.ptr, mk.length);
                tls13PushBytes(hy, xv.ptr, xv.length);
                ents.pushBack(hy);
            }
            else if (n == TLS13_GROUP_MLKEM768_NAME)
            {
                tls13EnsureMlkem768(rng);
                auto e = new TLS13KeyShareEntry;
                e.group = TLS13_GROUP_MLKEM768;
                auto mk = m_tls13_mlkem.x509SubjectPublicKey();
                tls13PushBytes(e, mk.ptr, mk.length);
                ents.pushBack(e);
            }
            else if (n == TLS13_GROUP_MLKEM512_NAME)
            {
                if (m_tls13_mlkem512.isEmpty)
                    m_tls13_mlkem512 = new MLKEMPrivateKey(MLKEMMode.Kem512, rng);
                auto e = new TLS13KeyShareEntry;
                e.group = TLS13_GROUP_MLKEM512;
                auto mk = m_tls13_mlkem512.x509SubjectPublicKey();
                tls13PushBytes(e, mk.ptr, mk.length);
                ents.pushBack(e);
            }
            else if (n == TLS13_GROUP_MLKEM1024_NAME)
            {
                if (m_tls13_mlkem1024.isEmpty)
                    m_tls13_mlkem1024 = new MLKEMPrivateKey(MLKEMMode.Kem1024, rng);
                auto e = new TLS13KeyShareEntry;
                e.group = TLS13_GROUP_MLKEM1024;
                auto mk = m_tls13_mlkem1024.x509SubjectPublicKey();
                tls13PushBytes(e, mk.ptr, mk.length);
                ents.pushBack(e);
            }
            static if (BOTAN_HAS_ECDH)
            {
                if (n == TLS13_GROUP_SECP256R1_MLKEM768_NAME)
                {
                    tls13EnsureMlkem768(rng);
                    if (!m_has_tls13_p256)
                    {
                        auto grp = ECGroup("secp256r1");
                        m_tls13_p256 = ECDHPrivateKey(rng, grp);
                        m_has_tls13_p256 = true;
                    }
                    auto hy = new TLS13KeyShareEntry;
                    hy.group = TLS13_GROUP_SECP256R1_MLKEM768;
                    auto ev = m_tls13_p256.publicValue();
                    auto mk = m_tls13_mlkem.x509SubjectPublicKey();
                    tls13PushBytes(hy, ev.ptr, ev.length);
                    tls13PushBytes(hy, mk.ptr, mk.length);
                    ents.pushBack(hy);
                }
                else if (n == TLS13_GROUP_SECP384R1_MLKEM1024_NAME)
                {
                    if (m_tls13_mlkem1024.isEmpty)
                        m_tls13_mlkem1024 = new MLKEMPrivateKey(MLKEMMode.Kem1024, rng);
                    if (!m_has_tls13_p384)
                    {
                        auto grp = ECGroup("secp384r1");
                        m_tls13_p384 = ECDHPrivateKey(rng, grp);
                        m_has_tls13_p384 = true;
                    }
                    auto hy = new TLS13KeyShareEntry;
                    hy.group = TLS13_GROUP_SECP384R1_MLKEM1024;
                    auto ev = m_tls13_p384.publicValue();
                    auto mk = m_tls13_mlkem1024.x509SubjectPublicKey();
                    tls13PushBytes(hy, ev.ptr, ev.length);
                    tls13PushBytes(hy, mk.ptr, mk.length);
                    ents.pushBack(hy);
                }
            }
            static if (BOTAN_HAS_FRODOKEM)
            {
                if (auto spec = tls13FrodoOqsByName(n))
                    tls13EmitFrodoOqsShare(ents, *spec, rng);
            }
        }

        static if (BOTAN_HAS_FRODOKEM)
        {
            void tls13EmitFrodoOqsShare(ref Vector!TLS13KeyShareEntry ents,
                                        const ref Tls13FrodoOqsGroup spec,
                                        RandomNumberGenerator rng)
            {
                auto fk = tls13EnsureFrodo(spec.frodo, rng);
                auto pk = fk.x509SubjectPublicKey();
                auto e = new TLS13KeyShareEntry;
                e.group = spec.id;
                if (spec.classical == TLS13_FRODO_CLASSICAL_X25519)
                {
                    auto xv = m_tls13_x25519.publicValue();
                    tls13PushBytes(e, xv.ptr, xv.length);
                }
                else if (spec.classical == TLS13_FRODO_CLASSICAL_X448)
                {
                    static if (BOTAN_HAS_X448)
                    {
                        if (!m_has_tls13_x448)
                        {
                            m_tls13_x448 = X448PrivateKey(rng);
                            m_has_tls13_x448 = true;
                        }
                        auto xv = m_tls13_x448.publicValue();
                        tls13PushBytes(e, xv.ptr, xv.length);
                    }
                    else
                        return;
                }
                else if (spec.classical == TLS13_FRODO_CLASSICAL_P256)
                {
                    static if (BOTAN_HAS_ECDH)
                    {
                        if (!m_has_tls13_p256)
                        {
                            auto grp = ECGroup("secp256r1");
                            m_tls13_p256 = ECDHPrivateKey(rng, grp);
                            m_has_tls13_p256 = true;
                        }
                        auto ev = m_tls13_p256.publicValue();
                        tls13PushBytes(e, ev.ptr, ev.length);
                    }
                    else
                        return;
                }
                else if (spec.classical == TLS13_FRODO_CLASSICAL_P384)
                {
                    static if (BOTAN_HAS_ECDH)
                    {
                        if (!m_has_tls13_p384)
                        {
                            auto grp = ECGroup("secp384r1");
                            m_tls13_p384 = ECDHPrivateKey(rng, grp);
                            m_has_tls13_p384 = true;
                        }
                        auto ev = m_tls13_p384.publicValue();
                        tls13PushBytes(e, ev.ptr, ev.length);
                    }
                    else
                        return;
                }
                else if (spec.classical == TLS13_FRODO_CLASSICAL_P521)
                {
                    static if (BOTAN_HAS_ECDH)
                    {
                        if (!m_has_tls13_p521)
                        {
                            auto grp = ECGroup("secp521r1");
                            m_tls13_p521 = ECDHPrivateKey(rng, grp);
                            m_has_tls13_p521 = true;
                        }
                        auto ev = m_tls13_p521.publicValue();
                        tls13PushBytes(e, ev.ptr, ev.length);
                    }
                    else
                        return;
                }
                tls13PushBytes(e, pk.ptr, pk.length);
                ents.pushBack(e);
            }
        }
    }
    TLSProtocolVersion m_version;
    Vector!ubyte m_session_id;
    Vector!ubyte m_random;
    Vector!ushort m_suites;
    Vector!ubyte m_comp_methods;
    Vector!ubyte m_hello_cookie; // DTLS only

    TLSExtensions m_extensions;
}

/**
* TLSServer Hello Message
*/
final class ServerHello : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return SERVER_HELLO; }

    TLSProtocolVersion Version() const { return m_version; }

    ref const(Vector!ubyte) random() const { return m_random; }

	const(ubyte[]) randomBytes() const { return m_random[]; }

	ref const(Vector!ubyte) sessionId() const { return m_session_id; }

	const(ubyte[]) sessionIdBytes() const { return m_session_id[]; }

    ushort ciphersuite() const { return m_ciphersuite; }

    ubyte compressionMethod() const { return m_comp_method; }

    bool secureRenegotiation() const
    {
        return m_extensions.get!RenegotiationExtension() !is null;
    }

    Vector!ubyte renegotiationInfo() const
    {
        if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            return reneg.renegotiationInfo().clone;
        return Vector!ubyte();
    }

    size_t fragmentSize() const
    {
        if (MaximumFragmentLength frag = m_extensions.get!MaximumFragmentLength())
            return frag.fragmentSize();
        return 0;
    }

	bool supportsExtendedMasterSecret() const
	{
		return m_extensions.get!ExtendedMasterSecret() !is null;
	}

    bool supportsSessionTicket() const
    {
        return m_extensions.get!SessionTicket() !is null;
    }

    bool supportsHeartbeats() const
    {
        return m_extensions.get!HeartbeatSupportIndicator() !is null;
    }

    bool supportsChannelID() const
    {
        return m_extensions.get!ChannelIDSupport() !is null;
    }

    bool peerCanSendHeartbeats() const
    {
        if (auto hb = m_extensions.get!HeartbeatSupportIndicator())
            return hb.peerAllowedToSend();
        return false;
    }

    string nextProtocol() const
    {
        if (auto alpn = m_extensions.get!ApplicationLayerProtocolNotification())
            return alpn.singleProtocol();
        return "";
    }

    const(Vector!HandshakeExtensionType) extensionTypes() const
    { return m_extensions.extensionTypes(); }

    static if (BOTAN_HAS_TLS_13)
    {
        TLS13KeyShare tls13KeyShare() const { return m_extensions.get!TLS13KeyShare(); }
    }

    /*
    * Create a new TLSServer Hello message
    */
    this(HandshakeIO io,
         ref HandshakeHash hash,
         in TLSPolicy policy,
         Vector!ubyte session_id,
         TLSProtocolVersion ver,
         ushort ciphersuite,
         ubyte compression,
         size_t max_fragment_size,
         bool client_has_secure_renegotiation,
         bool client_has_extended_master_secret,
         Vector!ubyte reneg_info,
         bool offer_session_ticket,
         bool client_has_alpn,
         in string next_protocol,
         bool client_has_heartbeat,
         RandomNumberGenerator rng,
         ushort tls13_group = 0,
         const(ubyte)[] tls13_share = null) 
    {
        m_version = ver;
        m_session_id = session_id.move();
        m_random = makeHelloRandom(rng, policy);
        m_ciphersuite = ciphersuite;
        m_comp_method = compression;
		m_extensions.reserve(8);

        static if (BOTAN_HAS_TLS_13)
        {
            if (ver == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
            {
                // RFC 8446 4.1.3: legacy_version 0x0303 + selected supported_versions.
                m_extensions.add(new TLS13SupportedVersions(
                    TLSProtocolVersion(TLSProtocolVersion.TLS_V13)));
                if (tls13_group)
                {
                    auto e = new TLS13KeyShareEntry;
                    e.group = tls13_group;
                    foreach (b; tls13_share)
                        e.key_exchange.pushBack(b);
                    Vector!TLS13KeyShareEntry ents;
                    ents.pushBack(e);
                    m_extensions.add(new TLS13KeyShare(TLS13KeyShare.Kind.Server, ents.move()));
                }
                hash.update(io.send(this));
                return;
            }
        }

		if (client_has_extended_master_secret)
			m_extensions.add(new ExtendedMasterSecret);

        if (client_has_heartbeat && policy.negotiateHeartbeatSupport())
            m_extensions.add(new HeartbeatSupportIndicator(true));
        
        if (client_has_secure_renegotiation)
            m_extensions.add(new RenegotiationExtension(reneg_info.move()));
        
        if (max_fragment_size)
            m_extensions.add(new MaximumFragmentLength(max_fragment_size));
        
        if (next_protocol != "" && client_has_alpn)
            m_extensions.add(new ApplicationLayerProtocolNotification(next_protocol));
        
        if (offer_session_ticket)
            m_extensions.add(new SessionTicket());
        
        hash.update(io.send(this));
    }

    /*
    * Deserialize a TLSServer Hello message
    */
    this(const ref Vector!ubyte buf)
    {
        if (buf.length < 38)
            throw new DecodingError("ServerHello: Packet corrupted");

        TLSDataReader reader = TLSDataReader("ServerHello", buf);
        
        const ubyte major_version = reader.get_byte();
        const ubyte minor_version = reader.get_byte();
        
        m_version = TLSProtocolVersion(major_version, minor_version);
        
        m_random = reader.getFixed!ubyte(32);

        m_session_id = reader.getRange!ubyte(1, 0, 32);

        m_ciphersuite = reader.get_ushort();
        
        m_comp_method = reader.get_byte();
        
		m_extensions.reserve(8);
        m_extensions.deserialize(reader, SERVER_HELLO);

        static if (BOTAN_HAS_TLS_13) {
            import botan.tls.tls13.hello_ext;
            if (auto sv = m_extensions.get!TLS13SupportedVersions())
            {
                if (sv.versions().length)
                    m_version = sv.versions()[0];
            }
        }
    }

    bool isHelloRetryRequest() const
    {
        static immutable ubyte[32] hrr = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        ];
        return m_random.length == 32 && m_random[] == hrr[];
    }

protected:
    /*
    * Serialize a TLSServer Hello message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
		buf.reserve(512);

        TLSProtocolVersion wire_ver = m_version;
        static if (BOTAN_HAS_TLS_13)
        {
            // RFC 8446 4.1.3: ServerHello.legacy_version is 0x0303.
            if (m_version == TLSProtocolVersion(TLSProtocolVersion.TLS_V13))
                wire_ver = TLSProtocolVersion(TLSProtocolVersion.TLS_V12);
        }
        buf.pushBack(wire_ver.majorVersion());
        buf.pushBack(wire_ver.minorVersion());
        buf ~= m_random[];
        
        appendTlsLengthValue(buf, m_session_id, 1);
        
        buf.pushBack(get_byte(0, m_ciphersuite));
        buf.pushBack(get_byte(1, m_ciphersuite));
        
        buf.pushBack(m_comp_method);
                
		auto vec = m_extensions.serialize();
		buf ~= vec[];
		return buf.move();
    }

private:
    TLSProtocolVersion m_version;
    Vector!ubyte m_session_id, m_random;
    ushort m_ciphersuite;
    ubyte m_comp_method;

    TLSExtensions m_extensions;
}

/**
* TLSClient Key Exchange Message
*/
final class ClientKeyExchange : HandshakeMessage
{
public:
    override HandshakeType type() const { return CLIENT_KEX; }

    ref const(SecureVector!ubyte) preMasterSecret() const
    { return m_pre_master; }

    /*
    * Read a TLSClient Key Exchange message
    */
    this(const ref Vector!ubyte contents,
         in HandshakeState state,
         in PrivateKey server_rsa_kex_key,
         TLSCredentialsManager creds,
         in TLSPolicy policy,
         RandomNumberGenerator rng)
    {
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "RSA")
        {
            assert(state.serverCerts() && !state.serverCerts().certChain().empty,
                         "RSA key exchange negotiated so server sent a certificate");
            
            if (!server_rsa_kex_key)
                throw new InternalError("Expected RSA kex but no server kex key set");
            
            if (server_rsa_kex_key.algoName != "RSA")
                throw new InternalError("Expected RSA key but got " ~ server_rsa_kex_key.algoName);
            
            auto decryptor = scoped!PKDecryptorEME(server_rsa_kex_key, "PKCS1v15");
            
            TLSProtocolVersion client_version = state.clientHello().Version();
            
            /*
            * This is used as the pre-master if RSA decryption fails.
            * Otherwise we can be used as an oracle. See Bleichenbacher
            * "Chosen Ciphertext Attacks against Protocols Based on RSA
            * Encryption Standard PKCS #1", Crypto 98
            *
            * Create it here instead if in the catch clause as otherwise we
            * expose a timing channel WRT the generation of the fake value.
            * Some timing channel likely remains due to exception handling
            * and the like.
            */
            SecureVector!ubyte fake_pre_master = rng.randomVec(48);
            fake_pre_master[0] = client_version.majorVersion();
            fake_pre_master[1] = client_version.minorVersion();
            
            try
            {
                TLSDataReader reader = TLSDataReader("ClientKeyExchange", contents);
                m_pre_master = decryptor.decrypt(reader.getRange!ubyte(2, 0, 65535));

                if (m_pre_master.length != 48 ||
                    client_version.majorVersion() != m_pre_master[0] ||
                    client_version.minorVersion() != m_pre_master[1])
                {
                    throw new DecodingError("ClientKeyExchange: Secret corrupted");
                }
            }
            catch (Exception)
            {
                m_pre_master = fake_pre_master;
            }
        }
        else
        {
            TLSDataReader reader = TLSDataReader("ClientKeyExchange", contents);
            
            auto psk = SymmetricKey();
            
            if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
            {
                const string psk_identity = reader.getString(2, 0, 65535);
                
                psk = creds.psk("tls-server",
                                state.clientHello().sniHostname(),
                                psk_identity);
                
                if (psk.length == 0)
                {
                    if (policy.hideUnknownUsers())
                        psk = SymmetricKey(rng, 16);
                    else
                        throw new TLSException(TLSAlert.UNKNOWN_PSK_IDENTITY,
                                                "No PSK for identifier " ~ psk_identity);
                }
            }
            
            if (kex_algo == "PSK")
            {
                Vector!ubyte zeros = Vector!ubyte(psk.length);
                appendTlsLengthValue(m_pre_master, zeros, 2);
                appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
            }
            else if (kex_algo == "SRP_SHA")
            {
				static if (BOTAN_HAS_SRP6) {
	                SRP6ServerSession srp = cast(SRP6ServerSession) state.serverKex().serverSrpParams();
	                auto param_a = BigInt.decode(reader.getRange!ubyte(2, 0, 65535));
	                m_pre_master = srp.step2(&param_a).bitsOf();
				}
				else {
					throw new InternalError("ClientKeyExchange: Unknown kex type " ~ kex_algo);
				}
            }
            else if (kex_algo == "DH" || kex_algo == "DHE_PSK" ||
                     kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
            {
                const PrivateKey private_key = state.serverKex().serverKexKey();
                
                const PKKeyAgreementKey ka_key = cast(const PKKeyAgreementKey)(private_key);
                
                if (!ka_key)
                    throw new InternalError("Expected key agreement key type but got " ~
                                             private_key.algoName);
                
                try
                {
                    auto ka = scoped!PKKeyAgreement(ka_key, "Raw");
                    
                    Vector!ubyte client_pubkey;
                    
                    if (ka_key.algoName == "DH")
                        client_pubkey = reader.getRange!ubyte(2, 0, 65535);
                    else
                        client_pubkey = reader.getRange!ubyte(1, 0, 255);
					auto derived_key = ka.deriveKey(0, client_pubkey);
					SecureVector!ubyte shared_secret = derived_key.bitsOf();
                    
                    if (ka_key.algoName == "DH")
                        shared_secret = stripLeadingZeros(shared_secret);
                    
                    if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
                    {
                        appendTlsLengthValue(m_pre_master, shared_secret, 2);
                        appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                    }
                    else
                        m_pre_master = shared_secret.move();
                }
                catch(Exception e)
                {
                    /*
                    * Something failed in the DH computation. To avoid possible
                    * timing attacks, randomize the pre-master output and carry
                    * on, allowing the protocol to fail later in the finished
                    * checks.
                    */
                    m_pre_master = rng.randomVec(ka_key.publicValue().length);
                }
            }
            else
                throw new InternalError("ClientKeyExchange: Unknown kex type " ~ kex_algo);
        }
    }

    /*
    * Create a new TLSClient Key Exchange message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         TLSCredentialsManager creds,
         const PublicKey server_public_key,
         in string hostname,
         RandomNumberGenerator rng)
    {
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "PSK")
        {
            string identity_hint = "";
            
            if (state.serverKex())
            {
                TLSDataReader reader = TLSDataReader("ClientKeyExchange", state.serverKex().params());
                identity_hint = reader.getString(2, 0, 65535);
            }
            
            const string hostname_ = state.clientHello().sniHostname();
            
            const string psk_identity = creds.pskIdentity("tls-client",
                                                           hostname_,
                                                           identity_hint);
            
            appendTlsLengthValue(m_key_material, psk_identity, 2);
            
            SymmetricKey psk = creds.psk("tls-client", hostname_, psk_identity);
            
            Vector!ubyte zeros = Vector!ubyte(psk.length);
            
            appendTlsLengthValue(m_pre_master, zeros, 2);
            appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
        }
        else if (state.serverKex())
        {
            TLSDataReader reader = TLSDataReader("ClientKeyExchange", state.serverKex().params());
            
            auto psk = SymmetricKey();
            
            if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
            {
                string identity_hint = reader.getString(2, 0, 65535);
                
                const string hostname_ = state.clientHello().sniHostname();
                
                const string psk_identity = creds.pskIdentity("tls-client",
                                                               hostname_,
                                                               identity_hint);
                
                appendTlsLengthValue(m_key_material, psk_identity, 2);
                
                psk = creds.psk("tls-client", hostname_, psk_identity);
            }
            
            if (kex_algo == "DH" || kex_algo == "DHE_PSK")
            {
                BigInt p = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                BigInt Y = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                
                if (reader.remainingBytes())
                    throw new DecodingError("Bad params size for DH key exchange");
                
                if (p.bits() < policy.minimumDhGroupSize())
                    throw new TLSException(TLSAlert.INSUFFICIENT_SECURITY,
                                            "TLSServer sent DH group of " ~
                                            to!string(p.bits()) ~
                                            " bits, policy requires at least " ~
                                            to!string(policy.minimumDhGroupSize()));
                
                /*
                * A basic check for key validity. As we do not know q here we
                * cannot check that Y is in the right subgroup. However since
                * our key is ephemeral there does not seem to be any
                * advantage to bogus keys anyway.
                */
                if (Y <= 1 || Y >= p - 1)
                    throw new TLSException(TLSAlert.INSUFFICIENT_SECURITY,
                                            "TLSServer sent bad DH key for DHE exchange");
                
                DLGroup group = DLGroup(p, g);
                
                if (!group.verifyGroup(rng, false))
                    throw new TLSException(TLSAlert.INSUFFICIENT_SECURITY, "DH group failed validation, possible attack");
                auto counterparty_key = DHPublicKey(group.clone, Y.move);
                
                auto priv_key = DHPrivateKey(rng, group.move);
                
                auto ka = scoped!PKKeyAgreement(priv_key, "Raw");
                
				auto octet_string = ka.deriveKey(0, counterparty_key.publicValue());
                SecureVector!ubyte dh_secret = stripLeadingZeros(octet_string.bitsOf());
                
                if (kex_algo == "DH")
                    m_pre_master = dh_secret.move();
                else
                {
                    appendTlsLengthValue(m_pre_master, dh_secret, 2);
                    appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                }
                
                appendTlsLengthValue(m_key_material, priv_key.publicValue(), 2);
            }
            else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
            {
                const ubyte curve_type = reader.get_byte();
                
                if (curve_type != 3)
                    throw new DecodingError("TLSServer sent non-named ECC curve");
                
                const ushort curve_id = reader.get_ushort();
                
                const string curve_name = SupportedEllipticCurves.curveIdToName(curve_id);
                
				if (curve_name == "")
                    throw new DecodingError("TLSServer sent unknown named curve " ~ to!string(curve_id));
				{
					Vector!string allowed_curves = policy.allowedEccCurves();
					if(!(allowed_curves[]).canFind(curve_name))
						throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Server sent ECC curve prohibited by policy");
				}
				Vector!ubyte ecdh_key = reader.getRange!ubyte(1, 1, 255);

				Vector!ubyte our_ecdh_public;
				SecureVector!ubyte ecdh_secret;

				if (curve_name == "x25519") {
					import botan.pubkey.algo.curve25519;
					if (ecdh_key.length != 32)
						throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Invalid X25519 key size");
					Curve25519PublicKey counterparty_key = Curve25519PublicKey(ecdh_key);
					Curve25519PrivateKey priv_key = Curve25519PrivateKey(rng);

					auto ka = scoped!PKKeyAgreement(priv_key, "Raw");
					auto public_value = counterparty_key.publicValue();
					auto derived_key = ka.deriveKey(0, public_value);

					ecdh_secret = derived_key.bitsOf();
					our_ecdh_public = priv_key.publicValue();

				} else {
					ECGroup group = ECGroup(curve_name);
	                
	                
	                auto counterparty_key = ECDHPublicKey(group, OS2ECP(ecdh_key, group.getCurve()));	                
	                auto priv_key = ECDHPrivateKey(rng, group);
					
					auto ka = scoped!PKKeyAgreement(priv_key, "Raw");
					auto public_value = counterparty_key.publicValue();
					auto derived_key = ka.deriveKey(0, public_value);

					ecdh_secret = derived_key.bitsOf();
					our_ecdh_public = priv_key.publicValue();
				}
                if (kex_algo == "ECDH")
                    m_pre_master = ecdh_secret.move();
                else
                {
                    appendTlsLengthValue(m_pre_master, ecdh_secret, 2);
                    appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                }
                
				appendTlsLengthValue(m_key_material, our_ecdh_public, 1);
            }
            else if (kex_algo == "SRP_SHA")
            {
				static if (BOTAN_HAS_SRP6) {
	                const BigInt N = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
	                const BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
	                Vector!ubyte salt = reader.getRange!ubyte(1, 1, 255);
	                const BigInt B = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
	                
	                const string srp_group = srp6GroupIdentifier(N, g);
	                
	                const string srp_identifier = creds.srpIdentifier("tls-client", hostname);
	                
	                const string srp_password = creds.srpPassword("tls-client", hostname, srp_identifier);
	                
	                SRP6KeyPair srp_vals = srp6ClientAgree(srp_identifier,
	                                                                       srp_password,
	                                                                       srp_group,
	                                                                       "SHA-1",
	                                                                       salt,
	                                                                       B,
	                                                                       rng);
	                
	                appendTlsLengthValue(m_key_material, BigInt.encode(srp_vals.privkey), 2);
	                m_pre_master = srp_vals.pubkey.bitsOf();
				} else {
					throw new InternalError("ClientKeyExchange: Unknown kex " ~ kex_algo);
				}
            }
            else
            {
                throw new InternalError("ClientKeyExchange: Unknown kex " ~
                                         kex_algo);
            }
            
            reader.assertDone();
        }
        else
        {
            // No server key exchange msg better mean RSA kex + RSA key in cert
            
            if (kex_algo != "RSA")
                throw new TLSUnexpectedMessage("No server kex but negotiated kex " ~ kex_algo);
            
            if (!server_public_key)
                throw new InternalError("No server public key for RSA exchange");
            
            if (server_public_key.algoName == "RSA")
            {
                auto rsa_pub = RSAPublicKey(cast(PublicKey)server_public_key);
                const TLSProtocolVersion offered_version = state.clientHello().Version();
                
                m_pre_master = rng.randomVec(48);
                m_pre_master[0] = offered_version.majorVersion();
                m_pre_master[1] = offered_version.minorVersion();
                
                auto encryptor = scoped!PKEncryptorEME(rsa_pub, "PKCS1v15");
                
                Vector!ubyte encrypted_key = encryptor.encrypt(m_pre_master, rng);
                
                appendTlsLengthValue(m_key_material, encrypted_key, 2);
            }
            else
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                        "Expected a RSA key in server cert but got " ~
                                        server_public_key.algoName);
        }
        
        state.hash().update(io.send(this));
    }


protected:
    override Vector!ubyte serialize() const { return m_key_material.clone; }

private:
    Vector!ubyte m_key_material;
    SecureVector!ubyte m_pre_master;
}

/**
* Certificate Message
*/
final class Certificate : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE; }
    ref const(Vector!X509Certificate) certChain() const { return *m_certs; }

    size_t count() const { return m_certs.length; }
    @property bool empty() const { return m_certs.empty; }

    /**
    * Create a new Certificate message
    */
    this()(HandshakeIO io,
           ref HandshakeHash hash,
           auto ref Array!X509Certificate cert_list)
    {
        m_certs = cert_list;
        hash.update(io.send(this));
    }

    /**
    * Create a new Certificate message
    */
    this()(HandshakeIO io,
        ref HandshakeHash hash,
        auto ref Vector!X509Certificate cert_list)
    {
        m_certs = cert_list.cloneToRef;
        hash.update(io.send(this));
    }

    /**
    * Store a certificate chain without sending (TLS 1.3 uses TLS13Certificate on the wire).
    */
    this()(auto ref Vector!X509Certificate cert_list)
    {
        m_certs = cert_list.cloneToRef;
    }

    /**
    * Deserialize a Certificate message
    */
    this()(const auto ref Vector!ubyte buf)
    {
        if (buf.length < 3)
            throw new DecodingError("Certificate: Message malformed");
        
        const size_t total_size = make_uint(0, buf[0], buf[1], buf[2]);

        if (total_size != buf.length - 3)
            throw new DecodingError("Certificate: Message malformed");
        
        const(ubyte)* certs = buf.ptr + 3;
        
        while (true)
        {
            size_t remaining_bytes = buf.ptr + buf.length - certs;
            if (remaining_bytes <= 0)
                break;
            if (remaining_bytes < 3)
                throw new DecodingError("Certificate: Message malformed");
            
            const size_t cert_size = make_uint(0, certs[0], certs[1], certs[2]);
            
            if (remaining_bytes < (3 + cert_size))
                throw new DecodingError("Certificate: Message malformed");
            
            auto cert_buf = DataSourceMemory(&certs[3], cert_size);
            auto cert = X509Certificate(cast(DataSource)cert_buf);
            m_certs.pushBack(cert);
            
            certs += cert_size + 3;
        }
    }

protected:
    /**
    * Serialize a Certificate message
    */
    override Vector!ubyte serialize() const
    {
		Vector!ubyte buf;
		buf.reserve(2048);
		buf.length = 3;
        for (size_t i = 0; i != m_certs.length; ++i)
        {
            auto cert = m_certs[i];
            if (!cert.isValid()) continue;
            Vector!ubyte raw_cert = cert.BER_encode();
            const size_t cert_size = raw_cert.length;
            foreach (size_t j; 0 .. 3)
                buf.pushBack(get_byte!uint(j+1, cast(uint) cert_size));
            buf ~= raw_cert;
        }
        
        const size_t buf_size = buf.length - 3;
        foreach (size_t i; 0 .. 3)
            buf[i] = get_byte!uint(i+1, cast(uint) buf_size);
        
        return buf.move();
    }

private:
    Array!X509Certificate m_certs;
}

/**
* Certificate Request Message
*/
final class CertificateReq : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE_REQUEST; }

    ref const(Vector!string) acceptableCertTypes() const
    { return m_cert_key_types; }

    ref const(Vector!X509DN) acceptableCAs() const { return m_names; }

    Vector!( Pair!(string, string) ) supportedAlgos() const
    { return m_supported_algos.clone; }

    /**
    * Create a new Certificate Request message
    */
    this(HandshakeIO io,
         ref HandshakeHash hash,
         in TLSPolicy policy,
         Vector!X509DN ca_certs,
         TLSProtocolVersion _version) 
    {
        m_names = ca_certs.move();
        m_cert_key_types = [ "RSA", "DSA", "ECDSA" ];
		static Vector!( Pair!(string, string)  ) last_supported_algos;
		static TLSPolicy last_tls_policy;
        static TLSProtocolVersion last_version;
		if (policy is last_tls_policy && _version == last_version)
			m_supported_algos = last_supported_algos.clone;
		else {
			m_supported_algos.reserve(16);
	        if (_version.supportsNegotiableSignatureAlgorithms())
	        {
	            Vector!string hashes = policy.allowedSignatureHashes();
	            Vector!string sigs = policy.allowedSignatureMethods();
	            
	            for (size_t i = 0; i != hashes.length; ++i)
	                for (size_t j = 0; j != sigs.length; ++j)
	                    m_supported_algos.pushBack(makePair(hashes[i], sigs[j]));
	        }
			last_tls_policy = cast() policy;
            last_version = _version;
			last_supported_algos = m_supported_algos.clone;
		}
        
        hash.update(io.send(this));
    }

    /**
    * Deserialize a Certificate Request message
    */
    this(const ref Vector!ubyte buf, TLSProtocolVersion _version)
    {
        if (buf.length < 4)
            throw new DecodingError("Certificate_Req: Bad certificate request");
        
        TLSDataReader reader = TLSDataReader("CertificateRequest", buf);

        Vector!ubyte cert_type_codes = reader.getRangeVector!ubyte(1, 1, 255);
        
        for (size_t i = 0; i != cert_type_codes.length; ++i)
        {
            const string cert_type_name = certTypeCodeToName(cert_type_codes[i]);
            
            if (cert_type_name == "") // something we don't know
                continue;
            
            m_cert_key_types.pushBack(cert_type_name);
        }
        
        if (_version.supportsNegotiableSignatureAlgorithms())
        {
            Vector!ubyte sig_hash_algs = reader.getRangeVector!ubyte(2, 2, 65534);
            
            if (sig_hash_algs.length % 2 != 0)
                throw new DecodingError("Bad length for signature IDs in certificate request");
            
            for (size_t i = 0; i != sig_hash_algs.length; i += 2)
            {
                string hash = SignatureAlgorithms.hashAlgoName(sig_hash_algs[i]);
                string sig = SignatureAlgorithms.sigAlgoName(sig_hash_algs[i+1]);
                m_supported_algos.pushBack(makePair(hash, sig));
            }
        }
        
        const ushort purported_size = reader.get_ushort();
        
        if (reader.remainingBytes() != purported_size)
            throw new DecodingError("Inconsistent length in certificate request");
        
        while (reader.hasRemaining())
        {
            Vector!ubyte name_bits = reader.getRangeVector!ubyte(2, 0, 65535);
            
            BERDecoder decoder = BERDecoder(name_bits.ptr, name_bits.length);
            X509DN name = X509DN();
            decoder.decode(name);
            m_names.pushBack(name);
        }
    }

protected:

    /**
    * Serialize a Certificate Request message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
		buf.reserve(256);
        Vector!ubyte cert_types;
		cert_types.reserve(64);
        for (size_t i = 0; i != m_cert_key_types.length; ++i)
            cert_types.pushBack(certTypeNameToCode(m_cert_key_types[i]));

        appendTlsLengthValue(buf, cert_types, 1);
        
        if (!m_supported_algos.empty) {
			Unique!SignatureAlgorithms sig_algos = new SignatureAlgorithms(m_supported_algos.clone);
            buf ~= sig_algos.serialize();
		}
        
        Vector!ubyte encoded_names;
        
        for (size_t i = 0; i != m_names.length; ++i)
        {
            DEREncoder encoder = DEREncoder();
            encoder.encode(m_names[i]);
            
            appendTlsLengthValue(encoded_names, encoder.getContents(), 2);
        }
        
        appendTlsLengthValue(buf, encoded_names, 2);
        
        return buf.move();
    }

private:
    Vector!X509DN m_names;
    Vector!string m_cert_key_types;

    Vector!( Pair!(string, string)  ) m_supported_algos;
}

/**
* Certificate Verify Message
*/
final class CertificateVerify : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE_VERIFY; }

    /**
    * Check the signature on a certificate verify message
    * Params:
    *  cert = the purported certificate
    *  state = the handshake state
    */
    bool verify(const X509Certificate cert,
                const HandshakeState state) const
    {
        Unique!PublicKey key = cert.subjectPublicKey();
        
        Pair!(string, SignatureFormat) format = state.understandSigFormat(*key, m_hash_algo, m_sig_algo, true);
        
        PKVerifier verifier = PKVerifier(*key, format.first, format.second);
        
        return verifier.verifyMessage(state.hash().getContents(), m_signature);
    }

    /*
    * Create a new Certificate Verify message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         const PrivateKey priv_key)
    {
        assert(priv_key, "No private key defined");
        
        Pair!(string, SignatureFormat) format = state.chooseSigFormat(priv_key, m_hash_algo, m_sig_algo, true, policy);
        
        PKSigner signer = PKSigner(priv_key, format.first, format.second);
        
		m_signature = signer.signMessage(state.hash().getContents(), rng);
                
        state.hash().update(io.send(this));
    }

    /*
    * Deserialize a Certificate Verify message
    */
    this(const ref Vector!ubyte buf,
         TLSProtocolVersion _version)
    {
        TLSDataReader reader = TLSDataReader("CertificateVerify", buf);
        
        if (_version.supportsNegotiableSignatureAlgorithms())
        {
            const ushort alg = reader.get_ushort();
            m_hash_algo = SignatureAlgorithms.hashAlgoName(cast(ubyte)(alg >> 8));
            m_sig_algo = SignatureAlgorithms.sigAlgoName(cast(ubyte) alg);
        }
        
        m_signature = reader.getRange!ubyte(2, 0, 65535);
    }

protected:
    /*
    * Serialize a Certificate Verify message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        if (m_hash_algo != "" && m_sig_algo != "")
        {
            buf.pushBack(SignatureAlgorithms.hashAlgoCode(m_hash_algo));
            buf.pushBack(SignatureAlgorithms.sigAlgoCode(m_sig_algo));
        }
        
        const ushort sig_len = cast(ushort) m_signature.length;
        buf.pushBack(get_byte(0, sig_len));
        buf.pushBack(get_byte(1, sig_len));
        buf ~= m_signature[];
        
        return buf.move();
    }

private:
    string m_sig_algo; // sig algo used to create signature
    string m_hash_algo; // hash used to create signature
    Vector!ubyte m_signature;
}

/**
* Finished Message
*/
final class Finished : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return FINISHED; }

    ref const(Vector!ubyte) verifyData() const
    { return m_verification_data; }

	const(ubyte[]) verifyDataBytes() const { return m_verification_data[]; }

    /*
    * Verify a Finished message
    */
    bool verify(in HandshakeState state, ConnectionSide side) const
    {
        return (m_verification_data == finishedComputeVerify(state, side));
    }

    /*
    * Create a new Finished message
    */
    this(HandshakeIO io,
         HandshakeState state,
         ConnectionSide side)
    {
        m_verification_data = finishedComputeVerify(state, side);
        state.hash().update(io.send(this));
    }

    /// TLS 1.3: verify_data already computed (HMAC of transcript hash).
    this(HandshakeIO io, ref HandshakeHash hash, Vector!ubyte verify_data)
    {
        m_verification_data = verify_data.move();
        hash.update(io.send(this));
    }

    /*
    * Deserialize a Finished message
    */
    this(Vector!ubyte buf)
    {
        m_verification_data = buf.move();
    }

protected:
    /*
    * Serialize a Finished message
    */
    override Vector!ubyte serialize() const
    {
        return m_verification_data.clone;
    }
   
private:
    Vector!ubyte m_verification_data;
}

/**
* Hello Request Message
*/
final class HelloRequest : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return HELLO_REQUEST; }

    /*
    * Create a new Hello Request message
    */
    this(HandshakeIO io)
    {
        io.send(this);
    }

    /*
    * Deserialize a Hello Request message
    */
    this(const ref Vector!ubyte buf)
    {
        if (buf.length)
            throw new DecodingError("Bad HelloRequest, has non-zero size");
    }

protected:
    /*
    * Serialize a Hello Request message
    */
    override Vector!ubyte serialize() const
    {
        return Vector!ubyte();
    }
}

/**
* TLSServer Key Exchange Message
*/
final class ServerKeyExchange : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return SERVER_KEX; }

    ref const(Vector!ubyte) params() const { return m_params; }

    /**
    * Verify a TLSServer Key Exchange message
    */
    bool verify(in PublicKey server_key,
                const HandshakeState state) const
    {
        Pair!(string, SignatureFormat) format = state.understandSigFormat(server_key, m_hash_algo, m_sig_algo, false);

        PKVerifier verifier = PKVerifier(server_key, format.first, format.second);
        verifier.update(state.clientHello().random());
        verifier.update(state.serverHello().random());
        verifier.update(params());
        return verifier.checkSignature(m_signature);
    }

    // Only valid for certain kex types
    const(PrivateKey) serverKexKey() const
    {
        assert(m_kex_key, "PrivateKey cannot be null");
        return *m_kex_key;
    }

	static if (BOTAN_HAS_SRP6) {
	    // Only valid for SRP negotiation
	    const(SRP6ServerSession) serverSrpParams() const
	    {
	        assert(m_srp_params, "SRP6ServerSession cannot be null");
	        return *m_srp_params;
	    }
	}

    /**
    * Deserialize a TLSServer Key Exchange message
    */
    this(const ref Vector!ubyte buf,
         in string kex_algo,
         in string sig_algo,
         TLSProtocolVersion _version) 
    {
        m_kex_key.free();
		static if (BOTAN_HAS_SRP6)
	        m_srp_params.free();
        if (buf.length < 6)
            throw new DecodingError("ServerKeyExchange: Packet corrupted");
        
        TLSDataReader reader = TLSDataReader("ServerKeyExchange", buf);
        
        /*
        * We really are just serializing things back to what they were
        * before, but unfortunately to know where the signature is we need
        * to be able to parse the whole thing anyway.
        */
        
        if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
        {
            const string identity_hint = reader.getString(2, 0, 65535);
            appendTlsLengthValue(m_params, identity_hint, 2);
        }
        
        if (kex_algo == "DH" || kex_algo == "DHE_PSK")
        {
            // 3 bigints, DH p, g, Y
            
            foreach (size_t i; 0 .. 3)
            {
                BigInt v = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                appendTlsLengthValue(m_params, BigInt.encode(v), 2);
            }
        }
        else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
        {
            const ubyte curve_type = reader.get_byte();
            
            if (curve_type != 3)
                throw new DecodingError("ServerKeyExchange: TLSServer sent non-named ECC curve");
            
            const ushort curve_id = reader.get_ushort();
            
            const string name = SupportedEllipticCurves.curveIdToName(curve_id);
            
            Vector!ubyte ecdh_key = reader.getRange!ubyte(1, 1, 255);
            
            if (name == "")
                throw new DecodingError("ServerKeyExchange: TLSServer sent unknown named curve " ~
                                         to!string(curve_id));
            
            m_params.pushBack(curve_type);
            m_params.pushBack(get_byte(0, curve_id));
            m_params.pushBack(get_byte(1, curve_id));
            appendTlsLengthValue(m_params, ecdh_key, 1);
        }
        else if (kex_algo == "SRP_SHA")
        {
            // 2 bigints (N,g) then salt, then server B
            
            const BigInt N = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            const BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            Vector!ubyte salt = reader.getRange!ubyte(1, 1, 255);
            const BigInt B = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            
            appendTlsLengthValue(m_params, BigInt.encode(N), 2);
            appendTlsLengthValue(m_params, BigInt.encode(g), 2);
            appendTlsLengthValue(m_params, salt, 1);
            appendTlsLengthValue(m_params, BigInt.encode(B), 2);
        }
        else if (kex_algo != "PSK")
                throw new DecodingError("ServerKeyExchange: Unsupported kex type " ~ kex_algo);
        
        if (sig_algo != "")
        {
            if (_version.supportsNegotiableSignatureAlgorithms())
            {
				ubyte hash_byte = reader.get_byte();
				ubyte sig_byte = reader.get_byte();
				if (hash_byte == 8) {
					m_hash_algo = SignatureAlgorithms.hashAlgoName(sig_byte);
					m_sig_algo = SignatureAlgorithms.sigAlgoName(hash_byte);
				}
				else {
	                m_hash_algo = SignatureAlgorithms.hashAlgoName(hash_byte);
	                m_sig_algo = SignatureAlgorithms.sigAlgoName(sig_byte);
				}
            }
            m_signature = reader.getRange!ubyte(2, 0, 65535);
        }
        
        reader.assertDone();
    }

    /**
    * Create a new TLSServer Key Exchange message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         TLSCredentialsManager creds,
         RandomNumberGenerator rng,
         in PrivateKey signing_key = null)
    {
        const string hostname = state.clientHello().sniHostname();
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
        {
            string identity_hint = creds.pskIdentityHint("tls-server", hostname);
            
            appendTlsLengthValue(m_params, identity_hint, 2);
        }
        
        if (kex_algo == "DH" || kex_algo == "DHE_PSK")
        {
            auto dh = DHPrivateKey(rng, policy.dhGroup());

            appendTlsLengthValue(m_params, BigInt.encode(dh.getDomain().getP()), 2);
            appendTlsLengthValue(m_params, BigInt.encode(dh.getDomain().getG()), 2);
            appendTlsLengthValue(m_params, dh.publicValue(), 2);
            m_kex_key = dh.release();
        }
        else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
        {
            Vector!string curves = state.clientHello().supportedEccCurves();
            
            if (curves.empty)
                throw new InternalError("TLSClient sent no ECC extension but we negotiated ECDH");
            
            const string curve_name = policy.chooseCurve(curves.move());
            
            if (curve_name == "")
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Could not agree on an ECC curve with the client");
			const ushort named_curve_id = SupportedEllipticCurves.nameToCurveId(curve_name);
			if (named_curve_id == 0)
				throw new InternalError("TLS does not support ECC with " ~ curve_name);
			Vector!ubyte ecdh_public_val;

			if (curve_name == "x25519") {
				import botan.pubkey.algo.curve25519;
				Curve25519PrivateKey x25519 = Curve25519PrivateKey(rng);
				ecdh_public_val = x25519.publicValue();
				m_kex_key = x25519.release();
			} else {
	            ECGroup ec_group = ECGroup(curve_name);	            
	            auto ecdh = ECDHPrivateKey(rng, ec_group);
				ecdh_public_val = ecdh.publicValue();
	            
				m_kex_key = ecdh.release();
			}
            m_params.pushBack(3); // named curve
            m_params.pushBack(get_byte(0, named_curve_id));
            m_params.pushBack(get_byte(1, named_curve_id));
            
            appendTlsLengthValue(m_params, ecdh_public_val, 1);
            
        }
        else if (kex_algo == "SRP_SHA")
        {
			static if (BOTAN_HAS_SRP6) {
	            const string srp_identifier = state.clientHello().srpIdentifier();
	            
	            string group_id;
	            BigInt v;
	            Vector!ubyte salt;
	            
	            const bool found = creds.srpVerifier("tls-server", hostname,
	                                                  srp_identifier,
	                                                  group_id, v, salt,
	                                                  policy.hideUnknownUsers());
	            
	            if (!found)
	                throw new TLSException(TLSAlert.UNKNOWN_PSK_IDENTITY, "Unknown SRP user " ~ srp_identifier);
	            
	            m_srp_params = new SRP6ServerSession;
	            
	            const BigInt* B = &m_srp_params.step1(v, group_id, "SHA-1", rng);
	            
	            DLGroup group = DLGroup(group_id);

	            appendTlsLengthValue(m_params, BigInt.encode(group.getP()), 2);
	            appendTlsLengthValue(m_params, BigInt.encode(group.getG()), 2);
	            appendTlsLengthValue(m_params, salt, 1);
	            appendTlsLengthValue(m_params, BigInt.encode(*B), 2);
			} else {
				throw new InternalError("ServerKeyExchange: Unknown kex type " ~ kex_algo);
			}
        }
        else if (kex_algo != "PSK")
            throw new InternalError("ServerKeyExchange: Unknown kex type " ~ kex_algo);
        
        if (state.ciphersuite().sigAlgo() != "")
        {
            assert(signing_key, "Signing key was set");
            
            Pair!(string, SignatureFormat) format = state.chooseSigFormat(signing_key, m_hash_algo, m_sig_algo, false, policy);
            
            PKSigner signer = PKSigner(signing_key, format.first, format.second);
            
            signer.update(state.clientHello().random());
            signer.update(state.serverHello().random());
            signer.update(params());
            m_signature = signer.signature(rng);
        }
        
        state.hash().update(io.send(this));
    }

protected:
    /**
    * Serialize a TLSServer Key Exchange message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = params().clone;
        
        if (m_signature.length)
        {
            // This should be an explicit version check
            if (m_hash_algo != "" && m_sig_algo != "")
            {
                buf.pushBack(SignatureAlgorithms.hashAlgoCode(m_hash_algo));
                buf.pushBack(SignatureAlgorithms.sigAlgoCode(m_sig_algo));
            }
            
            appendTlsLengthValue(buf, m_signature, 2);
        }
        
        return buf.move();
    }

private:
    Unique!PrivateKey m_kex_key;
	static if (BOTAN_HAS_SRP6)
	    Unique!SRP6ServerSession m_srp_params;

    Vector!ubyte m_params;

    string m_sig_algo; // sig algo used to create signature
    string m_hash_algo; // hash used to create signature
    Vector!ubyte m_signature;
}

/**
* TLSServer Hello Done Message
*/
final class ServerHelloDone : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return SERVER_HELLO_DONE; }

    /*
    * Create a new TLSServer Hello Done message
    */
    this(HandshakeIO io, ref HandshakeHash hash)
    {
        hash.update(io.send(this));
    }

    /*
    * Deserialize a TLSServer Hello Done message
    */
    this(const ref Vector!ubyte buf)
    {
        if (buf.length)
            throw new DecodingError("ServerHello_Done: Must be empty, and is not");
    }
protected:
    /*
    * Serialize a TLSServer Hello Done message
    */
    override Vector!ubyte serialize() const
    {
        return Vector!ubyte();
    }
}

static if (BOTAN_HAS_TLS_13):
/**
* RFC 8446 4.3.1 EncryptedExtensions (handshake type 8).
* Subsequent handshake flight is still the next T13d slice; this type is
* parse/emit only until TLSChannel wires 1.3 record protection.
*/
final class TLS13EncryptedExtensions : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return ENCRYPTED_EXTENSIONS; }

    this() {}

    this(in ClientHello ch, string alpn = "")
    {
        if (ch.sniHostname().length)
            m_extensions.add(new ServerNameIndicator("", true));
        if (alpn.length)
            m_extensions.add(new ApplicationLayerProtocolNotification(alpn));
    }

    this(HandshakeIO io, ref HandshakeHash hash, in ClientHello ch, string alpn = "")
    {
        this(ch, alpn);
        hash.update(io.send(this));
    }

    this(const ref Vector!ubyte buf)
    {
        if (buf.length < 2)
            throw new TLSException(TLSAlert.DECODE_ERROR, "Server sent an empty Encrypted Extensions message");
        TLSDataReader reader = TLSDataReader("EncryptedExtensions", buf);
        m_extensions.deserialize(reader, ENCRYPTED_EXTENSIONS);
    }

    const(Vector!HandshakeExtensionType) extensionTypes() const
    { return m_extensions.extensionTypes(); }

    string nextProtocol() const
    {
        if (auto alpn = m_extensions.get!ApplicationLayerProtocolNotification())
            return alpn.singleProtocol();
        return "";
    }

    override Vector!ubyte serialize() const
    {
        auto vec = m_extensions.serialize();
        // RFC 8446 4.3.1: empty list is still a 2-byte length prefix.
        if (vec.empty)
        {
            vec.pushBack(0);
            vec.pushBack(0);
        }
        return vec.move();
    }

private:
    TLSExtensions m_extensions;
}

/**
* RFC 8446 4.4.2 Certificate (request_context + CertificateEntry list).
* Optional leaf OCSP staple is a status_request extension on the first entry.
*/
final class TLS13Certificate : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE; }

    ref const(Vector!X509Certificate) certChain() const { return m_certs; }
    ref const(Vector!ubyte) ocspStaple() const { return m_ocsp_staple; }
    @property bool empty() const { return m_certs.empty; }

    this(Vector!X509Certificate certs, Vector!ubyte ocsp_staple = Vector!ubyte())
    {
        m_certs = certs.move();
        m_ocsp_staple = ocsp_staple.move();
    }

    this(HandshakeIO io, ref HandshakeHash hash, Vector!X509Certificate certs,
         Vector!ubyte ocsp_staple = Vector!ubyte())
    {
        this(certs.move(), ocsp_staple.move());
        hash.update(io.send(this));
    }

    this(const ref Vector!ubyte buf, ConnectionSide side)
    {
        TLSDataReader reader = TLSDataReader("Certificate13", buf);
        auto ctx = reader.getRange!ubyte(1, 0, 255);
        if (side == SERVER && ctx.length)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER,
                                   "Server Certificate message must not contain a request context");
        if (reader.remainingBytes() < 3)
            throw new DecodingError("Certificate: Message malformed");
        const size_t list_len = make_uint(0, reader.get_byte(), reader.get_byte(), reader.get_byte());
        if (reader.remainingBytes() != list_len)
            throw new DecodingError("Certificate: Message malformed");
        bool first = true;
        while (reader.hasRemaining())
        {
            if (reader.remainingBytes() < 3)
                throw new DecodingError("Certificate: Message malformed");
            const size_t cert_size = make_uint(0, reader.get_byte(), reader.get_byte(), reader.get_byte());
            auto raw = reader.getFixed!ubyte(cert_size);
            m_certs.pushBack(X509Certificate(raw));
            if (reader.remainingBytes() < 2)
                throw new DecodingError("Certificate: Message malformed");
            const ushort extn_size = reader.get_ushort();
            if (extn_size)
            {
                Vector!ubyte ext_buf;
                ext_buf.pushBack(get_byte(0, extn_size));
                ext_buf.pushBack(get_byte(1, extn_size));
                auto ext_body = reader.getFixed!ubyte(extn_size);
                ext_buf ~= ext_body[];
                if (first)
                {
                    TLSDataReader er = TLSDataReader("Certificate13Ext", ext_buf);
                    TLSExtensions entry_ext;
                    entry_ext.deserialize(er, CERTIFICATE);
                    if (auto sr = entry_ext.get!StatusRequest())
                        m_ocsp_staple = sr.ocspResponse().clone;
                }
            }
            first = false;
        }
        if (side == SERVER && m_certs.empty)
            throw new TLSException(TLSAlert.DECODE_ERROR, "No certificates sent by server");
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.pushBack(0); // empty request_context
        Vector!ubyte entries;
        bool first = true;
        foreach (const ref cert; m_certs[])
        {
            auto raw = cert.BER_encode();
            foreach (size_t j; 0 .. 3)
                entries.pushBack(get_byte!uint(j + 1, cast(uint) raw.length));
            entries ~= raw[];
            TLSExtensions entry_ext;
            static if (BOTAN_HAS_OCSP_STAPLE)
            {
                if (first && m_ocsp_staple.length)
                    entry_ext.add(new StatusRequest(m_ocsp_staple.clone));
            }
            first = false;
            auto extn = entry_ext.serialize();
            if (extn.empty)
            {
                entries.pushBack(0);
                entries.pushBack(0);
            }
            else
                entries ~= extn[];
        }
        foreach (size_t j; 0 .. 3)
            buf.pushBack(get_byte!uint(j + 1, cast(uint) entries.length));
        buf ~= entries[];
        return buf.move();
    }

private:
    Vector!X509Certificate m_certs;
    Vector!ubyte m_ocsp_staple;
}

/// RFC 8446 4.4.3 rsa_pss_rsae_sha256
enum ushort TLS13_RSA_PSS_RSAE_SHA256 = 0x0804;

/**
* RFC 8446 4.4.3 CertificateVerify (SignatureScheme + signature).
*/
final class TLS13CertificateVerify : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE_VERIFY; }

    this(HandshakeIO io, ref HandshakeHash hash, ushort scheme, Vector!ubyte signature)
    {
        m_scheme = scheme;
        m_signature = signature.move();
        hash.update(io.send(this));
    }

    this(const ref Vector!ubyte buf)
    {
        TLSDataReader reader = TLSDataReader("CertificateVerify13", buf);
        m_scheme = reader.get_ushort();
        m_signature = reader.getRange!ubyte(2, 0, 65535);
    }

    ushort scheme() const { return m_scheme; }
    ref const(Vector!ubyte) signature() const { return m_signature; }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.pushBack(get_byte(0, m_scheme));
        buf.pushBack(get_byte(1, m_scheme));
        const ushort sig_len = cast(ushort) m_signature.length;
        buf.pushBack(get_byte(0, sig_len));
        buf.pushBack(get_byte(1, sig_len));
        buf ~= m_signature[];
        return buf.move();
    }

private:
    ushort m_scheme;
    Vector!ubyte m_signature;
}

/**
 * New EncryptedExtensions Message used mainly for ChannelIDExtension
 */
final class ChannelID : HandshakeMessage
{
    override const(HandshakeType) type() const { return CHANNEL_ID; }

    this(HandshakeIO io, 
         ref HandshakeHash hash,
         TLSCredentialsManager creds, 
         string hostname, 
         SecureVector!ubyte hs_hash,
         SecureVector!ubyte orig_hs_hash = SecureVector!ubyte())
    {
        m_channel_id = new EncryptedChannelID(creds.channelPrivateKey(hostname), hs_hash.move(), orig_hs_hash.move());
        hash.update(io.send(this));
    }

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        buf.reserve(130);

        const ushort extn_code = m_channel_id.type();
        const Vector!ubyte extn_val = m_channel_id.serialize();
        
        buf.pushBack(get_byte(0, extn_code));
        buf.pushBack(get_byte(1, extn_code));
        
        buf.pushBack(get_byte(0, cast(ushort) extn_val.length));
        buf.pushBack(get_byte(1, cast(ushort) extn_val.length));
        
        buf ~= extn_val[];
        return buf.move();
    }

private:
    Unique!EncryptedChannelID m_channel_id;
}

/**
* New TLS Session Ticket Message
*/
final class NewSessionTicket : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return NEW_SESSION_TICKET; }

    const(Duration) ticketLifetimeHint() const { return m_ticket_lifetime_hint; }
    ref const(Vector!ubyte) ticket() const { return m_ticket; }

    this(HandshakeIO io,
         ref HandshakeHash hash,
         Vector!ubyte ticket,
         Duration lifetime) 
        
    {   
        m_ticket_lifetime_hint = lifetime;
        m_ticket = ticket.move();
        hash.update = io.send(this);
    }

    this(const ref Vector!ubyte buf)
    {
        if (buf.length < 6)
            throw new DecodingError("TLSSession ticket message too short to be valid");
        
        TLSDataReader reader = TLSDataReader("SessionTicket", buf);
        
        m_ticket_lifetime_hint = reader.get_uint().seconds;
        m_ticket = reader.getRange!ubyte(2, 0, 65535);
    }

    this(HandshakeIO io, ref HandshakeHash hash)
    {
        hash.update(io.send(this));
    }

protected:
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(4);
        storeBigEndian(m_ticket_lifetime_hint.total!"seconds", buf.ptr);
        appendTlsLengthValue(buf, m_ticket, 2);
        return buf.move();
    }

private:
    Duration m_ticket_lifetime_hint;
    Vector!ubyte m_ticket;
}

/**
* RFC 6066 CertificateStatus handshake message (type 22).
* Body: status_type (1 = OCSP) + 3-byte length + OCSP response.
*/
final class CertificateStatus : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return CERTIFICATE_STATUS; }

    ref const(Vector!ubyte) response() const { return m_response; }

    this(const ref Vector!ubyte buf)
    {
        if (buf.length < 5)
            throw new DecodingError("Invalid Certificate_Status message: too small");
        if (buf[0] != 1)
            throw new DecodingError("Unexpected Certificate_Status message: unexpected response type");
        const size_t len = make_uint(0, buf[1], buf[2], buf[3]);
        if (buf.length != len + 4)
            throw new DecodingError("Invalid Certificate_Status: invalid length field");
        m_response[] = buf.ptr[4 .. buf.length];
    }

    override Vector!ubyte serialize() const
    {
        if (m_response.length > 0xFFFFFF)
            throw new EncodingError("OCSP response too long to encode in TLS");
        Vector!ubyte buf;
        buf.pushBack(1);
        foreach (size_t j; 0 .. 3)
            buf.pushBack(get_byte!uint(j + 1, cast(uint) m_response.length));
        buf ~= m_response[];
        return buf.move();
    }

private:
    Vector!ubyte m_response;
}

/**
* Change Cipher Spec
*/
final class ChangeCipherSpec : HandshakeMessage
{
public:
    override const(HandshakeType) type() const { return HANDSHAKE_CCS; }

    override Vector!ubyte serialize() const
    { return Vector!ubyte(cast(ubyte[])[1]); }
}


package:

string certTypeCodeToName(ubyte code)
{
    switch(code)
    {
        case 1:
            return "RSA";
        case 2:
            return "DSA";
        case 64:
            return "ECDSA";
        default:
            return ""; // DH or something else
    }
}

ubyte certTypeNameToCode(in string name)
{
    if (name == "RSA")
        return 1;
    if (name == "DSA")
        return 2;
    if (name == "ECDSA")
        return 64;
    
    throw new InvalidArgument("Unknown cert type " ~ name);
}


SecureVector!ubyte stripLeadingZeros()(const auto ref SecureVector!ubyte input)
{
    size_t leading_zeros = 0;
    
    for (size_t i = 0; i != input.length; ++i)
    {
        if (input[i] != 0)
            break;
        ++leading_zeros;
    }
    
    SecureVector!ubyte output = SecureVector!ubyte(input.ptr[leading_zeros .. input.length]);
    return output;
}


/*
* Compute the verifyData
*/
Vector!ubyte finishedComputeVerify(in HandshakeState state, ConnectionSide side)
{
    __gshared immutable const(ubyte)[] TLS_CLIENT_LABEL = [
        0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
        0x73, 0x68, 0x65, 0x64 ];
    
    __gshared immutable const(ubyte)[] TLS_SERVER_LABEL = [
        0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
        0x73, 0x68, 0x65, 0x64 ];
    
    Unique!KDF prf = state.protocolSpecificPrf();
    
    Vector!ubyte input;
	input.reserve(64);
    if (side == CLIENT)
        input ~= cast(ubyte[])TLS_CLIENT_LABEL;
    else
        input ~= cast(ubyte[])TLS_SERVER_LABEL;
    
    auto vec = state.hash().flushInto(state.Version(), state.ciphersuite().prfAlgo());
	input ~= vec[];
	return unlock(prf.deriveKey(12, state.sessionKeys().masterSecret(), input));

}

Vector!ubyte makeHelloRandom(RandomNumberGenerator rng, in TLSPolicy policy)
{
    Vector!ubyte buf = Vector!ubyte(32);
    rng.randomize(&buf[0], buf.length);

    if (policy.includeTimeInHelloRandom())
    {
        const uint time32 = cast(uint)(Clock.currTime(UTC()).toUnixTime);
        storeBigEndian(time32, buf.ptr);
    }

    return buf;
}