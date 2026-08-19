/**
* Hooks for application level policies on TLS connections
* 
* Copyright:
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
* (C) 2016 Christian Mainka
* (C) 2017 Harry Reimann, Rohde & Schwarz Cybersecurity
* (C) 2022 René Meusel, Hannes Rantzsch - neXenio GmbH
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.policy;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.version_;
import botan.tls.ciphersuite;
import botan.cert.x509.x509cert;
import botan.pubkey.algo.dl_group;
import botan.tls.ciphersuite;
import botan.tls.magic;
import botan.tls.exceptn;
import memutils.dictionarylist;
import std.datetime;
import std.algorithm : uniq, sort;
import std.array : array, Appender;
import std.conv : to;
import botan.utils.types;
public import botan.tls.extensions;

/**
* TLSPolicy Base Class
* Inherit and overload as desired to suit local policy concerns
*/
class TLSPolicy
{
public:
    /// ClientHello / ServerHello extensions this policy will send.
	Vector!HandshakeExtensionType enabledExtensions() const {
		auto ret = Vector!HandshakeExtensionType([TLSEXT_SAFE_RENEGOTIATION,
				TLSEXT_SERVER_NAME_INDICATION,
				TLSEXT_EC_POINT_FORMATS,
				TLSEXT_USABLE_ELLIPTIC_CURVES,
				TLSEXT_EXTENDED_MASTER_SECRET,
				TLSEXT_SESSION_TICKET,
				TLSEXT_SIGNATURE_ALGORITHMS,
				//TLSEXT_NPN,
				//TLSEXT_SIGNED_CERT_TIMESTAMP,
				TLSEXT_ALPN,
				TLSEXT_CHANNEL_ID,
				TLSEXT_SRP_IDENTIFIER,
				TLSEXT_HEARTBEAT_SUPPORT,
				TLSEXT_MAX_FRAGMENT_LENGTH]);
		static if (BOTAN_HAS_OCSP_STAPLE)
			ret.pushBack(TLSEXT_STATUS_REQUEST);
		return ret.move();
	}

	/// Returns a list of EC Point Formats supported, only 0x00 (Uncompressed) is supported at the moment.
	Vector!ubyte ecPointFormats() const {
		return Vector!ubyte([cast(ubyte)0x00]); // uncompressed
	}

    /**
    * Returns a list of ciphers we are willing to negotiate, in
    * order of preference.
    */
    Vector!string allowedCiphers() const
    {
        return Vector!string([
			"AES-128/GCM",
            "AES-256/GCM",
			"ChaCha20Poly1305",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256/CCM-8",
            "AES-128/CCM-8",
            "Camellia-256/GCM",
            "Camellia-128/GCM",
            "AES-256/GCM",
            "AES-256/CBC",
            "AES-128",
            "AES-256",
            "Camellia-256",
            "Camellia-128",
            //"SEED",
            //"3DES",
            //"RC4",
        ]);
    }

    /**
    * Returns a list of hash algorithms we are willing to use for
    * signatures, in order of preference.
    */
    Vector!string allowedSignatureHashes() const
    {
        return Vector!string([
			"SHA-256",
            "SHA-512",
            "SHA-384",
            "SHA-224",
            //"SHA-1",
            //"MD5",
        ]);
    }


    /**
    * Returns a list of MAC algorithms we are willing to use.
    */
    Vector!string allowedMacs() const
    {
        return Vector!string([
            "AEAD",
            "SHA-384",
            "SHA-256",
            //"SHA-1",
            //"MD5",
        ]);
    }

    /**
    * Returns a list of key exchange algorithms we are willing to
    * use, in order of preference. Allowed values: DH, empty string
    * (representing RSA using server certificate key)
    */
    Vector!string allowedKeyExchangeMethods() const
    {
        return Vector!string([
            //"SRP_SHA",
            //"ECDHE_PSK",
            //"DHE_PSK",
            //"PSK",
			//"RSA",
			"ECDH",
            //"DH",
            "ECDSA",
            "ECDHE_RSA",
            "ECDHE_ECDSA"

        ]);
    }

    /**
    * Returns a list of signature algorithms we are willing to
    * use, in order of preference. Allowed values RSA and DSA.
    */
    Vector!string allowedSignatureMethods() const
    {
        Vector!string sigs = Vector!string([
            "ECDSA",
            "ECDHE_ECDSA",
            "Ed25519",
			"RSA",
            "ECDHE_RSA",
			//"ECDH",
            //"DH",
        ]);
        static if (is(typeof(BOTAN_HAS_ED448)) && BOTAN_HAS_ED448)
            sigs.pushBack("Ed448");
        return sigs.move;
    }

    /**
    * TLS 1.3 SignatureScheme names (IANA), in preference order.
    * Handshake code maps these to certChain algoName tokens via
    * certChainAlgoName before calling TLSCredentialsManager.certChain.
    * CustomTLSPolicy need not override this.
    */
    Vector!string allowedSignatureSchemes() const
    {
        Vector!string schemes = Vector!string([
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ]);
        static if (is(typeof(BOTAN_HAS_ED25519)) && BOTAN_HAS_ED25519)
            schemes.pushBack("ed25519");
        return schemes.move;
    }

    /**
    * Unique certChain algoName tokens implied by allowedSignatureSchemes.
    */
    final Vector!string certKeyTypesFromSchemes() const
    {
        auto schemes = allowedSignatureSchemes();
        return certChainAlgoNames(schemes);
    }

    /**
    * Return list of ECC curves we are willing to use in order of preference
    */
    Vector!string allowedEccCurves() const
    {
        return Vector!string([
			"x25519",
            "brainpool512r1",
            "brainpool384r1",
            "brainpool256r1",
            "secp521r1",
            "secp384r1",
            "secp256r1",
            "secp256k1",
            //"secp224r1",
            //"secp224k1",
            //"secp192r1",
            //"secp192k1",
            //"secp160r2",
            //"secp160r1",
            //"secp160k1",
        ]);
    }

    /**
    * Returns a list of compression algorithms we are willing to use,
    * in order of preference. Allowed values any value of
    * Compression_Method.
    *
    * @note Compression is not currently supported
    */
    Vector!ubyte compression() const
    {
        return Vector!ubyte([NO_COMPRESSION]);
    }


    /**
    * Choose an elliptic curve to use
    */
	string chooseCurve(in Vector!string curve_names) const
	{
		const Vector!string our_curves = allowedEccCurves();
		for (size_t i = 0; i != our_curves.length; ++i) 
			if (valueExists(curve_names, our_curves[i])) 
				return our_curves[i];
		
		return ""; // no shared curve
	}

    /**
    * Attempt to negotiate the use of the heartbeat extension
    */
    bool negotiateHeartbeatSupport() const
    {
        return false;
    }

    /**
    * Allow renegotiation even if the counterparty doesn't
    * support the secure renegotiation extension.
    *
    * Notes:
    *  Changing this to true exposes you to injected plaintext attacks. 
    *  Read RFC 5746 for background.
    */
    bool allowInsecureRenegotiation() const { return false; }

    /**
     * The protocol dictates that the first 32 bits of the random
     * field are the current time in seconds. However this allows
     * client fingerprinting attacks. Set to false to disable, in
     * which case random bytes will be used instead.
     */
    bool includeTimeInHelloRandom() const { return false; }

    /**
    * Allow servers to initiate a new handshake
    */
    bool allowServerInitiatedRenegotiation() const
    {
        return true;
    }

    /**
    * Return the group to use for ephemeral Diffie-Hellman key agreement
    */
    DLGroup dhGroup() const
    {
        return DLGroup("modp/ietf/2048");
    }

    /**
    * Return the minimum DH group size we're willing to use
    */
    size_t minimumDhGroupSize() const
    {
        return 1024;
    }

    /**
    * If this function returns false, unknown SRP/PSK identifiers
    * will be rejected with an unknown_psk_identifier alert as soon
    * as the non-existence is identified. Otherwise, a false
    * identifier value will be used and the protocol allowed to
    * proceed, causing the handshake to eventually fail without
    * revealing that the username does not exist on this system.
    */
    bool hideUnknownUsers() const { return false; }

    /**
    * Return the allowed lifetime of a session ticket. If 0, session
    * tickets do not expire until the session ticket key rolls over.
    * Expired session tickets cannot be used to resume a session.
    */
    Duration sessionTicketLifetime() const
    {
        return 24.hours; // 1 day
    }

    /**
    * Returns: true if and only if we are willing to accept this version
    * Default accepts only TLS, so if you want to enable DTLS override
    * in your application.
    */
    bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    {
        if (_version.isDatagramProtocol())
            return (_version >= TLSProtocolVersion.DTLS_V12);
        // Default still rejects 1.3. Offer 1.3 by passing TLS_V13 and a
        // policy that accepts it (TestPolicy / Offer13Policy). latest stays 1.2.
        return (_version >= TLSProtocolVersion.TLS_V10 &&
                _version <= TLSProtocolVersion.TLS_V12);
    }

    /**
    * Offer TLS 1.3 X25519MLKEM768 (IANA 0x11EC) in ClientHello key_share.
    * Default false: default policy stays 1.2-only and does not advertise PQC.
    * Ignored unless version(TLS_13_PQC) is compiled. TLS hybrid SS is
    * concat (see tls13PqcKeyShareGroups). Not Hybrid-ML-KEM-768-X25519 SHA-3-256.
    */
    bool offerTls13PqcHybrid() const { return false; }
    bool offerTls13Secp256Mlkem() const { return false; }
    bool offerTls13Secp384Mlkem() const { return false; }
    bool offerTls13Mlkem512() const { return false; }
    bool offerTls13Mlkem768() const { return false; }
    bool offerTls13Mlkem1024() const { return false; }
    /// One extra NamedGroup name (copyable; used for Frodo/OQS leftovers).
    string offerTls13PqcExtraGroup() const { return ""; }

    /**
    * Extra TLS 1.3 PQC/hybrid NamedGroup names to emit as key_share.
    * Default: X25519MLKEM768 when offerTls13PqcHybrid() is true.
    * Combiner is concat; ECDH-first for secp hybrids, ML-KEM-first
    * for X25519MLKEM768 (draft-kwiatkowski); classical-first for
    * libOQS eFrodo hybrids.
    */
    Vector!string tls13PqcKeyShareGroups() const
    {
        Vector!string g;
        if (offerTls13PqcHybrid())
            g.pushBack("x25519/ML-KEM-768");
        if (offerTls13Secp256Mlkem())
            g.pushBack("secp256r1/ML-KEM-768");
        if (offerTls13Secp384Mlkem())
            g.pushBack("secp384r1/ML-KEM-1024");
        if (offerTls13Mlkem512())
            g.pushBack("ML-KEM-512");
        if (offerTls13Mlkem768())
            g.pushBack("ML-KEM-768");
        if (offerTls13Mlkem1024())
            g.pushBack("ML-KEM-1024");
        auto extra = offerTls13PqcExtraGroup();
        if (extra.length)
        {
            bool seen;
            foreach (n; g[])
                if (n == extra)
                    seen = true;
            if (!seen)
                g.pushBack(extra);
        }
        return g.move();
    }
    /**
     * Returns the more recent protocol version we are willing to
     * use, for either TLS or DTLS depending on datagram param.
     * Shouldn't ever need to override this unless you want to allow
     * a user to disable use of TLS v1.2 (which is *not recommended*)
     */
    TLSProtocolVersion latestSupportedVersion(bool datagram) const
    {
        if (datagram)
            return TLSProtocolVersion.latestDtlsVersion();
        else
            return TLSProtocolVersion.latestTlsVersion();
    }

    /**
     * When offering this version, should we send a fallback SCSV?
     * Default returns true iff version is the latest version the
     * policy allows, exists to allow override in case of interop problems.
     */
    bool sendFallbackSCSV(in TLSProtocolVersion _version) const
    {
        return false;
    }
	
	/**
     * Allows policy to reject any ciphersuites which are undesirable
     * for whatever reason without having to reimplement ciphersuite_list
     */
	bool acceptableCiphersuite(in TLSCiphersuite) const
	{
		return true;
	}
	
	/**
     * Apply GREASE to TLS extensibility draft-davidben-tls-grease-01.
     * This will add 2 extensions of distinct types 0x?a?a (1 empty at the beginning and 1 with 1 byte at the end)
     * It will also add an invalid ciphersuite of type 0x?a?a and an invalid ECC curve of type 0x?a?a
     * These are purposely invalid and the client will fail and close the connection if the server accepts them
     */
	bool allowClientHelloGrease() const
	{
		return false;
	}

	/**
    * Returns: true if servers should choose the ciphersuite matching
    *            their highest preference, rather than the clients.
    *            Has no effect on client side.
    */
    bool serverUsesOwnCiphersuitePreferences() const { return true; }

    // Allows override of signature algorithms, providing raw bytes
    Vector!ubyte signatureAlgorithms() const
    {
        return Vector!ubyte();
    }

    /**
    * Return allowed ciphersuites, in order of preference
    */
    Vector!ushort ciphersuiteList(TLSProtocolVersion _version, bool have_srp) const
    {
        Vector!string ciphers = allowedCiphers();
        Vector!string macs = allowedMacs();
        Vector!string kex = allowedKeyExchangeMethods();
        Vector!string sigs = allowedSignatureMethods();
        
        CiphersuitePreferenceOrdering order = CiphersuitePreferenceOrdering(ciphers, macs, kex, sigs);
        
        Vector!(TLSCiphersuite) ciphersuites;
		ciphersuites.reserve(64);
		auto cipher_suites = TLSCiphersuite.allKnownCiphersuites();
		foreach (const ref TLSCiphersuite suite; cipher_suites)
        {
            if (!acceptableCiphersuite(suite))
                continue;
            
            if (!have_srp && suite.kexAlgo() == "SRP_SHA")
                continue;
            
            if (_version.isDatagramProtocol() && suite.cipherAlgo() == "RC4")
                continue;
            
            if (!_version.supportsAeadModes() && suite.macAlgo() == "AEAD")
                continue;
            
            if (!valueExists(kex, suite.kexAlgo()))
                continue; // unsupported key exchange
            
            if (!valueExists(ciphers, suite.cipherAlgo()))
                continue; // unsupported cipher
            
            if (!valueExists(macs, suite.macAlgo()))
                continue; // unsupported MAC algo
            
            if (!valueExists(sigs, suite.sigAlgo()))
            {
                // allow if it's an empty sig algo and we want to use PSK
                if (suite.sigAlgo() != "" || !suite.pskCiphersuite())
                    continue;
            }
            
            // OK, allow it:
            ciphersuites ~= suite;
        }
        
        if (ciphersuites.length == 0)
            throw new LogicError("TLSPolicy does not allow any available cipher suite");
        Vector!ushort ciphersuite_codes;
		auto ciphersuites_ordered = ciphersuites[].uniq.array.sort!((a,b){ return order.compare(a, b); }).array.to!(TLSCiphersuite[]);
		foreach (TLSCiphersuite i; ciphersuites_ordered)
            ciphersuite_codes.pushBack(i.ciphersuiteCode());
        return ciphersuite_codes;
    }

    ~this() {}
}

/**
* Map a TLS 1.3 SignatureScheme name (or a 1.2 algoName) to the
* TLSCredentialsManager.certChain key-type string.
* Unknown names return an empty string.
*/
string certChainAlgoName(in string scheme_or_algo)
{
    if (scheme_or_algo.length == 0)
        return "";

    switch (scheme_or_algo)
    {
        case "RSA", "ECDSA", "DSA", "Ed25519", "Ed448",
             "ECDHE_RSA", "ECDHE_ECDSA":
            if (scheme_or_algo == "ECDHE_RSA")
                return "RSA";
            if (scheme_or_algo == "ECDHE_ECDSA")
                return "ECDSA";
            return scheme_or_algo.idup;

        case "rsa_pkcs1_sha1", "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
             "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
             "rsa_pss_pss_sha256", "rsa_pss_pss_sha384", "rsa_pss_pss_sha512":
            return "RSA";

        case "ecdsa_sha1",
             "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512",
             "ecdsa_brainpoolP256r1tls13_sha256",
             "ecdsa_brainpoolP384r1tls13_sha384",
             "ecdsa_brainpoolP512r1tls13_sha512":
            return "ECDSA";

        case "dsa_sha1", "dsa_sha256", "dsa_sha384", "dsa_sha512":
            return "DSA";

        case "ed25519":
            return "Ed25519";

        case "ed448":
            return "Ed448";

        default:
            break;
    }

    // Prefix fallback for future IANA names
    if (scheme_or_algo.length >= 4 && scheme_or_algo[0 .. 4] == "rsa_")
        return "RSA";
    if (scheme_or_algo.length >= 6 && scheme_or_algo[0 .. 6] == "ecdsa_")
        return "ECDSA";
    if (scheme_or_algo.length >= 4 && scheme_or_algo[0 .. 4] == "dsa_")
        return "DSA";
    return "";
}

Vector!string certChainAlgoNames()(const auto ref Vector!string schemes)
{
    Vector!string names;
    foreach (s; schemes[])
    {
        auto name = certChainAlgoName(s);
        if (name.length && !valueExists(names, name))
            names.pushBack(name);
    }
    return names.move;
}

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto p = new TLSPolicy;
    auto list = p.ciphersuiteList(TLSProtocolVersion.latestTlsVersion(), false);
    foreach (id; list[])
    {
        auto suite = TLSCiphersuite.byId(id);
        assert(suite.kexAlgo() != "DH");
        assert(suite.kexAlgo() != "RSA");
        assert(suite.cipherAlgo() != "RC4");
        assert(suite.cipherAlgo() != "3DES");
        assert(suite.macAlgo() != "MD5");
    }
    auto sigs = p.allowedSignatureMethods();
    size_t ecdsa_i = size_t.max, rsa_i = size_t.max;
    foreach (i, s; sigs[])
    {
        if (s == "ECDSA" || s == "ECDHE_ECDSA")
            if (ecdsa_i == size_t.max) ecdsa_i = i;
        if (s == "RSA" || s == "ECDHE_RSA")
            if (rsa_i == size_t.max) rsa_i = i;
    }
    assert(ecdsa_i < rsa_i);

    assert(certChainAlgoName("rsa_pss_rsae_sha256") == "RSA");
    assert(certChainAlgoName("rsa_pkcs1_sha256") == "RSA");
    assert(certChainAlgoName("ecdsa_secp256r1_sha256") == "ECDSA");
    assert(certChainAlgoName("ed25519") == "Ed25519");
    assert(certChainAlgoName("RSA") == "RSA");
    assert(certChainAlgoName("ECDSA") == "ECDSA");
    assert(certChainAlgoName("ECDHE_RSA") == "RSA");
    assert(certChainAlgoName("not_a_scheme") == "");
    auto mapped = certChainAlgoNames(Vector!string([
        "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256"
    ]));
    assert(mapped.length == 2);
    assert(valueExists(mapped, "RSA"));
    assert(valueExists(mapped, "ECDSA"));
    auto from_policy = p.certKeyTypesFromSchemes();
    assert(valueExists(from_policy, "RSA"));
    assert(valueExists(from_policy, "ECDSA"));

    assert(TLSProtocolVersion.latestTlsVersion() == TLSProtocolVersion(TLSProtocolVersion.TLS_V12));
    assert(!p.acceptableProtocolVersion(TLSProtocolVersion(TLSProtocolVersion.TLS_V13)));
    assert(p.acceptableProtocolVersion(TLSProtocolVersion(TLSProtocolVersion.TLS_V12)));
}

/**
* NSA Suite B 128-bit security level (see @rfc 6460)
*/
class NSASuiteB128 : TLSPolicy
{
public:
    override Vector!string allowedCiphers() const
    { return Vector!string(["AES-128/GCM"]); }

    override Vector!string allowedSignatureHashes() const
    { return Vector!string(["SHA-256"]); }

    override Vector!string allowedMacs() const
    { return Vector!string(["AEAD"]); }

    override Vector!string allowedKeyExchangeMethods() const
    { return Vector!string(["ECDH"]); }

    override Vector!string allowedSignatureMethods() const
    { return Vector!string(["ECDSA"]); }

    override Vector!string allowedEccCurves() const
    { return Vector!string(["secp256r1"]); }

    override bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    { return _version == TLSProtocolVersion.TLS_V12; }
}

/**
* TLSPolicy for DTLS. We require DTLS v1.2 and an AEAD mode
*/
class DatagramPolicy : TLSPolicy
{
public:
    override Vector!string allowedMacs() const
    { return Vector!string(["AEAD"]); }

    override bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    { return _version == TLSProtocolVersion.DTLS_V12; }
}


private:

struct CiphersuitePreferenceOrdering
{
public:
    this(ref Vector!string ciphers, ref Vector!string macs, ref Vector!string kex, ref Vector!string sigs)
    {
        m_ciphers = ciphers.clone();
        m_macs = macs.clone();
        m_kex = kex.clone(); 
        m_sigs = sigs.clone();
    }
    
    bool compare(U : TLSCiphersuite)(in TLSCiphersuite a, auto ref U b) const
    {
        if (a.kexAlgo() != b.kexAlgo())
        {
            for (size_t i = 0; i != m_kex.length; ++i)
            {
                if (a.kexAlgo() == m_kex[i])
                    return true;
                if (b.kexAlgo() == m_kex[i])
                    return false;
            }
        }
        
        if (a.cipherAlgo() != b.cipherAlgo())
        {
            for (size_t i = 0; i != m_ciphers.length; ++i)
            {
                if (a.cipherAlgo() == m_ciphers[i])
                    return true;
                if (b.cipherAlgo() == m_ciphers[i])
                    return false;
            }
        }
        
        if (a.cipherKeylen() != b.cipherKeylen())
        {
            if (a.cipherKeylen() < b.cipherKeylen())
                return false;
            if (a.cipherKeylen() > b.cipherKeylen())
                return true;
        }
        
        if (a.sigAlgo() != b.sigAlgo())
        {
            for (size_t i = 0; i != m_sigs.length; ++i)
            {
                if (a.sigAlgo() == m_sigs[i])
                    return true;
                if (b.sigAlgo() == m_sigs[i])
                    return false;
            }
        }
        
        if (a.macAlgo() != b.macAlgo())
        {
            for (size_t i = 0; i != m_macs.length; ++i)
            {
                if (a.macAlgo() == m_macs[i])
                    return true;
                if (b.macAlgo() == m_macs[i])
                    return false;
            }
        }
        
        return false; // equal (?!?)
    }
private:
    Vector!string m_ciphers, m_macs, m_kex, m_sigs;
}