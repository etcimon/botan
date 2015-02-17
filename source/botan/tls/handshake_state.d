/**
* TLS Handshake State
* 
* Copyright:
* (C) 2004-2006,2011,2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.handshake_state;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.tls.handshake_hash;
import botan.tls.handshake_io;
import botan.tls.session_key;
import botan.tls.ciphersuite;
import botan.tls.exceptn;
import botan.tls.messages;
import botan.pubkey.pk_keys;
import botan.pubkey.pubkey;
import botan.kdf.kdf;
import botan.tls.messages;
import botan.tls.record;

package:
/**
* SSL/TLS Handshake State
*/
class HandshakeState
{
public:
    /*
    * Initialize the SSL/TLS Handshake State
    */
    this(HandshakeIO io, void delegate(in HandshakeMessage) msg_callback = null) 
    {
        m_ciphersuite = TLSCiphersuite.init;
        m_session_keys = TLSSessionKeys.init;
        m_msg_callback = msg_callback;
        m_handshake_io = io;
        m_version = m_handshake_io.initialRecordVersion();
    }

    ~this() {}

    HandshakeIO handshakeIo() { return *m_handshake_io; }

    /**
    * Return true iff we have received a particular message already
    * Params:
    *  msg_type = the message type
    */
    bool receivedHandshakeMsg(HandshakeType handshake_msg) const
    {
        const uint mask = bitmaskForHandshakeType(handshake_msg);
        
        return cast(bool)(m_hand_received_mask & mask);
    }

    /**
    * Confirm that we were expecting this message type
    * Params:
    *  msg_type = the message type
    */
    void confirmTransitionTo(HandshakeType handshake_msg)
    {
        const uint mask = bitmaskForHandshakeType(handshake_msg);
        
        m_hand_received_mask |= mask;
        
        const bool ok = cast(bool)(m_hand_expecting_mask & mask); // overlap?
        
        if (!ok)
            throw new TLSUnexpectedMessage("Unexpected state transition in handshake, got " ~
                                         to!string(handshake_msg) ~
                                         " expected " ~ to!string(m_hand_expecting_mask) ~
                                         " received " ~ to!string(m_hand_received_mask));
        
        /* We don't know what to expect next, so force a call to
            set_expected_next; if it doesn't happen, the next transition
            check will always fail which is what we want.
        */
        m_hand_expecting_mask = 0;
    }

    /**
    * Record that we are expecting a particular message type next
    * Params:
    *  msg_type = the message type
    */
    void setExpectedNext(HandshakeType handshake_msg)
    {
        m_hand_expecting_mask |= bitmaskForHandshakeType(handshake_msg);
    }

    NextRecord getNextHandshakeMsg()
    {
        const bool expecting_ccs = cast(bool)(bitmaskForHandshakeType(HANDSHAKE_CCS) & m_hand_expecting_mask);
        
        return m_handshake_io.getNextRecord(expecting_ccs);
    }

    Vector!ubyte sessionTicket() const
    {
        if (newSessionTicket() && !newSessionTicket().ticket().empty())
            return newSessionTicket().ticket().dup;
        
        return clientHello().sessionTicket();
    }

    const(Pair!(string, SignatureFormat))
        understandSigFormat(in PublicKey key, string hash_algo, string sig_algo, bool for_client_auth) const
    {
        const string algo_name = key.algoName;
        
        /*
        FIXME: This should check what was sent against the client hello
        preferences, or the certificate request, to ensure it was allowed
        by those restrictions.

        Or not?
        */
        
        if (this.Version().supportsNegotiableSignatureAlgorithms())
        {
            if (hash_algo == "")
                throw new DecodingError("Counterparty did not send hash/sig IDS");
            
            if (sig_algo != algo_name)
                throw new DecodingError("Counterparty sent inconsistent key and sig types");
        }
        else
        {
            if (hash_algo != "" || sig_algo != "")
                throw new DecodingError("Counterparty sent hash/sig IDs with old version");
        }
        
        if (algo_name == "RSA")
        {
            if (for_client_auth && this.Version() == TLSProtocolVersion.SSL_V3)
            {
                hash_algo = "Raw";
            }
            else if (!this.Version().supportsNegotiableSignatureAlgorithms())
            {
                hash_algo = "Parallel(MD5,SHA-160)";
            }
            
            const string padding = "EMSA3(" ~ hash_algo ~ ")";
            return makePair(padding, IEEE_1363);
        }
        else if (algo_name == "DSA" || algo_name == "ECDSA")
        {
            if (algo_name == "DSA" && for_client_auth && this.Version() == TLSProtocolVersion.SSL_V3)
            {
                hash_algo = "Raw";
            }
            else if (!this.Version().supportsNegotiableSignatureAlgorithms())
            {
                hash_algo = "SHA-1";
            }
            
            const string padding = "EMSA1(" ~ hash_algo ~ ")";
            
            return makePair(padding, DER_SEQUENCE);
        }
        
        throw new InvalidArgument(algo_name ~ " is invalid/unknown for TLS signatures");
    }

    const(Pair!(string, SignatureFormat))
        chooseSigFormat(in PrivateKey key,
                          ref string hash_algo_out,
                          ref string sig_algo_out,
                          bool for_client_auth,
                          in TLSPolicy policy) const
    {
        const string sig_algo = key.algoName;
        
        const string hash_algo = chooseHash(sig_algo,
                                             this.Version(),
                                             policy,
                                             for_client_auth,
                                             clientHello(),
                                             certReq());
        
        if (this.Version().supportsNegotiableSignatureAlgorithms())
        {
            hash_algo_out = hash_algo;
            sig_algo_out = sig_algo;
        }
        
        if (sig_algo == "RSA")
        {
            const string padding = "EMSA3(" ~ hash_algo ~ ")";
            
            return makePair(padding, IEEE_1363);
        }
        else if (sig_algo == "DSA" || sig_algo == "ECDSA")
        {
            const string padding = "EMSA1(" ~ hash_algo ~ ")";
            
            return makePair(padding, DER_SEQUENCE);
        }
        
        throw new InvalidArgument(sig_algo ~ " is invalid/unknown for TLS signatures");
    }

    const(string) srpIdentifier() const
    {
        if (ciphersuite().valid() && ciphersuite().kexAlgo() == "SRP_SHA")
            return clientHello().srpIdentifier();
        
        return "";
    }

    KDF protocolSpecificPrf() const
    {
        if (Version() == TLSProtocolVersion.SSL_V3)
        {
            return getKdf("SSL3-PRF");
        }
        else if (Version().supportsCiphersuiteSpecificPrf())
        {
            const string prf_algo = ciphersuite().prfAlgo();
            
            if (prf_algo == "MD5" || prf_algo == "SHA-1")
                return getKdf("TLS-12-PRF(SHA-256)");
            
            return getKdf("TLS-12-PRF(" ~ prf_algo ~ ")");
        }
        else
        {
            // TLS v1.0, v1.1 and DTLS v1.0
            return getKdf("TLS-PRF");
        }
        
        // throw new InternalError("Unknown version code " ~ Version().toString());
    }

    const(TLSProtocolVersion) Version() const { return m_version; }

    void setVersion(in TLSProtocolVersion _version)
    {
        m_version = _version;
    }

    void helloVerifyRequest(in HelloVerifyRequest hello_verify)
    {
        noteMessage(hello_verify);
        
        m_client_hello.updateHelloCookie(hello_verify);
        hash().reset();
        hash().update(handshakeIo().send(*m_client_hello));
        noteMessage(*m_client_hello);
    }


    void clientHello(ClientHello clientHello)
    {
        m_client_hello = clientHello;
        noteMessage(*m_client_hello);
    }
    
    void serverHello(ServerHello server_hello)
    {
        m_server_hello = server_hello;
        m_ciphersuite = TLSCiphersuite.byId(m_server_hello.ciphersuite());
        noteMessage(*m_server_hello);
    }
    
    void serverCerts(Certificate server_certs)
    {
        m_server_certs = server_certs;
        noteMessage(*m_server_certs);
    }
    
    void serverKex(ServerKeyExchange server_kex)
    {
        m_server_kex = server_kex;
        noteMessage(*m_server_kex);
    }
    
    void certReq(CertificateReq cert_req)
    {
        m_cert_req = cert_req;
        noteMessage(*m_cert_req);
    }

    void serverHelloDone(ServerHelloDone server_hello_done)
    {
        m_server_hello_done = server_hello_done;
        noteMessage(*m_server_hello_done);
    }
    
    void clientCerts(Certificate client_certs)
    {
        m_client_certs = client_certs;
        noteMessage(*m_client_certs);
    }
    
    void clientKex(ClientKeyExchange client_kex)
    {
        m_client_kex = client_kex;
        noteMessage(*m_client_kex);
    }
    
    void clientVerify(CertificateVerify client_verify)
    {
        m_client_verify = client_verify;
        noteMessage(*m_client_verify);
    }
    
    void nextProtocol(NextProtocol next_protocol)
    {
        m_next_protocol = next_protocol;
        noteMessage(*m_next_protocol);
    }

    void newSessionTicket(NewSessionTicket new_session_ticket)
    {
        m_new_session_ticket = new_session_ticket;
        noteMessage(*m_new_session_ticket);
    }
    
    void serverFinished(Finished server_finished)
    {
        m_server_finished = server_finished;
        noteMessage(*m_server_finished);
    }
    
    void clientFinished(Finished client_finished)
    {
        m_client_finished = client_finished;
        noteMessage(*m_client_finished);
    }

    const(ClientHello) clientHello() const
    { return *m_client_hello; }

    const(ServerHello) serverHello() const
    { return *m_server_hello; }

    const(Certificate) serverCerts() const
    { return *m_server_certs; }

    const(ServerKeyExchange) serverKex() const
    { return *m_server_kex; }

    const(CertificateReq) certReq() const
    { return *m_cert_req; }

    const(ServerHelloDone) serverHelloDone() const
    { return *m_server_hello_done; }

    const(Certificate) clientCerts() const
    { return *m_client_certs; }

    const(ClientKeyExchange) clientKex() const
    { return *m_client_kex; }

    const(CertificateVerify) clientVerify() const
    { return *m_client_verify; }

    const(NextProtocol) nextProtocol() const
    { return *m_next_protocol; }

    const(NewSessionTicket) newSessionTicket() const
    { return *m_new_session_ticket; }

    const(Finished) serverFinished() const
    { return *m_server_finished; }

    const(Finished) clientFinished() const
    { return *m_client_finished; }

    ref const(TLSCiphersuite) ciphersuite() const { return m_ciphersuite; }

    ref const(TLSSessionKeys) sessionKeys() const { return m_session_keys; }

    void computeSessionKeys()
    {
        m_session_keys = TLSSessionKeys(this, clientKex().preMasterSecret().dup, false);
    }

    void computeSessionKeys()(auto ref SecureVector!ubyte resume_master_secret)
    {
        m_session_keys = TLSSessionKeys(this, resume_master_secret, true);
    }

    ref HandshakeHash hash() { return m_handshake_hash; }

    ref const(HandshakeHash) hash() const { return m_handshake_hash; }

    void noteMessage(in HandshakeMessage msg)
    {
        if (m_msg_callback)
            m_msg_callback(msg);
    }

private:

    void delegate(in HandshakeMessage) m_msg_callback;

    Unique!HandshakeIO m_handshake_io;

    uint m_hand_expecting_mask = 0;
    uint m_hand_received_mask = 0;
    TLSProtocolVersion m_version;
    TLSCiphersuite m_ciphersuite;
    TLSSessionKeys m_session_keys;
    HandshakeHash m_handshake_hash;

    Unique!ClientHello m_client_hello;
    Unique!ServerHello m_server_hello;
    Unique!Certificate m_server_certs;
    Unique!ServerKeyExchange m_server_kex;
    Unique!CertificateReq m_cert_req;
    Unique!ServerHelloDone m_server_hello_done;
    Unique!Certificate m_client_certs;
    Unique!ClientKeyExchange m_client_kex;
    Unique!CertificateVerify m_client_verify;
    Unique!NextProtocol m_next_protocol;
    Unique!NewSessionTicket m_new_session_ticket;
    Unique!Finished m_server_finished;
    Unique!Finished m_client_finished;
}


private:

uint bitmaskForHandshakeType(HandshakeType type)
{
    switch(type)
    {
        case HELLO_VERIFY_REQUEST:
            return (1 << 0);
            
        case HELLO_REQUEST:
            return (1 << 1);
            
            /*
        * Same code point for both client hello styles
        */
        case CLIENT_HELLO:
        case CLIENT_HELLO_SSLV2:
            return (1 << 2);
            
        case SERVER_HELLO:
            return (1 << 3);
            
        case CERTIFICATE:
            return (1 << 4);
            
        case CERTIFICATE_URL:
            return (1 << 5);
            
        case CERTIFICATE_STATUS:
            return (1 << 6);
            
        case SERVER_KEX:
            return (1 << 7);
            
        case CERTIFICATE_REQUEST:
            return (1 << 8);
            
        case SERVER_HELLO_DONE:
            return (1 << 9);
            
        case CERTIFICATE_VERIFY:
            return (1 << 10);
            
        case CLIENT_KEX:
            return (1 << 11);
            
        case NEXT_PROTOCOL:
            return (1 << 12);
            
        case NEW_SESSION_TICKET:
            return (1 << 13);
            
        case HANDSHAKE_CCS:
            return (1 << 14);
            
        case FINISHED:
            return (1 << 15);
            
            // allow explicitly disabling new handshakes
        case HANDSHAKE_NONE:
            return 0;

        default:
            throw new InternalError("Unknown handshake type " ~ to!string(type));
    }
}



string chooseHash(in string sig_algo,
                   TLSProtocolVersion negotiated_version,
                   in TLSPolicy policy,
                   bool for_client_auth,
                   in ClientHello client_hello,
                   in CertificateReq cert_req)
{
    if (!negotiated_version.supportsNegotiableSignatureAlgorithms())
    {
        if (for_client_auth && negotiated_version == TLSProtocolVersion.SSL_V3)
            return "Raw";
        
        if (sig_algo == "RSA")
            return "Parallel(MD5,SHA-160)";
        
        if (sig_algo == "DSA")
            return "SHA-1";
        
        if (sig_algo == "ECDSA")
            return "SHA-1";
        
        throw new InternalError("Unknown TLS signature algo " ~ sig_algo);
    }
    
    Vector!(Pair!(string, string)) supported_algos = for_client_auth ? cert_req.supportedAlgos() : client_hello.supportedAlgos();
    
    if (!supported_algos.empty())
    {
        const Vector!string hashes = policy.allowedSignatureHashes();
        
        /*
        * Choose our most preferred hash that the counterparty supports
        * in pairing with the signature algorithm we want to use.
        */
        foreach (hash; hashes[])
        {
            foreach (algo; supported_algos[])
            {
                if (algo.first == hash && algo.second == sig_algo)
                    return hash;
            }
        }
    }
    
    // TLS v1.2 default hash if the counterparty sent nothing
    return "SHA-1";
}
