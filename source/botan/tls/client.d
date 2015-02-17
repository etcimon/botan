/**
* TLS Client
* 
* Copyright:
* (C) 2004-2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.client;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.tls.channel;
public import botan.tls.credentials_manager;
public import botan.tls.server_info;
public import botan.rng.rng;
import botan.tls.handshake_state;
import botan.tls.messages;
import memutils.dictionarylist;
import botan.utils.types;

/**
* SSL/TLS Client
*/
final class TLSClient : TLSChannel
{
public:
    /**
    * Set up a new TLS client session
    *
    * Params:
    *  socket_output_fn = is called with data for the outbound socket
    *
    *  proc_cb = is called when new application data is received
    *
    *  alert_cb = is called when a TLS alert is received
    *
    *  handshake_cb = is called when a handshake is completed
    *
    *  session_manager = manages session state
    *
    *  creds = manages application/user credentials
    *
    *  policy = specifies other connection policy information
    *
    *  rng = a random number generator
    *
    *  server_info = is identifying information about the TLS server
    *
    *  offer_version = specifies which version we will offer
    *          to the TLS server.
    *
    *  next_protocol = allows the client to specify what the next
    *          protocol will be. For more information read
    *          http://technotes.googlecode.com/git/nextprotoneg.html.
    *
    *          If the function is not empty, NPN will be negotiated
    *          and if the server supports NPN the function will be
    *          called with the list of protocols the server advertised;
    *          the client should return the protocol it would like to use.
    *
    *  reserved_io_buffer_size = This many bytes of memory will
    *          be preallocated for the read and write buffers. Smaller
    *          values just mean reallocations and copies are more likely.
    */
    this(void delegate(in ubyte[]) socket_output_fn,
         void delegate(in ubyte[]) proc_cb,
         void delegate(in TLSAlert, in ubyte[]) alert_cb,
         bool delegate(const ref TLSSession) handshake_cb,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         in TLSServerInformation server_info = TLSServerInformation(),
         in TLSProtocolVersion offer_version = TLSProtocolVersion.latestTlsVersion(),
         string delegate(const ref Vector!string) next_protocol = null,
         size_t reserved_io_buffer_size = 16*1024)
    { 
        super(socket_output_fn, proc_cb, alert_cb, handshake_cb, session_manager, rng, reserved_io_buffer_size);
        m_policy = policy;
        m_creds = creds;
        m_info = server_info;
        const string srp_identifier = m_creds.srpIdentifier("tls-client", m_info.hostname());
        HandshakeState state = createHandshakeState(offer_version);
        sendClientHello(state, false, offer_version, srp_identifier, next_protocol);
    }

protected:
    override Vector!X509Certificate getPeerCertChain(in HandshakeState state) const
    {
        if (state.serverCerts())
            return state.serverCerts().certChain().dup;
        return Vector!X509Certificate();
    }

    /*
    * Send a new client hello to renegotiate
    */
    override void initiateHandshake(HandshakeState state,
                            bool force_full_renegotiation)
    {
        sendClientHello(state,
                          force_full_renegotiation,
                          state.Version());
    }

    void sendClientHello(HandshakeState state_base,
                           bool force_full_renegotiation,
                           TLSProtocolVersion _version,
                           in string srp_identifier = "",
                           string delegate(const ref Vector!string) next_protocol = null)
    {
        ClientHandshakeState state = cast(ClientHandshakeState)(state_base);

        if (state.Version().isDatagramProtocol())
            state.setExpectedNext(HELLO_VERIFY_REQUEST); // optional
        state.setExpectedNext(SERVER_HELLO);
        state.client_npn_cb = next_protocol;

        const bool send_npn_request = cast(bool)(next_protocol);
        
        if (!force_full_renegotiation && !m_info.empty)
        {
            TLSSession session_info;
            if (sessionManager().loadFromServerInfo(m_info, session_info))
            {
                if (srp_identifier == "" || session_info.srpIdentifier() == srp_identifier)
                {
                    state.clientHello(new ClientHello(
                                      state.handshakeIo(),
                                      state.hash(),
                                      m_policy,
                                      rng(),
                                      secureRenegotiationDataForClientHello().dup,
                                      session_info,
                                      send_npn_request));
                    
                    state.resume_master_secret = session_info.masterSecret().dup;
                }
            }
        }

        if (!state.clientHello()) // not resuming
        {
            state.clientHello(new ClientHello(state.handshakeIo(),
                                              state.hash(),
                                              _version,
                                              m_policy,
                                              rng(),
                                              secureRenegotiationDataForClientHello().dup,
                                              send_npn_request,
                                              m_info.hostname(),
                                              srp_identifier));
        }

        secureRenegotiationCheck(state.clientHello());
    }

    /*
    * Process a handshake message
    */
    override void processHandshakeMsg(in HandshakeState active_state,
                               HandshakeState state_base,
                               HandshakeType type,
                               const ref Vector!ubyte contents)
    {
        ClientHandshakeState state = cast(ClientHandshakeState)(state_base);
        
        if (type == HELLO_REQUEST && active_state)
        {
            auto hello_request = scoped!HelloRequest(contents);
            
            // Ignore request entirely if we are currently negotiating a handshake
            if (state.clientHello())
                return;
            
            if (!m_policy.allowServerInitiatedRenegotiation() ||
                (!m_policy.allowInsecureRenegotiation() && !secureRenegotiationSupported()))
            {
                // RFC 5746 section 4.2
                sendWarningAlert(TLSAlert.NO_RENEGOTIATION);
                return;
            }
            
            this.initiateHandshake(state, false);
            
            return;
        }
        
        state.confirmTransitionTo(type);
        
        if (type != HANDSHAKE_CCS && type != FINISHED && type != HELLO_VERIFY_REQUEST)
            state.hash().update(state.handshakeIo().format(contents, type));
        
        if (type == HELLO_VERIFY_REQUEST)
        {
            state.setExpectedNext(SERVER_HELLO);
            state.setExpectedNext(HELLO_VERIFY_REQUEST); // might get it again
            
            auto hello_verify_request = scoped!HelloVerifyRequest(contents);

            state.helloVerifyRequest(hello_verify_request.Scoped_payload);
        }
        else if (type == SERVER_HELLO)
        {
            state.serverHello(new ServerHello(contents));
            
            if (!state.clientHello().offeredSuite(state.serverHello().ciphersuite()))
            {
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                        "TLSServer replied with ciphersuite we didn't send");
            }
            
            if (!valueExists(state.clientHello().compressionMethods(),
                             state.serverHello().compressionMethod()))
            {
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                        "TLSServer replied with compression method we didn't send");
            }
            
            auto client_extn = state.clientHello().extensionTypes()[];
            auto server_extn = state.serverHello().extensionTypes()[];
            
            import std.algorithm : setDifference;
            import std.range : empty, array;
            auto diff = setDifference(server_extn, client_extn);
            if (!diff.empty)
            {
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                       "TLSServer sent extension(s) " ~ diff.array.to!(string[]).joiner(", ").to!string ~ " but we did not request it");
            }
            
            state.setVersion(state.serverHello().Version());
            
            secureRenegotiationCheck(state.serverHello());
            
            const bool server_returned_same_session_id = !state.serverHello().sessionId().empty &&
                                                         (state.serverHello().sessionId() == state.clientHello().sessionId());
            
            if (server_returned_same_session_id)
            {
                // successful resumption
                
                /*
                * In this case, we offered the version used in the original
                * session, and the server must resume with the same version.
                */
                if (state.serverHello().Version() != state.clientHello().Version())
                    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSServer resumed session but with wrong version");
                
                state.computeSessionKeys(state.resume_master_secret);
                
                if (state.serverHello().supportsSessionTicket())
                    state.setExpectedNext(NEW_SESSION_TICKET);
                else
                    state.setExpectedNext(HANDSHAKE_CCS);
            }
            else
            {
                // new session
                
                if (state.clientHello().Version().isDatagramProtocol() !=
                    state.serverHello().Version().isDatagramProtocol())
                {
                    throw new TLSException(TLSAlert.PROTOCOL_VERSION, "TLSServer replied with different protocol type than we offered");
                }
                
                if (state.Version() > state.clientHello().Version())
                {
                    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSServer replied with later version than in hello");
                }
                
                if (!m_policy.acceptableProtocolVersion(state.Version()))
                {
                    throw new TLSException(TLSAlert.PROTOCOL_VERSION, "TLSServer version is unacceptable by policy");
                }
                
                if (state.ciphersuite().sigAlgo() != "")
                {
                    state.setExpectedNext(CERTIFICATE);
                }
                else if (state.ciphersuite().kexAlgo() == "PSK")
                {
                    /* PSK is anonymous so no certificate/cert req message is
                        ever sent. The server may or may not send a server kex,
                        depending on if it has an identity hint for us.

                        (EC)DHE_PSK always sends a server key exchange for the
                        DH exchange portion.
                    */
                    
                    state.setExpectedNext(SERVER_KEX);
                    state.setExpectedNext(SERVER_HELLO_DONE);
                }
                else if (state.ciphersuite().kexAlgo() != "RSA")
                {
                    state.setExpectedNext(SERVER_KEX);
                }
                else
                {
                    state.setExpectedNext(CERTIFICATE_REQUEST); // optional
                    state.setExpectedNext(SERVER_HELLO_DONE);
                }
            }
        }
        else if (type == CERTIFICATE)
        {
            if (state.ciphersuite().kexAlgo() != "RSA")
            {
                state.setExpectedNext(SERVER_KEX);
            }
            else
            {
                state.setExpectedNext(CERTIFICATE_REQUEST); // optional
                state.setExpectedNext(SERVER_HELLO_DONE);
            }
            
            state.serverCerts(new Certificate(contents));
            
            const Vector!X509Certificate* server_certs = &state.serverCerts().certChain();
            
            if (server_certs.empty)
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSClient: No certificates sent by server");
            
            try
            {
                m_creds.verifyCertificateChain("tls-client", m_info.hostname(), *server_certs);
            }
            catch(Exception e)
            {
                throw new TLSException(TLSAlert.BAD_CERTIFICATE, e.msg);
            }
            
            PublicKey peer_key = (*server_certs)[0].subjectPublicKey();
            
            if (peer_key.algoName != state.ciphersuite().sigAlgo())
                throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Certificate key type did not match ciphersuite");
            
            state.server_public_key = peer_key;
        }
        else if (type == SERVER_KEX)
        {
            state.setExpectedNext(CERTIFICATE_REQUEST); // optional
            state.setExpectedNext(SERVER_HELLO_DONE);
            
            state.serverKex(new ServerKeyExchange(contents,
                                                     state.ciphersuite().kexAlgo(),
                                                     state.ciphersuite().sigAlgo(),
                                                     state.Version()));
            
            if (state.ciphersuite().sigAlgo() != "")
            {
                const PublicKey server_key = state.getServerPublicKey();
                
                if (!state.serverKex().verify(server_key, state))
                {
                    throw new TLSException(TLSAlert.DECRYPT_ERROR, "Bad signature on server key exchange");
                }
            }
        }
        else if (type == CERTIFICATE_REQUEST)
        {
            state.setExpectedNext(SERVER_HELLO_DONE);
            state.certReq(new CertificateReq(contents, state.Version()));
        }
        else if (type == SERVER_HELLO_DONE)
        {
            state.serverHelloDone(new ServerHelloDone(contents));
            
            if (state.receivedHandshakeMsg(CERTIFICATE_REQUEST))
            {
                const(Vector!string)* types = &state.certReq().acceptableCertTypes();
                
                Vector!X509Certificate client_certs = m_creds.certChain(*types, "tls-client", m_info.hostname());
                
                state.clientCerts(new Certificate(state.handshakeIo(), state.hash(), client_certs));
            }
            
            state.clientKex(new ClientKeyExchange(state.handshakeIo(),
                                                     state,
                                                     m_policy,
                                                     m_creds,
                                                     state.server_public_key.get(),
                                                     m_info.hostname(),
                                                     rng()));
            
            state.computeSessionKeys();
            
            if (state.receivedHandshakeMsg(CERTIFICATE_REQUEST) && !state.clientCerts().empty)
            {
                PrivateKey priv_key = m_creds.privateKeyFor(state.clientCerts().certChain()[0], "tls-client", m_info.hostname());
                
                state.clientVerify(new CertificateVerify(state.handshakeIo(),
                                                         state,
                                                         m_policy,
                                                         rng(),
                                                         priv_key));
            }
            
            state.handshakeIo().send(scoped!ChangeCipherSpec());
            
            changeCipherSpecWriter(CLIENT);
            
            if (state.serverHello().nextProtocolNotification())
            {
                auto next_proto = state.serverHello().nextProtocols();
                const string protocol = state.client_npn_cb(next_proto);
                
                state.nextProtocol(new NextProtocol(state.handshakeIo(), state.hash(), protocol));
            }
            
            state.clientFinished(new Finished(state.handshakeIo(), state, CLIENT));
            
            if (state.serverHello().supportsSessionTicket())
                state.setExpectedNext(NEW_SESSION_TICKET);
            else
                state.setExpectedNext(HANDSHAKE_CCS);
        }
        else if (type == NEW_SESSION_TICKET)
        {
            state.newSessionTicket(new NewSessionTicket(contents));
            
            state.setExpectedNext(HANDSHAKE_CCS);
        }
        else if (type == HANDSHAKE_CCS)
        {
            state.setExpectedNext(FINISHED);
            
            changeCipherSpecReader(CLIENT);
        }
        else if (type == FINISHED)
        {
            state.serverFinished(new Finished(contents.dup));
            
            if (!state.serverFinished().verify(state, SERVER))
                throw new TLSException(TLSAlert.DECRYPT_ERROR, "Finished message didn't verify");
            
            state.hash().update(state.handshakeIo().format(contents, type));
            
            if (!state.clientFinished()) // session resume case
            {
                state.handshakeIo().send(scoped!ChangeCipherSpec());
                
                changeCipherSpecWriter(CLIENT);
                
                if (state.serverHello().nextProtocolNotification())
                {
                    auto next_proto = state.serverHello().nextProtocols();
                    const string protocol = state.client_npn_cb(next_proto);
                    
                    state.nextProtocol(new NextProtocol(state.handshakeIo(), state.hash(), protocol));
                }
                
                state.clientFinished(new Finished(state.handshakeIo(), state, CLIENT));
            }
            
            Vector!ubyte session_id = state.serverHello().sessionId().dup;
            
            Vector!ubyte session_ticket = state.sessionTicket();
            
            if (session_id.empty && !session_ticket.empty)
                session_id = makeHelloRandom(rng());

            TLSSession session_info = TLSSession(session_id.dup,
                                                 state.sessionKeys().masterSecret().dup,
                                                 state.serverHello().Version(),
                                                 state.serverHello().ciphersuite(),
                                                 state.serverHello().compressionMethod(),
                                                 CLIENT,
                                                 state.serverHello().fragmentSize(),
                                                 getPeerCertChain(state),
                                                 session_ticket.move(),
                                                 m_info,
                                                 "");
            
            const bool should_save = saveSession(session_info);
            
            if (!session_id.empty)
            {
                if (should_save)
                    sessionManager().save(session_info);
                else {
                    auto entry = &session_info.sessionId();
                    sessionManager().removeEntry(*entry);
                }
            }
            
            activateSession();
        }
        else
            throw new TLSUnexpectedMessage("Unknown handshake message received");
    }

    override HandshakeState newHandshakeState(HandshakeIO io)
    {
        return new ClientHandshakeState(io);
    }

private:
    const TLSPolicy m_policy;
    TLSCredentialsManager m_creds;
    const TLSServerInformation m_info;
}


private final class ClientHandshakeState : HandshakeState
{
public:
    
    this(HandshakeIO io, void delegate(in HandshakeMessage) msg_callback = null) 
    { 
        super(io, msg_callback);
    }
    
    const(PublicKey) getServerPublicKey() const
    {
        assert(server_public_key, "TLSServer sent us a certificate");
        return *server_public_key;
    }
    
    // Used during session resumption
    SecureVector!ubyte resume_master_secret;
    
    Unique!PublicKey server_public_key;
    
    // Used by client using NPN
    string delegate(const ref Vector!string) client_npn_cb;
}