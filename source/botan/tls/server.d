/**
* TLS Server
* 
* Copyright:
* (C) 2004-2011,2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.server;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.tls.channel;
import botan.tls.credentials_manager;
import botan.tls.handshake_state;
import botan.tls.messages;
import botan.tls.alert;
import botan.rng.rng;
import memutils.dictionarylist;
import memutils.hashmap;
import botan.utils.types;
import std.datetime;

alias NextProtocolHandler = string delegate(in Vector!string);
alias SNIHandler = SNIContextSwitchInfo delegate(string);

struct SNIContextSwitchInfo
{
	TLSSessionManager session_manager;
	TLSCredentialsManager credentials;
	TLSPolicy policy;
	NextProtocolHandler next_proto;
	void* user_data;
}


/**
* TLS Server
*/
final class TLSServer : TLSChannel
{
public:

    /**
    * TLSServer initialization
    */
    this(DataWriter output_fn,
         OnClearData data_cb,
         OnAlert alert_cb,
         OnHandshakeComplete handshake_cb,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         TLSPolicy policy,
         RandomNumberGenerator rng,
         NextProtocolHandler next_proto = null,
		 SNIHandler sni_handler = null,
         bool is_datagram = false,
         size_t io_buf_sz = 16*1024) 
    {
        super(output_fn, data_cb, alert_cb, handshake_cb, session_manager, rng, is_datagram, io_buf_sz);
		m_policy = policy;
        m_creds = creds;
        m_choose_next_protocol = next_proto;
		m_sni_handler = sni_handler;
    }

	void* getUserData() { return m_user_data; }

protected:
    override Vector!X509Certificate getPeerCertChain(in HandshakeState state) const
    {
        if (state.clientCerts())
            return state.clientCerts().certChain().dup();
        return Vector!X509Certificate();
    }

    /*
    * Send a hello request to the client
    */
    override void initiateHandshake(HandshakeState state, bool force_full_renegotiation)
    {
        (cast(ServerHandshakeState)state).allow_session_resumption = !force_full_renegotiation;
        
        auto hello_req = scoped!HelloRequest(state.handshakeIo());
    }

    /*
    * Process a handshake message
    */
    override void processHandshakeMsg(in HandshakeState active_state,
                                      HandshakeState state_base,
                                      HandshakeType type,
                                      const ref Vector!ubyte contents)
    {
        ServerHandshakeState state = cast(ServerHandshakeState)(state_base);
        
        state.confirmTransitionTo(type);
        
        /*
        * The change cipher spec message isn't technically a handshake
        * message so it's not included in the hash. The finished and
        * certificate verify messages are verified based on the current
        * state of the hash *before* this message so we delay adding them
        * to the hash computation until we've processed them below.
        */
        if (type != HANDSHAKE_CCS && type != FINISHED && type != CERTIFICATE_VERIFY)
        {
            state.hash().update(state.handshakeIo().format(contents, type));
        }
        
        if (type == CLIENT_HELLO)
        {
            const bool initial_handshake = !active_state;
            
            if (!m_policy.allowInsecureRenegotiation() &&
                !(initial_handshake || secureRenegotiationSupported()))
            {
                sendWarningAlert(TLSAlert.NO_RENEGOTIATION);
                return;
            }
            state.clientHello(new ClientHello(contents, type));

			// choose a proper context depending on hostname and register the userdata
			if (m_sni_handler) {
				const string sni_hostname = state.clientHello().sniHostname();
				SNIContextSwitchInfo ctx = m_sni_handler(sni_hostname);
				if (ctx !is SNIContextSwitchInfo.init)
					switchContext(ctx);
			}

            const TLSProtocolVersion client_version = state.clientHello().Version();
            
            TLSProtocolVersion negotiated_version;

            const TLSProtocolVersion latest_supported = m_policy.latestSupportedVersion(client_version.isDatagramProtocol());

            if ((initial_handshake && client_version.knownVersion()) ||
                (!initial_handshake && client_version == active_state.Version()))
            {
                /*
                Common cases: new client hello with some known version, or a
                renegotiation using the same version as previously
                negotiated.
                */
                
                negotiated_version = client_version;
            }
            else if (!initial_handshake && (client_version != active_state.Version()))
            {
                /*
                * If this is a renegotiation, and the client has offered a
                * later version than what it initially negotiated, negotiate
                * the old version. This matches OpenSSL's behavior. If the
                * client is offering a version earlier than what it initially
                * negotiated, reject as a probable attack.
                */
                if (active_state.Version() > client_version)
                {
                    throw new TLSException(TLSAlert.PROTOCOL_VERSION,
                                            "TLSClient negotiated " ~
                                            active_state.Version().toString() ~
                                            " then renegotiated with " ~
                                            client_version.toString());
                }
                else
                    negotiated_version = active_state.Version();
            }
            else
            {
                /*
                New negotiation using a version we don't know. Offer
                them the best we currently know and support.
                */
                negotiated_version = latest_supported;
            }
            
            if (!m_policy.acceptableProtocolVersion(negotiated_version))
            {
                throw new TLSException(TLSAlert.PROTOCOL_VERSION, "Client version " ~ negotiated_version.toString() ~ " is unacceptable by policy");
            }

            if (state.clientHello().sentFallbackSCSV())
            {
                if (latest_supported > client_version)
                    throw new TLSException(TLSAlert.INAPPROPRIATE_FALLBACK, "Client signalled fallback SCSV, possible attack");
            }

            secureRenegotiationCheck(state.clientHello());
            
            state.setVersion(negotiated_version);

            TLSSession session_info;
			scope(exit) destroy(session_info);
            const bool resuming = state.allow_session_resumption &&
                                    checkForResume(session_info,
                                                   sessionManager(),
                                                   m_creds,
                                                   state.clientHello(),
                                                   m_policy.sessionTicketLifetime());
            
            bool have_session_ticket_key = false;
            
			if (m_creds.hasPsk()) try
            {
                have_session_ticket_key = m_creds.psk("tls-server", "session-ticket", "").length > 0;
            }
            catch (Exception) {}

            m_application_protocol = "";

            if (m_choose_next_protocol && state.clientHello().supportsAlpn())
                m_application_protocol = m_choose_next_protocol(state.clientHello().nextProtocols());

            if (resuming)
            {
                // resume session
                
                const bool offer_new_session_ticket = (state.clientHello().supportsSessionTicket() &&
                                                        state.clientHello().sessionTicket().empty &&
                                                        have_session_ticket_key);
                
                state.serverHello(new ServerHello(state.handshakeIo(),
                                                  state.hash(),
                                                  m_policy,
                                                  state.clientHello().sessionId().dup,
                                                  session_info.Version(),
                                                  session_info.ciphersuiteCode(),
                                                  session_info.compressionMethod(),
                                                  session_info.fragmentSize(),
                                                  state.clientHello().secureRenegotiation(),
                                                  state.clientHello().supportsExtendedMasterSecret(),
                                                  secureRenegotiationDataForServerHello(),
                                                  offer_new_session_ticket,
                                                  state.clientHello().supportsAlpn(),
                                                  m_application_protocol,
                                                  state.clientHello().supportsHeartbeats(),
                                                  rng()));

                // Load ChannelID Original Handshake Hash
                if (state.clientHello().supportsChannelID() && state.serverHello().supportsChannelID()) 
                {
                    TLSSession sess;
                    scope(exit) if (sess) sess.destroy();
                    if (sessionManager() && sessionManager().loadFromSessionId(state.clientHello().sessionId(), sess))
                    {
                        state.setOriginalHandshakeHash(sess.originalHandshakeHash().dup());
                    }
                }

                secureRenegotiationCheck(state.serverHello());
                
                state.computeSessionKeys(session_info.masterSecret().dup);
                
                if (!saveSession(session_info))
                {
                    auto entry = &session_info.sessionId();
                    sessionManager().removeEntry(*entry);
                    
                    if (state.serverHello().supportsSessionTicket()) // send an empty ticket
                    {
                        state.newSessionTicket(new NewSessionTicket(state.handshakeIo(), state.hash()));
                    }
                }
                
                if (state.serverHello().supportsSessionTicket() && !state.newSessionTicket())
                {
					if (m_creds.hasPsk()) try
                    {

                        const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");
                        
                        state.newSessionTicket(new NewSessionTicket(state.handshakeIo(),
                                                                        state.hash(),
                                                                        session_info.encrypt(ticket_key, rng()),
                                                                        m_policy.sessionTicketLifetime()));
                    }
                    catch (Exception) {}
                    
                    if (!state.newSessionTicket())
                    {
                        state.newSessionTicket(new NewSessionTicket(state.handshakeIo(), state.hash()));
                    }
                }
                
                state.handshakeIo().send(scoped!ChangeCipherSpec());
                
                changeCipherSpecWriter(SERVER);
                
                state.serverFinished(new Finished(state.handshakeIo(), state, SERVER));
                
                state.setExpectedNext(HANDSHAKE_CCS);
            }
            else // new session
            {
                HashMapRef!(string, Array!X509Certificate) cert_chains;
                
                const string sni_hostname = state.clientHello().sniHostname();
                
                cert_chains = getServerCerts(sni_hostname, m_creds);
                
                if (sni_hostname != "" && cert_chains.length == 0)
                {
                    cert_chains = getServerCerts("", m_creds);
                        
                    /*
                    * Only send the unrecognized_name alert if we couldn't
                    * find any certs for the requested name but did find at
                    * least one cert to use in general. That avoids sending an
                    * unrecognized_name when a server is configured for purely
                    * anonymous operation.
                    */
                    if (cert_chains.length != 0)
                        sendAlert(TLSAlert(TLSAlert.UNRECOGNIZED_NAME));
                }
                state.serverHello(
                    new ServerHello(    state.handshakeIo(),
                                        state.hash(),
                                        m_policy,
                                        makeHelloRandom(rng(), m_policy), // new session ID
                                        state.Version(),
                                        chooseCiphersuite(m_policy, state.Version(), m_creds, cert_chains, state.clientHello()),
                                        chooseCompression(m_policy, state.clientHello().compressionMethods()),
                                        state.clientHello().fragmentSize(),
                                        state.clientHello().secureRenegotiation(),
                                        state.clientHello().supportsExtendedMasterSecret(),
                                        secureRenegotiationDataForServerHello(),
                                        state.clientHello().supportsSessionTicket() && have_session_ticket_key,
                                        state.clientHello().supportsAlpn(),
                                        m_application_protocol,
                                        state.clientHello().supportsHeartbeats(),
                                        rng()
                    )
                );

                secureRenegotiationCheck(state.serverHello());
                
                const string sig_algo = state.ciphersuite().sigAlgo();
                const string kex_algo = state.ciphersuite().kexAlgo();
                
                if (sig_algo != "")
                {
                    assert(!cert_chains[sig_algo].empty,
                    "Attempting to send empty certificate chain");
                    
                    state.serverCerts(new Certificate(state.handshakeIo(), state.hash(), cert_chains[sig_algo])
                    );
                }
                
                PrivateKey priv_key = null;
                
                if (kex_algo == "RSA" || sig_algo != "")
                {
                    priv_key = m_creds.privateKeyFor(state.serverCerts().certChain()[0],
                                                     "tls-server",
                                                     sni_hostname );
                    
                    if (!priv_key)
                        throw new InternalError("No private key located for associated server cert");
                }
                
                if (kex_algo == "RSA")
                {
                    state.server_rsa_kex_key = priv_key;
                }
                else
                {
                    state.serverKex(
                        new ServerKeyExchange(state.handshakeIo(),
                                                state,
                                                m_policy,
                                                m_creds,
                                                rng(),
                                                priv_key)
                        );
                }
                
                auto trusted_CAs = m_creds.trustedCertificateAuthorities("tls-server", sni_hostname);
                
                Vector!X509DN client_auth_CAs;
                
                foreach (store; trusted_CAs[])
                {
                    auto subjects = store.allSubjects();
                    client_auth_CAs ~= subjects[];
                }
                
                if (!client_auth_CAs.empty && state.ciphersuite().sigAlgo() != "")
                {
                    state.certReq(new CertificateReq(state.handshakeIo(), state.hash(), m_policy,
                                                     client_auth_CAs.move(), state.Version()));
                    
                    state.setExpectedNext(CERTIFICATE);
                }
                
                /*
                * If the client doesn't have a cert they want to use they are
                * allowed to send either an empty cert message or proceed
                * directly to the client key exchange, so allow either case.
                */
                state.setExpectedNext(CLIENT_KEX);
                
                state.serverHelloDone(new ServerHelloDone(state.handshakeIo(), state.hash()));
            }
        }
        else if (type == CERTIFICATE)
        {
            state.clientCerts(new Certificate(contents));
            
            state.setExpectedNext(CLIENT_KEX);
        }
        else if (type == CLIENT_KEX)
        {
            if (state.receivedHandshakeMsg(CERTIFICATE) && !state.clientCerts().empty)
                state.setExpectedNext(CERTIFICATE_VERIFY);
            else
                state.setExpectedNext(HANDSHAKE_CCS);
            
            state.clientKex(
                new ClientKeyExchange(contents, state, state.server_rsa_kex_key, m_creds, m_policy, rng())
            );
            
            state.computeSessionKeys();
        }
        else if (type == CERTIFICATE_VERIFY)
        {
            state.clientVerify(new CertificateVerify(contents, state.Version()));
            
            const(Vector!X509Certificate)* client_certs = &state.clientCerts().certChain();
            
            const bool sig_valid = state.clientVerify().verify((*client_certs)[0], state);
            
            state.hash().update(state.handshakeIo().format(contents, type));
            
            /*
            * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
            * "A handshake cryptographic operation failed, including being
            * unable to correctly verify a signature, ..."
            */
            if (!sig_valid)
                throw new TLSException(TLSAlert.DECRYPT_ERROR, "TLSClient cert verify failed");
            
            try
            {
                m_creds.verifyCertificateChain("tls-server", "", *client_certs);
            }
            catch(Exception e)
            {
                throw new TLSException(TLSAlert.BAD_CERTIFICATE, e.msg);
            }
            
            state.setExpectedNext(HANDSHAKE_CCS);
        }
        else if (type == HANDSHAKE_CCS)
        {

            if (state.originalHandshakeHash().length == 0)
                state.setExpectedNext(FINISHED);
            else state.setExpectedNext(CHANNEL_ID);

            changeCipherSpecReader(SERVER);            
        }
        else if (type == CHANNEL_ID) {
            // TODO: decode and verify

            state.setExpectedNext(FINISHED);
        }
        else if (type == FINISHED)
        {
            state.setExpectedNext(HANDSHAKE_NONE);
            
            state.clientFinished(new Finished(contents.dup));
            
            if (!state.clientFinished().verify(state, CLIENT))
                throw new TLSException(TLSAlert.DECRYPT_ERROR, "Finished message didn't verify");
            
            if (!state.serverFinished())
            {

                // already sent finished if resuming, so this is a new session
                
                state.hash().update(state.handshakeIo().format(contents, type));

                // Save Handshake Hash for ChannelID validation
                if (state.clientHello().supportsChannelID() && state.serverHello().supportsChannelID())
                    state.setOriginalHandshakeHash(state.hash().flushInto(state.Version(), state.ciphersuite().prfAlgo()));

                auto session_info =   new TLSSession(state.serverHello().sessionId().dup,
                                                     state.sessionKeys().masterSecret().dup,
                                                     state.originalHandshakeHash().dup,
                                                     state.serverHello().Version(),
                                                     state.serverHello().ciphersuite(),
                                                     state.serverHello().compressionMethod(),
                                                     SERVER,
                                                     state.serverHello().fragmentSize(),
                                                     state.serverHello().supportsExtendedMasterSecret(),
                                                     getPeerCertChain(state),
                                                     Vector!ubyte(),
                                                     TLSServerInformation(state.clientHello().sniHostname()),
                                                     state.srpIdentifier()
                    );
                
                if (saveSession(session_info))
                {
                    if (state.serverHello().supportsSessionTicket())
                    {
                        try
                        {
                            const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");
                            
                            state.newSessionTicket(
                                new NewSessionTicket(state.handshakeIo(),
                                                     state.hash(),
                                                     session_info.encrypt(ticket_key, rng()),
                                                     m_policy.sessionTicketLifetime())
                                );
                        }
                        catch (Exception) {}
                    }
                    else
                        sessionManager().save(session_info);
                }
                
                if (!state.newSessionTicket() && state.serverHello().supportsSessionTicket())
                {
                    state.newSessionTicket(new NewSessionTicket(state.handshakeIo(), state.hash()));
                }
                
                state.handshakeIo().send(scoped!ChangeCipherSpec());
                
                changeCipherSpecWriter(SERVER);
                
                state.serverFinished(new Finished(state.handshakeIo(), state, SERVER));
            }
            activateSession();
        }
        else
            throw new TLSUnexpectedMessage("Unknown handshake message received");
    }

    override HandshakeState newHandshakeState(HandshakeIO io)
    {
        HandshakeState state = new ServerHandshakeState(io);
        state.setExpectedNext(CLIENT_HELLO);
        return state;
    }

	void switchContext(SNIContextSwitchInfo info)
	{
		m_creds = info.credentials;
		m_session_manager = info.session_manager;
		m_policy = info.policy;
		m_choose_next_protocol = info.next_proto;
		m_user_data = info.user_data;
	}

private:
    TLSPolicy m_policy;
    TLSCredentialsManager m_creds;

    NextProtocolHandler m_choose_next_protocol;
	SNIHandler m_sni_handler;
	void* m_user_data;
}

private:

bool checkForResume(ref TLSSession session_info,
                    TLSSessionManager session_manager,
                    TLSCredentialsManager credentials,
                    in ClientHello clientHello,
                    Duration session_ticket_lifetime)
{
    const(Vector!ubyte)* client_session_id = &clientHello.sessionId();
    const Vector!ubyte session_ticket = clientHello.sessionTicket();
    
    if (session_ticket.empty)
    {
        if (client_session_id.empty) // not resuming
            return false;
        
        // not found
        if (!session_manager.loadFromSessionId(*client_session_id, session_info))
            return false;
    }
    else
    {
        // If a session ticket was sent, ignore client session ID
        try
        {
            session_info = TLSSession.decrypt(session_ticket,
            credentials.psk("tls-server", "session-ticket", ""));
            
            if (session_ticket_lifetime != Duration.init &&
                session_info.sessionAge() > session_ticket_lifetime)
                return false; // ticket has expired
        }
        catch (Exception)
        {
            return false;
        }
    }
    
	if (!session_info) 
		return false;

    // wrong version
    if (clientHello.Version() != session_info.Version())
        return false;
	import std.algorithm : canFind;
    // client didn't send original ciphersuite
    if (!clientHello.ciphersuitesData().canFind(session_info.ciphersuiteCode()))
        return false;
    
    // client didn't send original compression method
    if (!valueExists(clientHello.compressionMethods(),
                      session_info.compressionMethod()))
        return false;
    
    // client sent a different SRP identity
    if (clientHello.srpIdentifier() != "")
    {
        if (clientHello.srpIdentifier() != session_info.srpIdentifier())
            return false;
    }
    
    // client sent a different SNI hostname
    if (clientHello.sniHostname() != "")
    {
        if (clientHello.sniHostname() != session_info.serverInfo().hostname())
            return false;
    }

	if (clientHello.supportsExtendedMasterSecret() != session_info.supportsExtendedMasterSecret())
	{
		if (!session_info.supportsExtendedMasterSecret())
			return false;
		else {
			throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Client resumed extended ms session without sending extension");
		}
	}

    return true;
}

/*
* Choose which ciphersuite to use
*/
ushort chooseCiphersuite(in TLSPolicy policy,
                         TLSProtocolVersion _version,
                         TLSCredentialsManager creds,
                         in HashMapRef!(string, Array!X509Certificate) cert_chains,
                         in ClientHello client_hello)
{
	import std.algorithm : canFind;
    const bool our_choice = policy.serverUsesOwnCiphersuitePreferences();
    
    const bool have_srp = creds.attemptSrp("tls-server", client_hello.sniHostname());
    
    ushort[] client_suites = cast(ushort[])client_hello.ciphersuitesData();
    
    const Vector!ushort server_suites = policy.ciphersuiteList(_version, have_srp);
    
    if (server_suites.empty)
        throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSPolicy forbids us from negotiating any ciphersuite");
    
    const bool have_shared_ecc_curve = (policy.chooseCurve(client_hello.supportedEccCurves()) != "");
    
    ushort[] pref_list = cast()server_suites[];
       
    if (!our_choice)
        pref_list = client_suites;
	debug {
		string dbg_msg;
		string dbg_sig;
	}
    foreach (suite_id; pref_list)
    {
        if (!client_suites.canFind(suite_id))
            continue;
        
        TLSCiphersuite suite = TLSCiphersuite.byId(suite_id);
        
        if (!have_shared_ecc_curve && suite.eccCiphersuite())
            continue;
        
        if (suite.sigAlgo() != "" && cert_chains.get(suite.sigAlgo(), Array!X509Certificate(0)) == Array!X509Certificate(0))
		{
			debug  {
				dbg_msg = "Server Certificate type did not match a type that was accepted from policy: ";
				dbg_sig = suite.sigAlgo;
			}
            continue;
		}
        /*
        The client may offer SRP cipher suites in the hello message but
        omit the SRP extension.  If the server would like to select an
        SRP cipher suite in this case, the server SHOULD return a fatal
        "unknown_psk_identity" alert immediately after processing the
        client hello message.
         - RFC 5054 section 2.5.1.2
        */
        if (suite.kexAlgo() == "SRP_SHA" && client_hello.srpIdentifier() == "")
            throw new TLSException(TLSAlert.UNKNOWN_PSK_IDENTITY,
                                    "TLSClient wanted SRP but did not send username");
        
        return suite_id;
    }
	debug logDebug(dbg_msg, dbg_sig);
    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Can't agree on a ciphersuite with client");
}

/*
* Choose which compression algorithm to use
*/
ubyte chooseCompression(in TLSPolicy policy, const ref Vector!ubyte c_comp)
{
    Vector!ubyte s_comp = policy.compression();
    
    for (size_t i = 0; i != s_comp.length; ++i)
        for (size_t j = 0; j != c_comp.length; ++j)
            if (s_comp[i] == c_comp[j])
                return s_comp[i];
    
    return NO_COMPRESSION;
}

HashMapRef!(string, Array!X509Certificate) 
    getServerCerts(in string hostname, TLSCredentialsManager creds)
{
    string[] cert_types = [ "RSA", "DSA", "ECDSA", null ];
    
    HashMapRef!(string, Array!X509Certificate) cert_chains;
    
    for (size_t i = 0; cert_types[i]; ++i)
    {
        Vector!X509Certificate certs = creds.certChainSingleType(cert_types[i], "tls-server", hostname);
        
        if (!certs.empty)
            cert_chains[cert_types[i]] = certs.dupr;
    }
    
    return cert_chains;
}

private final class ServerHandshakeState : HandshakeState
{
public:    
    this(HandshakeIO io)
    {
        super(io);
    }
    
    // Used by the server only, in case of RSA key exchange. Not owned
    PrivateKey server_rsa_kex_key = null;
    
    /*
    * Used by the server to know if resumption should be allowed on
    * a server-initiated renegotiation
    */
    bool allow_session_resumption = true;
}