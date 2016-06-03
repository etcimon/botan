/**
* TLS Channel
* 
* Copyright:
* (C) 2011,2012,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.channel;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

public import botan.cert.x509.x509cert;
public import botan.tls.policy;
public import botan.tls.session;
public import botan.tls.alert;
public import botan.tls.session_manager;
public import botan.tls.version_;
public import botan.tls.exceptn;
public import botan.rng.rng;
import core.thread : Thread;
import botan.tls.handshake_state;
import botan.tls.messages;
import botan.tls.heartbeats;
import botan.tls.record;
import botan.tls.seq_numbers;
import botan.utils.rounding;
import memutils.dictionarylist;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.get_byte;
import memutils.hashmap;
import std.string : toStringz;

alias DataWriter = void delegate(in ubyte[]);
alias OnClearData = void delegate(in ubyte[]);
alias OnAlert = void delegate(in TLSAlert, in ubyte[]);
alias OnHandshakeComplete = bool delegate(in TLSSession);

/**
* Generic interface for TLS endpoint
*/
class TLSChannel
{
public:

	this(DataWriter output_fn,
		OnClearData data_cb,
		OnAlert alert_cb,
		OnHandshakeComplete handshake_cb,
		TLSSessionManager session_manager,
		RandomNumberGenerator rng,
		bool is_datagram,
		size_t reserved_io_buffer_size)
	{
		m_owner = Thread.getThis();
		m_handshake_cb = handshake_cb;
		m_data_cb = data_cb;
		m_alert_cb = alert_cb;
		m_output_fn = output_fn;
		m_rng = rng;
		m_session_manager = session_manager;
		/* epoch 0 is plaintext, thus null cipher state */
		//m_write_cipher_states[cast(ushort)0] = ConnectionCipherState.init;
		//m_read_cipher_states[cast(ushort)0] = ConnectionCipherState.init;
		
		m_writebuf.reserve(reserved_io_buffer_size);
		m_readbuf.reserve(reserved_io_buffer_size);
	}

    /**
    * Inject TLS traffic received from counterparty
    * Returns: a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t receivedData(const(ubyte)* input, size_t input_size)
    {
        
        const size_t max_fragment_size = maximumFragmentSize();
        
        try
        {
            while (!isClosed() && input_size)
            {
                SecureVector!ubyte record;
                ulong record_sequence = 0;
                RecordType record_type = NO_RECORD;
                TLSProtocolVersion record_version;

                size_t consumed = 0;
                const size_t needed = .readRecord(m_readbuf,
                                                  input,
                                                  input_size,
                                                  m_is_datagram,
                                                  consumed,
                                                  record,
                                                  record_sequence,
                                                  record_version,
                                                  record_type,
                                                  *m_sequence_numbers,
                                                  &readCipherStateEpoch);
                assert(consumed > 0, "Got to eat something");
                assert(consumed <= input_size, "Record reader consumed sane amount");
                
                input += consumed;
                input_size -= consumed;
                
                assert(input_size == 0 || needed == 0, "Got a full record or consumed all input");
                
                if (input_size == 0 && needed != 0)
                    return needed; // need more data to complete record
                
                if (record.length > max_fragment_size)
                    throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Plaintext record is too large");
                if (record_type == HANDSHAKE || record_type == CHANGE_CIPHER_SPEC)
                {
                    if (!m_pending_state)
                    {
                        if (record_version.isDatagramProtocol())
                        {
                            if (m_sequence_numbers)
                            {

                                /*
                                * Might be a peer retransmit under epoch - 1 in which
                                * case we must retransmit last flight
                                */

                                (*m_sequence_numbers).readAccept(record_sequence);
                                          
                                const ushort epoch = record_sequence >> 48;
                                
                                if (epoch == sequenceNumbers().currentReadEpoch())
                                {
                                    createHandshakeState(record_version);
                                }
                                else if (epoch == sequenceNumbers().currentReadEpoch() - 1)
                                {
                                    assert(m_active_state, "Have active state here");
                                    auto rec = unlock(record);
                                    m_active_state.handshakeIo().addRecord(rec, record_type, record_sequence);
                                }
                            }
                            else if (record_sequence == 0)
                            {
                                createHandshakeState(record_version);
                            }
                        }
                        else
                        {
                            createHandshakeState(record_version);
                        }
                        
                    }

                    if (m_pending_state)
                    {
                        auto rec = unlock(record);
                        m_pending_state.handshakeIo().addRecord(rec, record_type, record_sequence);
                        
                        while (true) {
                            if (auto pending = *m_pending_state) {
                                auto msg = pending.getNextHandshakeMsg();
                                
                                if (msg.type == HANDSHAKE_NONE) // no full handshake yet
                                    break;

                                processHandshakeMsg(activeState(), pending, msg.type, msg.data);
                            } else break;
                        }
                    }
                }
                else if (record_type == HEARTBEAT && peerSupportsHeartbeats())
                {
                    if (!activeState())
                        throw new TLSUnexpectedMessage("Heartbeat sent before handshake done");
                    
                    HeartbeatMessage heartbeat = HeartbeatMessage(unlock(record));
                    
                    const Vector!ubyte* payload = &heartbeat.payload();
                    
                    if (heartbeat.isRequest())
                    {
                        if (!pendingState())
                        {
                            HeartbeatMessage response = HeartbeatMessage(HeartbeatMessage.RESPONSE, payload.ptr, payload.length);
                            auto rec = response.contents();
                            sendRecord(HEARTBEAT, rec);
                        }
                    }
                    else
                    {
                        m_alert_cb(TLSAlert(TLSAlert.HEARTBEAT_PAYLOAD), cast(ubyte[])(*payload)[]);
                    }
                }
                else if (record_type == APPLICATION_DATA)
                {
                    if (!activeState())
                        throw new TLSUnexpectedMessage("Application data before handshake done");
                            
                    /*
                    * OpenSSL among others sends empty records in versions
                    * before TLS v1.1 in order to randomize the IV of the
                    * following record. Avoid spurious callbacks.
                    */
                    if (record.length > 0)
                        m_data_cb(cast(ubyte[])record[]);
                }
                else if (record_type == ALERT)
                {
                    TLSAlert alert_msg = TLSAlert(record);
                    
                    if (alert_msg.type() == TLSAlert.NO_RENEGOTIATION)
                    m_pending_state.free();
                    
                    m_alert_cb(alert_msg, null);
                    
                    if (alert_msg.isFatal())
                    {
                        if (auto active = activeState()) {
                            auto entry = &active.serverHello().sessionId();
                            m_session_manager.removeEntry(*entry);
                        }
                    }
                            
                    if (alert_msg.type() == TLSAlert.CLOSE_NOTIFY)
                        sendWarningAlert(TLSAlert.CLOSE_NOTIFY); // reply in kind
                                
                    if (alert_msg.type() == TLSAlert.CLOSE_NOTIFY || alert_msg.isFatal())
                    {
                        resetState();
                        return 0;
                    }
                }
                else if (record_type != NO_RECORD)
                    throw new TLSUnexpectedMessage("Unexpected record type " ~ to!string(record_type) ~ " from counterparty");
            }
                        
            return 0; // on a record boundary
        }
        catch(TLSException e)
        {
            sendFatalAlert(e.type());
            throw e;
        }
        catch(IntegrityFailure e)
        {
            sendFatalAlert(TLSAlert.BAD_RECORD_MAC);
            throw e;
        }
        catch(DecodingError e)
        {
            sendFatalAlert(TLSAlert.DECODE_ERROR);
            throw e;
        }
        catch(Exception e)
        {
            sendFatalAlert(TLSAlert.INTERNAL_ERROR);
            throw e;
        }
    }

    /**
    * Inject TLS traffic received from counterparty
    * Returns: a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t receivedData(const ref Vector!ubyte buf)
    {
        return this.receivedData(buf.ptr, buf.length);
    }

    /**
    * Inject plaintext intended for counterparty
    * Throws an exception if isActive() is false
    */
    void send(const(ubyte)* buf, size_t buf_size)
    {
        if (!isActive())
            throw new TLSClosedException("Data cannot be sent on inactive TLS connection");
        
        sendRecordArray(sequenceNumbers().currentWriteEpoch(), APPLICATION_DATA, buf, buf_size);
    }

    /**
    * Inject plaintext intended for counterparty
    * Throws an exception if isActive() is false
    */
    void send(in string str)
    {
        this.send(cast(const(ubyte)*)(str.toStringz), str.length);
    }

    /**
    * Inject plaintext intended for counterparty
    * Throws an exception if isActive() is false
    */
    void send(Alloc)(const ref Vector!( char, Alloc ) val)
    {
        send(val.ptr, val.length);
    }

    /**
    * Send a TLS alert message. If the alert is fatal, the internal
    * state (keys, etc) will be reset.
    *
    * Params:
    *  alert = the TLSAlert to send
    */
    void sendAlert(in TLSAlert alert)
    {
        if (alert.isValid() && !isClosed())
        {
            try
            {
                auto rec = alert.serialize();
                sendRecord(ALERT, rec);
            }
            catch (Exception) { /* swallow it */ }
        }
        
        if (alert.type() == TLSAlert.NO_RENEGOTIATION)
            m_pending_state.free();
        
        if (alert.isFatal()) {
            if (auto active = activeState()) {
                auto entry = &active.serverHello().sessionId();
                m_session_manager.removeEntry(*entry);
            }
        }
        if (alert.type() == TLSAlert.CLOSE_NOTIFY || alert.isFatal())
            resetState();
    }

    /**
    * Send a warning alert
    */
    void sendWarningAlert(TLSAlertType type) { sendAlert(TLSAlert(type, false)); }

    /**
    * Send a fatal alert
    */
    void sendFatalAlert(TLSAlertType type) { sendAlert(TLSAlert(type, true)); }

    /**
    * Send a close notification alert
    */
    void close() { sendWarningAlert(TLSAlert.CLOSE_NOTIFY); }

    /**
    * Returns: true iff the connection is active for sending application data
    */
    bool isActive() const
    {
        return (activeState() !is null);
    }

    /**
    * Returns: true iff the connection has been definitely closed
    */
    bool isClosed() const
    {
        if (activeState() || pendingState())
            return false;
        
        /*
        * If no active or pending state, then either we had a connection
        * and it has been closed, or we are a server which has never
        * received a connection. This case is detectable by also lacking
        * m_sequence_numbers
        */
        return (*m_sequence_numbers !is null);
    }

    /**
    * Attempt to renegotiate the session
    * Params:
    *  force_full_renegotiation = if true, require a full renegotiation,
    *                                            otherwise allow session resumption
    */
    void renegotiate(bool force_full_renegotiation = false)
    {
        if (pendingState()) // currently in handshake?
            return;
        
        if (const HandshakeState active = activeState())
            initiateHandshake(createHandshakeState(active.Version()),
                               force_full_renegotiation);
        else
            throw new Exception("Cannot renegotiate on inactive connection");
    }

    /**
    * Returns: true iff the peer supports heartbeat messages
    */
    bool peerSupportsHeartbeats() const
    {
        if (const HandshakeState active = activeState())
            return active.serverHello().supportsHeartbeats();
        return false;
    }

    /**
    * Returns: true iff we are allowed to send heartbeat messages
    */
    bool heartbeatSendingAllowed() const
    {
        if (const HandshakeState active = activeState())
            return active.serverHello().peerCanSendHeartbeats();
        return false;
    }

    /**
    * Attempt to send a heartbeat message (if negotiated with counterparty)
    * Params:
    *  payload = will be echoed back
    *  payload_size = size of payload in bytes
    */
    void heartbeat(const(ubyte)* payload, size_t payload_size)
    {
        if (heartbeatSendingAllowed())
        {
            HeartbeatMessage heartbeat = HeartbeatMessage(HeartbeatMessage.REQUEST, payload, payload_size);
            auto rec = heartbeat.contents();
            sendRecord(HEARTBEAT, rec);
        }
    }

    /**
    * Attempt to send a heartbeat message (if negotiated with counterparty)
    */
    void heartbeat() { heartbeat(null, 0); }

    /**
    * Returns: certificate chain of the peer (may be empty)
    */
    Vector!X509Certificate peerCertChain() const
    {
        if (const HandshakeState active = activeState())
            return getPeerCertChain(active).dup;
        return Vector!X509Certificate();
    }

    /**
    * Key material export (RFC 5705)
    * Params:
    *  label = a disambiguating label string
    *  context = a per-association context value
    *  length = the length of the desired key in bytes
    * Returns: key of length bytes
    */
    const(SymmetricKey) keyMaterialExport(in string label,
                                   in string context,
                                   size_t length) const
    {
        if (auto active = activeState())
        {
            Unique!KDF prf = active.protocolSpecificPrf();
            
            const(SecureVector!ubyte)* master_secret = &active.sessionKeys().masterSecret();
            
            Vector!ubyte salt;
            salt ~= label;
			salt ~= active.clientHello().randomBytes();
			salt ~= active.serverHello().randomBytes();

            if (context != "")
            {
                size_t context_size = context.length;
                if (context_size > 0xFFFF)
                    throw new Exception("key_material_export context is too long");
                salt.pushBack(get_byte(0, cast(ushort) context_size));
                salt.pushBack(get_byte(1, cast(ushort) context_size));
                salt ~= context;
            }
            
            return SymmetricKey(prf.deriveKey(length, *master_secret, salt));
        }
        else
            throw new Exception("key_material_export connection not active");
    }

	/// Returns the ALPN chosen in the ServerHello with the ALPN extention
	const(string) applicationProtocol() const { return m_application_protocol; }

	/// Returns the current session ID
	const(ubyte[]) sessionId() const {
		if (auto active = activeState()) {
			return active.serverHello().sessionIdBytes();
		}
		return null;
	}

    ~this()
    {

		version(TLSGC) if (m_owner != Thread.getThis()) return;

        resetState();
    }

protected:

    abstract void processHandshakeMsg(in HandshakeState active_state,
                                      HandshakeState pending_state,
                                      HandshakeType type,
                                      const ref Vector!ubyte contents);

    abstract void initiateHandshake(HandshakeState state,
                                    bool force_full_renegotiation);

    abstract Vector!X509Certificate getPeerCertChain(in HandshakeState state) const;

    abstract HandshakeState newHandshakeState(HandshakeIO io);

    HandshakeState createHandshakeState(TLSProtocolVersion _version)
    {
        if (pendingState())
            throw new InternalError("createHandshakeState called during handshake");
        
        if (const HandshakeState active = activeState())
        {
            TLSProtocolVersion active_version = active.Version();
            
            if (active_version.isDatagramProtocol() != _version.isDatagramProtocol())
                throw new Exception("Active state using version " ~ active_version.toString() ~
                                    " cannot change to " ~ _version.toString() ~ " in pending");
        }
        
        if (!m_sequence_numbers)
        {
            if (_version.isDatagramProtocol())
                m_sequence_numbers = new DatagramSequenceNumbers;
            else
                m_sequence_numbers = new StreamSequenceNumbers;
        }
        
        Unique!HandshakeIO io;
        if (_version.isDatagramProtocol()) {
			// default MTU is IPv6 min MTU minus UDP/IP headers (TODO: make configurable)
			const ushort mtu = 1280 - 40 - 8;
            io = new DatagramHandshakeIO(*m_sequence_numbers, &sendRecordUnderEpoch, mtu);
        }
        else
            io = new StreamHandshakeIO(&sendRecord);

        m_pending_state = newHandshakeState(io.release());
        
        if (auto active = activeState())
            m_pending_state.setVersion(active.Version());
        
        return *m_pending_state;
    }

    /**
    * Perform a handshake timeout check. This does nothing unless
    * this is a DTLS channel with a pending handshake state, in
    * which case we check for timeout and potentially retransmit
    * handshake packets.
    */
    bool timeoutCheck() {
        if (m_pending_state)
            return m_pending_state.handshakeIo().timeoutCheck();
        //FIXME: scan cipher suites and remove epochs older than 2*MSL
        return false;
    }

    void activateSession()
    {
        std.algorithm.swap(m_active_state, m_pending_state);
        m_pending_state.free();
        
        if (!m_active_state.Version().isDatagramProtocol())
        {
            // TLS is easy just remove all but the current state
            auto current_epoch = sequenceNumbers().currentWriteEpoch();

            foreach (const ref ushort k, const ref ConnectionCipherState v; m_write_cipher_states) {
                if (k != current_epoch) {
                    v.destroy();
                    m_write_cipher_states.remove(k);
                }
            }
            foreach (const ref ushort k, const ref ConnectionCipherState v; m_read_cipher_states) {
                if (k != current_epoch) {
                    v.destroy();
                    m_write_cipher_states.remove(k);                    
                }
            }
        }
    }

    void changeCipherSpecReader(ConnectionSide side)
    {
        auto pending = pendingState();
        
        assert(pending && pending.serverHello(), "Have received server hello");
        
        if (pending.serverHello().compressionMethod() != NO_COMPRESSION)
            throw new InternalError("Negotiated unknown compression algorithm");
        
        (*m_sequence_numbers).newReadCipherState();
        
        const ushort epoch = sequenceNumbers().currentReadEpoch();

        assert(m_read_cipher_states.get(epoch, ConnectionCipherState.init) is ConnectionCipherState.init, 
               "No read cipher state currently set for next epoch");
        
        // flip side as we are reading
        ConnectionCipherState read_state = new ConnectionCipherState(pending.Version(),
                                                                 (side == CLIENT) ? SERVER : CLIENT,
                                                                 false,
                                                                 pending.ciphersuite(),
                                                                 pending.sessionKeys());
        
        m_read_cipher_states[epoch] = read_state;
    }

    void changeCipherSpecWriter(ConnectionSide side)
    {
        auto pending = pendingState();
        
        assert(pending && pending.serverHello(), "Have received server hello");
        
        if (pending.serverHello().compressionMethod() != NO_COMPRESSION)
            throw new InternalError("Negotiated unknown compression algorithm");
        
        (*m_sequence_numbers).newWriteCipherState();
        
        const ushort epoch = sequenceNumbers().currentWriteEpoch();
        
        assert(m_write_cipher_states.get(epoch, ConnectionCipherState.init) is ConnectionCipherState.init, "No write cipher state currently set for next epoch");
        
        ConnectionCipherState write_state = new ConnectionCipherState(pending.Version(),
                                                                  side,
                                                                  true,
                                                                  pending.ciphersuite(),
                                                                  pending.sessionKeys());
        
        m_write_cipher_states[epoch] = write_state;
    }

    /* secure renegotiation handling */
    void secureRenegotiationCheck(const ClientHello client_hello)
    {
        const bool secure_renegotiation = client_hello.secureRenegotiation();
        
        if (auto active = activeState())
        {
            const bool active_sr = active.clientHello().secureRenegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSClient changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            Vector!ubyte data = client_hello.renegotiationInfo();
            
            if (data != secureRenegotiationDataForClientHello())
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSClient sent bad values for secure renegotiation");
        }
    }

    void secureRenegotiationCheck(const ServerHello server_hello)
    {
        const bool secure_renegotiation = server_hello.secureRenegotiation();
        
        if (auto active = activeState())
        {
            const bool active_sr = active.clientHello().secureRenegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSServer changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            const Vector!ubyte data = server_hello.renegotiationInfo();
            
            if (data != secureRenegotiationDataForServerHello())
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLSServer sent bad values for secure renegotiation");
        }
    }

    Vector!ubyte secureRenegotiationDataForClientHello() const
    {
        if (auto active = activeState())
            return active.clientFinished().verifyData().dup;
        return Vector!ubyte();
    }

    Vector!ubyte secureRenegotiationDataForServerHello() const
    {
        if (auto active = activeState())
        {
			auto client_data = active.clientFinished().verifyData();
            Vector!ubyte buf = client_data[];
			auto server_data = active.serverFinished().verifyData();
            buf ~= server_data[];
            return buf.move();
        }
        
        return Vector!ubyte();
    }

    /**
    * Returns: true iff the counterparty supports the secure
    * renegotiation extensions.
    */
    bool secureRenegotiationSupported() const
    {
        if (auto active = activeState())
            return active.serverHello().secureRenegotiation();
        
        if (auto pending = pendingState())
            if (auto hello = pending.serverHello())
                return hello.secureRenegotiation();
        
        return false;
    }

    RandomNumberGenerator rng() { return m_rng; }

    TLSSessionManager sessionManager() { return m_session_manager; }

    bool saveSession(in TLSSession session) const { return m_handshake_cb(session); }

private:

    size_t maximumFragmentSize() const
    {
        // should we be caching this value?
        
        if (auto pending = pendingState())
            if (auto server_hello = pending.serverHello())
                if (size_t frag = server_hello.fragmentSize())
                    return frag;
        
        if (auto active = activeState())
            if (size_t frag = active.serverHello().fragmentSize())
                return frag;
        
        return MAX_PLAINTEXT_SIZE;
    }

    void sendRecord(ubyte record_type, const ref Vector!ubyte record)
    {
        sendRecordArray(sequenceNumbers().currentWriteEpoch(), record_type, record.ptr, record.length);
    }

    void sendRecordUnderEpoch(ushort epoch, ubyte record_type, const ref Vector!ubyte record)
    {
        sendRecordArray(epoch, record_type, record.ptr, record.length);
    }

    void sendRecordArray(ushort epoch, ubyte type, const(ubyte)* input, size_t length)
    {
        if (length == 0)
            return;
        /*
        * If using CBC mode without an explicit IV (SSL v3 or TLS v1.0),
        * send a single ubyte of plaintext to randomize the (implicit) IV of
        * the following main block. If using a stream cipher, or TLS v1.1
        * or higher, this isn't necessary.
        *
        * An empty record also works but apparently some implementations do
        * not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
        *
        * See http://www.openssl.org/~bodo/tls-cbc.txt for background.
        */
        
        auto cipher_state = cast(ConnectionCipherState)writeCipherStateEpoch(epoch);
        
        if (type == APPLICATION_DATA && cipher_state.cbcWithoutExplicitIv())
        {
            writeRecord(cipher_state, epoch, type, input, 1);
            input += 1;
            length -= 1;
        }
        
        const size_t max_fragment_size = maximumFragmentSize();
        
        while (length)
        {
            const size_t sending = std.algorithm.min(length, max_fragment_size);
            writeRecord(cipher_state, epoch, type, input, sending);
            
            input += sending;
            length -= sending;
        }
    }

    void writeRecord(ConnectionCipherState cipher_state, ushort epoch, ubyte record_type, const(ubyte)* input, size_t length)
    {
        assert(m_pending_state || m_active_state, "Some connection state exists");
        
        TLSProtocolVersion record_version = (m_pending_state) ? (m_pending_state.Version()) : (m_active_state.Version());
        
        .writeRecord(m_writebuf,
                     record_type,
                     input,
                     length,
                     record_version,
                     (*m_sequence_numbers).nextWriteSequence(epoch),
                     cipher_state,
                     m_rng);
        
        m_output_fn(cast(ubyte[]) m_writebuf[]);
    }

    const(ConnectionSequenceNumbers) sequenceNumbers() const
    {
        assert(m_sequence_numbers, "Have a sequence numbers object");
        return *m_sequence_numbers;
    }

    const(ConnectionCipherState) readCipherStateEpoch(ushort epoch) const
    {
        auto state = m_read_cipher_states.get(epoch, ConnectionCipherState.init);
        
        assert(state !is ConnectionCipherState.init || epoch == 0, "Have a cipher state for the specified epoch");
        
        return state;
    }

    const(ConnectionCipherState) writeCipherStateEpoch(ushort epoch) const
    {
        auto state = m_write_cipher_states.get(epoch, ConnectionCipherState.init);
        
        assert(state !is ConnectionCipherState.init || epoch == 0, "Have a cipher state for the specified epoch");
        
        return state;
    }

    protected void resetState()
    {
        m_active_state.free();
        m_pending_state.free();
        m_readbuf.destroy();
		m_writebuf.destroy();
        foreach (const ref k, const ref v; m_write_cipher_states)
        {
            v.destroy();
        }
        m_write_cipher_states.clear();
        foreach (const ref k, const ref v; m_read_cipher_states)
        {
            v.destroy();
        }
        m_read_cipher_states.clear();
    }

    const(HandshakeState) activeState() const { return *m_active_state; }

    const(HandshakeState) pendingState() const { return *m_pending_state; }

	Thread m_owner;
	package string m_application_protocol;
    bool m_is_datagram;

    /* callbacks */
    OnHandshakeComplete m_handshake_cb;
    OnClearData m_data_cb;
    OnAlert m_alert_cb;
    DataWriter m_output_fn;

    /* external state */
    RandomNumberGenerator m_rng;
    package TLSSessionManager m_session_manager; // fixme: package protection for switchContext, use protected: method instead

    /* sequence number state */
    Unique!ConnectionSequenceNumbers m_sequence_numbers;

    /* pending and active connection states */
    Unique!HandshakeState m_active_state;
    Unique!HandshakeState m_pending_state;

    /* cipher states for each epoch */
    HashMap!(ushort, ConnectionCipherState) m_write_cipher_states;
    HashMap!(ushort, ConnectionCipherState) m_read_cipher_states;

    /* I/O buffers */
    SecureVector!ubyte m_writebuf;
    SecureVector!ubyte m_readbuf;
}