/**
* TLS Blocking API
* 
* Copyright:
* (C) 2013,2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.blocking;

import botan.constants;
static if (BOTAN_HAS_TLS):

import std.exception : enforce;
import botan.tls.client;
import botan.tls.server;
import botan.rng.rng;
import botan.tls.channel;
import botan.tls.session_manager;
import botan.tls.version_;
import botan.utils.mem_ops;
import memutils.unreadring;
import memutils.utils;
import std.algorithm;

/// Fill `buf` from the socket; return the slice actually read (empty on EOF).
alias DataReader = ubyte[] delegate(ubyte[]);

/**
* Blocking TLS Channel
*/
struct TLSBlockingChannel
{
public:
    @disable this(this);
    @disable this();

    /**
    * TLS client over blocking read/write callbacks
    * Params:
    *  read_fn = ciphertext from the socket
    *  write_fn = ciphertext to the socket
    *  alert_cb = called when a TLS alert is received
    *  hs_cb = called when a handshake completes
    *  session_manager = stores resumable sessions
    *  creds = client certificates (optional)
    *  policy = connection policy
    *  rng = random number generator
    *  server_info = SNI hostname / service
    *  offer_version = ClientHello version (default latestTlsVersion, TLS 1.2)
    *  next_protocols = ALPN offer
    */
    this(DataReader read_fn,
         DataWriter write_fn,
		 OnAlert alert_cb,
		 OnHandshakeComplete hs_cb,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         TLSPolicy policy,
         RandomNumberGenerator rng,
         in TLSServerInformation server_info = TLSServerInformation(),
         in TLSProtocolVersion offer_version = TLSProtocolVersion.latestTlsVersion(),
         Vector!string next_protocols = Vector!string())
    {
        m_is_client = true;
        m_read_fn = read_fn;
		m_alert_cb = alert_cb;
		m_handshake_complete = hs_cb;
		m_readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
		scope(failure) m_readbuf.destroy();
        m_impl.client = new TLSClient(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
            policy, rng, server_info, offer_version, next_protocols.move);
    }

    /**
    * TLS server over blocking read/write callbacks
    * Params:
    *  read_fn = ciphertext from the socket
    *  write_fn = ciphertext to the socket
    *  alert_cb = called when a TLS alert is received
    *  hs_cb = called when a handshake completes
    *  session_manager = stores resumable sessions
    *  creds = server certificates and keys
    *  policy = connection policy
    *  rng = random number generator
    *  next_proto = ALPN selector, or null
    *  sni_handler = optional hostname credentials switch
    *  is_datagram = true for DTLS
    *  io_buf_sz = preallocated I/O buffer size
    */
    this(DataReader read_fn,
         DataWriter write_fn,
		 OnAlert alert_cb,
		 OnHandshakeComplete hs_cb,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         TLSPolicy policy,
         RandomNumberGenerator rng,
         NextProtocolHandler next_proto = null,
		 SNIHandler sni_handler = null,
         bool is_datagram = false,
         size_t io_buf_sz = 16*1024)
    {
        m_is_client = false;
        m_read_fn = read_fn;
		m_alert_cb = alert_cb;
		m_handshake_complete = hs_cb;
		m_readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
		scope(failure) m_readbuf.destroy();
        m_impl.server = new TLSServer(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
			policy, rng, next_proto, sni_handler, is_datagram, io_buf_sz);
    }

    /**
    * Blocks until the full handhsake is complete
    */
    void doHandshake()
	{
        while (!m_closed && channel !is null && !channel.isActive())
        {
            ubyte[] readref = m_readbuf.ptr[0 .. m_readbuf.length];
            const ubyte[] from_socket = m_read_fn(readref);
			enforce(channel!is null, "Connection closed during handshake");
            channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);
        }
    }

    /**
    * Number of bytes pending read in the plaintext buffer (bytes
    * readable without blocking)
    */
	size_t pending() const { return unreadLength; }

	/// Returns an array of pending data
	const(ubyte)[] peek() {
		return unreadLength > 0 ? unreadPeek() : null;
	}

    /**
    * Block until `dest` is filled from decrypted plaintext
    * Params:
    *  dest = output buffer (must be non-empty)
    */
    void read(ubyte[] dest) 
    {
		enforce(dest.length > 0, "Empty destination array");
		ubyte[] destlog = dest;
		//logDebug("remaining length: ", dest.length);
        ubyte[] remaining = dest;
		int i;
        while (remaining.length > 0) {
            dest = readBuf(remaining);
			enforce(++i < 1000 && dest.length > 0, "readBuf returned 0 length (connection closed)");
            remaining = remaining[dest.length .. $];
			//logDebug("remaining length: ", remaining.length);
        }
		//logDebug("finished with: ", cast(string) destlog);
    }

    /**
    * Blocking read if pending() is 0. Returns at least 1 byte, or empty on close.
    * Params:
    *  buf = destination; a shorter return than buf.length means a short read
    * Returns: slice of buf that was filled
    */
	ubyte[] readBuf(ubyte[] buf)
    {
		m_reading = true;
		scope(exit) m_reading = false;

		if (unreadLength != 0) {
			size_t len = min(unreadLength, buf.length);
			unreadRead(buf[0 .. len]);
			return buf[0 .. len];
		}

        // if there's nothing in the buffers, read some packets and process them
		while (unreadEmpty)
        {
			ubyte[] slice;
			if (m_readbuf.length > 0) {
				slice = m_readbuf.ptr[0 .. m_readbuf.length];
			}
			const ubyte[] from_socket = m_read_fn(slice);
			if (from_socket.length == 0)
				return null;

			enforce(channel !is null, "Connection closed while reading from TLS Channel");
			channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);

			if (from_socket.length == slice.length && m_readbuf.length < 256*1024) {
				size_t next_len = m_readbuf.length * 2;
				m_readbuf.destroy();
				m_readbuf = Vector!ubyte(next_len);
				// increase for next time
			}

        }

		if (buf.length == 0) return null;

        const size_t returned = std.algorithm.min(buf.length, unreadLength);
		if (returned == 0) {
			//logDebug("Destroyed return object");
			return null;
		}
		unreadRead(buf[0 .. returned]);

        
		//logDebug("Returning data");
        return buf[0 .. returned];
    }

	void write(in ubyte[] buf) { 
		m_writing = true;
		scope(exit) m_writing = false;

		enforce(channel !is null, "Connection closed when attempting to write to channel"); 
		channel.send(cast(const(ubyte)*)buf.ptr, buf.length);
	}

    inout(TLSChannel) underlyingChannel() inout { return channel; }

	void close() { enforce(channel); m_closed = true; channel.close(); }

	bool isClosed() const { return m_closed || m_impl.client is null; }

	@property bool isBusy() const { return m_reading || m_writing; }

	const(Vector!X509Certificate) peerCertChain() const { enforce(channel); return channel.peerCertChain(); }

	~this()
	{
		unreadDispose();
		if (m_is_client)
			m_impl.client.destroy(); 
		else m_impl.server.destroy();
	}

    /**
     * get handshake complete notifications
    */
    @property void onHandshakeComplete(OnHandshakeComplete handshake_complete)
    { m_handshake_complete = handshake_complete; }

    /**
    * get notification of alerts 
    */
    @property void onAlertNotification(OnAlert alert_cb)
    {
        m_alert_cb = alert_cb;
    }

private:

    bool handshakeCb(in TLSSession session)
    {
		//logDebug("Handshake Complete");  
		if (m_handshake_complete)
	        return m_handshake_complete(session);
		return true;
    }

    void dataCb(in ubyte[] data)
    {
		unreadPut(data);
    }

    void alertCb(in TLSAlert alert, in ubyte[] ub)
    {
		//logDebug("Alert: ", alert.typeString(), " :", ub);  
		if (alert.isFatal)
			m_closed = true;
		if (m_alert_cb)
	        m_alert_cb(alert, ub); 
    }

    union TLSImpl {
        TLSClient client;
        TLSServer server;
    }

	@property inout(TLSChannel) channel() inout { 
		return (m_is_client ? cast(inout(TLSChannel)) m_impl.client : cast(inout(TLSChannel)) m_impl.server); 
	}

	bool m_reading;
	bool m_writing;
    bool m_is_client;
	bool m_closed;
    DataReader m_read_fn;
    TLSImpl m_impl;
    OnAlert m_alert_cb;
    OnHandshakeComplete m_handshake_complete;

    // Same unread-ring mixin as libasync leftover; SecureMem zeroises.
    mixin UnreadRingMixin!SecureMem;

	Vector!ubyte m_readbuf;
}

