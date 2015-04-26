/**
* TLS Blocking API
* 
* Copyright:
* (C) 2013,2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.blocking;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.client;
import botan.tls.server;
import botan.rng.rng;
import botan.tls.channel;
import botan.tls.session_manager;
import botan.tls.version_;
import botan.utils.mem_ops;
import memutils.circularbuffer;
import memutils.utils;
import std.algorithm;

alias DataReader = ubyte[] delegate(ubyte[]);

/**
* Blocking TLS Channel
*/
struct TLSBlockingChannel
{
public:
    @disable this(this);
    @disable this();

    /// Client constructor
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
        m_impl.client = new TLSClient(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
            policy, rng, server_info, offer_version, next_protocols.move);
    }

    /// Server constructor
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
        m_impl.server = new TLSServer(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
			policy, rng, next_proto, sni_handler, is_datagram, io_buf_sz);
    }

    /**
    * Blocks until the full handhsake is complete
    */
    void doHandshake()
	{
		assert(!m_slice);
        
        while (!m_closed && !channel.isActive())
        {
            ubyte[] readref = m_readbuf.ptr[0 .. m_readbuf.length];
            const ubyte[] from_socket = m_read_fn(readref);
            channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);
        }
    }

    /**
    * Number of bytes pending read in the plaintext buffer (bytes
    * readable without blocking)
    */
	size_t pending() const { assert(!m_slice); return m_plaintext.length; }

	/// Returns an array of pending data
	const(ubyte)[] peek() {
		assert(!m_slice);
		return m_plaintext.length > 0 ? m_plaintext.peek : null;
	}

    /// Reads until the destination ubyte array is full, utilizing internal buffers if necessary
    void read(ubyte[] dest) 
    {
		ubyte[] destlog = dest;
		assert(!m_slice);
		//logDebug("remaining length: ", dest.length);
        ubyte[] remaining = dest;
        while (remaining.length > 0) {
            dest = readBuf(remaining);
            remaining = remaining[dest.length .. $];
			//logDebug("remaining length: ", remaining.length);
        }
		//logDebug("finished with: ", cast(string) destlog);
    }

    /**
    * Blocking ( if !pending() ) read, will return at least 1 ubyte or 0 on connection close
    *  supports replacement of internal read buffer when called until buf.length != returned buffer length
    */
	ubyte[] readBuf(ubyte[] buf)
    {
		assert(!m_slice);

		if (m_plaintext.length != 0) {
			size_t len = min(m_plaintext.length, buf.length);
			m_plaintext.read(buf[0 .. len]);
			return buf[0 .. len];
		}
		else {
	        // we can use our own buffer to optimize the scenarios where the application flushes it instantly
	        m_plaintext_override = buf;
	        scope(exit) {
	            m_slice = null;
	            m_plaintext_override = null;
	        }
		}
    
        // if there's nothing in the buffers, read some packets and process them
        while (!m_slice && m_plaintext.empty && !m_closed)
        {
            const ubyte[] from_socket = m_read_fn(m_readbuf.ptr[0 .. m_readbuf.length]);
            channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);
        }

		if (buf.length == 0) return null;

        // we *should* have something in the override if plaintext/offset is empty
        if (m_plaintext.length == 0 && m_slice) {
            buf = m_slice;
			//logDebug("Read m_slice: ", buf); 
            return buf;
        }

        assert(!m_slice, "Cannot have both a slice and extensible buffer contents");

        // unless the override was too small or data was already pending
        const size_t returned = std.algorithm.min(buf.length, m_plaintext.length);
		if (returned == 0) {
			//logDebug("Destroyed return object");
			channel.destroy();
			return null;
		}
		m_plaintext.read(buf[0 .. returned]);

        
		//logDebug("Returning data");
        return buf[0 .. returned];
    }

	void write(in ubyte[] buf) { channel.send(cast(const(ubyte)*)buf.ptr, buf.length); }

    inout(TLSChannel) underlyingChannel() inout { return channel; }

	void close() { m_closed = true; channel.close(); }

    bool isClosed() const { return m_closed; }

    const(Vector!X509Certificate) peerCertChain() const { return channel.peerCertChain(); }

    ~this() { channel.destroy(); }

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
		//logDebug("Plaintext: ", cast(ubyte[])data);
        if (m_plaintext.length == 0 && m_plaintext_override && m_slice.length + data.length < m_plaintext_override.length) {
            m_plaintext_override[m_slice.length .. m_slice.length + data.length] = data[0 .. $];
            m_slice = m_plaintext_override[0 .. m_slice.length + data.length];
			m_plaintext.destroy();
            return;
        }
        else if (m_slice) {
            // data too large, abandon the override optimization, copy all to the plaintext buffer
			m_plaintext.capacity = 8192;
			m_plaintext.put(m_slice);
            m_plaintext_override = null;
            m_slice = null;
        }
		if (m_plaintext.freeSpace < data.length) {
			//logDebug("Growing m_plaintext from: ", m_plaintext.capacity, " to ", 8192 + m_plaintext.length + m_plaintext.freeSpace);
			m_plaintext.capacity = 8192 + m_plaintext.length + m_plaintext.freeSpace;
		}
		m_plaintext.put(data);
    }

    void alertCb(in TLSAlert alert, in ubyte[] ub)
    {
		logDebug("Alert: ", alert.typeString(), " :", ub);  
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

    bool m_is_client;
	bool m_closed;
    DataReader m_read_fn;
    TLSImpl m_impl;
    OnAlert m_alert_cb;
    OnHandshakeComplete m_handshake_complete;

    // Buffer
    CircularBuffer!(ubyte, 0, SecureMem) m_plaintext;

    // Buffer optimization
    ubyte[] m_plaintext_override;
    ubyte[] m_slice;

	Vector!ubyte m_readbuf;
}

