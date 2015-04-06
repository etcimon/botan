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
alias DataReader = ubyte[] delegate(in ubyte[]);
alias SecureRingBuffer(T) = CircularBuffer!( T, 0, SecureMem);

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
        m_impl.client = new TLSClient(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
            policy, rng, server_info, offer_version, next_protocols.move);
    }

    /// Server constructor
    this(DataReader read_fn,
         DataWriter write_fn,
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
        m_impl.server = new TLSServer(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
			policy, rng, next_proto, sni_handler, is_datagram, io_buf_sz);
    }

    /**
    * Blocks until the full handhsake is complete
    */
    void doHandshake()
    {
        Vector!ubyte readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
        
        while (!channel.isClosed() && !channel.isActive())
        {
            ubyte[] readref = readbuf.ptr[0 .. readbuf.length];
            const ubyte[] from_socket = m_read_fn(readref);
            channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);
        }
    }

    /**
    * Number of bytes pending read in the plaintext buffer (bytes
    * readable without blocking)
    */
    size_t pending() const { return m_plaintext.length; }

    /// Reads until the destination ubyte array is full, utilizing internal buffers if necessary
    void read(ubyte[] dest) 
    {
        ubyte[] remaining = dest;
        while (remaining.length > 0) {
            dest = readBuf(remaining);
            remaining = remaining[dest.length .. $];
        }
    }

    /**
    * Blocking ( if !pending() ) read, will return at least 1 ubyte or 0 on connection close
    *  supports replacement of internal read buffer when called until buf.length != returned buffer length
    */
	ubyte[] readBuf(ubyte[] buf)
    {

        // we can use our own buffer to optimize the scenarios where the application flushes it instantly
        if (m_plaintext_offset == 0) {
            assert(!m_slice);
            m_plaintext_override = buf;
            scope(exit) {
                m_slice = null;
                m_plaintext_override = null;
            }
        }

        Vector!ubyte readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
        // if there's nothing in the buffers, read some packets and process them
        while (!m_slice && m_plaintext.empty && m_plaintext_offset == 0 && !channel.isClosed())
        {
            const ubyte[] from_socket = m_read_fn(readbuf.ptr[0 .. readbuf.length]);
            channel.receivedData(cast(const(ubyte)*)from_socket.ptr, from_socket.length);
        }

        // we *should* have something in the override if plaintext/offset is empty
        if (m_plaintext.length == 0 && m_plaintext_offset == 0 && m_slice) {
            buf = m_slice;
            return buf;
        }

        assert(!m_slice, "Cannot have both a slice and extensible buffer contents");

        // unless the override was too small or data was already pending
        const size_t returned = std.algorithm.min(buf.length, m_plaintext.length - m_plaintext_offset);
        buf[0 .. returned] = m_plaintext[m_plaintext_offset .. m_plaintext_offset + returned];

        // if this function is used correctly, we'll read all the plaintext, until we can clear it

        // if we've read all the plaintext, clear the buffers
        if (m_plaintext_offset + returned == m_plaintext.length) {
            m_plaintext.clear();
            m_plaintext_offset = 0;
        }
        else {
            // otherwise we'll have to increment the offset for the next read call
            m_plaintext_offset += returned;
        }

        assert(!channel.isClosed() || ( returned == 0 && channel.isClosed() ), "Only return zero if channel is closed");

        return buf[0 .. returned];
    }

    void write(in ubyte[] buf) { channel.send(cast(const(ubyte)*)buf.ptr, buf.length); }

    inout(TLSChannel) underlyingChannel() inout { return channel; }

    void close() { channel.close(); }

    bool isClosed() const { return channel.isClosed(); }

    const(Vector!X509Certificate) peerCertChain() const { return channel.peerCertChain(); }

    ~this() { if (m_is_client) m_impl.client.destroy(); else m_impl.server.destroy(); }

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

    bool handshakeCb(const ref TLSSession session)
    {
        return m_handshake_complete(session);
    }

    void dataCb(in ubyte[] data)
    {
        assert(m_plaintext_offset == 0, "You must read the entire plaintext");

        if (!m_slice && m_plaintext_override && m_slice.length + data.length < m_plaintext_override.length) {
            m_plaintext_override[m_slice.length .. m_slice.length + data.length] = data[0 .. $];
            m_slice = m_plaintext_override[0 .. m_slice.length + data.length];
            return;
        }
        else if (m_slice) {
            // data too large, abandon the override optimization, copy all to the plaintext buffer
            m_plaintext[] = m_slice;
            m_plaintext_override = null;
            m_slice = null;
        }
        m_plaintext ~= cast(ubyte[])data;

        // account for case when the vector needs to be circular
        if (m_plaintext.length > 65536 && m_plaintext_offset > m_plaintext.length/10) {
            SecureVector!ubyte tmp;
            tmp[] = m_plaintext[m_plaintext_offset .. $];
            m_plaintext = tmp;
        }
        // also deal with connections using up too much memory
        // todo: Make this a parameter
        else if (m_plaintext.length > 1024*256) throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Buffering limit exceeded");
    }

    void alertCb(in TLSAlert alert, in ubyte[] ub)
    {
        m_alert_cb(alert, ub);
    }

    class TLSImpl {
        TLSClient client;
        TLSServer server;
    }
	@property inout(TLSChannel) channel() inout { return (m_is_client ? cast(inout(TLSChannel)) m_impl.client : cast(inout(TLSChannel)) m_impl.server); }

    bool m_is_client;
    DataReader m_read_fn;
    TLSImpl m_impl;
    OnAlert m_alert_cb;
    OnHandshakeComplete m_handshake_complete;

    // Buffer
    SecureVector!ubyte m_plaintext;
    size_t m_plaintext_offset;

    // Buffer optimization
    ubyte[] m_plaintext_override;
    ubyte[] m_slice;
}

