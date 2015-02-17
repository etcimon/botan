/**
* TLS Blocking API
* 
* Copyright:
* (C) 2013 Jack Lloyd
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

alias SecureRingBuffer(T) = CircularBuffer!( T, 0, SecureMem);

/**
* Blocking TLS Client
*/
class TLSBlockingClient
{
public:
    this(size_t delegate(in ubyte[]) read_fn,
         void delegate(in ubyte[]) write_fn,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         in TLSServerInformation server_info = TLSServerInformation(),
         in TLSProtocolVersion offer_version = TLSProtocolVersion.latestTlsVersion(),
         string delegate(const ref Vector!string) next_protocol = null)
    {
        m_read_fn = read_fn;
        m_channel = new TLSClient(write_fn, &dataCb, &alertCb, &handshakeCb, session_manager, creds,
                                   policy, rng, server_info, offer_version, next_protocol);
    }

    /**
    * Completes full handshake then returns
    */
    final void doHandshake()
    {
        Vector!ubyte readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
        
        while (!m_channel.isClosed() && !m_channel.isActive())
        {
            ubyte[] readref = readbuf.ptr[0 .. readbuf.length];
            const size_t from_socket = m_read_fn(readref);
            m_channel.receivedData(readbuf.ptr, from_socket);
        }
    }

    /**
    * Number of bytes pending read in the plaintext buffer (bytes
    * readable without blocking)
    */
    final size_t pending() const { return m_plaintext.length; }

    /**
    * Blocking read, will return at least 1 ubyte or 0 on connection close
    */
    final size_t read(ubyte* buf, size_t buf_len)
    {
        Vector!ubyte readbuf = Vector!ubyte(TLS_DEFAULT_BUFFERSIZE);
        
        while (m_plaintext.empty && !m_channel.isClosed())
        {
            const size_t from_socket = m_read_fn(readbuf.ptr[0 .. readbuf.length]);
            m_channel.receivedData(readbuf.ptr, from_socket);
        }
        
        const size_t returned = std.algorithm.min(buf_len, m_plaintext.length);
        m_plaintext.read(buf[0 .. returned]);

        assert(returned == 0 && m_channel.isClosed(), "Only return zero if channel is closed");
        
        return returned;
    }

    final void write(const(ubyte)* buf, size_t len) { m_channel.send(buf, len); }

    final inout(TLSChannel) underlyingChannel() inout { return m_channel; }

    final void close() { m_channel.close(); }

    final bool isClosed() const { return m_channel.isClosed(); }

    final const(Vector!X509Certificate) peerCertChain() const
    { return m_channel.peerCertChain(); }

    ~this() {}

protected:
    /**
     * Can to get the handshake complete notification override
    */
    abstract bool handshakeComplete(const ref TLSSession) { return true; }

    /**
    * Can to get notification of alerts override
    */
    abstract void alertNotification(in TLSAlert) {}

private:

    final bool handshakeCb(const ref TLSSession session)
    {
        return this.handshakeComplete(session);
    }

    final void dataCb(in ubyte[] data)
    {
        m_plaintext.put(data);
    }

    final void alertCb(in TLSAlert alert, in ubyte[])
    {
        this.alertNotification(alert);
    }

    size_t delegate(in ubyte[]) m_read_fn;
    TLSClient m_channel;
    SecureRingBuffer!ubyte m_plaintext;
}