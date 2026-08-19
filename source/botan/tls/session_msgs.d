/**
* TLS handshake messages that HandshakeState stores uniquely.
*
* Kept out of messages.d so handshake_state can import them without
* the messages ↔ handshake_state cycle that broke `-c standard`.
*/
module botan.tls.session_msgs;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.handshake_io;
import botan.tls.handshake_hash;
import botan.tls.credentials_manager;
import botan.tls.extensions;
import botan.tls.magic;
import botan.tls.reader;
import botan.utils.get_byte;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.exceptn;
import memutils.unique;
import std.datetime : Duration;

/**
 * Encrypted ChannelID handshake message
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
