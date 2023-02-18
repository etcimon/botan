/**
* TLS Heartbeats
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.heartbeats;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import memutils.vector;
import botan.tls.extensions;
import botan.tls.reader;
import botan.tls.exceptn;
import botan.utils.types;

/**
* TLS Heartbeat message
*/
struct HeartbeatMessage
{
public:
    alias MessageType = ubyte;
    enum : MessageType { REQUEST = 1, RESPONSE = 2 }

    Vector!ubyte contents() const
    {
        Vector!ubyte send_buf = Vector!ubyte(3 + m_payload.length + 16);
        send_buf[0] = m_type;
        send_buf[1] = get_byte(0, cast(ushort) m_payload.length);
        send_buf[2] = get_byte(1, cast(ushort) m_payload.length);
        copyMem(&send_buf[3], m_payload.ptr, m_payload.length);
        // leave padding as all zeros
        
        return send_buf;
    }

    ref const(Vector!ubyte) payload() const return { return m_payload; }

    bool isRequest() const { return m_type == REQUEST; }

    this()(auto const ref Vector!ubyte buf)
    {
        TLSDataReader reader = TLSDataReader("Heartbeat", buf);
        
        const ubyte type = reader.get_byte();
        
        if (type != 1 && type != 2)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER,
                                    "Unknown heartbeat message type");
        
        m_type = cast(MessageType)(type);
        
        m_payload = reader.getRange!ubyte(2, 0, 16*1024);
        
        // padding follows and is ignored
    }

    this(MessageType type,
         const(ubyte)* payload,
         size_t payload_len) 
    {
        m_type = type;
        m_payload = Vector!ubyte(payload[0 .. payload_len]);
    }
private:
    MessageType m_type;
    Vector!ubyte m_payload;
}