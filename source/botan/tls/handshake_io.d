/**
* TLS Handshake Serialization
* 
* Copyright:
* (C) 2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.handshake_io;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.tls.magic;
import botan.tls.version_;
import botan.utils.loadstor;
import botan.tls.messages;
import botan.tls.record;
import botan.tls.seq_numbers;
import botan.utils.exceptn;
import std.algorithm : count;
import botan.utils.types;
import memutils.hashmap;
import std.typecons : Tuple;

struct NextRecord
{
    HandshakeType type;
    Vector!ubyte data;
}

/**
* Handshake IO Interface
*/
interface HandshakeIO
{
public:
    abstract TLSProtocolVersion initialRecordVersion() const;

    abstract Vector!ubyte send(in HandshakeMessage msg);

    abstract const(Vector!ubyte) format(const ref Vector!ubyte handshake_msg,
                                        HandshakeType handshake_type) const;

    abstract void addRecord(const ref Vector!ubyte record,
                            RecordType type,
                            ulong sequence_number);

    /**
    * Returns (HANDSHAKE_NONE, Vector!(  )()) if no message currently available
    */
    abstract NextRecord getNextRecord(bool expecting_ccs);
}

/**
* Handshake IO for stream-based handshakes
*/
package final class StreamHandshakeIO : HandshakeIO
{
public:
    this(void delegate(ubyte, const ref Vector!ubyte) writer) 
    {
        m_send_hs = writer;
    }

    override TLSProtocolVersion initialRecordVersion() const
    {
        return cast(TLSProtocolVersion)TLSProtocolVersion.TLS_V10;
    }

    override Vector!ubyte send(in HandshakeMessage msg)
    {
        const Vector!ubyte msg_bits = msg.serialize();
        
        if (msg.type() == HANDSHAKE_CCS)
        {
            m_send_hs(CHANGE_CIPHER_SPEC, msg_bits);
            return Vector!ubyte(); // not included in handshake hashes
        }
        
        Vector!ubyte buf = format(msg_bits, msg.type()).dup;
        m_send_hs(HANDSHAKE, buf);
        return buf.move();
    }

    override const(Vector!ubyte) format(const ref Vector!ubyte msg, HandshakeType type) const
    {
        Vector!ubyte send_buf = Vector!ubyte(4 + msg.length);
        
        const size_t buf_size = msg.length;
        
        send_buf[0] = type;
        
        storeBigEndian24(send_buf.ptr[1 .. 4], buf_size);
        
        copyMem(send_buf.ptr+4, msg.ptr, msg.length);
        
        return send_buf;
    }

    override void addRecord(const ref Vector!ubyte record, RecordType record_type, ulong)
    {
        if (record_type == HANDSHAKE)
        {
            m_queue ~= record[];
        }
        else if (record_type == CHANGE_CIPHER_SPEC)
        {
            if (record.length != 1 || record[0] != 1)
                throw new DecodingError("Invalid ChangeCipherSpec");
            
            // Pretend it's a regular handshake message of zero length
            const(ubyte)[] ccs_hs = [ HANDSHAKE_CCS, 0, 0, 0 ];
            m_queue.insert(ccs_hs);
        }
        else
            throw new DecodingError("Unknown message type in handshake processing");
    }

    override NextRecord getNextRecord(bool)
    {
        if (m_queue.length >= 4)
        {
            const size_t length = make_uint(0, m_queue[1], m_queue[2], m_queue[3]);
            if (m_queue.length >= length + 4)
            {
                HandshakeType type = cast(HandshakeType)(m_queue[0]);
                
                Vector!ubyte contents = Vector!ubyte(m_queue.ptr[4 .. 4 + length]);

                Vector!ubyte ret = Vector!ubyte(m_queue.ptr[4 + length .. m_queue.length]);
                m_queue = ret;
                
                return NextRecord(type, contents.move());
            }
        }

        return NextRecord(HANDSHAKE_NONE, Vector!ubyte());
    }

private:
    Vector!ubyte m_queue;
    void delegate(ubyte, const ref Vector!ubyte) m_send_hs;
}

/**
* Handshake IO for datagram-based handshakes
*/
package final class DatagramHandshakeIO : HandshakeIO
{
public:
    this(ConnectionSequenceNumbers seq, void delegate(ushort, ubyte, const ref Vector!ubyte) writer) 
    {
        m_seqs = seq;
        m_flights.length = 1;
        m_send_hs = writer; 
    }

    override TLSProtocolVersion initialRecordVersion() const
    {
        return TLSProtocolVersion(TLSProtocolVersion.DTLS_V10);
    }

    override Vector!ubyte send(in HandshakeMessage msg)
    {
        Vector!ubyte msg_bits = msg.serialize();
        ushort epoch = m_seqs.currentWriteEpoch();
        HandshakeType msg_type = msg.type();
        
        FlightData msg_info = FlightData(epoch, msg_type, msg_bits.dupr());
        
        if (msg_type == HANDSHAKE_CCS)
        {
            m_send_hs(epoch, CHANGE_CIPHER_SPEC, msg_bits);
            return Vector!ubyte(); // not included in handshake hashes
        }
        
        const Vector!ubyte no_fragment = formatWSeq(msg_bits, msg_type, m_out_message_seq);
        
        if (no_fragment.length + DTLS_HEADER_SIZE <= m_mtu)
            m_send_hs(epoch, HANDSHAKE, no_fragment);
        else
        {
            const size_t parts = splitForMtu(m_mtu, msg_bits.length);
            
            const size_t parts_size = (msg_bits.length + parts) / parts;
            
            size_t frag_offset = 0;
            
            while (frag_offset != msg_bits.length)
            {
                const size_t frag_len =    std.algorithm.min(msg_bits.length - frag_offset, parts_size);
                auto frag = formatFragment(cast(const(ubyte)*)&msg_bits[frag_offset],
                                           frag_len,
                                           cast(ushort)frag_offset,
                                           cast(ushort)msg_bits.length,
                                           msg_type,
                                           m_out_message_seq);

                m_send_hs(epoch, HANDSHAKE, frag);
                
                frag_offset += frag_len;
            }
        }
        
        // Note: not saving CCS, instead we know it was there due to change in epoch
        m_flights[$-1].pushBack(m_out_message_seq);
        m_flight_data[m_out_message_seq] = msg_info;
        
        m_out_message_seq += 1;
        
        return no_fragment.dup;
    }

    override const(Vector!ubyte) format(const ref Vector!ubyte msg, HandshakeType type) const
    {
        return formatWSeq(msg, type, cast(ushort) (m_in_message_seq - 1));
    }

    override void addRecord(const ref Vector!ubyte record,
                             RecordType record_type,
                             ulong record_sequence)
    {
        const ushort epoch = cast(ushort)(record_sequence >> 48);
        
        if (record_type == CHANGE_CIPHER_SPEC)
        {
            if (!m_ccs_epochs.canFind(epoch))
                m_ccs_epochs ~= epoch;
            return;
        }
        
        __gshared immutable size_t DTLS_HANDSHAKE_HEADER_LEN = 12;
        
        const(ubyte)* record_bits = record.ptr;
        size_t record_size = record.length;
        
        while (record_size)
        {
            if (record_size < DTLS_HANDSHAKE_HEADER_LEN)
                return; // completely bogus? at least degenerate/weird
            
            const ubyte msg_type = record_bits[0];
            const size_t msg_len = loadBigEndian24((&record_bits[1])[0 .. 3]);
            const ushort message_seq = loadBigEndian!ushort(&record_bits[4], 0);
            const size_t fragment_offset = loadBigEndian24((&record_bits[6])[0 .. 3]);
            const size_t fragment_length = loadBigEndian24((&record_bits[9])[0 .. 3]);
            
            const size_t total_size = DTLS_HANDSHAKE_HEADER_LEN + fragment_length;
            
            if (record_size < total_size)
                throw new DecodingError("Bad lengths in DTLS header");
            
            if (message_seq >= m_in_message_seq)
            {
                m_messages[message_seq] = HandshakeReassembly.init;
                m_messages[message_seq].addFragment(&record_bits[DTLS_HANDSHAKE_HEADER_LEN],
                                                    fragment_length,
                                                    fragment_offset,
                                                    epoch,
                                                    msg_type,
                                                    msg_len);
            }
            
            record_bits += total_size;
            record_size -= total_size;
        }
    }

    override NextRecord getNextRecord(bool expecting_ccs)
    {
        if (!m_flights[$-1].empty)
            m_flights.pushBack(Vector!ushort());
        
        if (expecting_ccs)
        {
            if (m_messages.length > 0)
            {
                const ushort current_epoch = m_messages[cast(ushort)0].epoch();

                if (m_ccs_epochs.canFind(current_epoch))
                    return NextRecord(HANDSHAKE_CCS, Vector!ubyte());
            }
            
            return NextRecord(HANDSHAKE_NONE, Vector!ubyte());
        }
        
        auto rec = m_messages.get(m_in_message_seq, HandshakeReassembly.init);
        
        if (rec is HandshakeReassembly.init || !rec.complete())
            return NextRecord(HANDSHAKE_NONE, Vector!ubyte());
        
        m_in_message_seq += 1;
        
        return rec.message();
    }

private:

    Vector!ubyte formatFragment(const(ubyte)* fragment,
                                 size_t frag_len,
                                 ushort frag_offset,
                                 ushort msg_len,
                                 HandshakeType type,
                                 ushort msg_sequence) const
    {
        Vector!ubyte send_buf = Vector!ubyte(12 + frag_len);
        
        send_buf[0] = type;
        
        storeBigEndian24((&send_buf[1])[0 .. 3], msg_len);
        
        storeBigEndian(msg_sequence, &send_buf[4]);
        
        storeBigEndian24((&send_buf[6])[0 .. 3], frag_offset);
        storeBigEndian24((&send_buf[9])[0 .. 3], frag_len);
        
        copyMem(&send_buf[12], fragment, frag_len);
        
        return send_buf;
    }

    Vector!ubyte formatWSeq(const ref Vector!ubyte msg,
                     HandshakeType type,
                     ushort msg_sequence) const
    {
        return formatFragment(msg.ptr, msg.length, cast(ushort)  0, cast(ushort) msg.length, type, msg_sequence);
    }

    struct HandshakeReassembly
    {
    public:
        void addFragment(const(ubyte)* fragment,
                            size_t fragment_length,
                            size_t fragment_offset,
                            ushort epoch,
                            ubyte msg_type,
                            size_t msg_length)
        {
            if (complete())
                return; // already have entire message, ignore this
            
            if (m_msg_type == HANDSHAKE_NONE)
            {
                m_epoch = epoch;
                m_msg_type = msg_type;
                m_msg_length = msg_length;
            }
            
            if (msg_type != m_msg_type || msg_length != m_msg_length || epoch != m_epoch)
                throw new DecodingError("Inconsistent values in DTLS handshake header");
            
            if (fragment_offset > m_msg_length)
                throw new DecodingError("Fragment offset past end of message");
            
            if (fragment_offset + fragment_length > m_msg_length)
                throw new DecodingError("Fragment overlaps past end of message");
            
            if (fragment_offset == 0 && fragment_length == m_msg_length)
            {
                m_fragments.clear();
                m_message[] = fragment[0 .. fragment_length];
            }
            else
            {
                /*
                * FIXME. This is a pretty lame way to do defragmentation, huge
                * overhead with a tree node per ubyte.
                *
                * Also should confirm that all overlaps have no changes,
                * otherwise we expose ourselves to the classic fingerprinting
                * and IDS evasion attacks on IP fragmentation.
                */
                foreach (size_t i; 0 .. fragment_length)
                    m_fragments[fragment_offset+i] = cast(ubyte)fragment[i];
                
                if (m_fragments.length == m_msg_length)
                {
                    m_message.resize(m_msg_length);
                    foreach (size_t i; 0 .. m_msg_length)
                        m_message[i] = m_fragments[i];
                    m_fragments.clear();
                }
            }
        }

        bool complete() const
        {
            return (m_msg_type != HANDSHAKE_NONE && m_message.length == m_msg_length);
        }

        ushort epoch() const { return m_epoch; }

        NextRecord message() const
        {
            if (!complete())
                throw new InternalError("DatagramHandshakeIO - message not complete");
            
            return NextRecord(cast(HandshakeType)(m_msg_type), m_message.dup);
        }

        private:
            ubyte m_msg_type = HANDSHAKE_NONE;
            size_t m_msg_length = 0;
            ushort m_epoch = 0;

            HashMapRef!(size_t, ubyte) m_fragments;
            Array!ubyte m_message;
    }

    ConnectionSequenceNumbers m_seqs;
    HashMap!(ushort, HandshakeReassembly) m_messages;
    ushort[] m_ccs_epochs;
    Vector!( Array!ushort ) m_flights;
    HashMap!(ushort, FlightData ) m_flight_data;

    // default MTU is IPv6 min MTU minus UDP/IP headers
    ushort m_mtu = 1280 - 40 - 8;
    ushort m_in_message_seq = 0;
    ushort m_out_message_seq = 0;
    void delegate(ushort, ubyte, const ref Vector!ubyte) m_send_hs;

    static struct FlightData {
        ushort epoch;
        ubyte msg_type;
        Array!ubyte msg_bits;
    }
}


private:

size_t loadBigEndian24(in ubyte[3] q)
{
    return make_uint(0, q[0], q[1], q[2]);
}

void storeBigEndian24(ubyte[3] output, size_t val)
{
    output[0] = get_byte!uint(1, cast(uint) val);
    output[1] = get_byte!uint(2, cast(uint) val);
    output[2] = get_byte!uint(3, cast(uint) val);
}

size_t splitForMtu(size_t mtu, size_t msg_size)
{
    __gshared immutable size_t DTLS_HEADERS_SIZE = 25; // DTLS record+handshake headers
    
    const size_t parts = (msg_size + mtu) / mtu;
    
    if (parts + DTLS_HEADERS_SIZE > mtu)
        return parts + 1;
    
    return parts;
}
