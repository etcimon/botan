/**
* TLS 1.3 record protocol (RFC 8446 5)
*
* Copyright:
* (C) 2022 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.tls13.record_layer;

import botan.constants;
static if (BOTAN_HAS_TLS && BOTAN_HAS_TLS_13):

import botan.tls.magic;
import botan.tls.exceptn;
import botan.tls.alert;
import botan.tls.tls13.cipher_state;
import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.get_byte;

/// One decrypted TLS 1.3 record (inner type, fragment, sequence).
struct TLS13Record
{
    RecordType type;
    SecureVector!ubyte fragment;
    ulong seq_no;
    bool has_seq;
}

/// Result of `nextRecord`: either a record or a bytes-needed hint.
struct TLS13ReadResult
{
    bool has_record;
    size_t bytes_needed;
    TLS13Record record;
}

private RecordType readRecordType(ubyte type_byte)
{
    if (type_byte != APPLICATION_DATA && type_byte != HANDSHAKE &&
        type_byte != ALERT && type_byte != CHANGE_CIPHER_SPEC)
        throw new TLSException(TLSAlert.UNEXPECTED_MESSAGE, "TLS record type had unexpected value");
    return type_byte;
}

private bool verifyCcs(const(ubyte)* data, size_t size)
{
    return size == 1 && data[0] == 0x01;
}

/**
* TLS 1.3 record layer. Unprotected parse/serialize plus AEAD wrap when a
* cipher state is provided. TLSChannel installs handshake then application
* traffic keys after ServerHello / server Finished.
*/
final class TLS13RecordLayer
{
public:
    /**
    * Params:
    *  side = CLIENT or SERVER (clients send the TLS 1.2 version in the record header until after ServerHello)
    */
    this(ConnectionSide side)
    {
        m_side = side;
        m_out_limit = MAX_PLAINTEXT_SIZE + 1;
        m_in_limit = MAX_PLAINTEXT_SIZE + 1;
        m_sending_compat = (side == CLIENT);
        m_receiving_compat = true;
    }

    /// Record headers use 0x0303 after the handshake is no longer in compatibility mode.
    void disableSendingCompatMode() { m_sending_compat = false; }
    /// ditto for inbound parse.
    void disableReceivingCompatMode() { m_receiving_compat = false; }

    /**
    * RFC 8449 record_size_limit
    * Params:
    *  outgoing_limit = max inner plaintext we will send
    *  incoming_limit = max inner plaintext we will accept
    */
    void setRecordSizeLimits(ushort outgoing_limit, ushort incoming_limit)
    {
        m_out_limit = outgoing_limit;
        m_in_limit = incoming_limit;
    }

    /**
    * Append ciphertext from the socket
    * Params:
    *  data = bytes
    *  len = length of data
    */
    void copyData(const(ubyte)* data, size_t len)
    {
        if (m_read_off > 0)
        {
            auto keep = Vector!ubyte(m_read_buf.ptr[m_read_off .. m_read_buf.length]);
            m_read_buf = keep.move();
            m_read_off = 0;
        }
        if (len)
            m_read_buf ~= data[0 .. len];
    }

    void copyData(in ubyte[] data)
    {
        copyData(data.ptr, data.length);
    }

    void copyData()(const auto ref Vector!ubyte data)
    {
        copyData(data.ptr, data.length);
    }

    void clearReadBuffer()
    {
        m_read_buf.clear();
        m_read_off = 0;
    }

    TLS13ReadResult nextRecord(TLS13CipherState cs = null)
    {
        TLS13ReadResult r;
        if (m_read_buf.empty)
            return r;

        const size_t remaining = m_read_buf.length - m_read_off;
        if (remaining < TLS_HEADER_SIZE)
        {
            r.bytes_needed = TLS_HEADER_SIZE - remaining;
            return r;
        }

        const(ubyte)* hdr = m_read_buf.ptr + m_read_off;
        const RecordType typ = readRecordType(hdr[0]);
        const ushort ver = cast(ushort)((hdr[1] << 8) | hdr[2]);
        const ushort frag_len = cast(ushort)((hdr[3] << 8) | hdr[4]);

        if (hdr[1] != 0x03)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Received unexpected record version");
        if (!m_receiving_compat && ver != 0x0303)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER, "Received unexpected record version");
        if (frag_len == 0 && typ != APPLICATION_DATA)
            throw new TLSException(TLSAlert.DECODE_ERROR, "empty record received");
        if (typ == APPLICATION_DATA)
        {
            if (frag_len > MAX_CIPHERTEXT_SIZE_TLS13)
                throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Received an encrypted record that exceeds maximum size");
        }
        else if (frag_len > MAX_PLAINTEXT_SIZE)
            throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Received a record that exceeds maximum size");

        if (cs !is null && typ != APPLICATION_DATA && typ != CHANGE_CIPHER_SPEC &&
            !(typ == ALERT && cs.mustExpectUnprotectedAlert()))
            throw new TLSException(TLSAlert.UNEXPECTED_MESSAGE, "unprotected record received where protected traffic was expected");

        if (remaining < TLS_HEADER_SIZE + frag_len)
        {
            r.bytes_needed = TLS_HEADER_SIZE + frag_len - remaining;
            return r;
        }

        const(ubyte)* frag = hdr + TLS_HEADER_SIZE;
        if (typ == CHANGE_CIPHER_SPEC && !verifyCcs(frag, frag_len))
            throw new TLSException(TLSAlert.UNEXPECTED_MESSAGE, "malformed change cipher spec record received");

        TLS13Record rec;
        rec.type = typ;
        rec.fragment = SecureVector!ubyte(frag[0 .. frag_len]);
        m_read_off += TLS_HEADER_SIZE + frag_len;
        if (m_read_off == m_read_buf.length)
            clearReadBuffer();

        if (typ == APPLICATION_DATA)
        {
            if (cs is null)
                throw new TLSException(TLSAlert.UNEXPECTED_MESSAGE, "premature Application Data received");
            if (rec.fragment.length < cs.minimumDecryptionInputLength())
                throw new TLSException(TLSAlert.BAD_RECORD_MAC, "incomplete record mac received");
            if (cs.decryptOutputLength(rec.fragment.length) > m_in_limit)
                throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Received an encrypted record that exceeds maximum plaintext size");
            rec.seq_no = cs.decryptRecordFragment(hdr, TLS_HEADER_SIZE, rec.fragment);
            rec.has_seq = true;

            // TLSInnerPlaintext: content || type || zero padding
            size_t end = rec.fragment.length;
            while (end > 0 && rec.fragment[end - 1] == 0)
                --end;
            if (end == 0)
                throw new TLSException(TLSAlert.UNEXPECTED_MESSAGE, "No content type in TLSInnerPlaintext");
            rec.type = readRecordType(rec.fragment[end - 1]);
            auto trimmed = SecureVector!ubyte(rec.fragment.ptr[0 .. end - 1]);
            rec.fragment = trimmed.move();
        }

        r.has_record = true;
        r.record.type = rec.type;
        r.record.seq_no = rec.seq_no;
        r.record.has_seq = rec.has_seq;
        r.record.fragment = rec.fragment.move();
        return r;
    }

    /**
    * Serialize one or more TLS 1.3 records. The returned slice is valid
    * until the next prepareRecords.
    * Params:
    *  type = inner content type
    *  data = plaintext
    *  data_len = length of data
    *  cs = AEAD state, or null for an unprotected record (CCS only)
    * Returns: wire bytes (header || ciphertext)
    */
    ubyte[] prepareRecords(RecordType type, const(ubyte)* data, size_t data_len, TLS13CipherState cs = null)
    {
        const bool protect = cs !is null && type != CHANGE_CIPHER_SPEC;
        if (!protect && type == APPLICATION_DATA)
            throw new InvalidArgument("Application Data records MUST NOT be written unprotected");
        if (data_len == 0 && type != APPLICATION_DATA)
            throw new InvalidArgument("zero-length fragments of types other than application data are not allowed");
        if (type == CHANGE_CIPHER_SPEC && !verifyCcs(data, data_len))
            throw new InvalidArgument("TLS 1.3 deprecated CHANGE_CIPHER_SPEC");

        const size_t max_pt = protect ? (m_out_limit - 1) : MAX_PLAINTEXT_SIZE;
        const size_t nrec = (data_len == 0) ? 1 : ((data_len + max_pt - 1) / max_pt);
        m_out_ws.length = 0;
        m_out_ws.reserve(nrec * (TLS_HEADER_SIZE + max_pt + 32));
        size_t off = 0;
        size_t left = data_len;
        const bool at_least_one = protect && data_len == 0;
        do
        {
            const size_t pt_size = (left == 0 && at_least_one) ? 0 : (left < max_pt ? left : max_pt);
            const size_t ct_size = protect ? cs.encryptOutputLength(pt_size + 1) : pt_size;
            const ubyte wire_type = protect ? APPLICATION_DATA : type;
            const ushort rec_ver = m_sending_compat ? 0x0301 : 0x0303;

            const size_t rec_start = m_out_ws.length;
            const size_t rec_len = TLS_HEADER_SIZE + ct_size;
            m_out_ws.expandUninitialized(rec_start + rec_len);
            auto rec = m_out_ws.ptr + rec_start;
            rec[0] = wire_type;
            rec[1] = cast(ubyte)(rec_ver >> 8);
            rec[2] = cast(ubyte) rec_ver;
            rec[3] = cast(ubyte)(ct_size >> 8);
            rec[4] = cast(ubyte) ct_size;

            if (protect)
            {
                if (pt_size)
                    copyMem(rec + TLS_HEADER_SIZE, data + off, pt_size);
                rec[TLS_HEADER_SIZE + pt_size] = type;
                cs.encryptRecordFragment(rec, TLS_HEADER_SIZE, rec + TLS_HEADER_SIZE, pt_size + 1);
            }
            else if (pt_size)
                copyMem(rec + TLS_HEADER_SIZE, data + off, pt_size);

            off += pt_size;
            left -= pt_size;
        } while (left > 0);

        return m_out_ws[];
    }

    ubyte[] prepareRecords()(RecordType type, const auto ref Vector!ubyte data, TLS13CipherState cs = null)
    {
        return prepareRecords(type, data.ptr, data.length, cs);
    }

private:
    ConnectionSide m_side;
    Vector!ubyte m_read_buf;
    Vector!ubyte m_out_ws;
    size_t m_read_off;
    ushort m_out_limit;
    ushort m_in_limit;
    bool m_sending_compat;
    bool m_receiving_compat;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.global_state;

static if (BOTAN_HAS_TESTS && !SKIP_TLS_TEST) unittest
{
    auto state = globalState();
    logDebug("Testing tls13/record_layer.d ...");
    size_t fails = 0;

    const auto ccs = hexDecode("140303000101");
    const auto hello = hexDecode(
        "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dff" ~
        "a21a8d9912ec18a2ef6283024dece700000613011303130201000091" ~
        "0000000b0009000006736572766572ff01000100000a00140012001d" ~
        "0017001800190100010101020103010400230000003300260024001d" ~
        "002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413" ~
        "691e529aaf2c002b0003020304000d0020001e040305030603020308" ~
        "040805080604010501060102010402050206020202002d0002010100" ~
        "1c00024001");

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(SERVER);
        rl.copyData(ccs);
        auto got = rl.nextRecord();
        if (!got.has_record || got.record.type != CHANGE_CIPHER_SPEC)
            ++fails;
        else if (got.record.fragment.length != 1 || got.record.fragment[0] != 0x01)
            ++fails;
        auto more = rl.nextRecord();
        if (more.has_record || more.bytes_needed != 0)
            ++fails;
    }

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(SERVER);
        rl.copyData(hello);
        auto got = rl.nextRecord();
        if (!got.has_record || got.record.type != HANDSHAKE)
            ++fails;
        else if (got.record.fragment.length != hello.length - TLS_HEADER_SIZE)
            ++fails;
        else if (got.record.fragment[] != hello.ptr[TLS_HEADER_SIZE .. hello.length])
            ++fails;
    }

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(CLIENT);
        rl.disableSendingCompatMode();
        ubyte[1] ccsb = [0x01];
        auto wire = rl.prepareRecords(CHANGE_CIPHER_SPEC, ccsb.ptr, 1, null);
        if (wire.length != 6 || wire[0] != CHANGE_CIPHER_SPEC || wire[5] != 0x01)
            ++fails;
    }

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(CLIENT);
        rl.disableSendingCompatMode();
        auto payload = hexDecode("01");
        auto rec = rl.prepareRecords(CHANGE_CIPHER_SPEC, payload);
        if (rec[] != ccs[])
            ++fails;
    }

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(SERVER);
        ubyte[3] partial = [0x23, 0x03, 0x03];
        rl.copyData(partial.ptr, 3);
        auto got = rl.nextRecord();
        if (got.has_record || got.bytes_needed != 2)
            ++fails;
    }

    {
        Unique!TLS13RecordLayer rl = new TLS13RecordLayer(CLIENT);
        rl.disableSendingCompatMode();
        auto hs = hexDecode("010000");
        auto rec = rl.prepareRecords(HANDSHAKE, hs);
        if (rec.length < TLS_HEADER_SIZE || rec[0] != HANDSHAKE || rec[1] != 0x03 || rec[2] != 0x03)
            ++fails;
        Unique!TLS13RecordLayer peer = new TLS13RecordLayer(SERVER);
        peer.disableReceivingCompatMode();
        peer.copyData(rec);
        auto got = peer.nextRecord();
        if (!got.has_record || got.record.type != HANDSHAKE || got.record.fragment[] != hs[])
            ++fails;
    }

    static if (BOTAN_HAS_AEAD_GCM) {
        ubyte[16] key = 1;
        ubyte[12] iv = 2;
        // Warm AEAD factory so the leak snapshot does not count first-use cache.
        {
            Unique!TLS13CipherState warm = new TLS13CipherState("AES-128/GCM", key.ptr, 16, iv.ptr, 12, key.ptr, 16, iv.ptr, 12);
        }
        auto rec_snap = takeMemutilsSnap();
        {
            Unique!TLS13CipherState c_cs = new TLS13CipherState("AES-128/GCM", key.ptr, 16, iv.ptr, 12, key.ptr, 16, iv.ptr, 12);
            Unique!TLS13CipherState s_cs = new TLS13CipherState("AES-128/GCM", key.ptr, 16, iv.ptr, 12, key.ptr, 16, iv.ptr, 12);
            Unique!TLS13RecordLayer cl = new TLS13RecordLayer(CLIENT);
            cl.disableSendingCompatMode();
            auto inner = hexDecode("080000020000");
            auto wire = cl.prepareRecords(HANDSHAKE, inner, *c_cs);
            if (wire[0] != APPLICATION_DATA)
                ++fails;
            Unique!TLS13RecordLayer sv = new TLS13RecordLayer(SERVER);
            sv.disableReceivingCompatMode();
            sv.copyData(wire);
            auto got = sv.nextRecord(*s_cs);
            if (!got.has_record || got.record.type != HANDSHAKE || got.record.fragment[] != inner[])
                ++fails;
        }
        if (memutilsGrowth(rec_snap, "tls13 record aead wrap"))
            ++fails;

        {
            ubyte[32] ws = 9;
            ubyte[32] rs = 10;
            Unique!TLS13CipherState cs = TLS13CipherState.fromTrafficSecrets(
                "AES-128/GCM", "SHA-256", ws.ptr, ws.length, rs.ptr, rs.length);
            Unique!TLS13RecordLayer rl = new TLS13RecordLayer(SERVER);
            rl.disableReceivingCompatMode();
            ubyte[7] alert_wire = [ALERT, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
            rl.copyData(alert_wire.ptr, alert_wire.length);
            bool threw;
            try
            {
                rl.nextRecord(*cs);
            }
            catch (TLSException)
            {
                threw = true;
            }
            if (!threw)
                ++fails;
            Unique!TLS13RecordLayer rl2 = new TLS13RecordLayer(SERVER);
            rl2.disableReceivingCompatMode();
            cs.setAllowUnprotectedAlert(true);
            rl2.copyData(alert_wire.ptr, alert_wire.length);
            auto got_al = rl2.nextRecord(*cs);
            if (!got_al.has_record || got_al.record.type != ALERT || got_al.record.fragment.length != 2)
                ++fails;
        }
    }

    if (fails)
        logError("tls13 record_layer failures: ", fails);
    testReport("tls13_record", 6, fails);
    assert(fails == 0);
}
