/**
* TLS Record Handling
* 
* Copyright:
* (C) 2004-2012 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.tls.record;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.libstate.libstate;
import botan.tls.magic;
import botan.tls.version_;
import botan.tls.seq_numbers;
import botan.tls.session_key;
import botan.tls.ciphersuite;
import botan.tls.exceptn;
import botan.modes.aead.aead;
import botan.mac.mac;
import botan.algo_factory.algo_factory;
import botan.rng.rng;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.utils.rounding;
import botan.utils.xor_buf;
import botan.utils.loadstor;
import botan.utils.types;
import std.algorithm;
import std.datetime;

/**
* TLS Cipher State
*/
final class ConnectionCipherState
{
public:
    /**
    * Initialize a new cipher state
    */
    this()(TLSProtocolVersion _version, 
           ConnectionSide side, bool our_side, 
           in TLSCiphersuite suite, auto const ref TLSSessionKeys keys) 
    {
        m_start_time = Clock.currTime();
        m_is_ssl3 = _version == TLSProtocolVersion.SSL_V3;
        SymmetricKey mac_key, cipher_key;
        InitializationVector iv;
        
        if (side == CLIENT)
        {
            cipher_key = keys.clientCipherKey().dup;
            iv = keys.clientIv().dup;
            mac_key = keys.clientMacKey().dup;
        }
        else
        {
            cipher_key = keys.serverCipherKey().dup;
            iv = keys.serverIv().dup;
            mac_key = keys.serverMacKey().dup;
        }
        
        const string cipher_algo = suite.cipherAlgo();
        const string mac_algo = suite.macAlgo();
        
        if (AEADMode aead = getAead(cipher_algo, our_side ? ENCRYPTION : DECRYPTION))
        {
            m_aead = aead;
            m_aead.setKey(cipher_key ~ mac_key);
            
            assert(iv.length == 4, "Using 4/8 partial implicit nonce");
            m_nonce = iv.bitsOf();
            m_nonce.resize(12);
            return;
        }
        
        AlgorithmFactory af = globalState().algorithmFactory();
        
        if (const BlockCipher bc = af.prototypeBlockCipher(cipher_algo))
        {
            m_block_cipher = bc.clone();
            m_block_cipher.setKey(cipher_key);
            m_block_cipher_cbc_state = iv.bitsOf();
            m_block_size = bc.blockSize;
            
            if (_version.supportsExplicitCbcIvs())
                m_iv_size = m_block_size;
        }
        else if (const StreamCipher sc = af.prototypeStreamCipher(cipher_algo))
        {
            m_stream_cipher = sc.clone();
            m_stream_cipher.setKey(cipher_key);
        }
        else
            throw new InvalidArgument("Unknown TLS cipher " ~ cipher_algo);
        
        if (_version == TLSProtocolVersion.SSL_V3)
            m_mac = af.makeMac("SSL3-MAC(" ~ mac_algo ~ ")");
        else
            m_mac = af.makeMac("HMAC(" ~ mac_algo ~ ")");
        
        m_mac.setKey(mac_key);
    }

    AEADMode aead() { return *m_aead; }

    ref const(SecureVector!ubyte) aeadNonce(ulong seq)
    {
        assert(m_aead, "Using AEAD mode");
        assert(m_nonce.length == 12, "Expected nonce size");
        storeBigEndian(seq, &m_nonce[4]);
        return m_nonce;
    }

    ref const(SecureVector!ubyte) aeadNonce(const(ubyte)* record, size_t record_len)
    {
        assert(m_aead, "Using AEAD mode");
        assert(m_nonce.length == 12, "Expected nonce size");
        assert(record_len >= 8, "Record includes nonce");
        copyMem(&m_nonce[4], record, 8);
        return m_nonce;
    }


    ref const(SecureVector!ubyte) formatAd(ulong msg_sequence, ubyte msg_type, TLSProtocolVersion _version, ushort msg_length)
    {
        m_ad.clear();
        foreach (size_t i; 0 .. 8)
            m_ad.pushBack(get_byte(i, msg_sequence));
        m_ad.pushBack(msg_type);
        
        if (_version != TLSProtocolVersion.SSL_V3)
        {
            m_ad.pushBack(_version.majorVersion());
            m_ad.pushBack(_version.minorVersion());
        }
        
        m_ad.pushBack(get_byte(0, msg_length));
        m_ad.pushBack(get_byte(1, msg_length));
        
        return m_ad;
    }

    BlockCipher blockCipher() { return *m_block_cipher; }

    StreamCipher streamCipher() { return *m_stream_cipher; }

    MessageAuthenticationCode mac() { return *m_mac; }

    ref SecureVector!ubyte cbcState() { return m_block_cipher_cbc_state; }

    size_t blockSize() const { return m_block_size; }

    size_t macSize() const { return m_mac.outputLength; }

    size_t ivSize() const { return m_iv_size; }

    bool macIncludesRecordVersion() const { return !m_is_ssl3; }

    bool cipherPaddingSingleByte() const { return m_is_ssl3; }

    bool cbcWithoutExplicitIv() const
    { return (m_block_size > 0) && (m_iv_size == 0); }

    Duration age() const
    {
        return Clock.currTime() - m_start_time;
    }

private:
    SysTime m_start_time;
    Unique!BlockCipher m_block_cipher;
    SecureVector!ubyte m_block_cipher_cbc_state;
    Unique!StreamCipher m_stream_cipher;
    Unique!MessageAuthenticationCode m_mac;

    Unique!AEADMode m_aead;
    SecureVector!ubyte m_nonce, m_ad;

    size_t m_block_size;
    size_t m_iv_size;
    bool m_is_ssl3;
}

/**
* Create a TLS record
* Params:
*  output = the output record is placed here
*  msg_type = is the type of the message (handshake, alert, ...)
*  msg = is the plaintext message
*  msg_length = is the length of msg
*  _version = is the protocol version
*  msg_sequence = is the sequence number
*  cipherstate = is the writing cipher state
*  rng = is a random number generator
* Returns: number of bytes written to write_buffer
*/
void writeRecord(ref SecureVector!ubyte output,
                  ubyte msg_type, const(ubyte)* msg, size_t msg_length,
                  TLSProtocolVersion _version,
                  ulong msg_sequence,
                  ConnectionCipherState cipherstate,
                  RandomNumberGenerator rng)
{
    output.clear();
    
    output.pushBack(msg_type);
    output.pushBack(_version.majorVersion());
    output.pushBack(_version.minorVersion());
    
    if (_version.isDatagramProtocol())
    {
        foreach (size_t i; 0 .. 8)
            output.pushBack(get_byte(i, msg_sequence));
    }
    
    if (!cipherstate) // initial unencrypted handshake records
    {
        output.pushBack(get_byte(0, cast(ushort) msg_length));
        output.pushBack(get_byte(1, cast(ushort) msg_length));
        
        output ~= msg[0 .. msg_length];
        
        return;
    }
    
    if (AEADMode aead = cipherstate.aead())
    {
        const size_t ctext_size = aead.outputLength(msg_length);
        
        const(SecureVector!ubyte)* nonce = &cipherstate.aeadNonce(msg_sequence);
        const size_t implicit_nonce_bytes = 4; // FIXME, take from ciphersuite
        const size_t explicit_nonce_bytes = 8;
        
        assert(nonce.length == implicit_nonce_bytes + explicit_nonce_bytes, "Expected nonce size");
        
        // wrong if startVec returns something
        const size_t rec_size = ctext_size + explicit_nonce_bytes;

        assert(rec_size <= 0xFFFF, "Ciphertext length fits in field");
        
        output.pushBack(get_byte!ushort(0, cast(ushort) rec_size));
        output.pushBack(get_byte!ushort(1, cast(ushort) rec_size));
        
        aead.setAssociatedDataVec(cipherstate.formatAd(msg_sequence, msg_type, _version, cast(ushort) msg_length));
        
        output ~= nonce.ptr[implicit_nonce_bytes .. implicit_nonce_bytes + explicit_nonce_bytes];
        output ~= aead.startVec(*nonce);
        
        const size_t offset = output.length;
        output ~= msg[0 .. msg_length];
        aead.finish(output, offset);
        
        assert(output.length == offset + ctext_size, "Expected size");
        
        assert(output.length < MAX_CIPHERTEXT_SIZE,
                     "Produced ciphertext larger than protocol allows");
        return;
    }
    
    cipherstate.mac().update(cipherstate.formatAd(msg_sequence, msg_type, _version, cast(ushort) msg_length));
    
    cipherstate.mac().update(msg, msg_length);
    
    const size_t block_size = cipherstate.blockSize();
    const size_t iv_size = cipherstate.ivSize();
    const size_t mac_size = cipherstate.macSize();
    
    const size_t buf_size = roundUp(iv_size + msg_length + mac_size + (block_size ? 1 : 0), block_size);
    
    if (buf_size > MAX_CIPHERTEXT_SIZE)
        throw new InternalError("Output record is larger than allowed by protocol");
    
    output.pushBack(get_byte!ushort(0, cast(ushort) buf_size));
    output.pushBack(get_byte!ushort(1, cast(ushort) buf_size));
    
    const size_t header_size = output.length;
    
    if (iv_size)
    {
        output.resize(output.length + iv_size);
        rng.randomize(&output[$- iv_size], iv_size);
    }
    
    output ~= msg[0 .. msg_length];
    
    output.resize(output.length + mac_size);
    cipherstate.mac().flushInto(&output[output.length - mac_size]);
    
    if (block_size)
    {
        const size_t pad_val = buf_size - (iv_size + msg_length + mac_size + 1);
        
        foreach (size_t i; 0 .. (pad_val + 1))
            output.pushBack(pad_val);
    }
    
    if (buf_size > MAX_CIPHERTEXT_SIZE)
        throw new InternalError("Produced ciphertext larger than protocol allows");
    
    assert(buf_size + header_size == output.length,
                 "Output buffer is sized properly");
    
    if (StreamCipher sc = cipherstate.streamCipher())
    {
        sc.cipher1(&output[header_size], buf_size);
    }
    else if (BlockCipher bc = cipherstate.blockCipher())
    {
        SecureVector!ubyte* cbc_state = &cipherstate.cbcState();
        
        assert(buf_size % block_size == 0,
                     "Buffer is an even multiple of block size");
        
        ubyte* buf = &output[header_size];
        
        const size_t blocks = buf_size / block_size;
        
        xorBuf(buf, cbc_state.ptr, block_size);
        bc.encrypt(buf);
        
        for (size_t i = 1; i < blocks; ++i)
        {
            xorBuf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
            bc.encrypt(&buf[block_size*i]);
        }
        
        (*cbc_state)[] = buf[block_size*(blocks-1) .. block_size*blocks];
    }
    else
        throw new InternalError("NULL cipher not supported");
}

/**
* Decode a TLS record
* Returns: zero if full message, else number of bytes still needed
*/
size_t readRecord(ref SecureVector!ubyte readbuf,
                  const(ubyte)* input, size_t input_sz,
                  ref size_t consumed,
                  ref SecureVector!ubyte record,
                  ref ulong record_sequence,
                  ref TLSProtocolVersion record_version,
                  ref RecordType record_type,
                  ConnectionSequenceNumbers sequence_numbers,
                  in const(ConnectionCipherState) delegate(ushort) get_cipherstate)
{
    consumed = 0;
    if (readbuf.length < TLS_HEADER_SIZE) // header incomplete?
    {
        if (size_t needed = fillBufferTo(readbuf, input, input_sz, consumed, TLS_HEADER_SIZE))
            return needed;
            
            assert(readbuf.length == TLS_HEADER_SIZE, "Have an entire header");
    }
    
    // Possible SSLv2 format client hello
    if (!sequence_numbers && (readbuf[0] & 0x80) && (readbuf[2] == 1))
    {
        if (readbuf[3] == 0 && readbuf[4] == 2)
            throw new TLSException(TLSAlert.PROTOCOL_VERSION, "TLSClient claims to only support SSLv2, rejecting");
        
        if (readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
        {
            const size_t record_len = make_ushort(readbuf[0], readbuf[1]) & 0x7FFF;
            
            if (size_t needed = fillBufferTo(readbuf,
                                             input, input_sz, consumed,
                                             record_len + 2))
                return needed;
            
            assert(readbuf.length == (record_len + 2), "Have the entire SSLv2 hello");
            
            // Fake v3-style handshake message wrapper
            record_version = TLSProtocolVersion(TLSProtocolVersion.TLS_V10);
            record_sequence = 0;
            record_type = HANDSHAKE;
            
            record.resize(4 + readbuf.length - 2);
            
            record[0] = CLIENT_HELLO_SSLV2;
            record[1] = 0;
            record[2] = readbuf[0] & 0x7F;
            record[3] = readbuf[1];
            copyMem(&record[4], &readbuf[2], readbuf.length - 2);
            
            readbuf.clear();
            return 0;
        }
    }

    record_version = TLSProtocolVersion(readbuf[1], readbuf[2]);
    
    const bool is_dtls = record_version.isDatagramProtocol();
    
    if (is_dtls && readbuf.length < DTLS_HEADER_SIZE)
    {
        if (size_t needed = fillBufferTo(readbuf, input, input_sz, consumed, DTLS_HEADER_SIZE))
            return needed;
        
        assert(readbuf.length == DTLS_HEADER_SIZE,
                           "Have an entire header");
    }
    
    const size_t header_size = (is_dtls) ? DTLS_HEADER_SIZE : TLS_HEADER_SIZE;
    
    const size_t record_len = make_ushort(readbuf[header_size-2],
    readbuf[header_size-1]);
    
    if (record_len > MAX_CIPHERTEXT_SIZE)
        throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Got message that exceeds maximum size");
    
    if (size_t needed = fillBufferTo(readbuf, input, input_sz, consumed, header_size + record_len))
        return needed; // wrong for DTLS?
    
    assert(cast(size_t)(header_size) + record_len == readbuf.length, "Have the full record");
    
    record_type = cast(RecordType)(readbuf[0]);
    
    ushort epoch = 0;
    
    if (is_dtls)
    {
        record_sequence = loadBigEndian!ulong(&readbuf[3], 0);
        epoch = (record_sequence >> 48);
    }
    else if (sequence_numbers)
    {
        record_sequence = sequence_numbers.nextReadSequence();
        epoch = sequence_numbers.currentReadEpoch();
    }
    else
    {
        // server initial handshake case
        record_sequence = 0;
        epoch = 0;
    }

    if (sequence_numbers && sequence_numbers.alreadySeen(record_sequence))
        return 0;
    
    ubyte* record_contents = &readbuf[header_size];
    
    if (epoch == 0) // Unencrypted initial handshake
    {
        record[] = readbuf.ptr[header_size .. header_size + record_len];
        readbuf.clear();
        return 0; // got a full record
    }
    
    // Otherwise, decrypt, check MAC, return plaintext
    ConnectionCipherState cipherstate = cast(ConnectionCipherState) get_cipherstate(epoch);
    
    // FIXME: DTLS reordering might cause us not to have the cipher state
    
    assert(cipherstate, "Have cipherstate for this epoch");
    
    decryptRecord(record,
                  record_contents,
                  record_len,
                  record_sequence,
                  record_version,
                  record_type,
                  cipherstate);
    
    if (sequence_numbers)
        sequence_numbers.readAccept(record_sequence);
    
    readbuf.clear();
    return 0;
}


private:
                    
size_t fillBufferTo(ref SecureVector!ubyte readbuf, ref const(ubyte)* input, 
                    ref size_t input_size, ref size_t input_consumed, 
                    size_t desired)
{
    if (readbuf.length >= desired)
        return 0; // already have it
    
    const size_t taken = std.algorithm.min(input_size, desired - readbuf.length);
    
    readbuf ~= input[0 .. taken];
    input_consumed += taken;
    input_size -= taken;
    input += taken;
    
    return (desired - readbuf.length); // how many bytes do we still need?
}

/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one ubyte long), or the length
* of the padding otherwise. This is actually padding_length + 1
* because both the padding and padding_length fields are padding from
* our perspective.
*
* Returning 0 in the error case should ensure the MAC check will fail.
* This approach is suggested in section 6.2.3.2 of RFC 5246.
*
* Also returns 0 if block_size == 0, so can be safely called with a
* stream cipher in use.
*
* @fixme This should run in constant time
*/
size_t tlsPaddingCheck(bool sslv3_padding, size_t block_size, const(ubyte)* record, in size_t record_len)
{
    const size_t padding_length = record[(record_len-1)];

    if (padding_length >= record_len)
        return 0;
    
    /*
    * SSL v3 requires that the padding be less than the block size
    * but not does specify the value of the padding bytes.
    */
    if (sslv3_padding)
    {
        if (padding_length > 0 && padding_length < block_size)
            return (padding_length + 1);
        else
            return 0;
    }
    
    /*
    * TLS v1.0 and up require all the padding bytes be the same value
    * and allows up to 255 bytes.
    */
    const size_t pad_start = record_len - padding_length - 1;
    
    size_t cmp = 0;
    
    foreach (size_t i; 0 .. padding_length)
        cmp += record[pad_start + i] ^ padding_length;
    
    return cmp ? 0 : padding_length + 1;
}

void cbcDecryptRecord(const(ubyte)* record_contents, size_t record_len, 
                      ConnectionCipherState cipherstate, BlockCipher bc)
{
    const size_t block_size = cipherstate.blockSize();
    
    assert(record_len % block_size == 0, "Buffer is an even multiple of block size");
    
    const size_t blocks = record_len / block_size;
    
    assert(blocks >= 1, "At least one ciphertext block");
    
    ubyte* buf = cast(ubyte*)record_contents;
    
    SecureVector!ubyte last_ciphertext = SecureVector!ubyte(block_size);
    copyMem(last_ciphertext.ptr, buf, block_size);
    
    bc.decrypt(buf);
    xorBuf(buf, &cipherstate.cbcState()[0], block_size);
    
    SecureVector!ubyte last_ciphertext2;
    
    for (size_t i = 1; i < blocks; ++i)
    {
        last_ciphertext2[] = buf[block_size*i .. block_size*(i+1)];
        bc.decrypt(&buf[block_size*i]);
        xorBuf(&buf[block_size*i], last_ciphertext.ptr, block_size);
        std.algorithm.swap(last_ciphertext, last_ciphertext2);
    }
    
    cipherstate.cbcState() = last_ciphertext;
}

void decryptRecord(ref SecureVector!ubyte output,
                   const(ubyte)* record_contents, size_t record_len,
                   ulong record_sequence,
                   TLSProtocolVersion record_version,
                   RecordType record_type,
                   ConnectionCipherState cipherstate)
{
    if (Unique!AEADMode aead = cipherstate.aead())
    {
        const(SecureVector!ubyte)* nonce = &cipherstate.aeadNonce(record_contents, record_len);
        __gshared immutable size_t nonce_length = 8; // fixme, take from ciphersuite
        
        assert(record_len > nonce_length, "Have data past the nonce");
        const(ubyte)* msg = &record_contents[nonce_length];
        const size_t msg_length = record_len - nonce_length;
        
        const size_t ptext_size = aead.outputLength(msg_length);
        
        aead.setAssociatedDataVec(cipherstate.formatAd(record_sequence, record_type, record_version, cast(ushort) ptext_size));
        
        output ~= aead.startVec(*nonce);
        
        const size_t offset = output.length;
        output ~= msg[0 .. msg_length];
        aead.finish(output, offset);
        
        assert(output.length == ptext_size + offset, "Produced expected size");
    }
    else
    {
        // GenericBlockCipher / GenericStreamCipher case
        
        bool padding_bad = false;
        size_t pad_size = 0;
        
        if (Unique!StreamCipher sc = cipherstate.streamCipher())
        {
            sc.cipher1(record_contents, record_len);
            // no padding to check or remove
        }
        else if (Unique!BlockCipher bc = cipherstate.blockCipher())
        {
            cbcDecryptRecord(record_contents, record_len, cipherstate, *bc);
            
            pad_size = tlsPaddingCheck(cipherstate.cipherPaddingSingleByte(),
                                         cipherstate.blockSize(),
                                         record_contents, record_len);
            
            padding_bad = (pad_size == 0);
        }
        else
        {
            throw new InternalError("No cipher state set but needed to decrypt");
        }
        
        const size_t mac_size = cipherstate.macSize();
        const size_t iv_size = cipherstate.ivSize();
        
        const size_t mac_pad_iv_size = mac_size + pad_size + iv_size;
        
        if (record_len < mac_pad_iv_size)
            throw new DecodingError("Record sent with invalid length");
        
        const(ubyte)* plaintext_block = &record_contents[iv_size];
        const ushort plaintext_length = cast(ushort)(record_len - mac_pad_iv_size);
        
        cipherstate.mac().update(cipherstate.formatAd(record_sequence, record_type, record_version, plaintext_length));
        
        cipherstate.mac().update(plaintext_block, plaintext_length);
        
        Vector!ubyte mac_buf = Vector!ubyte(mac_size);
        cipherstate.mac().flushInto(mac_buf.ptr);
        
        const size_t mac_offset = record_len - (mac_size + pad_size);
        
        const bool mac_bad = !sameMem(&record_contents[mac_offset], mac_buf.ptr, mac_size);
        
        if (mac_bad || padding_bad)
            throw new TLSException(TLSAlert.BAD_RECORD_MAC, "Message authentication failure");
        
        output[] = plaintext_block[0 .. plaintext_length];
    }
}