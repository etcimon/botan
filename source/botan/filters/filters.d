/**
* Filters
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.filters;

public import botan.filters.filter;
public import botan.filters.pipe;
public import botan.filters.basefilt;
public import botan.filters.key_filt;
import botan.algo_factory.algo_factory;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;

import botan.libstate.libstate;
import botan.algo_base.scan_token;

import botan.constants;
static if (BOTAN_HAS_CODEC_FILTERS) {
  import botan.filters.b64_filt;
  import botan.filters.hex_filt;
}

import std.algorithm;

/**
* Stream Cipher Filter
*/
final class StreamCipherFilter : KeyedFilter, Filterable
{
public:

    override @property string name() const { return m_cipher.name; }

    /**
    * Write input data
    * Params:
    *  input = data
    *  input_len = length of input in bytes
    */
    override void write(const(ubyte)* input, size_t length)
    {
        while (length)
        {
            size_t copied = std.algorithm.min(length, m_buffer.length);
            m_cipher.cipher(input, m_buffer.ptr, copied);
            send(m_buffer, copied);
            input += copied;
            length -= copied;
        }
    }

    override bool validIvLength(size_t iv_len) const
    { return m_cipher.validIvLength(iv_len); }

    /**
    * Set the initialization vector for this filter.
    *
    * Params:
    *  iv = the initialization vector to set
    */
    override void setIv(in InitializationVector iv)
    {
        m_cipher.setIv(iv.ptr, iv.length);
    }


    /**
    * Set the key of this filter.
    *
    * Params:
    *  key = the key to set
    */
    override void setKey(in SymmetricKey key) { m_cipher.setKey(key); }

    override KeyLengthSpecification keySpec() const { return m_cipher.keySpec(); }

    /**
    * Construct a stream cipher filter.
    *
    * Params:
    *  cipher_obj = a cipher object to use
    */
    this(StreamCipher stream_cipher)
    {
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        m_cipher = stream_cipher;
    }

    /**
    * Construct a stream cipher filter.
    *
    * Params:
    *  stream_cipher = a cipher object to use
    *  key = the key to use inside this filter
    */
    this(StreamCipher stream_cipher, in SymmetricKey key)
    {
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        m_cipher = stream_cipher;
        m_cipher.setKey(key);
    }

    /**
    * Construct a stream cipher filter.
    *
    * Params:
    *  sc_name = the name of the desired cipher
    */
    this(in string sc_name)
        
    {
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        AlgorithmFactory af = globalState().algorithmFactory();
        m_cipher = af.makeStreamCipher(sc_name);
    }

    /**
    * Construct a stream cipher filter.
    *
    * Params:
    *  sc_name = the name of the desired cipher
    *  key = the key to use inside this filter
    */
    this(in string sc_name, in SymmetricKey key)
    {
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        AlgorithmFactory af = globalState().algorithmFactory();
        m_cipher = af.makeStreamCipher(sc_name);
        m_cipher.setKey(key);
    }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void endMsg() { super.endMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    SecureVector!ubyte m_buffer;
    Unique!StreamCipher m_cipher;
}

/**
* Hash Filter.
*/
final class HashFilter : Filter, Filterable
{
public:
    override void write(const(ubyte)* input, size_t len) { m_hash.update(input, len); }

    /*
    * Complete a calculation by a HashFilter
    */
    override void endMsg()
    {
        SecureVector!ubyte output = m_hash.finished();
        if (m_OUTPUT_LENGTH)
            send(output, std.algorithm.min(m_OUTPUT_LENGTH, output.length));
        else
            send(output);
    }

    override @property string name() const { return m_hash.name; }

    /**
    * Construct a hash filter.
    *
    * Params:
    *  hash_fun = the hash function to use
    *  len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the hashfunction
    * hash. Otherwise, specify a smaller value here so that the
    * output of the hash algorithm will be cut off.
    */
    this(HashFunction hash_fun, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        m_hash = hash_fun;
    }

    /**
    * Construct a hash filter.
    *
    * Params:
    *  algo_spec = the name of the hash algorithm to use
    *  len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the hashfunction
    * hash. Otherwise, specify a smaller value here so that the
    * output of the hash algorithm will be cut off.
    */
    this(in string algo_spec, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        AlgorithmFactory af = globalState().algorithmFactory();
        m_hash = af.makeHashFunction(algo_spec);
    }

    ~this() { destroy(m_hash); }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    const size_t m_OUTPUT_LENGTH;
    HashFunction m_hash;
}

/**
* MessageAuthenticationCode Filter.
*/
final class MACFilter : KeyedFilter, Filterable
{
public:
    override void write(const(ubyte)* input, size_t len) { m_mac.update(input, len); }

    /*
    * Complete a calculation by a MACFilter
    */
    override void endMsg()
    {
        SecureVector!ubyte output = m_mac.finished();
        if (m_OUTPUT_LENGTH)
            send(output, std.algorithm.min(m_OUTPUT_LENGTH, output.length));
        else
            send(output);
    }

    override @property string name() const { return m_mac.name; }

    /**
    * Set the key of this filter.
    *
    * Params:
    *  key = the key to set
    */
    override void setKey(in SymmetricKey key) { m_mac.setKey(key); }

    override KeyLengthSpecification keySpec() const { return m_mac.keySpec(); }

    override bool validIvLength(size_t length) const { return length == 0; }

    /**
    * Construct a MAC filter. The MAC key will be left empty.
    *
    * Params:
    *  mac_obj = the MAC to use
    *  out_len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(MessageAuthenticationCode mac_obj, size_t out_len = 0) 
    {
        m_OUTPUT_LENGTH = out_len;
        m_mac = mac_obj;
    }

    /**
    * Construct a MAC filter.
    *
    * Params:
    *  mac_obj = the MAC to use
    *  key = the MAC key to use
    *  out_len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(MessageAuthenticationCode mac_obj, in SymmetricKey key, size_t out_len = 0)
    {
        m_OUTPUT_LENGTH = out_len;
        m_mac = mac_obj;
        m_mac.setKey(key);
    }

    /**
    * Construct a MAC filter. The MAC key will be left empty.
    *
    * Params:
    *  mac = the name of the MAC to use
    *  len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(in string mac_name, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        AlgorithmFactory af = globalState().algorithmFactory();
        m_mac = af.makeMac(mac_name);
    }

    /**
    * Construct a MAC filter.
    *
    * Params:
    *  mac = the name of the MAC to use
    *  key = the MAC key to use
    *  len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(in string mac_name, in SymmetricKey key, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        AlgorithmFactory af = globalState().algorithmFactory();
        m_mac = af.makeMac(mac_name);
        m_mac.setKey(key);
    }

    ~this() { destroy(m_mac); }

    // Interface fallthrough
    override bool attachable() { return super.attachable(); }
    override void startMsg() { super.startMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    const size_t m_OUTPUT_LENGTH;
    MessageAuthenticationCode m_mac;
}