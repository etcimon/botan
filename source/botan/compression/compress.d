/*
* Compression Transform
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.compression.compress;

import botan.constants;

import botan.algo_base.transform;
import botan.utils.types;
import botan.utils.mem_ops;
public import botan.compression.compress_utils;
import botan.compression.zlib;
import botan.compression.lzma;
import botan.compression.bzip2;

abstract class CompressorTransform : Transformation
{
public:
    override size_t updateGranularity() const { return 1; }
    
    override size_t minimumFinalSize() const { return 0; }
    
    override size_t defaultNonceLength() const { return 0; }

    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    
    abstract void flush(ref SecureVector!ubyte buf, size_t offset = 0) { update(buf, offset); }
    
    override size_t outputLength(size_t) const 
    {
        throw new Exception(name() ~ " output length indeterminate");
    }
}

interface CompressionStream
{
public:
    void nextIn(ubyte* b, size_t len);
    
    void nextOut(ubyte* b, size_t len);
    
    size_t availIn() const;
    
    size_t availOut() const;
    
    uint runFlag() const;
    uint flushFlag() const;
    uint finishFlag() const;
    
    bool run(uint flags);
}

abstract class StreamCompression : CompressorTransform, Transformation
{
public:
    void update(ref SecureVector!ubyte buf, size_t offset = 0) { process(buf, offset, m_stream.runFlag()); }
    
    override void flush(ref SecureVector!ubyte buf, size_t offset = 0) { process(buf, offset, m_stream.flushFlag()); }
    
    void finish(ref SecureVector!ubyte buf, size_t offset = 0)
    {
        process(buf, offset, m_stream.finishFlag());
        clear();
    }

    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    
    void clear() { m_stream.free(); }

protected:
    abstract CompressionStream makeStream() const;

    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);

        m_stream = makeStream();
        return SecureVector!ubyte();
    }
    
    void process(ref SecureVector!ubyte buf, size_t offset, uint flags)
    {
        assert(m_stream, "Initialized");
        assert(buf.length >= offset, "Offset is sane");
        
        if (m_buffer.length < buf.length + offset)
            m_buffer.resize(buf.length + offset);
        
        m_stream.nextIn(&buf[offset], buf.length - offset);
        m_stream.nextOut(&m_buffer[offset], m_buffer.length - offset);
        
        while(true)
        {
            m_stream.run(flags);
            
            if (m_stream.availOut() == 0)
            {
                const size_t added = 8 + m_buffer.length;
                m_buffer.resize(m_buffer.length + added);
                m_stream.nextOut(&m_buffer[m_buffer.length - added], added);
            }
            else if (m_stream.availIn() == 0)
            {
                m_buffer.resize(m_buffer.length - m_stream.availOut());
                break;
            }
        }
        
        copyMem(&m_buffer[0], &buf[0], offset);
        buf.swap(m_buffer);
    }

    
    SecureVector!ubyte m_buffer;
    Unique!CompressionStream m_stream;
}

abstract class StreamDecompression : CompressorTransform, Transformation
{
public:
    void update(ref SecureVector!ubyte buf, size_t offset = 0)
    {
        process(buf, offset, m_stream.runFlag());
    }
    
    void finish(ref SecureVector!ubyte buf, size_t offset = 0)
    {
        if (buf.length != offset || m_stream.get())
            process(buf, offset, m_stream.finishFlag());
        
        if (m_stream.get())
            throw new Exception(name() ~ " finished but not at stream end");
    }
    
    void clear() { m_stream.free(); }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    
protected:
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);
        
        m_stream = makeStream();
        
        return SecureVector!ubyte();
    }
    
    void process(ref SecureVector!ubyte buf, size_t offset, uint flags)
    {
        assert(m_stream, "Initialized");
        assert(buf.length >= offset, "Offset is sane");
        
        if (m_buffer.length < buf.length + offset)
            m_buffer.resize(buf.length + offset);
        
        m_stream.nextIn(&buf[offset], buf.length - offset);
        m_stream.nextOut(&m_buffer[offset], m_buffer.length - offset);
        
        while(true)
        {
            const bool stream_end = m_stream.run(flags);
            
            if (stream_end)
            {
                if (m_stream.availIn() == 0) // all data consumed?
                {
                    m_buffer.resize(m_buffer.length - m_stream.availOut());
                    clear();
                    break;
                }
                
                // More data follows: try to process as a following stream
                const size_t read = (buf.length - offset) - m_stream.availIn();
                start();
                m_stream.nextIn(&buf[offset + read], buf.length - offset - read);
            }
            
            if (m_stream.availOut() == 0)
            {
                const size_t added = 8 + m_buffer.length;
                m_buffer.resize(m_buffer.length + added);
                m_stream.nextOut(&m_buffer[m_buffer.length - added], added);
            }
            else if (m_stream.availIn() == 0)
            {
                m_buffer.resize(m_buffer.length - m_stream.availOut());
                break;
            }
        }
        
        copyMem(m_buffer.ptr, buf.ptr, offset);
        buf.swap(m_buffer);
    }
    
    abstract CompressionStream makeStream() const;
    
    SecureVector!ubyte m_buffer;
    Unique!CompressionStream m_stream;
}


CompressorTransform makeCompressor(in string type, size_t level)
{
    static if (BOTAN_HAS_ZLIB)
        
    {
        if (type == "zlib")
            return new ZlibCompression(level);
        if (type == "deflate")
            return new DeflateCompression(level);
    }
    
    static if (BOTAN_HAS_BZIP2)
    {
        if (type == "bzip2")
            return new BzipCompression(level);
    }
    
    static if (BOTAN_HAS_LZMA)
    {
        if (type == "lzma")
            return new LZMACompression(level);
    }
    
    throw new Exception("Unknown compression type " ~ type);
}

CompressorTransform makeDecompressor(in string type)
{
    static if (BOTAN_HAS_ZLIB)
    {
        if (type == "zlib")
            return new ZlibDecompression();
        if (type == "deflate")
            return new DeflateDecompression();
    }
    
    static if (BOTAN_HAS_BZIP2)
    {
        if (type == "bzip2")
            return new BzipDecompression;
    }
    
    static if (BOTAN_HAS_LZMA)
    {
        if (type == "lzma")
            return new LZMADecompression;
    }

    throw new Exception("Unknown compression type " ~ type);
}

static if (!SKIP_COMPRESSION_TEST) unittest {  
    logDebug("Testing compress.d ...");  
	static if (BOTAN_HAS_ZLIB) {
	    CompressorTransform zlib = makeCompressor("zlib", 9);
	    SecureVector!ubyte buf;
	    SecureVector!ubyte verif;
	    buf ~= "Some message";
	    verif = buf.dup;
		zlib.start();
	    zlib.finish(buf);

	    CompressorTransform dec = makeDecompressor("zlib");
		dec.start();
		dec.finish(buf);
	    assert(buf == verif);
		logDebug("Zlib ... PASSED");
	}
}