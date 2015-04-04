/**
* Zlib Compressor
* 
* Copyright:
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.compression.zlib;

import botan.constants;
static if (BOTAN_HAS_ZLIB):

import botan.compression.compress;
import botan.utils.exceptn;
import etc.c.zlib;
import botan.algo_base.transform;
import botan.utils.types;
import core.exception;
import std.datetime;
import botan.utils.mem_ops;

/**
* Zlib Compression
*/
class ZlibCompression : StreamCompression, Transformation
{
public:
    /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
    this(size_t level = 6)
    {
        m_level = level; 
    }
    
    override string name() const { return "ZlibCompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new ZlibCompressionStream(m_level, 15);
    }

    const size_t m_level;

    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

/**
* Zlib Decompression
*/
class ZlibDecompression : StreamDecompression, Transformation
{
public:
    override string name() const { return "ZlibDecompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new ZlibDecompressionStream(15);
    }

    alias startRaw = StreamDecompression.startRaw;
    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

/**
* Deflate Compression
*/
class DeflateCompression : StreamCompression, Transformation
{
public:
    /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
    this(size_t level = 6) 
    { m_level = level; }
    
    override string name() const { return "DeflateCompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new DeflateCompressionStream(m_level, 15);
    }

    const size_t m_level;
    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

/**
* Deflate Decompression
*/
class DeflateDecompression : StreamDecompression, Transformation
{
public:
    override string name() const { return "DeflateDecompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new DeflateDecompressionStream(15);
    }

    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

/**
* Gzip Compression
*/
class GzipCompression : StreamCompression, Transformation
{
public:
    /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
    this(size_t level = 6, ubyte os_code = 255)
    {
        m_level = level; 
        m_os_code = os_code;
    }
    override string name() const { return "GzipCompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new GzipCompressionStream(m_level, 15, m_os_code);
    }
    
    const size_t m_level;
    const byte m_os_code;

    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

/**
* Gzip Decompression
*/
class GzipDecompression : StreamCompression, Transformation
{
public:
    override string name() const { return "GzipDecompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new GzipDecompressionStream(15);
    }

    // interface fall-through
    override void flush(ref SecureVector!ubyte buf, size_t offset) { super.flush(buf, offset); }
    override string provider() const { return "core"; }
    override size_t updateGranularity() const { return 1; }
    override size_t minimumFinalSize() const { return 0; }    
    override size_t defaultNonceLength() const { return 0; }    
    override bool validNonceLength(size_t nonce_len) const { return nonce_len == 0; }
    override SecureVector!ubyte startRaw(const(ubyte)* data, size_t data_len) { return super.startRaw(data, data_len); }
    override void update(ref SecureVector!ubyte buf, size_t offset) { super.update(buf, offset); }
    override void finish(ref SecureVector!ubyte buf, size_t offset) { super.finish(buf, offset); }
    override size_t outputLength(size_t input_length) const { return super.outputLength(input_length); }
    override void clear() { return super.clear(); }
}

package:

abstract class ZlibStream : ZlibStyleStream!(z_stream, ubyte), CompressionStream
{
public:
    this()
    {
        streamp().opaque = cast(void*)alloc();
        streamp().zalloc = &CompressionAllocInfo.malloc!uint;
        streamp().zfree = &CompressionAllocInfo.free;
    }
    
    override uint runFlag() const { return Z_NO_FLUSH; }
    override uint flushFlag() const { return Z_FULL_FLUSH; }
    override uint finishFlag() const { return Z_FINISH; }
    
    int computeWindowBits(int wbits, int wbits_offset) const
    {
        if (wbits_offset == -1)
            return -wbits;
        else
            return wbits + wbits_offset;
    }
    // interface fall-through
    override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
    override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
    override size_t availIn() const { return super.availIn(); }    
    override size_t availOut() const { return super.availOut; }
}

class ZlibCompressionStream : ZlibStream, CompressionStream
{
public:
    this(size_t level, int wbits, int wbits_offset = 0)
    {
        wbits = computeWindowBits(wbits, wbits_offset);
        
        int rc = deflateInit2(streamp(), cast(int) level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY);
        if (rc != Z_OK)
            throw new Exception("zlib deflate initialization failed: " ~ rc.to!string);
    }
    
    ~this()
    {
        deflateEnd(streamp());
    }


    override bool run(uint flags)
    {
        int rc = deflate(streamp(), flags);
        
        if (rc == Z_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != Z_OK && rc != Z_STREAM_END)
            throw new Exception("zlib deflate error");
        
        return (rc == Z_STREAM_END);
    }

    // interface fall-through
    override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
    override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
    override size_t availIn() const { return super.availIn(); }    
    override size_t availOut() const { return super.availOut; }
    override uint runFlag() const { return super.runFlag(); }
    override uint flushFlag() const { return super.flushFlag(); }
    override uint finishFlag() const { return super.finishFlag(); }
}

class ZlibDecompressionStream : ZlibStream, CompressionStream
{
public:
    this(int wbits, int wbits_offset = 0)
    {
        int rc = inflateInit2(streamp(), computeWindowBits(wbits, wbits_offset));
        
        if (rc == Z_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != Z_OK)
            throw new Exception("zlib inflate initialization failed");
    }
    
    ~this()
    {
        inflateEnd(streamp());
    }
    
    override bool run(uint flags)
    {
        int rc = inflate(streamp(), flags);
        
        if (rc == Z_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != Z_OK && rc != Z_STREAM_END)
            throw new Exception("zlib deflate error");
        
        return (rc == Z_STREAM_END);
    }
    // interface fall-through
    override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
    override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
    override size_t availIn() const { return super.availIn(); }    
    override size_t availOut() const { return super.availOut; }
    override uint runFlag() const { return super.runFlag(); }
    override uint flushFlag() const { return super.flushFlag(); }
    override uint finishFlag() const { return super.finishFlag(); }
}

class DeflateCompressionStream : ZlibCompressionStream
{
public:
    this(size_t level, int wbits)
    {
        super(level, wbits, -1);
    }
}

class DeflateDecompressionStream : ZlibDecompressionStream
{
public:
    this(int wbits)
    {
        super(wbits, -1);
    }
}

class GzipCompressionStream : ZlibCompressionStream
{
public:
    this(size_t level, int wbits, ubyte os_code)
    {
        super(level, wbits, 16);
        clearMem(&m_header, 1);
        m_header.os = os_code;
        m_header.time = Clock.currTime(UTC()).toUnixTime();
        
        int rc = deflateSetHeader(streamp(), &m_header);
        if (rc != Z_OK)
            throw new Exception("setting gzip header failed");
    }
    
protected:
    .gz_header m_header;
}

class GzipDecompressionStream : ZlibDecompressionStream
{
public:
    this(int wbits)
    { super(wbits, 16); }
}