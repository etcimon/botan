/**
* Lzma Compressor
* 
* Copyright:
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2012 Vojtech Kral
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.compression.lzma;

import botan.constants;
static if (BOTAN_HAS_LZMA):

import botan.filters.filter;

import botan.utils.exceptn;
import std.exception;
import botan.compression.lzma_hd;
import botan.compression.compress;
import botan.algo_base.transform;
import botan.utils.types;
import core.exception;

/**
* LZMA Compression
*/
class LZMACompression : StreamCompression, Transformation
{
public:
    /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
    this(size_t level = 6) {
        m_level = level;
    }
    
    override string name() const { return "LZMACompression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new LZMACompressionStream(m_level);
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
* LZMA Deccompression
*/
class LZMADecompression : StreamDecompression, Transformation
{
public:
    override string name() const { return "LZMADecompression"; }
protected:
    override CompressionStream makeStream() const
    {
        return new LZMADecompressionStream;
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

class LZMAStream : ZlibStyleStream!(lzma_stream, ubyte), CompressionStream
{
public:
    this()
    {
        auto a = new .lzma_allocator;
        a.opaque = cast(void*)alloc();
        a.alloc = &CompressionAllocInfo.malloc!size_t;
        a.free = &CompressionAllocInfo.free;
        streamp().allocator = a;
    }
    
    ~this()
    {
        .lzma_end(streamp());
        delete streamp().allocator;
    }
    
    override bool run(uint flags)
    {
        lzma_ret rc = .lzma_code(streamp(), cast(lzma_action)(flags));
        
        if (rc == LZMA_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != LZMA_OK && rc != LZMA_STREAM_END)
            throw new Exception("Lzma error");
        
        return (rc == LZMA_STREAM_END);
    }
    
    override uint runFlag() const { return LZMA_RUN; }
    override uint flushFlag() const { return LZMA_FULL_FLUSH; }
    override uint finishFlag() const { return LZMA_FINISH; }

	override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
	override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
	override size_t availIn() const { return super.availIn(); }    
	override size_t availOut() const { return super.availOut; }
}

class LZMACompressionStream : LZMAStream
{
public:
    this(size_t level)
    {
        lzma_ret rc = .lzma_easy_encoder(streamp(), cast(uint) level, LZMA_CHECK_CRC64);
        
        if (rc == LZMA_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != LZMA_OK)
            throw new Exception("lzma compress initialization failed: " ~ rc.to!string);
    }
}

class LZMADecompressionStream : LZMAStream
{
public:
    this()
    {
        lzma_ret rc = .lzma_stream_decoder(streamp(), ulong.max,
            LZMA_TELL_UNSUPPORTED_CHECK);
        
        if (rc == LZMA_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != LZMA_OK)
            throw new Exception("Bad setting in lzma_stream_decoder");
    }
}