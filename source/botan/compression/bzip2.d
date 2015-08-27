/**
* Bzip Compressor
* 
* Copyright:
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.compression.bzip2;

import botan.constants;
static if (BOTAN_HAS_BZIP2):

import botan.utils.exceptn;
import botan.compression.bzip2_hd;
import botan.compression.compress;
import std.exception;
import botan.algo_base.transform;
import botan.utils.types;
import core.exception;

/**
* Bzip2 Compression
*/
class Bzip2Compression : StreamCompression, Transformation
{
public:
    /**
      * @param block_size in 1024 KiB increments, in range from 1 to 9.
      *
      * Lowering this does not noticably modify the compression or
      * decompression speed, though less memory is required for both
      * compression and decompression.
      */
    this(size_t block_size = 9) 
    {
        m_block_size = block_size; 

    }
    
    override string name() const { return "Bzip2Compression"; }
    
protected:
    override CompressionStream makeStream() const
    {
        return new Bzip2CompressionStream(m_block_size);
    }
    
    const size_t m_block_size;
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
* Bzip2 Deccompression
*/
class Bzip2Decompression : StreamDecompression, Transformation
{
public:
    override string name() const { return "Bzip2Decompression"; }
protected:
    override CompressionStream makeStream() const
    {
        return new Bzip2DecompressionStream;
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


class Bzip2Stream : ZlibStyleStream!(bz_stream, ubyte), CompressionStream
{
public:
    this()
    {
        streamp().opaque = cast(void*)alloc();
        streamp().bzalloc = &CompressionAllocInfo.malloc!int;
        streamp().bzfree = &CompressionAllocInfo.free;
    }
    
    override uint runFlag() const { return BZ_RUN; }
    override uint flushFlag() const { return BZ_FLUSH; }
    override uint finishFlag() const { return BZ_FINISH; }

	override bool run(uint flags) { return false; }
	override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
	override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
	override size_t availIn() const { return super.availIn(); }    
	override size_t availOut() const { return super.availOut; }
}

class Bzip2CompressionStream : Bzip2Stream, CompressionStream
{
public:
    this(size_t block_size)
    {
        int rc = BZ2_bzCompressInit(streamp(), cast(int)block_size, 0, 0);
        
        if (rc == BZ_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != BZ_OK)
            throw new Exception("bzip compress initialization failed");
    }
    
    ~this()
    {
        BZ2_bzCompressEnd(streamp());
    }
    
    override bool run(uint flags)
    {
        int rc = BZ2_bzCompress(streamp(), flags);
        
        if (rc == BZ_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc < 0)
            throw new Exception("bzip compress error");
        
        return (rc == BZ_STREAM_END);
    }

	override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
	override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
	override size_t availIn() const { return super.availIn(); }    
	override size_t availOut() const { return super.availOut; }
	override uint runFlag() const { return super.runFlag(); }
	override uint flushFlag() const { return super.flushFlag(); }
	override uint finishFlag() const { return super.finishFlag(); }
}

class Bzip2DecompressionStream : Bzip2Stream, CompressionStream
{
public:
    this()
    {
        int rc = BZ2_bzDecompressInit(streamp(), 0, 0);
        
        if (rc == BZ_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != BZ_OK)
            throw new Exception("bzip decompress initialization failed");
    }
    
    ~this()
    {
        BZ2_bzDecompressEnd(streamp());
    }
    
    override bool run(uint)
    {
        int rc = BZ2_bzDecompress(streamp());
        
        if (rc == BZ_MEM_ERROR)
            throw new InvalidMemoryOperationError();
        else if (rc != BZ_OK && rc != BZ_STREAM_END)
            throw new Exception("bzip decompress error");
        
        return (rc == BZ_STREAM_END);
    }

	override void nextIn(ubyte* b, size_t len) { super.nextIn(b, len); }    
	override void nextOut(ubyte* b, size_t len) { super.nextOut(b, len); }    
	override size_t availIn() const { return super.availIn(); }    
	override size_t availOut() const { return super.availOut; }
	override uint runFlag() const { return super.runFlag(); }
	override uint flushFlag() const { return super.flushFlag(); }
	override uint finishFlag() const { return super.finishFlag(); }
}
