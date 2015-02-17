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
module botan.filters.zlib;

import botan.constants;

static if (BOTAN_HAS_ZLIB):

import botan.filters.filter;
import botan.utils.exceptn;

import std.c.string;
import std.c.stdio;
import botan.utils.types;
import memutils.hashmap;
import etc.c.zlib;
import std.c.stdlib;
import botan.constants;
import botan.utils.mem_ops;

/**
* Zlib Compression Filter
*/
final class ZlibCompression : Filter, Filterable
{
public:
    override @property string name() const { return "ZlibCompression"; }

    /*
    * Compress Input with Zlib
    */
    override void write(const(ubyte)* input, size_t length)
    {
        m_zlib.m_stream.next_in = cast(ubyte*)input;
        m_zlib.m_stream.avail_in = cast(uint)length;
        
        while (m_zlib.m_stream.avail_in != 0)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = cast(uint)m_buffer.length;
            deflate(m_zlib.m_stream, Z_NO_FLUSH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
    }

    /*
    * Start Compressing with Zlib
    */
    override void startMsg()
    {
        clear();
        m_zlib = new Zlib_Stream;
        
        int res = deflateInit2(m_zlib.m_stream,
                               cast(int) m_level,
                               Z_DEFLATED,
                               (m_raw_deflate ? -15 : 15),
                               8,
                               Z_DEFAULT_STRATEGY);
        
        if (res == Z_STREAM_ERROR)
            throw new InvalidArgument("Bad setting in deflateInit2");
        else if (res != Z_OK)
            throw new MemoryExhaustion("Couldn't start message, not enough memory.");
    }

    /*
    * Finish Compressing with Zlib
    */
    override void endMsg()
    {
        m_zlib.m_stream.next_in = null;
        m_zlib.m_stream.avail_in = 0;
        
        int rc = Z_OK;
        while (rc != Z_STREAM_END)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = cast(uint)m_buffer.length;
            
            rc = deflate(m_zlib.m_stream, Z_FINISH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
        
        clear();
    }

    /**
    * Flush the compressor
    */
    void finished()
    {
        m_zlib.m_stream.next_in = null;
        m_zlib.m_stream.avail_in = 0;
        
        while (true)
        {
            m_zlib.m_stream.avail_out = cast(uint)m_buffer.length;
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            
            deflate(m_zlib.m_stream, Z_FULL_FLUSH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
            
            if (m_zlib.m_stream.avail_out == m_buffer.length)
                break;
        }
    }

    /**
    * Params:
    *  level = how much effort to use on compressing (0 to 9);
    *          higher levels are slower but tend to give better
    *          compression
    *  raw_deflate = if true no m_zlib header/trailer will be used
    */
    this(size_t level = 6, bool raw_deflate = false)
    {
        
        m_level = (level >= 9) ? 9 : level;
        m_raw_deflate = raw_deflate;
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        m_zlib = null;
    }

    ~this() { clear(); }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:
    /*
    * Clean up Compression Context
    */
    void clear()
    {
        zeroise(m_buffer);
        
        if (m_zlib)
        {
            deflateEnd(m_zlib.m_stream);
            destroy(m_zlib);
            m_zlib = null;
        }
    }

    const size_t m_level;
    const bool m_raw_deflate;

    SecureVector!ubyte m_buffer;
    Zlib_Stream m_zlib;
}

/**
* Zlib Decompression Filter
*/
final class Zlib_Decompression : Filter, Filterable
{
public:
    override @property string name() const { return "Zlib_Decompression"; }

    /*
    * Decompress Input with Zlib
    */
    override void write(const(ubyte)* input_arr, size_t length)
    {
        if (length) m_no_writes = false;
        
        // non-const needed by m_zlib api :(
        const(ubyte)* input = cast(const(ubyte)*)(input_arr);
        
        m_zlib.m_stream.next_in = cast(ubyte*)input;
        m_zlib.m_stream.avail_in = cast(uint)length;
        
        while (m_zlib.m_stream.avail_in != 0)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = cast(uint)m_buffer.length;
            
            int rc = inflate(m_zlib.m_stream, Z_SYNC_FLUSH);
            
            if (rc != Z_OK && rc != Z_STREAM_END)
            {
                clear();
                if (rc == Z_DATA_ERROR)
                    throw new DecodingError("Zlib_Decompression: Data integrity error");
                else if (rc == Z_NEED_DICT)
                    throw new DecodingError("Zlib_Decompression: Need preset dictionary");
                else if (rc == Z_MEM_ERROR)
                    throw new MemoryExhaustion("Couldn't write during Zlib Decompression");
                else
                    throw new Exception("Zlib decompression: Unknown error");
            }
            
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
            
            if (rc == Z_STREAM_END)
            {
                size_t read_from_block = length - m_zlib.m_stream.avail_in;
                startMsg();
                
                m_zlib.m_stream.next_in = cast(ubyte*)( input + read_from_block);
                m_zlib.m_stream.avail_in = cast(uint)(length - read_from_block);
                
                input += read_from_block;
                length -= read_from_block;
            }
        }
    }

    /*
    * Start Decompressing with Zlib
    */
    override void startMsg()
    {
        clear();
        m_zlib = new Zlib_Stream;
        
        if (inflateInit2(m_zlib.m_stream, (m_raw_deflate ? -15 : 15)) != Z_OK)
            throw new MemoryExhaustion("Couldnt' start message in decompression");
    }

    /*
    * Finish Decompressing with Zlib
    */
    override void endMsg()
    {
        if (m_no_writes) return;
        m_zlib.m_stream.next_in = null;
        m_zlib.m_stream.avail_in = 0;
        
        int rc = Z_OK;
        
        while (rc != Z_STREAM_END)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = cast(uint)m_buffer.length;
            rc = inflate(m_zlib.m_stream, Z_SYNC_FLUSH);
            
            if (rc != Z_OK && rc != Z_STREAM_END)
            {
                clear();
                throw new DecodingError("Zlib_Decompression: Error finalizing");
            }
            
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
        
        clear();
    }


    /*
    * Zlib_Decompression Constructor
    */
    this(bool _raw_deflate = false)
    {
        m_raw_deflate = _raw_deflate;
        m_buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
        m_zlib = null;
        m_no_writes = true;
    }

    ~this() { clear(); }

    // Interface fallthrough
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }
private:

    /*
    * Clean up Decompression Context
    */
    void clear()
    {
        zeroise(m_buffer);
        
        m_no_writes = true;
        
        if (m_zlib)
        {
            inflateEnd(m_zlib.m_stream);
            destroy(m_zlib);
            m_zlib = null;
        }
    }

    const bool m_raw_deflate;

    SecureVector!ubyte m_buffer;
    Zlib_Stream m_zlib;
    bool m_no_writes;
}


/*
* Allocation Information for Zlib
*/
class Zlib_Alloc_Info
{
public:
    HashMapRef!(void*, size_t) current_allocs;
}

/*
* Allocation Function for Zlib
*/
extern(C) void* zlib_malloc(void* info_ptr, uint n, uint size)
{
    Zlib_Alloc_Info info = cast(Zlib_Alloc_Info)(info_ptr);
    
    const size_t total_sz = n * size;
    
    void* ptr = .malloc(total_sz);
    info.current_allocs[ptr] = total_sz;
    return ptr;
}

/*
* Allocation Function for Zlib
*/
extern(C) void zlib_free(void* info_ptr, void* ptr)
{
    Zlib_Alloc_Info info = cast(Zlib_Alloc_Info)(info_ptr);
    auto len = (cast(const)info.current_allocs).get(ptr);
    if (!len)
        throw new InvalidArgument("zlib_free: Got pointer not allocated by us");
    
    memset(ptr, 0, len);
    .free(ptr);
}

/**
* Wrapper Type for Zlib z_stream
*/
class Zlib_Stream
{
public:
    /**
    * Underlying m_stream
    */
    z_stream* m_stream;
    
    /**
    * Constructor
    */
    this()
    {
        m_stream = new z_stream;
        memset(m_stream, 0, (z_stream).sizeof);
        m_stream.zalloc = &zlib_malloc;
        m_stream.zfree = &zlib_free;
        m_stream.opaque = cast(void*)new Zlib_Alloc_Info;
    }
    
    /**
    * Destructor
    */
    ~this()
    {
        Zlib_Alloc_Info info = cast(Zlib_Alloc_Info)(m_stream.opaque);
        destroy(info);
        memset(m_stream, 0, (z_stream).sizeof);
        destroy(m_stream);
    }
}