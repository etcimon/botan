/**
* EGD EntropySource
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.es_egd;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_EGD):

import botan.entropy.entropy_src;
// import string;
import botan.utils.types;

import botan.utils.parsing;
import botan.utils.exceptn;
import std.exception;

import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;

import core.sys.posix.sys.socket;
import core.sys.posix.sys.un;

import std.c.string;
import std.string : toStringz;

enum PF_LOCAL = AF_UNIX;

/**
* EGD Entropy Source
*/
final class EGDEntropySource : EntropySource
{
public:
    @property string name() const { return "EGD/PRNGD"; }

    /**
    * Gather Entropy from EGD
    */
    void poll(ref EntropyAccumulator accum)
    {
        __gshared immutable size_t READ_ATTEMPT = 32;
        
        SecureVector!ubyte* io_buffer = &accum.getIoBuffer(READ_ATTEMPT);
        
        ubyte[] io_buf_mutable = io_buffer.ptr[0 .. READ_ATTEMPT];
        foreach (socket; m_sockets[])
        {
            size_t got = socket.read(io_buf_mutable);
            
            if (got)
            {
                accum.add(io_buffer.ptr, got, 6);
                break;
            }
        }
    }

    /**
    * EGD_EntropySource constructor
    */
    this()(auto const ref Vector!string paths)
    {
        foreach (path; paths[])
            m_sockets.pushBack(EGDSocket(path));
    }
    ~this()
    {
        foreach (socket; m_sockets[]) {
            socket.close();
        }
        m_sockets.clear();
    }
private:
    struct EGDSocket
    {
    public:
        this(in string path)
        {
            m_socket_path = path;
            m_fd = -1;
        }


        void close()
        {
            if (m_fd > 0)
            {
                .close(m_fd);
                m_fd = -1;
            }
        }

        /**
        * Attempt to read entropy from EGD
        */
        size_t read(ref ubyte[] outbuf)
        {
            size_t length = outbuf.length;
            if (length == 0)
                return 0;
            
            if (m_fd < 0)
            {
                m_fd = openSocket(m_socket_path);
                if (m_fd < 0)
                    return 0;
            }

            try
            {
                // 1 == EGD command for non-blocking read
                ubyte[2] egd_read_command = [ 1, cast(ubyte)(std.algorithm.min(length, 255)) ];
                
                if (.write(m_fd, egd_read_command.ptr, 2) != 2)
                    throw new Exception("Writing entropy read command to EGD failed");
                
                ubyte out_len = 0;
                if (.read(m_fd, &out_len, 1) != 1)
                    throw new Exception("Reading response length from EGD failed");
                
                if (out_len > egd_read_command[1])
                    throw new Exception("Bogus length field received from EGD");
                
                ssize_t count = .read(m_fd, outbuf.ptr, out_len);
                
                if (count != out_len)
                    throw new Exception("Reading entropy result from EGD failed");
                
                return cast(size_t)(count);
            }
            catch(Exception e)
            {
                this.close();
                // Will attempt to reopen next poll
            }
            
            return 0;
        }

    private:
        /**
        * Attempt a connection to an EGD/PRNGD socket
        */
        static int openSocket(in string path)
        {
            logDebug("OpenSocket: ", path);
            int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
            
            if (fd >= 0)
            {
                sockaddr_un addr;
                memset(&addr, 0, (addr).sizeof);
                addr.sun_family = PF_LOCAL;
                
                if (addr.sun_path.sizeof < path.length + 1)
                    throw new InvalidArgument("EGD socket path is too long");
                
                strncpy(cast(char*) addr.sun_path.ptr, path.toStringz, addr.sun_path.sizeof);
                
                int len = cast(int)( addr.sun_family.sizeof + strlen(cast(const(char*))addr.sun_path.ptr) + 1 );
                
                if (.connect(fd, cast(sockaddr*)(&addr), len) < 0)
                {
                    .close(fd);
                    fd = -1;
                }
            }
            
            return fd;
        }

        string m_socket_path;
        int m_fd; // cached fd
    }

    Vector!EGDSocket m_sockets;
}