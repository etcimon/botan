/**
* Pipe I/O for Unix
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.fd_unix;
version(none):
import botan.filters.pipe;
import botan.utils.exceptn;
import core.sys.posix.unistd;

// TODO: make this work?


/*
* Stream output operator; dumps the results from pipe's default
* message to the output stream.
* Params:
*  output = file descriptor for an open output stream
*  pipe = the pipe
*/
/*int operator<<(int fd, Pipe& pipe)
{
    SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
    while (pipe.remaining())
    {
        size_t got = pipe.read(buffer.ptr, buffer.length);
        size_t position = 0;
        while (got)
        {
            ssize_t ret = write(fd, &buffer[position], got);
            if (ret == -1)
                throw new Stream_IO_Error("Pipe output operator (unixfd) has failed");
            position += ret;
            got -= ret;
        }
    }
    return fd;
}*/

/*
* File descriptor input operator; dumps the remaining bytes of input
* to the (assumed open) pipe message.
* Params:
*  input = file descriptor for an open input stream
*  pipe = the pipe
*/
/*int opBinary(string op)(int fd, ref Pipe pipe)
{
    SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
    while (true)
    {
        ssize_t ret = read(fd, buffer.ptr, buffer.length);
        if (ret == 0) break;
        if (ret == -1)
            throw new Stream_IO_Error("Pipe input operator (unixfd) has failed");
        pipe.write(buffer.ptr, ret);
    }
    return fd;
}
*/