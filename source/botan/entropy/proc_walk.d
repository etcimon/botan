/**
* File Tree Walking EntropySource
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.proc_walk;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_PROC_WALKER):

import botan.entropy.entropy_src;
import memutils.vector;
import botan.utils.types;
import core.stdc.string;
import core.stdc.config;
import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.sys.posix.dirent;
import std.string : toStringz;
import std.array;

final class DirectoryWalker : FileDescriptorSource
{
public:
    this(in string root) 
    {
        m_cur_dir = makePair!(DIR*, string)(null, "");
        if (DIR* root_dir = opendir(root.toStringz))
            m_cur_dir = makePair(root_dir, root);
    }
    
    ~this()
    {
        if (m_cur_dir.first)
            closedir(m_cur_dir.first);
    }
    
    override int nextFd() 
    {
        while (true)
        {
            Pair!(dirent*, string) entry = getNextDirent();
            
            if (!entry.first)
                break; // no more dirs
            
            const string filename = cast(string) entry.first.d_name[0 .. strlen(entry.first.d_name.ptr)];
            
            if (filename == "." || filename == "..")
                continue;
            
            const string full_path = entry.second ~ '/' ~ filename;
            
            stat_t stat_buf;
            if (.lstat(full_path.toStringz, &stat_buf) == -1)
                continue;
            
            if (S_ISDIR(stat_buf.st_mode))
            {
                addDirectory(full_path);
            }
            else if (S_ISREG(stat_buf.st_mode) && (stat_buf.st_mode & S_IROTH))
            {
                int fd = .open(full_path.toStringz, O_RDONLY | O_NOCTTY);
                
                if (fd > 0)
                    return fd;
            }
        }
        
        return -1;
    }

private:
    void addDirectory(in string dirname)
    {
        m_dirlist.insertBack(dirname);
    }
    
    Pair!(dirent*, string) getNextDirent()
    {
        while (m_cur_dir.first)
        {
            if (dirent* dir = readdir(m_cur_dir.first))
                return makePair(dir, m_cur_dir.second);
            
            closedir(m_cur_dir.first);
            m_cur_dir = makePair!(DIR*, string)(null, "");
            
            while (!m_dirlist.empty && !m_cur_dir.first)
            {
                const string next_dir_name = m_dirlist.front;
                m_dirlist = Vector!string(m_dirlist[1 .. $]);
                
                if (DIR* next_dir = opendir(next_dir_name.toStringz))
                    m_cur_dir = makePair(next_dir, next_dir_name);
            }
        }
        
        return Pair!(dirent*, string)(); // nothing left
    }
    
    Pair!(DIR*, string) m_cur_dir;
    Vector!string m_dirlist;
}


interface FileDescriptorSource
{
public:
    abstract int nextFd();

}

/**
* File Tree Walking Entropy Source
*/
final class ProcWalkingEntropySource : EntropySource
{
public:
    @property string name() const { return "Proc Walker"; }

    void poll(ref EntropyAccumulator accum)
    {
        __gshared immutable size_t MAX_FILES_READ_PER_POLL = 2048;
        const double ENTROPY_ESTIMATE = 1.0 / (8*1024);
        
        if (!m_dir)
            m_dir = new DirectoryWalker(m_path);
        
        SecureVector!ubyte* io_buffer = &accum.getIoBuffer(4096);
        foreach (size_t i; 0 .. MAX_FILES_READ_PER_POLL)
        {
            int fd = m_dir.nextFd();
            
            // If we've exhaused this walk of the directory, halt the poll
            if (fd == -1)
            {
                destroy(m_dir);
                m_dir = null;
                break;
            }
            
            ssize_t got = .read(fd, io_buffer.ptr, 4096);
            close(fd);
            
            if (got > 0)
                accum.add(io_buffer.ptr, got, ENTROPY_ESTIMATE);
            
            if (accum.pollingGoalAchieved())
                break;
        }
    }

    this(in string root_dir)
    {
        m_path = root_dir;
    }

    ~this() { if (m_dir) destroy(m_dir); }

private:
    const string m_path;
    FileDescriptorSource m_dir;
}

@nogc nothrow pure private:
bool S_ISTYPE( mode_t mode, uint mask ) { return ( mode & S_IFMT ) == mask; }
bool S_ISDIR( mode_t mode )  { return S_ISTYPE( mode, S_IFDIR );  }
bool S_ISREG( mode_t mode )  { return S_ISTYPE( mode, S_IFREG );  }