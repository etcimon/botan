/**
* Win32 EntropySource
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.es_win32;

version(Windows):
import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_WIN32):

import botan.entropy.entropy_src;

import core.sys.windows.windows;

/**
* Win32 Entropy Source
*/
final class Win32EntropySource : EntropySource
{
public:
    @property string name() const { return "Win32 Statistics"; }
    
    /**
    * Win32 poll using stats functions including Tooltip32
    */
    void poll(ref EntropyAccumulator accum)
    {
        /*
        First query a bunch of basic statistical stuff, though
        don't count it for much in terms of contributed entropy.
        */
        accum.add(GetTickCount(), 0);
        accum.add(GetMessagePos(), 0);
        accum.add(GetMessageTime(), 0);
        accum.add(GetInputState(), 0);
        accum.add(GetCurrentProcessId(), 0);
        accum.add(GetCurrentThreadId(), 0);
        
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        accum.add(sys_info, 1);
        
        MEMORYSTATUS mem_info;
        GlobalMemoryStatus(&mem_info);
        accum.add(mem_info, 1);
        
        POINT point;
        GetCursorPos(&point);
        accum.add(point, 1);
        
        GetCaretPos(&point);
        accum.add(point, 1);
        
        LARGE_INTEGER perf_counter;
        QueryPerformanceCounter(&perf_counter);
        accum.add(perf_counter, 0);
        
        /*
        Now use the Tooltip library to iterate throug various objects on
        the system, including processes, threads, and heap objects.
        */
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
        
        
        TOOLHELP32_ITER!(MODULEENTRY32, Module32First, Module32Next)(accum);
        TOOLHELP32_ITER!(PROCESSENTRY32, Process32First, Process32Next)(accum);
        TOOLHELP32_ITER!(THREADENTRY32, Thread32First, Thread32Next)(accum);
        
        
        if (!accum.polling_goal_achieved())
        {
            size_t heap_lists_found = 0;
            HEAPLIST32 heap_list;
            heap_list.dwSize = (HEAPLIST32).sizeof;
            
            __gshared immutable size_t HEAP_LISTS_MAX = 32;
            __gshared immutable size_t HEAP_OBJS_PER_LIST = 128;
            
            if (Heap32ListFirst(snapshot, &heap_list))
            {
                do
                {
                    accum.add(heap_list, 1);
                    
                    if (++heap_lists_found > HEAP_LISTS_MAX)
                        break;
                    
                    size_t heap_objs_found = 0;
                    HEAPENTRY32 heap_entry;
                    heap_entry.dwSize = (HEAPENTRY32).sizeof;
                    if (Heap32First(&heap_entry, heap_list.th32ProcessID,
                                    heap_list.th32HeapID))
                    {
                        do
                        {
                            if (heap_objs_found++ > HEAP_OBJS_PER_LIST)
                                break;
                            accum.add(heap_entry, 1);
                        } while(Heap32Next(&heap_entry));
                    }
                    
                    if (accum.polling_goal_achieved())
                        break;
                    
                } while(Heap32ListNext(snapshot, &heap_list));
            }
        }
        
        CloseHandle(snapshot);
    }
}



void TOOLHELP32_ITER(alias DATA_TYPE, alias FUNC_FIRST, alias FUNC_NEXT)(ref EntropyAccumulator accum) {
    if (!accum.polling_goal_achieved())
    {
        DATA_TYPE info;
        info.dwSize = (DATA_TYPE).sizeof;
        if (FUNC_FIRST(snapshot, &info))
        {
            do
            {
                accum.add(info, 1);
            } while(FUNC_NEXT(snapshot, &info));
        }
    }
}

import std.c.windows.windows;

extern(Windows) private nothrow @nogc:

enum : uint {
    HF32_DEFAULT = 1,
    HF32_SHARED
}

enum : uint {
    LF32_FIXED    = 0x1,
    LF32_FREE     = 0x2,
    LF32_MOVEABLE = 0x4
}

const MAX_MODULE_NAME32 = 255;

enum : uint {
    TH32CS_SNAPHEAPLIST = 0x1,
    TH32CS_SNAPPROCESS  = 0x2,
    TH32CS_SNAPTHREAD   = 0x4,
    TH32CS_SNAPMODULE   = 0x8,
    TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST|TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD|TH32CS_SNAPMODULE),
    TH32CS_INHERIT      = 0x80000000
}

struct HEAPLIST32 {
    DWORD dwSize;
    DWORD th32ProcessID;
    DWORD th32HeapID;
    DWORD dwFlags;
} 
alias HEAPLIST32* PHEAPLIST32;
alias HEAPLIST32* LPHEAPLIST32;

struct HEAPENTRY32 {
    DWORD dwSize;
    HANDLE hHandle;
    DWORD dwAddress;
    DWORD dwBlockSize;
    DWORD dwFlags;
    DWORD dwLockCount;
    DWORD dwResvd;
    DWORD th32ProcessID;
    DWORD th32HeapID;
}
alias HEAPENTRY32* PHEAPENTRY32;
alias HEAPENTRY32* LPHEAPENTRY32;

struct PROCESSENTRY32W {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    DWORD th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    WCHAR[MAX_PATH] szExeFile;
}
alias PROCESSENTRY32W* PPROCESSENTRY32W;
alias PROCESSENTRY32W* LPPROCESSENTRY32W;

struct THREADENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG tpBasePri;
    LONG tpDeltaPri;
    DWORD dwFlags;
}
alias THREADENTRY32* PTHREADENTRY32;
alias THREADENTRY32* LPTHREADENTRY32;

struct MODULEENTRY32W {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule; 
    WCHAR[MAX_MODULE_NAME32 + 1] szModule;
    WCHAR[MAX_PATH] szExePath;
}
alias MODULEENTRY32W* PMODULEENTRY32W;
alias MODULEENTRY32W* LPMODULEENTRY32W;

struct PROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    DWORD th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR[MAX_PATH]  szExeFile;
}
alias PROCESSENTRY32* PPROCESSENTRY32;
alias PROCESSENTRY32* LPPROCESSENTRY32;

struct MODULEENTRY32 {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    char[MAX_MODULE_NAME32 + 1] szModule;
    char[MAX_PATH] szExePath;
}
alias MODULEENTRY32* PMODULEENTRY32;
alias MODULEENTRY32* LPMODULEENTRY32;

BOOL Heap32First(LPHEAPENTRY32,DWORD,DWORD);
BOOL Heap32ListFirst(HANDLE,LPHEAPLIST32);
BOOL Heap32ListNext(HANDLE,LPHEAPLIST32);
BOOL Heap32Next(LPHEAPENTRY32);
BOOL Thread32First(HANDLE,LPTHREADENTRY32);
BOOL Thread32Next(HANDLE,LPTHREADENTRY32);
BOOL Toolhelp32ReadProcessMemory(DWORD,LPCVOID,LPVOID,DWORD,LPDWORD);
HANDLE CreateToolhelp32Snapshot(DWORD,DWORD);
BOOL Module32FirstW(HANDLE,LPMODULEENTRY32W);
BOOL Module32NextW(HANDLE,LPMODULEENTRY32W);
BOOL Process32FirstW(HANDLE,LPPROCESSENTRY32W);
BOOL Process32NextW(HANDLE,LPPROCESSENTRY32W);

BOOL Module32First(HANDLE,LPMODULEENTRY32);
BOOL Module32Next(HANDLE,LPMODULEENTRY32);
BOOL Process32First(HANDLE,LPPROCESSENTRY32);
BOOL Process32Next(HANDLE,LPPROCESSENTRY32);
