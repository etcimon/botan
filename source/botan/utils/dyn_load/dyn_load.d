/**
* Dynamically Loaded Object
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.dyn_load.dyn_load;
//todo : Mac OSX
import std.exception;
import std.string : toStringz, fromStringz;
version(linux)
    import core.sys.linux.dlfcn;
version(Windows)
    import std.c.windows.windows;

void raiseRuntimeLoaderException(in string lib_name, string msg)
{
    throw new Exception("Failed to load " ~ lib_name ~ ": " ~ (msg ? msg : "Unknown error"));
}

/**
* Represents a DLL or shared object
*/
class DynamicallyLoadedLibrary
{
public:
    /**
    * Load a DLL (or fail with an exception)
    * Params:
    *  lib_name = name or path to a library
    *
    * If you don't use a full path, the search order will be defined
    * by whatever the system linker does by default. Always using fully
    * qualified pathnames can help prevent code injection attacks (eg
    * via manipulation of LD_LIBRARY_PATH on Linux)
    */
    this(in string library)
    {
        lib_name = library;
        
        version(linux) {
            lib = dlopen(lib_name.toStringz, RTLD_LAZY);
            
            if (!lib)
                raiseRuntimeLoaderException(lib_name, cast(string)fromStringz(dlerror()));
            
        }
        version(Windows) {
            
            lib = LoadLibraryA(lib_name.toStringz);
            
            if (!lib)
                raiseRuntimeLoaderException(lib_name, "LoadLibrary failed");
        }
        
        if (!lib)
            raiseRuntimeLoaderException(lib_name, "Dynamic load not supported");
    }

    /**
    * Unload the DLL
    * Notes:
    * Any pointers returned by resolve()/resolveSymbol()
    * should not be used after this destructor runs.
    */
    ~this()
    {
        version(linux)
            dlclose(lib);
        version(Windows)
            FreeLibrary(cast(HMODULE)lib);
    }

    /**
    * Load a symbol (or fail with an exception)
    * Params:
    *  symbol = names the symbol to load
    * Returns: address of the loaded symbol
    */
    void* resolveSymbol(in string symbol)
    {
        void* addr = null;
        
        version(linux)
            addr = dlsym(lib, symbol.toStringz);
        version(Windows)
            addr = cast(void*)(GetProcAddress(cast(HMODULE)lib, symbol.toStringz));
        if (!addr)
            throw new Exception("Failed to resolve symbol " ~ symbol ~ " in " ~ lib_name);
        
        return addr;
    }

    /**
    * Convenience function for casting symbol to the right type
    * Params:
    *  symbol = names the symbol to load
    * Returns: address of the loaded symbol
    */
    T resolve(T)(in string symbol)
    {
        return cast(T)(resolveSymbol(symbol));
    }

private:
    string lib_name;
    void* lib;
}