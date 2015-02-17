/**
* Library Initialization
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.libstate.init;

import botan.libstate.libstate;
import botan.libstate.global_state;

/**
* This class represents the Library Initialization/Shutdown Object. It
* has to exceed the lifetime of any Botan object used in an
* application.  You can call initialize/deinitialize or use
* LibraryInitializer in the RAII style.
*/
struct LibraryInitializer
{
public:
    /**
    * Initialize the library
    * Params:
    *  options = a string listing initialization options
    */
    static void initialize()
    {
        
        try
        {
            setGlobalState(LibraryState.init);
            
            globalState().initialize();
        }
        catch (Throwable)
        {
            deinitialize();
            throw new Exception("Library innullitialization failed");
        }
    }

    /**
    * Shutdown the library
    */
    static void deinitialize() {
        setGlobalState(LibraryState.init);
    }

    /**
    * Initialize the library
    * Params:
    *  options = a string listing initialization options
    */
    this(string options = "")  { LibraryInitializer.initialize(); }

    ~this() { LibraryInitializer.deinitialize(); }
}
