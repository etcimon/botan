/**
* Global State Management
* 
* Copyright:
* (C) 2010 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.libstate.global_state;
import botan.constants;
import botan.libstate.libstate;
/// Thread-Local, no locks needed.
private LibraryState g_lib_state;

/**
* Access the global library state
* Returns: reference to the global library state
*/
LibraryState globalState()
{
    if (!g_lib_state) { 

        g_lib_state = new LibraryState;
        /* Lazy initialization. Botan still needs to be deinitialized later
            on or memory might leak.
        */
        try g_lib_state.initialize();
        catch (Throwable e){
            logError(e.toString());
            foreach(line; e.info) { logError(line); }
            assert(false);
        }
    }
    return g_lib_state;
}

/**
* Set the global state object
* Params:
*  state = the new global state to use
*/
void setGlobalState(LibraryState new_state)
{
    if (g_lib_state) destroy(g_lib_state);
    g_lib_state = new_state;
}


/**
* Set the global state object unless it is already set
* Params:
*  state = the new global state to use
* Returns: true if the state parameter is now being used as the global
*            state, or false if one was already set, in which case the
*            parameter was deleted immediately
*/
bool setGlobalStateUnlessSet(LibraryState new_state)
{
    if (g_lib_state)
    {
        return false;
    }
    else
    {
        g_lib_state = new_state;
        return true;
    }
}

/**
* Query if the library is currently initialized
* Returns: true iff the library is initialized
*/
bool globalStateExists()
{
    return (g_lib_state !is LibraryState.init);
}

static ~this() {
    import core.thread : thread_isMainThread;
    if (g_lib_state) destroy(g_lib_state); 
}
