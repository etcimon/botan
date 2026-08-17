/**
* Unit test helper
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.test;

import botan.constants;
//static if (BOTAN_TEST):

public import std.stdio : File, writeln;
public import std.algorithm : sort, canFind;
public import std.range : walkLength;
public import std.string : indexOf, lastIndexOf;
public import botan.utils.types;
private import botan.libstate.libstate;
import memutils.constants : HasDebugAllocations;
import memutils.hashmap;
import std.file;
import std.array;
import std.exception;
import std.datetime.stopwatch : StopWatch;
import std.datetime.date;
import std.datetime.interval;

@property bool ok(File f) { return f.isOpen && !f.eof() && !f.error(); }

string CHECK_MESSAGE (string expr, string print) {
    return "
    {
        import core.atomic : atomicOp;
        static if (is(typeof(total_tests) == shared)) atomicOp!`+=`(total_tests, cast(size_t) 1);
        else total_tests++;
        try { 
            if (!(" ~ expr ~ ")) { 
                ++fails; 
                logError( `" ~ print ~ "` ); 
            } 
        } 
        catch(Exception e) 
        { 
            logError(__FUNCTION__, ` : ` ~ e.msg); 
        }
    }";
}

string CHECK (string expr) {
    return `
    {
        import core.atomic : atomicOp;
        static if (is(typeof(total_tests) == shared)) atomicOp!"+="(total_tests, cast(size_t) 1);
        else total_tests++;
        mixin( q{
            bool success = ` ~ expr ~ `;
        } );
        try { 
            if (!success)
            { ++fails; logError( q{ ` ~ expr ~ ` } ); } 
        } 
        catch(Exception e) 
        { 
            logError(__FUNCTION__ ~ " : " ~ e.msg); 
        }
    }`;
}


string[] listDir(string dir_path)
{
    auto dirfiles = dirEntries(dir_path, "*.vec", SpanMode.depth);
    string[] files;
    foreach(file; dirfiles) {
        files ~= file.name;
    }
    files.sort();
    return files;
}

StopWatch g_sw;

size_t runTestsInDir(string dir, size_t delegate(string) fn)
{

    assert(exists(cast(char[])dir), "Directory `" ~ dir ~ "` does not exist");
    logTrace("Running tests for directory: " ~ dir);
    import std.parallelism;
    import core.atomic;
    shared(size_t) shared_fails;
    auto dirs = listDir(dir);
    foreach (vec; dirs) {
        size_t local_fails = fn(vec);
        if (local_fails > 0) {
            assert(false);
        }
        atomicOp!"+="(shared_fails, local_fails);
    }
    return cast(size_t)atomicLoad(shared_fails);
}

void testReport(string name, size_t ran, size_t failed)
{    
	static long last_msecs;
    if (failed)
        logError(name, " ... ", failed, " / ", ran, " ************** FAILED ****************");
    else
		logDebug(name, " ... PASSED (all of ", ran, " tests in ", g_sw.peek().total!"msecs" - last_msecs, " msecs)");
	last_msecs = g_sw.peek().total!"msecs";
}

/// Snapshot of memutils DebugAllocator live bytes (0/0 when the debugger is off).
struct MemutilsSnap
{
    size_t lockless;
    size_t cryptosafe;
}

/// Collect GC-owned objects that hold Vector/Unique, then read DebugAllocator counters.
MemutilsSnap takeMemutilsSnap()
{
    MemutilsSnap s;
    static if (HasDebugAllocations)
    {
        import core.memory : GC;
        import memutils.allocators : getAllocator, LocklessAllocator, CryptoSafeAllocator;
        GC.collect();
        GC.minimize();
        s.lockless = getAllocator!LocklessAllocator().bytesAllocated();
        s.cryptosafe = getAllocator!CryptoSafeAllocator().bytesAllocated();
    }
    return s;
}

/**
* Extra live bytes vs `before` after another collect.
* Factory caches / LibraryState must already be in `before` (call after globalState()).
* Returns 0 when HasDebugAllocations is false.
*/
size_t memutilsGrowth(MemutilsSnap before, string label = "")
{
    static if (!HasDebugAllocations)
        return 0;
    else
    {
        auto after = takeMemutilsSnap();
        const grow_l = after.lockless > before.lockless ? after.lockless - before.lockless : 0;
        const grow_c = after.cryptosafe > before.cryptosafe ? after.cryptosafe - before.cryptosafe : 0;
        if ((grow_l || grow_c) && label.length)
            logError("memutils growth ", label, ": lockless +", grow_l,
                     " cryptosafe +", grow_c,
                     " (now ", after.lockless, "/", after.cryptosafe, ")");
        return grow_l + grow_c;
    }
}

/**
* Warm `body` once (factory / first-use caches), then run it again.
* Returns 1 if DebugAllocator live bytes grew. `body` must Unique-wrap
* anything that holds Vector/Unique so teardown is not a GC finalizer.
*/
size_t checkMemutilsRepeat(string label, void delegate() body)
{
    body();
    auto snap = takeMemutilsSnap();
    body();
    return memutilsGrowth(snap, label) ? 1 : 0;
}

static if (HasDebugAllocations)
{
    import memutils.allocators : getAllocator, LocklessAllocator;
    private __gshared int[size_t] g_memutils_net;
    private void memutilsNetAlloc(size_t sz) { g_memutils_net[sz] = g_memutils_net.get(sz, 0) + 1; }
    private void memutilsNetFree(size_t sz) { g_memutils_net[sz] = g_memutils_net.get(sz, 0) - 1; }
}

/// Hook DebugAllocator size callbacks. Call `memutilsNetStop` after the region of interest.
void memutilsNetStart()
{
    static if (HasDebugAllocations)
    {
        g_memutils_net = null;
        getAllocator!LocklessAllocator().setAllocSizeCallbacks(&memutilsNetAlloc, &memutilsNetFree);
    }
}

/// Unhook callbacks and log sizes whose alloc count != free count.
void memutilsNetStop(string label)
{
    static if (HasDebugAllocations)
    {
        getAllocator!LocklessAllocator().setAllocSizeCallbacks(null, null);
        foreach (sz, n; g_memutils_net)
            if (n)
                logError("memutils net ", label, ": ", n, " x ", sz, " B");
        g_memutils_net = null;
    }
}

size_t runTestsBb(ref File src,
                  string name_key,
                  string output_key,
                  bool clear_between_cb,
                  size_t delegate(ref HashMap!(string, string)) cb)
{

    if (src.eof || src.error)
    {
        logError("Could not open input file for " ~ name_key);
        return 1;
    }
	if (!g_sw.running)
		g_sw.start();
    HashMap!(string, string) vars;
    vars[name_key] = name_key;
    size_t test_fails = 0, algo_fail = 0;
    size_t test_count = 0, algo_count = 0;
    
    string fixed_name = name_key;
    
    string line;

    while(!src.eof && !src.error)
    {

        line = src.readln();
        if (line.length && line[$-1] == '\n')
            line = line[0 .. $-1];
        if (line.length && line[$-1] == '\r')
            line = line[0 .. $-1];

        if (line.length == 0)
            continue;

        if (line[0] == '#')
            continue;
        
        if (line[0] == '[' && line[$-1] == ']')
        {
            if (fixed_name != "" && algo_count > 0)
                testReport(fixed_name, algo_count, algo_fail);
            
            test_count += algo_count;
            test_fails += algo_fail;
            algo_count = 0;
            algo_fail = 0;
            fixed_name = line[1 .. $ - 1];
            vars[name_key] = fixed_name;
            continue;
        }
        import std.string : strip;
        const eq = line.indexOf('=');
        if (eq < 1) continue;
        const string key = line[0 .. eq].strip;
        string val = (eq + 1 < line.length) ? line[eq + 1 .. $].strip : "";
        if (!key.length) continue;
        
        vars[key] = val;
        
        if (key == name_key)
            fixed_name.length = 0;
        
        if (key == output_key)
        {
            ++algo_count;
            try
            {
                const size_t fails = cb(vars);
                if (fails)
                {
                    logError(vars[name_key] ~ " test ", algo_count, " : ", fails, " failure");
                    algo_fail += fails;
                }
            }
            catch(Exception e)
            {
                logError(vars[name_key] ~ " test ", algo_count, " failed: " ~ e.msg);
                ++algo_fail;
                assert(false);
            }
            
            if (clear_between_cb)
            {
                vars.clear();
                vars[name_key] = fixed_name;
            }
        }
    }
    test_count += algo_count;
    test_fails += algo_fail;
    
    if (fixed_name != "" && (algo_count > 0 || algo_fail > 0))
        testReport(fixed_name, algo_count, algo_fail);
    else
        testReport(name_key, test_count, test_fails);
    
    return test_fails;
}

size_t runTests(string filename,
                 string name_key,
                 string output_key,
                 bool clear_between_cb,
                 string delegate(ref HashMap!(string, string)) cb)
{
    File vec = File(filename, "r");

    if (vec.error || vec.eof)
    {
        logError("Failure opening " ~ filename);
        return 1;
    }
    
    return runTests(vec, name_key, output_key, clear_between_cb, cb);
}

size_t runTests(ref File src,
                 string name_key,
                 string output_key,
                 bool clear_between_cb,
                 string delegate(ref HashMap!(string, string)) cb)
{
    return runTestsBb(src, name_key, output_key, clear_between_cb, 
        (ref HashMap!(string, string) vars)
        {
            const string got = cb(vars);
            if (got != vars[output_key])
            {
                logTrace(name_key ~ ' ' ~ vars[name_key] ~ " got " ~ got ~ " expected " ~ vars[output_key]);
                return 1;
            }
            return 0;
        });
}
