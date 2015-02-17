/**
* Unit test helper
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.test;

import botan.constants;
static if (BOTAN_TEST):

public import std.stdio : File, writeln;
public import std.algorithm : sort, canFind, walkLength;
public import std.string : indexOf, lastIndexOf;
public import botan.utils.types;
public import botan.libstate.libstate;
import memutils.hashmap;
import std.file;
import std.array;
import std.exception;

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
    if (failed)
        logError(name, " ... ", failed, " / ", ran, " ************** FAILED ****************");
    else
        logDebug(name, " ... PASSED (all of ", ran, " tests)");
}

size_t runTestsBb(ref File src,
                  string name_key,
                  string output_key,
                  bool clear_between_cb,
                  size_t delegate(ref HashMap!(string, string)) cb)
{
    if(src.eof || src.error)
    {
        logError("Could not open input file for " ~ name_key);
        return 1;
    }
    
    HashMap!(string, string) vars;
    vars[name_key] = name_key;
    size_t test_fails = 0, algo_fail = 0;
    size_t test_count = 0, algo_count = 0;
    
    string fixed_name = name_key;
    
    string line;

    while(!src.eof && !src.error)
    {

        line = src.readln();
        if (line.length > 0)
            line = line[0 .. $-1];

        if (line.length == 0)
            continue;

        if(line[0] == '#')
            continue;
        
        if(line[0] == '[' && line[$-1] == ']')
        {
            if(fixed_name != "" && algo_count > 0)
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
        if (line.indexOf('=') == -1) continue;
        assert(line[line.indexOf('=') - 1] == ' ' && line[line.indexOf('=') + 1] == ' ', "= must be wrapped with spaces");
        const string key = line[0 .. line.indexOf('=') - 1].strip;
        const string val = line[line.indexOf('=') + 2 .. $].strip;
        
        vars[key] = val;
        
        if(key == name_key)
            fixed_name.length = 0;
        
        if(key == output_key)
        {
            //logTrace(vars[name_key] " ~ " ~ algo_count);
            ++algo_count;
            try
            {
                const size_t fails = cb(vars);
                if(fails)
                {
                    logTrace(vars[name_key] ~ " test ", algo_count, " : ", fails, " failure");
                    algo_fail += fails;
                }
            }
            catch(Exception e)
            {
                logTrace(vars[name_key] ~ " test ", algo_count, " failed: " ~ e.msg);
                ++algo_fail;
                assert(false);
            }
            
            if(clear_between_cb)
            {
                vars.clear();
                vars[name_key] = fixed_name;
            }
        }
    }
    
    test_count += algo_count;
    test_fails += algo_fail;
    
    if(fixed_name != "" && (algo_count > 0 || algo_fail > 0))
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
    
    if(vec.error || vec.eof)
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
            if(got != vars[output_key])
            {
                logTrace(name_key ~ ' ' ~ vars[name_key] ~ " got " ~ got ~ " expected " ~ vars[output_key]);
                return 1;
            }
            return 0;
        });
}