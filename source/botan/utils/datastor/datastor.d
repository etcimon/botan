/**
* Data Store
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.datastor.datastor;
import botan.constants;
public import botan.utils.exceptn;
import botan.utils.parsing;
import botan.codec.hex;
import memutils.dictionarylist;
import memutils.vector;
import botan.utils.types;
import memutils.hashmap;
import std.traits : isNumeric;
import std.conv : to;

/**
* Data Store
*/
struct DataStore
{
public:
    /*
    * DataStore Equality Comparison
    */
    bool opEquals(in DataStore other) const
    {
        return (m_contents == other.m_contents);
    }

    /*
    * Search based on an arbitrary predicate
    */
    DictionaryListRef!(string, string) searchFor(bool delegate(string, string) predicate) const
    {
        DictionaryListRef!(string, string) output;

        foreach (const ref string key, const ref string val; m_contents)
            if (predicate(key, val))
                output.insert(key, val);
        
        return output;
    }

    /*
    * Search based on key equality
    */
    Vector!string get(in string looking_for) const
    {
        Vector!string output;
        foreach (const ref string k, const ref string v; m_contents) {
            if (looking_for == k)
                output.pushBack(v);
        }
        return output.move;
    }


    /*
    * Get a single atom
    */
    string get1(in string key) const
    {
        Vector!string vals = get(key);
        
        if (vals.empty)
            throw new InvalidState("get1: No values set for " ~ key);
        if (vals.length > 1)
            throw new InvalidState("get1: More than one value for " ~ key);
        
        return vals[0];
    }

    string get1(in string key,
                in string default_value) const
    {
        Vector!string vals = get(key);
        
        if (vals.length > 1)
            throw new InvalidState("get1: More than one value for " ~ key);
        
        if (vals.empty)
            return default_value;
        
        return vals[0];
    }

    /*
    * Get a single std::vector atom
    */
    Vector!ubyte
        get1Memvec(in string key) const
    {
        Vector!string vals = get(key);
        
        if (vals.empty)
            return Vector!ubyte();
        
        if (vals.length > 1)
            throw new InvalidState("get1_memvec: Multiple values for " ~  key);
        
        return hexDecode(vals[0]);
    }

    /*
    * Get a single uint atom
    */
    uint get1Uint(in string key, uint default_val = 0) const
    {
        Vector!string vals = get(key);
        
        if (vals.empty)
            return default_val;
        else if (vals.length > 1)
            throw new InvalidState("get1_uint: Multiple values for " ~ key);
        return to!uint(vals[0]);
    }

    /*
    * Check if this key has at least one value
    */
    bool hasValue(in string key) const
    {
        return (m_contents.get(key, string.init) != string.init);
    }
    
    /*
    * Insert a single key and value
    */
    void add(in string key, in string val)
    {
        m_contents.insert(key.idup, val.idup);
    }
    
    /*
    * Insert a single key and value
    */
    void add(T)(in string key, in T val)
        if (isNumeric!T)
    {
        add(key.idup, to!string(cast(long)val));
    }
    
    /*
    * Insert a single key and value
    */
    void add(ALLOC)(in string key, auto const ref Vector!(ubyte, ALLOC) val)
    {
        add(key.idup, hexEncode(val.ptr, val.length));
    }
    
    void add(ALLOC)(in string key, auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) val)
    {
        add(key.idup, hexEncode(val.ptr, val.length));
    }
    
    /*
    * Insert a mapping of key/value pairs
    */
    void add(in DictionaryListRef!(string, string) input)
    {
        foreach (const ref string k, const ref string v; input)
            m_contents.insert(k.idup, v.idup);
    }

    string toString() const {
        Vector!ubyte buffer;
        foreach (const ref string k, const ref string v; m_contents) {
            buffer ~= "Key: ";
            buffer ~= k;
            buffer ~= ", Value: ";
            buffer ~= v;
            buffer ~= "\n";
        }
        return buffer[].idup;
    }

private:
    DictionaryListRef!(string, string) m_contents;
}