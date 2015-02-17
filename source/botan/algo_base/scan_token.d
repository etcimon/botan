/**
* SCAN Name Abstraction
* 
* Copyright:
* (C) 2008-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.algo_base.scan_token;

import botan.utils.parsing;
import botan.utils.exceptn;
import std.exception;
import std.array : Appender;
import botan.utils.types;
import std.conv : to;
import core.sync.mutex;
import memutils.hashmap;
import botan.constants;

/**
* A class encapsulating a SCAN name (similar to JCE conventions)
* http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
struct SCANToken
{
public:
    /**
    * Params:
    *  algo_spec = A SCAN-format name
    */
    this(string algo_spec)
    {
        m_args = Array!string();
        m_mode_info = Array!string();
        m_orig_algo_spec = algo_spec;
        
        Vector!( Pair!(size_t, string)  ) names;
        size_t level = 0;
        Array!ubyte def_buf;
        def_buf.reserve(8);
        auto accum = makePair(level, def_buf);
        
        string decoding_error = "Bad SCAN name '" ~ algo_spec ~ "': ";
        
        algo_spec = derefAlias(algo_spec);
        
        foreach (immutable(char) c; algo_spec)
        {

            if (c == '/' || c == ',' || c == '(' || c == ')')
            {
                if (c == '(')
                    ++level;
                else if (c == ')')
                {
                    if (level == 0)
                        throw new DecodingError(decoding_error ~ "Mismatched parens");
                    --level;
                }
                
                if (c == '/' && level > 0) {
                    accum.second ~= c;

                }
                else
                {
                    if (accum.second.length > 0) {
                        names ~= makePair(accum.first, derefAlias(cast(string)accum.second[]));
                    }
                    Array!ubyte str;
                    str.reserve(8);
                    accum = makePair(level, str);
                }
            }
            else {
                accum.second ~= c;
            }
        }
        
        if (accum.second.length > 0) {
            names ~= makePair(accum.first, derefAlias(cast(string)accum.second[]));
        }
        if (level != 0)
            throw new DecodingError(decoding_error ~ "Missing close paren");
        
        if (names.length == 0)
            throw new DecodingError(decoding_error ~ "Empty name");
        
        m_alg_name = names[0].second[].idup;

        if (names.length == 1)
            return;

        bool in_modes;
        size_t i = 1;
        foreach (name; names[1 .. $])
        {
            if (name.first == 0)
            {
                string val = makeArg(names, i);
                m_mode_info.pushBack(val);
                in_modes = true;
            }
            else if (name.first == 1 && !in_modes) { 
                string val = makeArg(names, i);
                m_args.pushBack(val);
            }
            i++;
        }
    }
    
    /**
    * Returns: original input string
    */
    string toString() const { return m_orig_algo_spec; }
    
    /**
    * Returns: algorithm name
    */
    @property string algoName() const { return m_alg_name; }
    
    /**
    * Returns: algorithm name plus any arguments
    */
    string algoNameAndArgs() const
    {
        Appender!string output;
        
        output ~= algoName;
        
        if (argCount())
        {
            output ~= '(';
            foreach (size_t i; 0 .. argCount())
            {
                output ~= arg(i);
                if (i != argCount() - 1)
                    output ~= ',';
            }
            output ~= ')';
            
        }
        
        return output.data;
    }
    
    /**
    * Returns: number of arguments
    */
    size_t argCount() const { return m_args.length; }
    
    /**
    * Params:
    *  lower = is the lower bound
    *  upper = is the upper bound
    * 
    * Returns: true if the number of arguments is between lower and upper
    */
    bool argCountBetween(size_t lower, size_t upper) const
    { return ((argCount() >= lower) && (argCount() <= upper)); }
    
    /**
    * Params:
    *  i = which argument
    * 
    * Returns: ith argument
    */
    string arg(size_t i) const
    {
        if (i >= argCount())
            throw new RangeError("SCANToken.argument - i out of range");
        return m_args[i];
    }
    
    /**
    * Params:
    *  i = which argument
    *  def_value = the default value
    * 
    * Returns: ith argument or the default value
    */
    string arg(size_t i, in string def_value) const
    {
        if (i >= argCount())
            return def_value;
        return m_args[i];
    }
    
    /**
    * Params:
    *  i = which argument
    *  def_value = the default value
    * 
    * Returns: ith argument as an integer, or the default value
    */
    size_t argAsInteger(size_t i, size_t def_value) const
    {
        if (i >= argCount())
            return def_value;
        return to!uint(m_args[i]);
    }
    
    /**
    * Returns: cipher mode (if any)
    */
    string cipherMode() const
    { return (m_mode_info.length >= 1) ? m_mode_info[0] : ""; }
    
    /**
    * Returns: cipher mode padding (if any)
    */
    string cipherModePad() const
    { return (m_mode_info.length >= 2) ? m_mode_info[1] : ""; }
    
    static void addAlias(string _alias, in string basename)
    {
        if (!s_alias_map.get(_alias, null))
            s_alias_map[_alias] = basename;
    }

    
    static string derefAlias(string input)
    {
        auto name = s_alias_map.get(input, null);
        if (name)
            return name;
        else
            return input.idup;
    }

    static void setDefaultAliases()
    {
        // common variations worth supporting
        addAlias("EME-PKCS1-v1_5",  "PKCS1v15");
        addAlias("3DES",            "TripleDES");
        addAlias("DES-EDE",         "TripleDES");
        addAlias("CAST5",           "CAST-128");
        addAlias("SHA1",            "SHA-160");
        addAlias("SHA-1",           "SHA-160");
        addAlias("MARK-4",          "RC4(256)");
        addAlias("ARC4",            "RC4");
        addAlias("OMAC",            "CMAC");
            
        addAlias("EMSA-PSS",        "PSSR");
        addAlias("PSS-MGF1",        "PSSR");
        addAlias("EME-OAEP",        "OAEP");
            
        addAlias("EMSA2",           "EMSA_X931");
        addAlias("EMSA3",           "EMSA_PKCS1");
        addAlias("EMSA-PKCS1-v1_5", "EMSA_PKCS1");
            
            // should be renamed in sources
        addAlias("X9.31",           "EMSA2");
            
            // kept for compatability with old library versions
        addAlias("EMSA4",           "PSSR");
        addAlias("EME1",            "OAEP");
            
            // probably can be removed
        addAlias("GOST",            "GOST-28147-89");
        addAlias("GOST-34.11",      "GOST-R-34.11-94");
    }
    

private:
    static HashMapRef!(string, string) s_alias_map;
    
    string m_orig_algo_spec;
    string m_alg_name;
    Array!string m_args;
    Array!string m_mode_info;
}

private:

string makeArg(ref Vector!(Pair!(size_t, string)) names, size_t start)
{
    Appender!string output;
    output ~= names[start].second;
    size_t level = names[start].first;

    size_t paren_depth = 0;

    foreach (name; names[(start + 1) .. $])
    {
        if (name.first <= names[start].first)
            break;

        if (name.first > level)
        {
            output ~= '(' ~ name.second;
            ++paren_depth;
        }
        else if (name.first < level)
        {
            output ~= ")," ~ name.second;
            --paren_depth;
        }
        else
        {
            if (output.data[output.data.length - 1] != '(')
                output ~= ",";
            output ~= name.second;
        }

        level = name.first;
    }

    foreach (size_t i; 0 .. paren_depth)
        output ~= ')';

    return output.data;
}