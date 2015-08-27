/**
* SRP-6a File Handling
* 
* Copyright:
* (C) 2011 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.srp6_files;

import botan.constants;
static if (BOTAN_HAS_SRP6):
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.utils.mem_ops;
import botan.codec.base64;
import memutils.hashmap;
import std.stdio;
import std.array;

/**
* A GnuTLS compatible SRP6 authenticator file
*/
final class SRP6AuthenticatorFile
{
public:
    /**
    * Params:
    *  filename = will be opened and processed as a SRP
    * authenticator file
    */
    this(in string filename)
    {
        auto file = File(filename);
        auto range = file.byLine();
        
        foreach (line; range) {    
            string[] parts = cast(string[])line.split(':');
            
            if (parts.length != 4)
                throw new DecodingError("Invalid line in SRP authenticator file");
            
            string username = parts[0];
            BigInt v = BigInt.decode(base64Decode(parts[1]));
            Vector!ubyte salt = unlock(base64Decode(parts[2]));
            BigInt group_id_idx = BigInt.decode(base64Decode(parts[3]));
            
            string group_id;
            
            if (group_id_idx == 1)
                group_id = "modp/srp/1024";
            else if (group_id_idx == 2)
                group_id = "modp/srp/1536";
            else if (group_id_idx == 3)
                group_id = "modp/srp/2048";
            else
                continue; // unknown group, ignored
            
            m_entries[username] = SRP6Data(&v, &salt, group_id);
        }
    }

    bool lookupUser(in string username,
                    ref BigInt v,
                    ref Vector!ubyte salt,
                    ref string group_id) const
    {
        SRP6Data entry = m_entries.get(username);
        if (*entry == SRP6DataImpl.init)
            return false;

        v = entry.v.dup;
        salt = entry.salt.dup;
        group_id = entry.group_id;
        
        return true;
    }

private:
    alias SRP6Data = RefCounted!SRP6DataImpl;
    struct SRP6DataImpl
    {

        this(BigInt* _v,
             Vector!ubyte* _salt,
             in string _group_id) 
        {
            v = (*_v).move();
            salt = (*_salt).move(); 
            group_id = _group_id;
        }

        BigInt v;
        Vector!ubyte salt;
        string group_id;
    }

    HashMapRef!(string, SRP6Data) m_entries;
}