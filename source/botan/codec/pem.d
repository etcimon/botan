/**
* PEM Encoding/Decoding
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/

module botan.codec.pem;
import botan.filters.filters;
import botan.utils.parsing;
import botan.filters.data_src;
import botan.filters.b64_filt;
import botan.utils.types;
import std.array : Appender;
import botan.constants;

struct PEM
{

    /**
    * Encode some binary data in PEM format
    */
    static string encode(const(ubyte)* der, size_t length, in string label, size_t width = 64)
    {
        immutable(string) PEM_HEADER = "-----BEGIN " ~ label ~ "-----\n";
        immutable(string) PEM_TRAILER = "-----END " ~ label ~ "-----\n";
        
        Pipe pipe = Pipe(new Base64Encoder(true, width));
        pipe.processMsg(der, length);
        return (PEM_HEADER ~ pipe.toString() ~ PEM_TRAILER);
    }

    /**
    * Encode some binary data in PEM format
    */
    static string encode(ALLOC)(auto const ref Vector!(ubyte, ALLOC) data, 
                                    in string label, size_t line_width = 64)
    {
        return encode(data.ptr, data.length, label, line_width);
    }

    /**
    * Encode some binary data in PEM format
    */
    static string encode(ALLOC)(auto const ref RefCounted!(Vector!(ubyte, ALLOC), ALLOC) data, 
                                    in string label, size_t line_width = 64)
    {
        return encode(data.ptr, data.length, label, line_width);
    }

    /**
    * Decode PEM data
    * Params:
    *  pem = a datasource containing PEM encoded data
    *  label = is set to the PEM label found for later inspection
    */
    /*
    * Decode PEM down to raw BER/DER
    */
    static SecureVector!ubyte decode(DataSource source, ref string label)
    {
        //logTrace("PEM decode");
        Appender!string label_buf;
        __gshared immutable size_t RANDOM_CHAR_LIMIT = 8;
        
        const string PEM_HEADER1 = "-----BEGIN ";
        const string PEM_HEADER2 = "-----";
        size_t position = 0;
        
        while (position != PEM_HEADER1.length)
        {
            ubyte b;
            if (!source.readByte(b))
                throw new DecodingError("PEM: No PEM header found");
            if (b == PEM_HEADER1[position])
                ++position;
            else if (position >= RANDOM_CHAR_LIMIT)
                throw new DecodingError("PEM: Malformed PEM header");
            else
                position = 0;
        }
        position = 0;
        while (position != PEM_HEADER2.length)
        {
            ubyte b;
            if (!source.readByte(b))
                throw new DecodingError("PEM: No PEM header found");
            if (b == PEM_HEADER2[position])
                ++position;
            else if (position)
                throw new DecodingError("PEM: Malformed PEM header");
            
            if (position == 0)
                label_buf ~= cast(char) b;
        }
        label = label_buf.data;

        Pipe base64 = Pipe(new Base64Decoder);
        base64.startMsg();
        const string PEM_TRAILER = "-----END " ~ label ~ "-----";
        position = 0;
        while (position != PEM_TRAILER.length)
        {
            ubyte b;
            if (!source.readByte(b))
                throw new DecodingError("PEM: No PEM trailer found");
            if (b == PEM_TRAILER[position])
                ++position;
            else if (position)
                throw new DecodingError("PEM: Malformed PEM trailer");
            
            if (position == 0)
                base64.write(b);
        }
        base64.endMsg();
        return base64.readAll();
    }

    /**
    * Decode PEM data
    * Params:
    *  pem = a string containing PEM encoded data
    *  label = is set to the PEM label found for later inspection
    */
    static SecureVector!ubyte decode(in string pem, ref string label)
    {
        auto src = DataSourceMemory(pem);
        return decode(cast(DataSource)src, label);
    }
    /**
    * Decode PEM data
    * Params:
    *  pem = a datasource containing PEM encoded data
    *  label = is what we expect the label to be
    */
    static SecureVector!ubyte decodeCheckLabel(DataSource source, in string label_want)
    {
        string label_got;
        SecureVector!ubyte ber = decode(source, label_got);
        if (label_got != label_want)
            throw new DecodingError("PEM: Label mismatch, wanted " ~ label_want ~ ", got " ~ label_got);
        return ber;
    }

    /**
    * Decode PEM data
    * Params:
    *  pem = a string containing PEM encoded data
    *  label = is what we expect the label to be
    */
    static SecureVector!ubyte decodeCheckLabel(in string pem,
                                               in string label_want)
    {
        auto src = DataSourceMemory(pem);
        return decodeCheckLabel(cast(DataSource) src, label_want);
    }

    /**
    * Heuristic test for PEM data.
    * Search for a PEM signature
    */
    static bool matches(DataSource source, in string extra = "", size_t search_range = 4096)
    {
        const string PEM_HEADER = "-----BEGIN " ~ extra;
        
        SecureVector!ubyte search_buf = SecureVector!ubyte(search_range);
        size_t got = source.peek(search_buf.ptr, search_buf.length, 0);
        
        if (got < PEM_HEADER.length)
            return false;
        
        size_t index = 0;
        
        foreach (size_t j; 0 .. got)
        {
            if (search_buf[j] == PEM_HEADER[index])
                ++index;
            else
                index = 0;
            if (index == PEM_HEADER.length)
                return true;
        }
        return false;
    }

}