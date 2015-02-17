/**
* Read ref bytes
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.get_byte;

import botan.constants;
public import botan.utils.mem_ops;
import botan.utils.types;
import std.bitmanip;
/**
* Byte extraction
* Params:
*  byte_num = which ubyte to extract, 0 == highest ubyte
*  input = the value to extract from
* Returns: ubyte byte_num of input
*/
ubyte get_byte(T)(size_t byte_num, T input)
{
    return cast(ubyte)(input >> ( ( T.sizeof - 1 - (byte_num & (T.sizeof - 1) ) ) << 3) );
}