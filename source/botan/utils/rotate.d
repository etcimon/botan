/**
* Word Rotation Operations
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.rotate;

import botan.utils.types;
pure:

/**
* Bit rotation left
* Params:
*  input = the input word
*  rot = the number of bits to rotate
* Returns: input rotated left by rot bits
*/
T rotateLeft(T)(T input, size_t rot)
{
    if (rot == 0)
        return input;
    return cast(T)((input << rot) | (input >> (8*T.sizeof-rot)));
}

/**
* Bit rotation right
* Params:
*  input = the input word
*  rot = the number of bits to rotate
* Returns: input rotated right by rot bits
*/
T rotateRight(T)(T input, size_t rot)
{
    if (rot == 0)
        return input;
    return cast(T)((input >> rot) | (input << (8*T.sizeof-rot)));
}