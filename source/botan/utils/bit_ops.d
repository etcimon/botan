/**
* Bit/Word Operations
* 
* Copyright:
* (C) 1999-2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.bit_ops;

import botan.constants;
import botan.utils.get_byte;
import botan.utils.types;
/**
* Power of 2 test. T should be an uinteger type
* Params:
*  arg = an integer value
* Returns: true iff arg is 2^n for some n > 0
*/
bool isPowerOf2(T)(T arg)
{
    return ((arg != 0 && arg != 1) && ((arg & (arg-1)) == 0));
}

/**
* Return the index of the highest set bit
* T is an uinteger type
* Params:
*  n = an integer value
* Returns: index of the highest set bit in n
*/
size_t highBit(T)(T n)
{
    for (size_t i = 8*T.sizeof; i > 0; --i)
        if ((n >> (i - 1)) & 0x01)
            return i;
    return 0;
}

/**
* Return the index of the lowest set bit
* T is an uinteger type
* Params:
*  n = an integer value
* Returns: index of the lowest set bit in n
*/
size_t lowBit(T)(T n)
{
    for (size_t i = 0; i != 8*T.sizeof; ++i)
        if ((n >> i) & 0x01)
            return (i + 1);
    return 0;
}

/**
* Return the number of significant bytes in n
* Params:
*  n = an integer value
* Returns: number of significant bytes in n
*/
size_t significantBytes(T)(T n)
{
    for (size_t i = 0; i != T.sizeof; ++i)
        if (get_byte(i, n))
            return T.sizeof-i;
    return 0;
}

/**
* Compute Hamming weights
* Params:
*  n = an integer value
* Returns: number of bits in n set to 1
*/
size_t hammingWeight(T)(T n)
{
    __gshared immutable ubyte[] NIBBLE_WEIGHTS = [
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 ];

    size_t weight = 0;
    for (size_t i = 0; i != 2*T.sizeof; ++i)
        weight += NIBBLE_WEIGHTS[(n >> (4*i)) & 0x0F];
    return weight;
}

/**
* Count the trailing zero bits in n
* Params:
*  n = an integer value
* Returns: maximum x st 2^x divides n
*/
size_t ctz(T)(T n)
{
    for (size_t i = 0; i != 8*T.sizeof; ++i)
        if ((n >> i) & 0x01)
            return i;
    return 8*T.sizeof;
}