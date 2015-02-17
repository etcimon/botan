/**
* Integer Rounding Functions
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.rounding;

import botan.utils.types;

/**
* Round up
* Params:
*  n = an integer
*  align_to = the alignment boundary
* Returns: n rounded up to a multiple of align_to
*/
T roundUp(T)(T n, T align_to)
{
    if (align_to == 0)
        return n;

    if (n % align_to || n == 0)
        n += align_to - (n % align_to);
    return n;
}

/**
* Round down
* Params:
*  n = an integer
*  align_to = the alignment boundary
* Returns: n rounded down to a multiple of align_to
*/
T roundDown(T)(T n, T align_to)
{
    if (align_to == 0)
        return n;

    return (n - (n % align_to));
}

/**
* Clamp
*/
size_t clamp(size_t n, size_t lower_bound, size_t upper_bound)
{
    if (n < lower_bound)
        return lower_bound;
    if (n > upper_bound)
        return upper_bound;
    return n;
}