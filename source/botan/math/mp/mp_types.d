/**
* Low Level MPI Types
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.math.mp.mp_types;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
import botan.utils.mul128;
import botan.constants;

static if (BOTAN_MP_WORD_BITS == 8) {
    alias word = ubyte;
    alias dword = ushort;
    enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 16) {
    alias word = ushort;
    alias dword = uint;
    enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 32) {
    alias word = uint;
    alias dword = ulong;
    enum BOTAN_HAS_MP_DWORD = 1;
}
else static if (BOTAN_MP_WORD_BITS == 64) {
    alias word = ulong;

    static if (BOTAN_TARGET_HAS_NATIVE_UINT128) {
        static assert(false);
        //alias uint128_t dword;
        //enum BOTAN_HAS_MP_DWORD = 1;
    }
    else enum BOTAN_HAS_MP_DWORD = 0;

} else
    static assert(false, "BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64");


__gshared immutable word MP_WORD_MASK = ~cast(word)(0);
__gshared immutable word MP_WORD_TOP_BIT = (cast(word) 1) << (8*(word).sizeof - 1);
__gshared immutable word MP_WORD_MAX = MP_WORD_MASK;