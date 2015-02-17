/**
* xmmintrin.h style functions
* 
* Copyright:
* (C) 2014-2015 Etienne Cimon
*
* License:
* Released under the MIT license
*/
module botan.utils.simd.xmmintrin;

/*
* LDC, GDC, DMD Intrinsics for SSSE 3
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/

import botan.constants;
static if (BOTAN_HAS_AES_SSSE3):

