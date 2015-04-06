/*-------------------------------------------------------------*/
/*--- Public header file for the library.                   ---*/
/*---                                               bzlib.h ---*/
/*-------------------------------------------------------------*/
/**
*   This file is part of bzip2/libbzip2, a program and library for
*   lossless, block-sorting data compression.
*   
*   bzip2/libbzip2 version 1.0.6 of 6 September 2010
*   Copyright (C) 1996-2010 Julian Seward <jseward@bzip.org>
*   
*   Please read the WARNING, DISCLAIMER and PATENTS sections in the 
*   README file.
*   
*   This program is released under the terms of the license contained
*   in the file LICENSE.
*/
module botan.compression.bzip2_hd;

import botan.constants;
static if (BOTAN_HAS_BZIP2):

package extern(C) nothrow:

enum BZ_RUN               = 0;
enum BZ_FLUSH             = 1;
enum BZ_FINISH            = 2;

enum BZ_OK                = 0;
enum BZ_RUN_OK            = 1;
enum BZ_FLUSH_OK          = 2;
enum BZ_FINISH_OK         = 3;
enum BZ_STREAM_END        = 4;
enum BZ_SEQUENCE_ERROR    = -1;
enum BZ_PARAM_ERROR       = -2;
enum BZ_MEM_ERROR         = -3;
enum BZ_DATA_ERROR        = -4;
enum BZ_DATA_ERROR_MAGIC  = -5;
enum BZ_IO_ERROR          = -6;
enum BZ_UNEXPECTED_EOF    = -7;
enum BZ_OUTBUFF_FULL      = -8;
enum BZ_CONFIG_ERROR      = -9;


struct bz_stream
{
    ubyte* next_in;
    uint   avail_in;
    uint   total_in_lo32;
    uint   total_in_hi32;
    
    ubyte* next_out;
    uint   avail_out;
    uint   total_out_lo32;
    uint   total_out_hi32;
    
    void*  state;
    
    void* function(void*, int, int) nothrow bzalloc;
    void  function(void*, void*) nothrow    bzfree;
    void* opaque;
} 

/*-- Core (low-level) library functions --*/

int BZ2_bzCompressInit( 
    bz_stream* strm, 
    int        blockSize100k, 
    int        verbosity, 
    int        workFactor 
    );

int BZ2_bzCompress( 
    bz_stream* strm, 
    int action 
    );

int BZ2_bzCompressEnd( 
    bz_stream* strm 
    );

int BZ2_bzDecompressInit( 
    bz_stream* strm, 
    int        verbosity, 
    int        small
    );

int BZ2_bzDecompress( 
    bz_stream* strm 
    );

int BZ2_bzDecompressEnd( 
    bz_stream *strm 
    );

/*--
   Code contributed by Yoshioka Tsuneo (tsuneo@rr.iij4u.or.jp)
   to support better zlib compatibility.
   This code is not _officially_ part of libbzip2 (yet);
   I haven't tested it, documented it, or considered the
   threading-safeness of it.
   If this code breaks, please contact both Yoshioka and me.
--*/

const(char)* BZ2_bzlibVersion();

/*-------------------------------------------------------------*/
/*--- end                                           bzlib.h ---*/
/*-------------------------------------------------------------*/