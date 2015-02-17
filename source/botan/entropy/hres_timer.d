/**
* High Resolution Timestamp Entropy Source
* 
* Copyright:
* (C) 1999-2009 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.hres_timer;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER):

import botan.entropy.entropy_src;

import botan.utils.cpuid;
import std.datetime;

version(Windows) import core.sys.windows.windows;
else version(Posix) import core.sys.linux.time;


/**
* Entropy source using high resolution timers
*
* @note Any results from timers are marked as not contributing entropy
* to the poll, as a local attacker could observe them directly.
*/
final class HighResolutionTimestamp : EntropySource
{
public:
    @property string name() const { return "High Resolution Timestamp"; }
    /*
* Get the timestamp
*/
    void poll(ref EntropyAccumulator accum)
    {
        // Don't count any timestamps as contributing any entropy
        const double ESTIMATED_ENTROPY_PER_BYTE = 1.0;

        {
            auto timestamp = Clock.currStdTime();
            accum.add(timestamp, ESTIMATED_ENTROPY_PER_BYTE);
        }

        static if (is(typeof(QueryPerformanceCounter)))
        {
            long tv;
            QueryPerformanceCounter(&tv);
            accum.add(tv, ESTIMATED_ENTROPY_PER_BYTE);
        }

        
        static if (is(typeof(clock_gettime))) {

            void CLOCK_GETTIME_POLL(clockid_t src)
            {
                timespec ts;
                clock_gettime(src, &ts);
                accum.add(&ts, (ts).sizeof, ESTIMATED_ENTROPY_PER_BYTE);
            }
            
            static if (is(typeof(CLOCK_REALTIME))) {
                CLOCK_GETTIME_POLL(CLOCK_REALTIME);
            }
            
            static if (is(typeof(CLOCK_REALTIME_COARSE))) {
                CLOCK_GETTIME_POLL(CLOCK_REALTIME_COARSE);
            }
            
            static if (is(typeof(CLOCK_MONOTONIC))) {
                CLOCK_GETTIME_POLL(CLOCK_MONOTONIC);
            }
            
            static if (is(typeof(CLOCK_MONOTONIC_COARSE))) {
                CLOCK_GETTIME_POLL(CLOCK_MONOTONIC_COARSE);
            }
            
            static if (is(typeof(CLOCK_MONOTONIC_RAW))) {
                CLOCK_GETTIME_POLL(CLOCK_MONOTONIC_RAW);
            }
            
            static if (is(typeof(CLOCK_BOOTTIME))) {
                CLOCK_GETTIME_POLL(CLOCK_BOOTTIME);
            }
            
            static if (is(typeof(CLOCK_PROCESS_CPUTIME_ID))) {
                CLOCK_GETTIME_POLL(CLOCK_PROCESS_CPUTIME_ID);
            }
            
            static if (is(typeof(CLOCK_THREAD_CPUTIME_ID))) {
                CLOCK_GETTIME_POLL(CLOCK_THREAD_CPUTIME_ID);
            }
            
        }
            
    }

}



version (Windows)
{
    extern (Windows)
    {
        export int queryPerformanceCounter(long *);
    }
}
else version (D_InlineAsm_X86)
{
    extern (D)
    {
        void queryPerformanceCounter(long* ctr)
        {
            asm
            {
                naked                   ;
                mov       ECX,EAX       ;
                rdtsc                   ;
                mov   [ECX],EAX         ;
                mov   4[ECX],EDX        ;
                ret                     ;
            }
        }
    }
}
else version (D_InlineAsm_X86_64)
{
    extern (D)
    {
        void queryPerformanceCounter(long* ctr)
        {
            asm
            {
                naked                   ;
                rdtsc                   ;
                mov   [RDI],EAX         ;
                mov   4[RDI],EDX        ;
                ret                     ;
            }
        }
    }
}
else
{
    static assert(0);
}