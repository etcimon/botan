/**
* Runtime CPU detection
* 
* Copyright:
* (C) 2009-2010,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.cpuid;

import core.cpuid;
import botan.constants;
import botan.utils.types;
import botan.utils.types;
import botan.utils.get_byte;
import botan.utils.mem_ops;

/**
* A class handling runtime CPU feature detection
*/
class CPUID
{
public:
    /**
    * Probe the CPU and see what extensions are supported
    */
    static this()
    {
        if (max_cpuid == 0)
            return;

        version(PPC)    
            if (altivecCheckSysctl() || altivecCheckPvrEmul())
                m_altivec_capable = true;


        m_x86_processor_flags[0] = (cast(ulong)(miscfeatures) << 32) | features;
        
        m_cache_line_size = get_byte(3, l1cache); 
        
        if (max_cpuid >= 7)
            m_x86_processor_flags[1] = (cast(ulong)(extreserved) << 32) | extfeatures;
        
        if (is_amd)
        {            
            version(X86_64) {
                /*
                * If we don't have access to CPUID, we can still safely assume that
                * any x86-64 processor has SSE2 and RDTSC
                */
                if (m_x86_processor_flags[0] == 0)
                    m_x86_processor_flags[0] = (1 << CPUID_SSE2_BIT) | (1 << CPUID_RDTSC_BIT);
            }
        }
        
    }


    /**
    * Return a best guess of the cache line size
    */
    static size_t cacheLineSize() { return m_cache_line_size; }

    /**
    * Check if the processor supports RDTSC
    */
    static bool hasRdtsc()
    { return x86_processor_flags_has(CPUID_RDTSC_BIT); }

    /**
    * Check if the processor supports SSE2
    */
    static bool hasSse2()
    { return x86_processor_flags_has(CPUID_SSE2_BIT); }

    /**
    * Check if the processor supports SSSE3
    */
    static bool hasSsse3()
    { return x86_processor_flags_has(CPUID_SSSE3_BIT); }

    /**
    * Check if the processor supports SSE4.1
    */
    static bool hasSse41()
    { return x86_processor_flags_has(CPUID_SSE41_BIT); }

    /**
    * Check if the processor supports SSE4.2
    */
    static bool hasSse42()
    { return x86_processor_flags_has(CPUID_SSE42_BIT); }

    /**
    * Check if the processor supports AVX2
    */
    static bool hasAvx2()
    { return x86_processor_flags_has(CPUID_AVX2_BIT); }

    /**
    * Check if the processor supports AVX-512F
    */
    static bool hasAvx512f()
    { return x86_processor_flags_has(CPUID_AVX512F_BIT); }

    /**
    * Check if the processor supports BMI2
    */
    static bool hasBmi2()
    { return x86_processor_flags_has(CPUID_BMI2_BIT); }

    /**
    * Check if the processor supports AES-NI
    */
    static bool hasAesNi()
    { return x86_processor_flags_has(CPUID_AESNI_BIT); }

    /**
    * Check if the processor supports CLMUL
    */
    static bool hasClmul()
    { return x86_processor_flags_has(CPUID_CLMUL_BIT); }

    /**
    * Check if the processor supports Intel SHA extension
    */
    static bool hasIntelSha()
    { return x86_processor_flags_has(CPUID_SHA_BIT); }

    /**
    * Check if the processor supports ADX extension
    */
    static bool hasAdx()
    { return x86_processor_flags_has(CPUID_ADX_BIT); }

    /**
    * Check if the processor supports RDRAND
    */
    static bool hasRdrand()
    { return x86_processor_flags_has(CPUID_RDRAND_BIT); }

    /**
    * Check if the processor supports RDSEED
    */
    static bool hasRdseed()
    { return x86_processor_flags_has(CPUID_RDSEED_BIT); }

    /**
    * Check if the processor supports AltiVec/VMX
    */
    static bool hasAltivec() { return m_altivec_capable; }

    static string toString()
    {
        import std.array : Appender;
        Appender!string app;
        
        app ~= "CPUID flags: ";
        
        app ~= CPUID.hasSse2;
        app ~= CPUID.hasSsse3;
        app ~= CPUID.hasSse41;
        app ~= CPUID.hasSse42;
        app ~= CPUID.hasAvx2;
        app ~= CPUID.hasAvx512f;
        app ~= CPUID.hasAltivec;
        
        app ~= CPUID.hasRdtsc;
        app ~= CPUID.hasBmi2;
        app ~= CPUID.hasClmul;
        app ~= CPUID.hasAesNi;
        app ~= CPUID.hasRdrand;
        app ~= CPUID.hasRdseed;
        app ~= CPUID.hasIntelSha;
        app ~= CPUID.hasAdx;

        return app.data;
    }
private:
    alias CPUIDbits = int;
    enum : CPUIDbits {
        CPUID_RDTSC_BIT = 4,
        CPUID_SSE2_BIT = 26,
        CPUID_CLMUL_BIT = 33,
        CPUID_SSSE3_BIT = 41,
        CPUID_SSE41_BIT = 51,
        CPUID_SSE42_BIT = 52,
        CPUID_AESNI_BIT = 57,
        CPUID_RDRAND_BIT = 62,

        CPUID_AVX2_BIT = 64+5,
        CPUID_BMI2_BIT = 64+8,
        CPUID_AVX512F_BIT = 64+16,
        CPUID_RDSEED_BIT = 64+18,
        CPUID_ADX_BIT = 64+19,
        CPUID_SHA_BIT = 64+29,
    }

    static bool x86_processor_flags_has(int bit)
    {
        return ((m_x86_processor_flags[bit/64] >> (bit % 64)) & 1);
    }

    static ulong[2] m_x86_processor_flags;
    static size_t m_cache_line_size;
    static bool m_altivec_capable;
}

package:

private __gshared {
    bool is_intel; // true = _probably_ an Intel processor, might be faking
    bool is_amd; // true = _probably_ an AMD processor

    uint apic;
    uint max_cpuid;
    uint max_extended_cpuid; // 0
    uint extfeatures;
    uint extreserved;
    uint miscfeatures;
    uint amdmiscfeatures;
    uint features;
    uint amdfeatures; 
    uint l1cache;
}
// EBX is used to store GOT's address in PIC on x86, so we must preserve its value
version(D_PIC)
    version(X86)
        version = PreserveEBX;
        
// todo: LDC/GDC
version(GNU)
{
    private void rawCpuid(uint ain, uint cin, ref uint a, ref uint b, ref uint c, ref uint d)
    {
        version(PreserveEBX)
        {
            asm pure nothrow { 
                "xchg %1, %%ebx
                cpuid 
                xchg %1, %%ebx"
                    : "=a" a, "=r" b, "=c" c, "=d" d 
                        : "0" ain, "2" cin; 
            }
        }
        else
        {
            asm pure nothrow { 
                "cpuid"
                    : "=a" a, "=b" b, "=c" c, "=d" d 
                        : "0" ain, "2" cin; 
            }
        }
    }
}

version(LDC) {
    private void rawCpuid(uint ain, uint cin, ref uint a, ref uint b, ref uint c, ref uint d)
    {
        version(PreserveEBX)
        {
            mixin( q{
                __asm pure nothrow { 
                    "xchg %1, %%ebx
                    cpuid 
                    xchg %1, %%ebx"
                        : "=a" a, "=r" b, "=c" c, "=d" d 
                            : "0" ain, "2" cin; 
                }
            } );
        }
        else
        {
            mixin( q{
                __asm pure nothrow { 
                    "cpuid"
                        : "=a" a, "=b" b, "=c" c, "=d" d 
                            : "0" ain, "2" cin; 
                }
            });

        }
    }
}

shared static this() {
    
    logTrace("Loading CPUID ...");
    string processorName;
    char[12] vendorID;
    uint unused;
    {
        uint a, b, c, d, a2;
        char * venptr = vendorID.ptr;

        version(GNU)
        {
            rawCpuid(0, 0, a, venptr[0], venptr[2], venptr[1]);     
        }
        else version(LDC) rawCpuid(0, 0, a, venptr[0], venptr[2], venptr[1]);
        else {
            version(D_InlineAsm_X86)
            {
                asm pure nothrow {
                    mov EAX, 0;
                    cpuid;
                    mov a, EAX;
                    mov EAX, venptr;
                    mov [EAX], EBX;
                    mov [EAX + 4], EDX;
                    mov [EAX + 8], ECX;
                }
            }
            else version(D_InlineAsm_X86_64)
            {
                asm pure nothrow {
                    mov EAX, 0;
                    cpuid;
                    mov a, EAX;
                    mov RAX, venptr;
                    mov [RAX], EBX;
                    mov [RAX + 4], EDX;
                    mov [RAX + 8], ECX;
                }
            }
        }

        
        version(GNU)
        {
            rawCpuid(0x8000_0000, 0, a2, unused, unused, unused);
        }
        else version(LDC) rawCpuid(0x8000_0000, 0, a2, unused, unused, unused);
        else {
            asm pure nothrow {
                mov EAX, 0x8000_0000;
                cpuid;
                mov a2, EAX;
            }
        }
        max_cpuid = a;
        max_extended_cpuid = a2;
    
    }

    is_intel = vendorID == "GenuineIntel";
    is_amd = vendorID == "AuthenticAMD";

    {
        uint a, b, c, d;
        version(GNU)
        {
            rawCpuid(1, 0, a, apic, c, d);
        } else version(LDC) rawCpuid(1, 0, a, apic, c, d);
        else
        {
            asm pure nothrow {
                mov EAX, 1; // model, stepping
                cpuid;
                mov a, EAX;
                mov b, EBX;
                mov c, ECX;
                mov d, EDX;
            }
        }
        /// EAX(a) contains stepping, model, family, processor type, extended model,
        /// extended family

        apic = b;
        miscfeatures = c;
        features = d;
    }

    if (max_cpuid >= 7)
    {
        uint ext, reserved;

        version(GNU) rawCpuid(7, 0, unused, ext, reserved, unused);
        else version (LDC) rawCpuid(7, 0, unused, ext, reserved, unused);
        else
        {
            asm
            {
                mov EAX, 7; // Structured extended feature leaf.
                mov ECX, 0; // Main leaf.
                cpuid;
                mov ext, EBX; // HLE, AVX2, RTM, etc.
                mov reserved, ECX;
            }
        }
        extreserved = reserved;
        extfeatures = ext;
    }
    
    /*if (miscfeatures & OSXSAVE_BIT)
    {
        uint a, d;
        version(GNU)
        {
            // xgetbv does not affect ebx
            asm pure nothrow {
                "mov $0, %%ecx
                xgetbv"
              : "=a" a, "=d" d
              :
              : "ecx";
            }    
        }
        else {
            asm pure nothrow {
                mov ECX, 0;
                xgetbv;
                mov d, EDX;
                mov a, EAX;
            }
        }
        xfeatures = cast(ulong)d << 32 | a;
    }*/

    if (max_extended_cpuid >= 0x8000_0001) {
        uint c, d;
        version(GNU)
        {
            rawCpuid(0x8000_0001, 0, unused, unused, c, d);
        } else version(LDC) rawCpuid(0x8000_0001, 0, unused, unused, c, d);
        else
        {
            asm pure nothrow {
                mov EAX, 0x8000_0001;
                cpuid;
                mov c, ECX;
                mov d, EDX;
            }
        }
        amdmiscfeatures = c;
        amdfeatures = d;

    }
    if (max_extended_cpuid >= 0x8000_0005) {
        uint c;
        version(GNU)
        {
            rawCpuid(0x8000_0005, 0, unused, unused, c, unused);
        }
        else version(LDC) rawCpuid(0x8000_0005, 0, unused, unused, c, unused);
        else
        {
            asm pure nothrow {
                mov EAX, 0x8000_0005; // L1 cache
                cpuid;
                // EAX has L1_TLB_4M.
                // EBX has L1_TLB_4K
                // EDX has L1 instruction cache
                mov c, ECX;
            }
        }
        l1cache = c;

    }
    

    // Try to detect fraudulent vendorIDs
    if (amd3dnow) is_intel = false;


}


version (PPC) {
    bool altivecCheckSysctl()
    {
        version (OSX)
            enum supported = true;
        else version (BSD)
            enum supported = true;
        else enum supported = false;
        static if (supported) {
            int[2] sels = [ CTL_MACHDEP, CPU_ALTIVEC ];
            // From Apple's docs
            int[2] sels = [ CTL_HW, HW_VECTORUNIT ];
            int vector_type = 0;
            size_t length = (vector_type).sizeof;
            int error = sysctl(sels, 2, &vector_type, &length, NULL, 0);
            
            if (error == 0 && vector_type > 0)
                return true;
        }
        return false;
    }
    
    bool altivecCheckPvrEmul()
    {
        bool altivec_capable = false;
        
        version(linux) {
            
            
            /*
            On PowerPC, MSR 287 is PVR, the Processor Version Number
            Normally it is only accessible to ring 0, but Linux and NetBSD
            (others, too, maybe?) will trap and emulate it for us.

            PVR identifiers for various AltiVec enabled CPUs. Taken from
            PearPC and Linux sources, mostly.
            */
            
            const ushort PVR_G4_7400  = 0x000C;
            const ushort PVR_G5_970    = 0x0039;
            const ushort PVR_G5_970FX = 0x003C;
            const ushort PVR_G5_970MP = 0x0044;
            const ushort PVR_G5_970GX = 0x0045;
            const ushort PVR_POWER6    = 0x003E;
            const ushort PVR_POWER7    = 0x003F;
            const ushort PVR_CELL_PPU = 0x0070;
            
            // Motorola produced G4s with PVR 0x800[0123C] (at least)
            const ushort PVR_G4_74xx_24  = 0x800;
            
            uint pvr = 0;
            
            mixin(`asm pure nothrow { mfspr [pvr], 287; }`); // not supported in DMD?
            
            // Top 16 bit suffice to identify model
            pvr >>= 16;
            
            altivec_capable |= (pvr == PVR_G4_7400);
            altivec_capable |= ((pvr >> 4) == PVR_G4_74xx_24);
            altivec_capable |= (pvr == PVR_G5_970);
            altivec_capable |= (pvr == PVR_G5_970FX);
            altivec_capable |= (pvr == PVR_G5_970MP);
            altivec_capable |= (pvr == PVR_G5_970GX);
            altivec_capable |= (pvr == PVR_POWER6);
            altivec_capable |= (pvr == PVR_POWER7);
            altivec_capable |= (pvr == PVR_CELL_PPU);
            
        }
        
        return altivec_capable;
        
    }
    
}
