/**
* Processor_RNG — CPU hardware RNG (RDRAND on x86, DARN on POWER)
*
* Copyright:
* (C) 2016,2019,2020 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.processor_rng;

import botan.constants;
static if (BOTAN_HAS_PROCESSOR_RNG):

import botan.rng.rng;
import botan.utils.cpuid;
import botan.utils.exceptn;
import botan.utils.types;

enum size_t HWRNG_RETRIES = 10;

/**
* Directly invokes a CPU RNG instruction. On x86 this is RDRAND;
* on POWER this is DARN (conditioned 64-bit, XOR of two draws).
* Constructor throws if the instruction is not available.
*/
final class ProcessorRNG : RandomNumberGenerator
{
public:
    /// Throws if the CPU RNG instruction is unavailable.
    this()
    {
        if (!available())
            throw new InvalidState("Current CPU does not support RNG instruction");
    }

    static bool available()
    {
        version (X86)
            return CPUID.hasRdrand();
        else version (X86_64)
            return CPUID.hasRdrand();
        else version (PPC64)
            return CPUID.hasDarn();
        else version (PPC)
            return CPUID.hasDarn();
        else
            return false;
    }

    override void randomize(ubyte* output, size_t length)
    {
        if (length == 0)
            return;
        fill(output, length);
    }

    override bool isSeeded() const { return true; }
    override void clear() {}
    override void reseed(size_t) {}
    override void addEntropy(const(ubyte)*, size_t) {}
    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }

    override @property string name() const
    {
        version (X86)
            return "rdrand";
        else version (X86_64)
            return "rdrand";
        else version (PPC64)
            return "darn";
        else version (PPC)
            return "darn";
        else
            return "hwrng";
    }

private:
    static void fill(ubyte* output, size_t length)
    {
        version (X86_64)
        {
            while (length >= 8)
            {
                const ulong r = readHwrng64();
                storeLe64(r, output);
                output += 8;
                length -= 8;
            }
            if (length)
            {
                ubyte[8] tmp;
                storeLe64(readHwrng64(), tmp.ptr);
                output[0 .. length] = tmp[0 .. length];
            }
        }
        else version (X86)
        {
            while (length >= 4)
            {
                const uint r = readHwrng32();
                storeLe32(r, output);
                output += 4;
                length -= 4;
            }
            if (length)
            {
                ubyte[4] tmp;
                storeLe32(readHwrng32(), tmp.ptr);
                output[0 .. length] = tmp[0 .. length];
            }
        }
        else version (PPC64)
        {
            while (length >= 8)
            {
                const ulong r = readDarn64();
                storeLe64(r, output);
                output += 8;
                length -= 8;
            }
            if (length)
            {
                ubyte[8] tmp;
                storeLe64(readDarn64(), tmp.ptr);
                output[0 .. length] = tmp[0 .. length];
            }
        }
        else version (PPC)
        {
            while (length >= 8)
            {
                const ulong r = readDarn64();
                storeLe64(r, output);
                output += 8;
                length -= 8;
            }
            if (length)
            {
                ubyte[8] tmp;
                storeLe64(readDarn64(), tmp.ptr);
                output[0 .. length] = tmp[0 .. length];
            }
        }
        else
            throw new PRNGUnseeded("Processor RNG instruction is not available");
    }
}

private void storeLe32(uint v, ubyte* p)
{
    p[0] = cast(ubyte) v;
    p[1] = cast(ubyte)(v >> 8);
    p[2] = cast(ubyte)(v >> 16);
    p[3] = cast(ubyte)(v >> 24);
}

private void storeLe64(ulong v, ubyte* p)
{
    storeLe32(cast(uint) v, p);
    storeLe32(cast(uint)(v >> 32), p + 4);
}

private bool rdrand32(ref uint output)
{
    version (GDC)
    {
        import gcc.builtins;
        return __builtin_ia32_rdrand32_step(&output) == 1;
    }
    else version (D_InlineAsm_X86)
    {
        uint val, cf;
        asm
        {
            xor ECX, ECX;
            db 0x0F, 0xC7, 0xF0;
            adc ECX, ECX;
            mov val, EAX;
            mov cf, ECX;
        }
        output = val;
        return cf != 0;
    }
    else version (D_InlineAsm_X86_64)
    {
        uint val, cf;
        asm
        {
            xor ECX, ECX;
            db 0x0F, 0xC7, 0xF0;
            adc ECX, ECX;
            mov val, EAX;
            mov cf, ECX;
        }
        output = val;
        return cf != 0;
    }
    else
        return false;
}

private bool rdrand64(ref ulong output)
{
    version (X86_64)
    {
        version (GDC)
        {
            import gcc.builtins;
            return __builtin_ia32_rdrand64_step(&output) == 1;
        }
        else version (D_InlineAsm_X86_64)
        {
            ulong val;
            uint cf;
            asm
            {
                xor ECX, ECX;
                db 0x48, 0x0F, 0xC7, 0xF0;
                adc ECX, ECX;
                mov val, RAX;
                mov cf, ECX;
            }
            output = val;
            return cf != 0;
        }
        else
            return false;
    }
    else
        return false;
}

private bool darn64(ref ulong output)
{
    version (PPC)
    {
        ulong a = 0, b = 0;
        version (LDC)
        {
            mixin(`asm { "darn %0, 1" : "=r" a; }`);
            mixin(`asm { "darn %0, 1" : "=r" b; }`);
        }
        else version (GNU)
        {
            mixin(`asm { "darn %0, 1" : "=r" a; }`);
            mixin(`asm { "darn %0, 1" : "=r" b; }`);
        }
        else
            return false;
        if ((~a) != 0 && (~b) != 0)
        {
            output = a ^ b;
            return true;
        }
        return false;
    }
    else version (PPC64)
    {
        ulong a = 0, b = 0;
        version (LDC)
        {
            mixin(`asm { "darn %0, 1" : "=r" a; }`);
            mixin(`asm { "darn %0, 1" : "=r" b; }`);
        }
        else version (GNU)
        {
            mixin(`asm { "darn %0, 1" : "=r" a; }`);
            mixin(`asm { "darn %0, 1" : "=r" b; }`);
        }
        else
            return false;
        if ((~a) != 0 && (~b) != 0)
        {
            output = a ^ b;
            return true;
        }
        return false;
    }
    else
        return false;
}

private ulong readDarn64()
{
    foreach (i; 0 .. HWRNG_RETRIES)
    {
        ulong v;
        if (darn64(v))
            return v;
    }
    throw new PRNGUnseeded("Processor RNG instruction failed to produce output within expected iterations");
}

private uint readHwrng32()
{
    foreach (i; 0 .. HWRNG_RETRIES)
    {
        uint v;
        if (rdrand32(v))
            return v;
    }
    throw new PRNGUnseeded("Processor RNG instruction failed to produce output within expected iterations");
}

private ulong readHwrng64()
{
    foreach (i; 0 .. HWRNG_RETRIES)
    {
        ulong v;
        if (rdrand64(v))
            return v;
    }
    throw new PRNGUnseeded("Processor RNG instruction failed to produce output within expected iterations");
}

static if (BOTAN_HAS_TESTS && !SKIP_PROCESSOR_RNG_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import core.stdc.string : memcmp;

    auto state = globalState();
    logDebug("Testing processor_rng.d ...");
    size_t fails;

    if (ProcessorRNG.available())
    {
        auto rng = new ProcessorRNG;
        if (rng.name != "rdrand")
            ++fails;
        if (!rng.isSeeded())
            ++fails;
        rng.clear();
        if (!rng.isSeeded())
            ++fails;
        rng.addEntropy(null, 0);
        rng.reseed(256);

        foreach (i; 0 .. 128)
        {
            auto buf = new ubyte[i];
            rng.randomize(buf.ptr, buf.length);
        }

        ubyte[32] a, b;
        rng.randomize(a.ptr, a.length);
        rng.randomize(b.ptr, b.length);
        ubyte acc;
        foreach (x; a) acc |= x;
        if (acc == 0)
            ++fails;
        if (memcmp(a.ptr, b.ptr, 32) == 0)
            ++fails;
    }
    else
    {
        bool threw;
        try
            auto rng = new ProcessorRNG;
        catch (InvalidState)
            threw = true;
        if (!threw)
            ++fails;
    }

    testReport("processor_rng", 6, fails);
    assert(fails == 0);
}
