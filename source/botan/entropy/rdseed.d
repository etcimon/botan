/**
* Entropy Source Using Intel's rdseed instruction
*
* Copyright:
* (C) 2015 Daniel Neus
* (C) 2015,2019 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.rdseed;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_RDSEED):

import botan.entropy.entropy_src;
import botan.utils.cpuid;

enum size_t RDSEED_RETRIES = 1024;
enum size_t RDSEED_BYTES = 1024;

/**
* Entropy source using the rdseed instruction (Broadwell+).
* Bytes are mixed in but not trusted (0 claimed entropy bits).
*/
final class IntelRdseed : EntropySource
{
public:
    @property string name() const { return "rdseed"; }

    void poll(ref EntropyAccumulator accum)
    {
        if (!CPUID.hasRdseed())
            return;

        auto seed = new uint[RDSEED_BYTES / 4];
        size_t n;
        foreach (i; 0 .. seed.length)
        {
            uint r;
            if (!rdseed32(r))
                break;
            seed[n++] = r;
        }
        if (n)
            accum.add(seed.ptr, n * uint.sizeof, 0.0);
    }
}

private void pause()
{
    version (D_InlineAsm_X86)
        asm { db 0xF3, 0x90; }
    else version (D_InlineAsm_X86_64)
        asm { db 0xF3, 0x90; }
}

private bool rdseed32Once(ref uint output)
{
    version (GDC)
    {
        import gcc.builtins;
        return __builtin_ia32_rdseed_si_step(&output) == 1;
    }
    else version (D_InlineAsm_X86)
    {
        uint val, cf;
        asm
        {
            xor ECX, ECX;
            db 0x0F, 0xC7, 0xF8;
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
            db 0x0F, 0xC7, 0xF8;
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

private bool rdseed32(ref uint output)
{
    foreach (i; 0 .. RDSEED_RETRIES)
    {
        if (rdseed32Once(output))
            return true;
        pause();
    }
    return false;
}

static if (BOTAN_HAS_TESTS && !SKIP_ENTROPY_RDSEED_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;

    auto state = globalState();
    logDebug("Testing rdseed.d ...");
    size_t fails;

    auto src = new IntelRdseed;
    if (src.name != "rdseed")
        ++fails;

    size_t got;
    bool sink(const(ubyte)*, size_t n, double)
    {
        got += n;
        return false;
    }
    auto acc = EntropyAccumulator(&sink);
    src.poll(acc);
    if (CPUID.hasRdseed() && got == 0)
        ++fails;
    if (!CPUID.hasRdseed() && got != 0)
        ++fails;

    testReport("rdseed", 3, fails);
    assert(fails == 0);
}
