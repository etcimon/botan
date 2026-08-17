/**
* Operating-system CSPRNG (RtlGenRandom / /dev/urandom)
*
* Copyright:
* (C) 2014,2015,2017,2018,2022 Jack Lloyd
* (C) 2021 Tom Crowley
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.system_rng;

import botan.constants;
static if (BOTAN_HAS_SYSTEM_RNG):

import botan.rng.rng;
import botan.utils.types;
import botan.utils.exceptn;

/**
* Instantiable handle to the process-wide OS CSPRNG.
* Does not own the backend; `clear` / `addEntropy` / `reseed` are no-ops.
*/
final class SystemRNG : RandomNumberGenerator
{
public:
    override void randomize(ubyte* output, size_t length)
    {
        systemRngImpl().randomize(output, length);
    }

    override bool isSeeded() const { return true; }

    override void clear() {}

    override @property string name() const { return systemRngImpl().name; }

    override void reseed(size_t) {}

    override void addEntropy(const(ubyte)*, size_t) {}

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }
}

/// Shared OS CSPRNG (same object for every `SystemRNG`).
RandomNumberGenerator systemRng()
{
    return systemRngImpl();
}

private:

RandomNumberGenerator systemRngImpl()
{
    __gshared SystemRNGBackend g_impl;
    if (!g_impl)
        g_impl = new SystemRNGBackend;
    return g_impl;
}

final class SystemRNGBackend : RandomNumberGenerator
{
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

    version (Windows)
        override @property string name() const { return "RtlGenRandom"; }
    else
        override @property string name() const { return "/dev/urandom"; }

private:
    version (Windows)
    {
        import core.sys.windows.windows;

        // BOOLEAN SystemFunction036(PVOID, ULONG) — RtlGenRandom
        extern (Windows) alias RtlGenRandomFn = ubyte function(void*, uint);
        RtlGenRandomFn m_rtl;

        this()
        {
            HMODULE adv = GetModuleHandleA("advapi32.dll");
            if (!adv)
                adv = LoadLibraryA("advapi32.dll");
            if (!adv)
                throw new Exception("System_RNG: advapi32.dll not available");
            m_rtl = cast(RtlGenRandomFn) GetProcAddress(adv, "SystemFunction036");
            if (!m_rtl)
                throw new Exception("System_RNG: RtlGenRandom not available");
        }

        void fill(ubyte* output, size_t length)
        {
            size_t left = length;
            ubyte* p = output;
            while (left)
            {
                uint block = left > uint.max ? uint.max : cast(uint) left;
                if (m_rtl(p, block) == 0)
                    throw new Exception("System_RNG: RtlGenRandom failed");
                p += block;
                left -= block;
            }
        }
    }
    else
    {
        import core.sys.posix.fcntl;
        import core.sys.posix.unistd;
        import std.string : toStringz;

        int m_fd = -1;

        this()
        {
            m_fd = open("/dev/urandom".toStringz, O_RDONLY);
            if (m_fd < 0)
                throw new Exception("System_RNG: failed to open /dev/urandom");
        }

        ~this()
        {
            if (m_fd >= 0)
            {
                close(m_fd);
                m_fd = -1;
            }
        }

        void fill(ubyte* output, size_t length)
        {
            size_t got = 0;
            while (got < length)
            {
                auto n = read(m_fd, output + got, length - got);
                if (n <= 0)
                    throw new Exception("System_RNG: /dev/urandom read failed");
                got += cast(size_t) n;
            }
        }
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_SYSTEM_RNG_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;
    import core.stdc.string : memcmp;

    auto state = globalState();
    logDebug("Testing system_rng.d ...");
    size_t fails = 0;

    auto rng = new SystemRNG;
    if (rng.name.length == 0)
        ++fails;
    if (!rng.isSeeded())
        ++fails;

    ubyte[32] a, b;
    rng.randomize(a.ptr, a.length);
    rng.randomize(b.ptr, b.length);

    ubyte acc;
    foreach (x; a) acc |= x;
    if (acc == 0)
        ++fails;
    if (memcmp(a.ptr, b.ptr, 32) == 0)
        ++fails;

    rng.addEntropy(a.ptr, a.length);
    rng.reseed(128);
    rng.clear();
    if (!rng.isSeeded())
        ++fails;

    testReport("system_rng", 5, fails);
    assert(fails == 0);
}
