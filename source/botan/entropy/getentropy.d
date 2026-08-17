/**
* Entropy Source Using getentropy(2)
*
* Copyright:
* (C) 2017 Alexander Bluhm (genua GmbH)
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.entropy.getentropy;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_GETENTROPY):

import botan.entropy.entropy_src;

/**
* Entropy source using the getentropy(2) syscall (OpenBSD, Linux, macOS).
* On platforms without the call, poll is a no-op.
*/
final class Getentropy : EntropySource
{
public:
    @property string name() const { return "getentropy"; }

    void poll(ref EntropyAccumulator accum)
    {
        version (Posix)
        {
            ubyte[256] buf;
            if (sysGetentropy(buf.ptr, buf.length) == 0)
                accum.add(buf.ptr, buf.length, 8.0);
        }
    }
}

version (Posix)
{
    private extern (C) int getentropy(void* buffer, size_t length) @nogc nothrow;

    private int sysGetentropy(void* buffer, size_t length)
    {
        return getentropy(buffer, length);
    }
}

static if (BOTAN_HAS_TESTS && !SKIP_ENTROPY_GETENTROPY_TEST) unittest
{
    import botan.test;
    import botan.libstate.global_state;

    auto state = globalState();
    logDebug("Testing getentropy.d ...");
    size_t fails;

    auto src = new Getentropy;
    if (src.name != "getentropy")
        ++fails;

    size_t got;
    bool sink(const(ubyte)*, size_t n, double e)
    {
        got += n;
        if (e <= 0)
            ++fails;
        return false;
    }
    auto acc = EntropyAccumulator(&sink);
    src.poll(acc);
    version (Posix)
    {
        if (got != 256)
            ++fails;
    }
    else
    {
        if (got != 0)
            ++fails;
    }

    testReport("getentropy", 3, fails);
    assert(fails == 0);
}
