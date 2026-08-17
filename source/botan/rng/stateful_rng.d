/**
* Stateful RNG (reseed interval + optional fork detection)
*
* Copyright:
* (C) 2016,2020 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.stateful_rng;

import botan.constants;
static if (BOTAN_HAS_STATEFUL_RNG):

import botan.rng.rng;
import botan.entropy.entropy_src;
import botan.utils.exceptn;
import botan.libstate.libstate;
import botan.utils.types;
import core.sync.mutex;

private uint currentPid()
{
    version (Windows)
    {
        import core.sys.windows.winbase : GetCurrentProcessId;
        return GetCurrentProcessId();
    }
    else version (Posix)
    {
        import core.sys.posix.unistd : getpid;
        return cast(uint) getpid();
    }
    else
        return 0;
}

/**
* RNGs that keep in-process state (HMAC_DRBG, ChaCha_RNG).
* Reseeds after `reseed_interval` requests, or when a fork is detected.
*/
abstract class StatefulRNG : RandomNumberGenerator
{
public:
    enum size_t defaultReseedInterval = 1024;
    enum size_t defaultPollBits = 256;

    this() { m_reseed_interval = 0; m_mutex = new Mutex; }

    this(RandomNumberGenerator underlying, size_t reseed_interval = defaultReseedInterval)
    {
        m_underlying = underlying;
        m_reseed_interval = reseed_interval;
        m_mutex = new Mutex;
    }

    /// Consume seed and mark initialized regardless of length.
    final void initializeWith(const(ubyte)* input, size_t length)
    {
        synchronized (m_mutex)
        {
            doClear();
            doAddEntropy(input, length);
        }
    }

    final void initializeWith(const(ubyte)[] input)
    {
        initializeWith(input.ptr, input.length);
    }

    final void forceReseed()
    {
        synchronized (m_mutex) m_reseed_counter = 0;
    }

    override bool isSeeded() const
    {
        synchronized (m_mutex) return m_reseed_counter > 0;
    }

    override void clear()
    {
        synchronized (m_mutex) doClear();
    }

    override void randomize(ubyte* output, size_t length)
    {
        synchronized (m_mutex) fillBytes(output, length, null, 0);
    }

    override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }

    /// Generate output, mixing in additional input first (C++ `randomize_with_input`).
    final void randomizeWithInput(ubyte* output, size_t out_len,
                                  const(ubyte)* input, size_t in_len)
    {
        synchronized (m_mutex) fillBytes(output, out_len, input, in_len);
    }

    override void addEntropy(const(ubyte)* input, size_t length)
    {
        synchronized (m_mutex) doAddEntropy(input, length);
    }

    override void reseed(size_t poll_bits)
    {
        synchronized (m_mutex)
        {
            if (m_underlying)
                doReseedFromRng(m_underlying, poll_bits);
            else
                doReseedFromSources(poll_bits);
        }
    }

    abstract size_t securityLevel() const;
    abstract size_t maxBytesPerRequest() const;
    final size_t reseedInterval() const { return m_reseed_interval; }

protected:
    abstract void generateOutput(ubyte* output, size_t out_len,
                                 const(ubyte)* input, size_t in_len);
    abstract void update(const(ubyte)* input, size_t in_len);
    abstract void clearState();

    final void reseedCheck()
    {
        const uint cur_pid = currentPid();
        const bool fork_detected = (m_last_pid > 0) && (cur_pid != m_last_pid);

        if (m_reseed_counter == 0 || fork_detected ||
            (m_reseed_interval > 0 && m_reseed_counter >= m_reseed_interval))
        {
            m_reseed_counter = 0;
            m_last_pid = cur_pid;

            if (m_underlying)
                doReseedFromRng(m_underlying, securityLevel());
            else if (m_poll_sources)
                doReseedFromSources(securityLevel());

            if (m_reseed_counter == 0)
            {
                if (fork_detected)
                    throw new InvalidState("Detected use of fork but cannot reseed DRBG");
                throw new PRNGUnseeded(name);
            }
        }
        else
            ++m_reseed_counter;
    }

private:
    void doClear()
    {
        m_reseed_counter = 0;
        m_last_pid = 0;
        clearState();
    }

    void doAddEntropy(const(ubyte)* input, size_t length)
    {
        update(input, length);
        if (8 * length >= securityLevel())
            resetCounter();
    }

    void fillBytes(ubyte* output, size_t out_len, const(ubyte)* input, size_t in_len)
    {
        if (out_len == 0)
        {
            update(input, in_len);
            if (8 * in_len >= securityLevel())
                resetCounter();
            return;
        }

        const size_t max_per = maxBytesPerRequest();
        if (max_per == 0)
        {
            reseedCheck();
            generateOutput(output, out_len, input, in_len);
            return;
        }

        auto inp = input;
        auto inpl = in_len;
        while (out_len)
        {
            const size_t n = (out_len < max_per) ? out_len : max_per;
            reseedCheck();
            generateOutput(output, n, inp, inpl);
            inp = null;
            inpl = 0;
            output += n;
            out_len -= n;
        }
    }

    void resetCounter()
    {
        m_reseed_counter = 1;
        m_last_pid = currentPid();
    }

    void doReseedFromRng(RandomNumberGenerator rng, size_t poll_bits)
    {
        auto buf = rng.randomVec(poll_bits / 8);
        doAddEntropy(buf.ptr, buf.length);
        if (poll_bits >= securityLevel())
            resetCounter();
    }

    void doReseedFromSources(size_t poll_bits)
    {
        double bits_collected = 0;
        EntropyAccumulator accum = EntropyAccumulator(
            (const(ubyte)* input, size_t in_len, double entropy_estimate)
            {
                update(input, in_len);
                bits_collected += entropy_estimate;
                return (bits_collected >= poll_bits);
            });
        globalState().pollAvailableSources(accum);
        if (bits_collected >= securityLevel())
            resetCounter();
    }

    Mutex m_mutex;
    RandomNumberGenerator m_underlying;
    bool m_poll_sources;
    const size_t m_reseed_interval;
    uint m_last_pid;
    size_t m_reseed_counter;
}
