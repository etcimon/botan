/**
* Auto Seeded RNG
* 
* Copyright:
* (C) 2016 Jack Lloyd
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.auto_rng;

import botan.constants;
static if (BOTAN_HAS_AUTO_SEEDING_RNG):

public import botan.rng.rng;
import botan.utils.types;

/**
* HMAC_RNG seeded from the global factory. Preferred application RNG.
*/
final class AutoSeededRNG : RandomNumberGenerator
{
public:
    override void randomize(ubyte* output, size_t len)
    { m_rng.randomize(output, len); }

    override bool isSeeded() const { return m_rng.isSeeded(); }

    override void clear() { m_rng.clear(); }

    override @property string name() const { return m_rng.name; }

    override void reseed(size_t poll_bits = 256) { m_rng.reseed(poll_bits); }

    override void addEntropy(const(ubyte)* input, size_t len)
    { m_rng.addEntropy(input, len); }

	override SecureVector!ubyte randomVec(size_t bytes) { return super.randomVec(bytes); }

    /// Seeded HMAC_RNG from LibraryState.
    this()
    {
        m_rng = RandomNumberGenerator.makeRng();
    }
private:
    Unique!RandomNumberGenerator m_rng;
}