/**
* Auto Seeded RNG
* 
* Copyright:
* (C) 2008 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.rng.auto_rng;

public import botan.rng.rng;
import botan.utils.types;

alias AutoSeededRNG = RefCounted!AutoSeededRNGImpl;
final class AutoSeededRNGImpl : RandomNumberGenerator
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

    this()
    {
        m_rng = RandomNumberGenerator.makeRng();
    }
private:
    Unique!RandomNumberGenerator m_rng;
}