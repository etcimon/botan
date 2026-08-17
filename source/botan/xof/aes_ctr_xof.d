/**
* XOF based on AES-256/CTR for CRYSTALS Kyber/Dilithium 90s-modes
*
* Copyright:
* (C) 2023 Jack Lloyd
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.xof.aes_ctr_xof;

import botan.constants;
static if (BOTAN_HAS_AES_CTR_XOF):

import botan.xof.xof;
import botan.stream.stream_cipher;
import botan.libstate.lookup;
import botan.utils.exceptn;
import botan.utils.types;
import botan.algo_base.key_spec;

/**
* Internal AES-256/CTR XOF (C++ `AES_256_CTR_XOF`). Does not accept absorb input.
* `copyState` is not implemented (same as C++).
*/
final class AES_256_CTR_XOF : XOF
{
public:
    this()
    {
        m_stream = retrieveStreamCipher("CTR-BE(AES-256)").clone();
    }

    override @property string name() const { return "CTR-BE(AES-256)"; }
    override @property size_t blockSize() const { return 16; }
    override bool acceptsInput() const { return false; }

    override bool validSaltLength(size_t iv_length) const
    {
        return m_stream.validIvLength(iv_length);
    }

    override KeyLengthSpecification keySpec() const
    {
        return m_stream.keySpec();
    }

    override XOF copyState() const
    {
        throw new InvalidState("Copying the state of XOF CTR-BE(AES-256) is not implemented");
    }

    override XOF newObject() const { return new AES_256_CTR_XOF; }

protected:
    override void startMsg(const(ubyte)* salt, size_t salt_len,
                           const(ubyte)* key, size_t key_len)
    {
        m_stream.setKey(key, key_len);
        m_stream.setIv(salt, salt_len);
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if (length)
            throw new InvalidState("XOF CTR-BE(AES-256) does not support data input");
    }

    override void generateBytes(ubyte* output, size_t length)
    {
        foreach (i; 0 .. length)
            output[i] = 0;
        m_stream.cipher1(output, length);
    }

    override void reset()
    {
        m_stream.clear();
    }

private:
    Unique!StreamCipher m_stream;
}
