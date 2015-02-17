/**
* CMAC
* 
* Copyright:
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.mac.cmac;

import botan.constants;

static if (BOTAN_HAS_CMAC):

import botan.utils.types;
import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.mem_ops;
import std.conv : to;
/**
* CMAC, also known as OMAC1
*/
final class CMAC : MessageAuthenticationCode, BufferedComputation, SymmetricAlgorithm
{
public:
    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "CMAC(" ~ m_cipher.name ~ ")";
    }

    override @property size_t outputLength() const { return m_cipher.blockSize(); }
    /*
    * Return a clone of this object
    */
    override MessageAuthenticationCode clone() const
    {
        return new CMAC(m_cipher.clone());
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        m_cipher.clear();
        zeroise(m_state);
        zeroise(m_buffer);
        zeroise(m_B);
        zeroise(m_P);
        m_position = 0;
    }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    /**
    * CMAC's polynomial doubling operation
    * Params:
    *  input = the input
    *  polynomial = the ubyte value of the polynomial
    */
    static SecureVector!ubyte polyDouble(const ref SecureVector!ubyte input)
    {
        const bool top_carry = (input[0] & 0x80) != 0;
        
        SecureVector!ubyte output = input.dup;
        
        ubyte carry = 0;
        for (size_t i = output.length; i != 0; --i)
        {
            ubyte temp = output[i-1];
            output[i-1] = cast(ubyte)( (temp << 1) | carry );
            carry = (temp >> 7);
        }
        
        if (top_carry)
        {
            switch(input.length)
            {
                case 8:
                    output[$-1] ^= 0x1B;
                    break;
                case 16:
                    output[$-1] ^= 0x87;
                    break;
                case 32:
                    output[$-2] ^= 0x4;
                    output[$-1] ^= 0x25;
                    break;
                case 64:
                    output[$-2] ^= 0x1;
                    output[$-1] ^= 0x25;
                    break;
                default:
                    assert(false, "Unhandled length input");
            }
        }
        
        return output.move;
    }

    /**
    * Params:
    *  cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher)
    {
        m_cipher = cipher;
        if (m_cipher.blockSize() !=  8 && m_cipher.blockSize() != 16 &&
            m_cipher.blockSize() != 32 && m_cipher.blockSize() != 64)
        {
            throw new InvalidArgument("CMAC cannot use the " ~ to!string(m_cipher.blockSize() * 8) ~ " bit cipher " ~ m_cipher.name);
        }
        
        m_state.resize(outputLength());
        m_buffer.resize(outputLength());
        m_B.resize(outputLength());
        m_P.resize(outputLength());
        m_position = 0;
    }

protected:
    /*
    * Update an CMAC Calculation
    */
    override void addData(const(ubyte)* input, size_t length)
    {
        bufferInsert(m_buffer, m_position, input, length);
        if (m_position + length > outputLength())
        {
            xorBuf(m_state, m_buffer, outputLength());
            m_cipher.encrypt(m_state);
            input += (outputLength() - m_position);
            length -= (outputLength() - m_position);
            while (length > outputLength())
            {
                xorBuf(m_state, input, outputLength());
                m_cipher.encrypt(m_state);
                input += outputLength();
                length -= outputLength();
            }
            copyMem(m_buffer.ptr, input, length);
            m_position = 0;
        }
        m_position += length;
    }

    /*
    * Finalize an CMAC Calculation
    */
    override void finalResult(ubyte* mac)
    {
        xorBuf(m_state, m_buffer, m_position);
        
        if (m_position == outputLength())
        {
            xorBuf(m_state, m_B, outputLength());
        }
        else
        {
            m_state[m_position] ^= 0x80;
            xorBuf(m_state, m_P, outputLength());
        }
        
        m_cipher.encrypt(m_state);
        
        for (size_t i = 0; i != outputLength(); ++i)
            mac[i] = m_state[i];
        
        zeroise(m_state);
        zeroise(m_buffer);
        m_position = 0;
    }

    /*
    * CMAC Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        clear();
        m_cipher.setKey(key, length);
        m_cipher.encrypt(m_B);
        m_B = polyDouble(m_B);
        m_P = polyDouble(m_B);
    }


    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_buffer, m_state, m_B, m_P;
    size_t m_position;
}