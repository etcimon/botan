/**
* The Skein-512 hash function
* 
* Copyright:
* (C) 2009,2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.hash.skein_512;

import botan.constants;
static if (BOTAN_HAS_SKEIN_512):

import botan.hash.hash;
import botan.block.threefish;
import botan.utils.loadstor;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.types;
import botan.utils.get_byte;
import std.conv : to;
import std.algorithm;

/**
* Skein-512, a SHA-3 candidate
*/
final class Skein512 : HashFunction
{
public:
    /**
    * Params:
    *  m_output_bits = the output size of Skein in bits
    *  arg_personalization = is a string that will paramaterize the
    * hash output
    */
    this(size_t arg_output_bits = 512, string arg_personalization = "") 
    {
        m_personalization = arg_personalization;
        m_output_bits = arg_output_bits;
        m_threefish = new Threefish512;
        m_T = SecureVector!ulong(2);
        m_buffer = SecureVector!ubyte(64); 
        m_buf_pos = 0;

        if (m_output_bits == 0 || m_output_bits % 8 != 0 || m_output_bits > 512)
            throw new InvalidArgument("Bad output bits size for Skein-512");
        
        initialBlock();
    }

    override @property size_t hashBlockSize() const { return 64; }
    override @property size_t outputLength() const { return m_output_bits / 8; }

    override HashFunction clone() const
    {
        return new Skein512(m_output_bits, m_personalization);
    }

    override @property string name() const
    {
        if (m_personalization != "")
            return "Skein-512(" ~ to!string(m_output_bits) ~ "," ~ m_personalization ~ ")";
        return "Skein-512(" ~ to!string(m_output_bits) ~ ")";
    }

    override void clear()
    {
        zeroise(m_buffer);
        m_buf_pos = 0;
        
        initialBlock();
    }

protected:
    enum type_code {
        SKEIN_KEY = 0,
        SKEIN_CONFIG = 4,
        SKEIN_PERSONALIZATION = 8,
        SKEIN_PUBLIC_KEY = 12,
        SKEIN_KEY_IDENTIFIER = 16,
        SKEIN_NONCE = 20,
        SKEIN_MSG = 48,
        SKEIN_OUTPUT = 63
    }

    override void addData(const(ubyte)* input, size_t length)
    {
        if (length == 0)
            return;
        
        if (m_buf_pos)
        {
            bufferInsert(m_buffer, m_buf_pos, input, length);
            if (m_buf_pos + length > 64)
            {
                ubi_512(m_buffer.ptr, m_buffer.length);
                
                input += (64 - m_buf_pos);
                length -= (64 - m_buf_pos);
                m_buf_pos = 0;
            }
        }
        
        const size_t full_blocks = (length - 1) / 64;
        
        if (full_blocks)
            ubi_512(input, 64*full_blocks);
        
        length -= full_blocks * 64;
        
        bufferInsert(m_buffer, m_buf_pos, input + full_blocks * 64, length);
        m_buf_pos += length;
    }

    override void finalResult(ubyte* output)
    {
        m_T[1] |= ((cast(ulong)1) << 63); // final block flag
        
        foreach (size_t i; m_buf_pos .. m_buffer.length)
            m_buffer[i] = 0;
        
        ubi_512(m_buffer.ptr, m_buf_pos);
        
        const ubyte[8] counter;
        
        resetTweak(type_code.SKEIN_OUTPUT, true);
        ubi_512(counter.ptr, counter.length);
        
        const size_t out_bytes = m_output_bits / 8;
        
        foreach (size_t i; 0 .. out_bytes)
            output[i] = get_byte(7-i%8, m_threefish.m_K[i/8]);
        
        m_buf_pos = 0;
        initialBlock();
    }

    void ubi_512(const(ubyte)* msg, size_t msg_len)
    {
        SecureVector!ulong M = SecureVector!ulong(8);
        
        do
        {
            const size_t to_proc = std.algorithm.min(msg_len, 64);
            m_T[0] += to_proc;
            
            loadLittleEndian(M.ptr, msg, to_proc / 8);
            
            if (to_proc % 8)
            {
                foreach (size_t j; 0 .. (to_proc % 8))
                    M[to_proc/8] |= cast(ulong)(msg[8*(to_proc/8)+j]) << (8*j);
            }
            
            m_threefish.skeinFeedfwd(M, m_T);
            
            // clear first flag if set
            m_T[1] &= ~(cast(ulong)(1) << 62);
            
            msg_len -= to_proc;
            msg += to_proc;
        } while (msg_len);
    }


    void initialBlock()
    {
        const ubyte[64] zeros;
        
        m_threefish.setKey(zeros.ptr, zeros.length);
        
        // ASCII("SHA3") followed by version (0x0001) code
        ubyte[32] config_str;
        config_str[0 .. 7] = [0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 ];
        storeLittleEndian(cast(uint) m_output_bits, config_str.ptr + 8);
        
        resetTweak(type_code.SKEIN_CONFIG, true);
        ubi_512(config_str.ptr, config_str.length);
        
        if (m_personalization != "")
        {
            /*
              This is a limitation of this implementation, and not of the
              algorithm specification. Could be fixed relatively easily, but
              doesn't seem worth the trouble.
            */
            if (m_personalization.length > 64)
                throw new InvalidArgument("Skein m_personalization must be less than 64 bytes");
            
            const(ubyte)* bits = cast(const(ubyte)*)(m_personalization.ptr);
            resetTweak(type_code.SKEIN_PERSONALIZATION, true);
            ubi_512(bits, m_personalization.length);
        }
        
        resetTweak(type_code.SKEIN_MSG, false);
    }

    void resetTweak(type_code type, bool fin)
    {
        m_T[0] = 0;
        
        m_T[1] = (cast(ulong)(type) << 56) |
            (cast(ulong)(1) << 62) |
                (cast(ulong)(fin) << 63);
    }

    string m_personalization;
    size_t m_output_bits;

    Unique!Threefish512 m_threefish;
    SecureVector!ulong m_T;
    SecureVector!ubyte m_buffer;
    size_t m_buf_pos;
}
