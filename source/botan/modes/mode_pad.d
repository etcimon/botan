/**
* ECB/CBC Padding Methods
* 
* Copyright:
* (C) 1999-2007,2013,2018,2020 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2025 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.mode_pad;

import memutils.vector;
import botan.utils.exceptn;
import botan.constants;
static if (BOTAN_HAS_CIPHER_MODE_PADDING):
static if (BOTAN_HAS_CT) import botan.utils.ct;

/**
* Block Cipher Mode Padding Method
* This class is pretty limited, it cannot deal well with
* randomized padding methods, or any padding method that
* wants to add more than one block. For instance, it should
* be possible to define cipher text stealing mode as simply
* a padding mode for CBC, which happens to consume the last
* two block (and requires use of the block cipher).
*/
interface BlockCipherModePaddingMethod
{
public:
    abstract void addPadding(ref SecureVector!ubyte buffer, size_t final_block_bytes, size_t block_size) const;

    /**
    * Params:
    *  block = the last block
    *  size = the of the block
    */
    abstract size_t unpad(const(ubyte)* block,
                                size_t size) const;

    /**
    * Params:
    *  block_size = of the cipher
    * Returns: valid block size for this padding mode
    */
    abstract bool validBlocksize(size_t block_size) const;

    /**
    * Returns: name of the mode
    */
    abstract @property string name() const;

}

/**
* PKCS#7 Padding
*/
final class PKCS7Padding : BlockCipherModePaddingMethod
{
public:
    /*
    * Pad with PKCS #7 Method
    */
    override void addPadding(ref SecureVector!ubyte buffer, size_t last_byte_pos, size_t block_size) const
    {
        const ubyte pad_value = cast(ubyte)( block_size - last_byte_pos );
        
        foreach (size_t i; 0 .. pad_value)
            buffer.pushBack(cast(ubyte)pad_value);
    }

    /*
    * Unpad with PKCS #7 Method
    */
    override size_t unpad(const(ubyte)* block, size_t size) const
    {
        static if (BOTAN_HAS_CT)
        {
            const ubyte last_byte = block[size - 1];
            auto bad = CTMask!size_t.isGt(last_byte, size);
            const size_t pad_pos = size - last_byte;
            foreach (i; 0 .. size - 1)
            {
                const auto pad_eq = CTMask!size_t.isEqual(block[i], last_byte);
                const auto in_range = CTMask!size_t.isGte(i, pad_pos);
                bad = bad | (in_range & (~pad_eq));
            }
            return bad.select(size, pad_pos);
        }
        else
        {
            const ubyte last_byte = block[size - 1];
            if (last_byte == 0 || last_byte > size)
                return size;
            foreach (i; size - last_byte .. size)
                if (block[i] != last_byte)
                    return size;
            return size - last_byte;
        }
    }

    override bool validBlocksize(size_t bs) const { return (bs > 0 && bs < 256); }

    override @property string name() const { return "PKCS7"; }
}

/**
* ANSI X9.23 Padding
*/
final class ANSIX923Padding : BlockCipherModePaddingMethod
{
public:
    /*
    * Pad with ANSI X9.23 Method
    */
    override void addPadding(ref SecureVector!ubyte buffer,
                                 size_t last_byte_pos,
                                 size_t block_size) const
    {
        const ubyte pad_value = cast(ubyte) (block_size - last_byte_pos);
        foreach (size_t i; 0 .. pad_value)
        {
            if (i + 1 == pad_value)
                buffer.pushBack(pad_value);
            else
                buffer.pushBack(0);
        }
    }

    /*
    * Unpad with ANSI X9.23 Method
    */
    override size_t unpad(const(ubyte)* block, size_t size) const
    {
        static if (BOTAN_HAS_CT)
        {
            const size_t last_byte = block[size - 1];
            auto bad = CTMask!size_t.isGt(last_byte, size);
            const size_t pad_pos = size - last_byte;
            foreach (i; 0 .. size - 1)
            {
                const auto in_range = CTMask!size_t.isGte(i, pad_pos);
                const auto pad_nz = CTMask!size_t.expand(block[i]);
                bad = bad | (pad_nz & in_range);
            }
            return bad.select(size, pad_pos);
        }
        else
        {
            const size_t last_byte = block[size - 1];
            if (last_byte == 0 || last_byte > size)
                return size;
            foreach (i; size - last_byte .. size - 1)
                if (block[i] != 0)
                    return size;
            return size - last_byte;
        }
    }

    override bool validBlocksize(size_t bs) const { return (bs > 0 && bs < 256); }

    override @property string name() const { return "X9.23"; }
}

/**
* One And Zeros Padding
*/
final class OneAndZerosPadding : BlockCipherModePaddingMethod
{
public:
    /*
    * Pad with One and Zeros Method
    */
    override void addPadding(ref SecureVector!ubyte buffer, size_t last_byte_pos, size_t block_size) const
    {
        buffer.pushBack(0x80);
        
        for (size_t i = last_byte_pos + 1; i % block_size; ++i)
            buffer.pushBack(0x00);
    }

    /*
    * Unpad with One and Zeros Method
    */
    override size_t unpad(const(ubyte)* block, size_t size) const
    {
        static if (BOTAN_HAS_CT)
        {
            auto bad = CTMask!ubyte.cleared();
            auto seen_80 = CTMask!ubyte.cleared();
            size_t pad_pos = size - 1;
            foreach_reverse (i; 1 .. size + 1)
            {
                const auto is_80 = CTMask!ubyte.isEqual(block[i - 1], 0x80);
                const auto is_zero = CTMask!ubyte.isZero(block[i - 1]);
                seen_80 = seen_80 | is_80;
                pad_pos -= seen_80.ifNotSetReturn(1);
                bad = bad | ((~seen_80) & (~is_zero));
            }
            bad = bad | (~seen_80);
            return ctExpandU8(bad).select(size, pad_pos);
        }
        else
        {
            foreach_reverse (i; 0 .. size)
            {
                if (block[i] == 0x80)
                    return i;
                if (block[i] != 0)
                    return size;
            }
            return size;
        }
    }

    override bool validBlocksize(size_t bs) const { return (bs > 0); }

    override @property string name() const { return "OneAndZeros"; }
}

/**
* ESP Padding (RFC 4303)
*
* Last block is filled with the incrementing sequence 01 02 03 ... N
* where N is the number of padding bytes (1 .. block_size).
*/
final class ESPPadding : BlockCipherModePaddingMethod
{
public:
    /*
    * Pad with ESP Method
    */
    override void addPadding(ref SecureVector!ubyte buffer, size_t last_byte_pos, size_t block_size) const
    {
        const ubyte pad_len = cast(ubyte)(block_size - last_byte_pos);
        foreach (ubyte i; 1 .. pad_len + 1)
            buffer.pushBack(i);
    }

    /*
    * Unpad with ESP Method
    */
    override size_t unpad(const(ubyte)* block, size_t size) const
    {
        static if (BOTAN_HAS_CT)
        {
            const ubyte last_byte = block[size - 1];
            auto bad = CTMask!size_t.isZero(last_byte) | CTMask!size_t.isGt(last_byte, size);
            const size_t pad_pos = size - last_byte;
            foreach_reverse (i; 1 .. size)
            {
                const auto in_range = CTMask!size_t.isGt(i, pad_pos);
                const auto incrementing = CTMask!size_t.isEqual(block[i - 1], cast(size_t) block[i] - 1);
                bad = bad | (in_range & (~incrementing));
            }
            return bad.select(size, pad_pos);
        }
        else
        {
            const ubyte last_byte = block[size - 1];
            if (last_byte == 0 || last_byte > size)
                return size;
            const size_t pad_pos = size - last_byte;
            foreach_reverse (i; 1 .. size)
                if (i > pad_pos && block[i - 1] != cast(ubyte)(block[i] - 1))
                    return size;
            return pad_pos;
        }
    }

    override bool validBlocksize(size_t bs) const { return (bs > 2 && bs < 256); }

    override @property string name() const { return "ESP"; }
}

/**
* Null Padding
*/
final class NullPadding : BlockCipherModePaddingMethod
{
public:
    override void addPadding(ref SecureVector!ubyte, size_t, size_t) const {}

    override size_t unpad(const(ubyte)*, size_t size) const { return size; }

    override bool validBlocksize(size_t) const { return true; }

    override @property string name() const { return "NoPadding"; }
}

static if (BOTAN_HAS_TESTS && !SKIP_CIPHER_MODE_TEST) unittest
{
    import botan.test;
    size_t fails;
    auto p = new PKCS7Padding;
    ubyte[16] good = 4;
    good[0 .. 12] = 0xAB;
    if (p.unpad(good.ptr, 16) != 12)
        ++fails;
    ubyte[16] bad = 4;
    bad[15] = 17;
    if (p.unpad(bad.ptr, 16) != 16)
        ++fails;
    ubyte[16] bad2 = 3;
    bad2[14] = 0xFF;
    if (p.unpad(bad2.ptr, 16) != 16)
        ++fails;
    auto e = new ESPPadding;
    SecureVector!ubyte esp_in;
    foreach (i; 0 .. 3)
        esp_in.pushBack(0xFF);
    e.addPadding(esp_in, 3, 16);
    if (esp_in.length != 16)
        ++fails;
    foreach (i; 0 .. 3)
        if (esp_in[i] != 0xFF)
            ++fails;
    foreach (i; 0 .. 13)
        if (esp_in[3 + i] != i + 1)
            ++fails;
    if (e.unpad(esp_in.ptr, 16) != 3)
        ++fails;
    ubyte[4] esp_good = [0xFF, 0x01, 0x02, 0x03];
    if (e.unpad(esp_good.ptr, 4) != 1)
        ++fails;
    ubyte[4] esp_bad_inc = [0xFF, 0x01, 0x02, 0x02];
    if (e.unpad(esp_bad_inc.ptr, 4) != 4)
        ++fails;
    ubyte[4] esp_zero = 0;
    if (e.unpad(esp_zero.ptr, 4) != 4)
        ++fails;
    testReport("mode_pad_ct", 8, fails);

    import botan.libstate.global_state;
    import botan.codec.hex;
    import botan.utils.types;
    import memutils.hashmap;
    import std.stdio : File;
    import std.conv : to;
    auto state = globalState();
    File pvec = File("test_data/pad.vec", "r");
    fails += runTestsBb(pvec, "Pad", "Blocksize", false,
        (ref HashMap!(string, string) m)
        {
            if (!("In" in m) || !("Blocksize" in m))
                return 0;
            string algo = m["Pad"];
            bool invalid = false;
            if (algo.length > 8 && algo[$ - 8 .. $] == "_Invalid")
            {
                invalid = true;
                algo = algo[0 .. $ - 8];
            }
            Unique!BlockCipherModePaddingMethod pad;
            if (algo == "NoPadding") pad = new NullPadding;
            else if (algo == "PKCS7") pad = new PKCS7Padding;
            else if (algo == "OneAndZeros") pad = new OneAndZerosPadding;
            else if (algo == "X9.23") pad = new ANSIX923Padding;
            else if (algo == "ESP") pad = new ESPPadding;
            else
                return 0;
            const size_t block_size = to!size_t(m["Blocksize"]);
            auto input = hexDecode(m["In"]);
            if (invalid || !("Out" in m) || !m["Out"].length)
            {
                if (input.length < block_size)
                    return 0;
                if (pad.unpad(&input[input.length - block_size], block_size) != block_size)
                    return 1;
                return 0;
            }
            auto expect = hexDecode(m["Out"]);
            SecureVector!ubyte buf;
            foreach (b; input[])
                buf.pushBack(b);
            pad.addPadding(buf, input.length % block_size, block_size);
            if (buf[] != expect[])
                return 2;
            const size_t last = (algo == "NoPadding")
                ? (buf.length < block_size ? buf.length : block_size)
                : block_size;
            const size_t pad_bytes = last - pad.unpad(&buf[buf.length - last], last);
            buf.resize(buf.length - pad_bytes);
            if (buf[] != input[])
                return 3;
            return 0;
        });

    fails += checkMemutilsRepeat("mode_pad PKCS7", {
        Unique!PKCS7Padding p = new PKCS7Padding;
        SecureVector!ubyte buf;
        foreach (i; 0 .. 3)
            buf.pushBack(0xFF);
        p.addPadding(buf, 3, 16);
        if (p.unpad(buf.ptr, 16) != 3)
            throw new Exception("mode_pad leak probe");
    });

    if (fails)
        logError("mode_pad failures: ", fails);
    assert(fails == 0);
}
