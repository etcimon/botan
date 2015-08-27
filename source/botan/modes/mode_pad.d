/**
* ECB/CBC Padding Methods
* 
* Copyright:
* (C) 1999-2008,2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.mode_pad;

import memutils.vector;
import botan.utils.exceptn;
import botan.constants;

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
        size_t position = block[size-1];
        
        if (position > size)
            throw new DecodingError("Bad padding in " ~ name);
        
        foreach (size_t j; (size-position) .. (size-1))
            if (block[j] != position)
                throw new DecodingError("Bad padding in " ~ name);
        
        return (size-position);
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
        
        for (size_t i = last_byte_pos; i < block_size; ++i)
            buffer.pushBack(0);
        buffer.pushBack(pad_value);
    }

    /*
    * Unpad with ANSI X9.23 Method
    */
    override size_t unpad(const(ubyte)* block, size_t size) const
    {
        size_t position = block[size-1];
        if (position > size)
            throw new DecodingError(name);
        foreach (size_t j; (size-position) .. (size-1))
            if (block[j] != 0)
                throw new DecodingError(name);
        return (size-position);
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
        while (size)
        {
            if (block[size-1] == 0x80)
                break;
            if (block[size-1] != 0x00)
                throw new DecodingError(name);
            size--;
        }
        if (!size)
            throw new DecodingError(name);
        return (size-1);
    }

    override bool validBlocksize(size_t bs) const { return (bs > 0); }

    override @property string name() const { return "OneAndZeros"; }
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
