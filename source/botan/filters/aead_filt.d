/**
* Filter interface for AEAD Modes
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.filters.aead_filt;

import botan.constants;
static if (BOTAN_HAS_AEAD_FILTER && BOTAN_HAS_AEAD_CCM):

import botan.filters.transform_filter;
import botan.modes.aead.aead;
/**
* Filter interface for AEAD Modes
*/
final class AEADFilter : TransformationFilter, Filterable
{
public:
    this(AEADMode aead)
    {
        super(aead);
    }

    /**
    * Set associated data that is not included in the ciphertext but
    * that should be authenticated. Must be called after setKey
    * and before endMsg.
    *
    * Params:
    *  ad = the associated data
    *  ad_len = length of add in bytes
    */
    void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        (cast(AEADMode)(getTransform())).setAssociatedData(ad, ad_len);
    }

    // void setNext(Filter f, size_t n) { super.setNext(&f, 1); }

    override bool attachable() { return super.attachable(); }

    override @property string name() const { return super.name; }
    override void write(const(ubyte)* input, size_t len) { return super.write(input, len); }

    override void startMsg() { super.startMsg(); }
    override void endMsg() { super.endMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }

}