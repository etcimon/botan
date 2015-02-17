/**
* PBE
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pbe.pbe;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.filters.filter;
import botan.rng.rng;
import botan.utils.types;

/**
* Password Based Encryption (PBE) Filter.
*/
abstract class PBE : Filter, Filterable
{
public:
    /**
    * DER encode the params (the number of iterations and the salt value)
    * Returns: encoded params
    */
    abstract Vector!ubyte encodeParams() const;

    /**
    * Get this PBE's OID.
    * Returns: object identifier
    */
    abstract OID getOid() const;

    override void setNext(Filter* filters, size_t size) {
        super.setNext(filters, size);
    }
}
