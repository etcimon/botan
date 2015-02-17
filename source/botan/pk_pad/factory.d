/**
* EMSA/EME Retrieval
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pk_pad.factory;

import botan.pk_pad.emsa;
import botan.pk_pad.eme;
import botan.libstate.libstate;
import botan.algo_base.scan_token;
import botan.utils.exceptn;

import botan.constants;
static if (BOTAN_HAS_EMSA1)          import botan.pk_pad.emsa1;
static if (BOTAN_HAS_EMSA1_BSI)      import botan.pk_pad.emsa1_bsi;
static if (BOTAN_HAS_EMSA_X931)      import botan.pk_pad.emsa_x931;
static if (BOTAN_HAS_EMSA_PKCS1)     import botan.pk_pad.emsa_pkcs1;
static if (BOTAN_HAS_EMSA_PSSR)      import botan.pk_pad.pssr;
static if (BOTAN_HAS_EMSA_RAW)       import botan.pk_pad.emsa_raw;
static if (BOTAN_HAS_EME_OAEP)       import botan.pk_pad.oaep;
static if (BOTAN_HAS_EME_PKCS1_V15)  import botan.pk_pad.eme_pkcs;

/**
* Factory method for EMSA (message-encoding methods for signatures
* with appendix) objects
* Params:
*  algo_spec = the name of the EME to create
* Returns: pointer to newly allocated object of that type
*/
EMSA getEmsa(in string algo_spec)
{
    SCANToken request = SCANToken(algo_spec);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    static if (BOTAN_HAS_EMSA_RAW) {
        if (request.algoName == "Raw" && request.argCount() == 0)
            return new EMSARaw;
    }
    
    if (request.algoName == "EMSA1" && request.argCount() == 1)
    {
        static if (BOTAN_HAS_EMSA_RAW) {
            if (request.arg(0) == "Raw")
                return new EMSARaw;
        }
        
        static if (BOTAN_HAS_EMSA1) {
            return new EMSA1(af.makeHashFunction(request.arg(0)));
        }
    }
    
    static if (BOTAN_HAS_EMSA1_BSI) {
        if (request.algoName == "EMSA1_BSI" && request.argCount() == 1)
            return new EMSA1BSI(af.makeHashFunction(request.arg(0)));
    }
    
    static if (BOTAN_HAS_EMSA_X931) {
        if (request.algoName == "EMSA_X931" && request.argCount() == 1)
            return new EMSAX931(af.makeHashFunction(request.arg(0)));
    }
    
    static if (BOTAN_HAS_EMSA_PKCS1) {
        if (request.algoName == "EMSA_PKCS1" && request.argCount() == 1)
        {
            if (request.arg(0) == "Raw")
                return new EMSAPKCS1v15Raw;
            return new EMSAPKCS1v15(af.makeHashFunction(request.arg(0)));
        }
    }
    
    static if (BOTAN_HAS_EMSA_PSSR) {
        if (request.algoName == "PSSR" && request.argCountBetween(1, 3))
        {
            // 3 args: Hash, MGF, salt size (MGF is hardcoded MGF1 in Botan)
            if (request.argCount() == 1)
                return new PSSR(af.makeHashFunction(request.arg(0)));
            
            if (request.argCount() == 2 && request.arg(1) != "MGF1")
                return new PSSR(af.makeHashFunction(request.arg(0)));
            
            if (request.argCount() == 3)
                return new PSSR(af.makeHashFunction(request.arg(0)), request.argAsInteger(2, 0));
        }
    }
    
    throw new AlgorithmNotFound(algo_spec);
}

/**
* Factory method for EME (message-encoding methods for encryption) objects
* Params:
*  algo_spec = the name of the EME to create
* Returns: pointer to newly allocated object of that type
*/
EME getEme(in string algo_spec)
{
    SCANToken request = SCANToken(algo_spec);
    
    if (request.algoName == "Raw")
        return null; // No padding
    
    static if (BOTAN_HAS_EME_PKCS1_V15) {
        if (request.algoName == "PKCS1v15" && request.argCount() == 0)
            return new EMEPKCS1v15;
    }
    
    static if (BOTAN_HAS_EME_OAEP) {
        AlgorithmFactory af = globalState().algorithmFactory();
        
        if (request.algoName == "OAEP" && request.argCountBetween(1, 2))
        {
            if (request.argCount() == 1 ||
                (request.argCount() == 2 && request.arg(1) == "MGF1"))
            {
                return new OAEP(af.makeHashFunction(request.arg(0)));
            }
        }
    }
    
    throw new AlgorithmNotFound(algo_spec);
}