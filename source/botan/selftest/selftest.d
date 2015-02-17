/**
* Startup Self Test
* 
* Copyright:
* (C) 1999-2007 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.selftest.selftest;

import botan.constants;
static if (BOTAN_HAS_SELFTESTS):

import botan.algo_factory.algo_factory;
import botan.algo_base.scan_token;

import botan.filters.filters;
import botan.filters.hex_filt;
import botan.filters.aead_filt;
import botan.codec.hex;
import botan.hash.hash;
import botan.mac.mac;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.engine.core_engine;
import botan.algo_base.symkey;
import memutils.dictionarylist;
import memutils.hashmap;
import botan.utils.exceptn;
import botan.utils.types;

/**
* Run a set of self tests on some basic algorithms like AES and SHA-1
* Params:
*  af = an algorithm factory
* Throws: $(D SelfTestFailure) if a failure occured
*/
/*
* Perform Self Tests
*/
void confirmStartupSelfTests(AlgorithmFactory af)
{
    logInfo("************************");
    logInfo("*** START SELF TESTS ***");
    logInfo("************************");
    cipherKat(af, "DES",
               "0123456789ABCDEF", "1234567890ABCDEF",
               "4E6F77206973207468652074696D6520666F7220616C6C20",
               "3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53",
               "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6",
               "F3096249C7F46E51A69E839B1A92F78403467133898EA622",
               "F3096249C7F46E5135F24A242EEB3D3F3D6D5BE3255AF8C3",
               "F3096249C7F46E51163A8CA0FFC94C27FA2F80F480B86F75");
    
    cipherKat(af, "TripleDES",
               "385D7189A5C3D485E1370AA5D408082B5CCCCB5E19F2D90E",
               "C141B5FCCD28DC8A",
               "6E1BD7C6120947A464A6AAB293A0F89A563D8D40D3461B68",
               "64EAAD4ACBB9CEAD6C7615E7C7E4792FE587D91F20C7D2F4",
               "6235A461AFD312973E3B4F7AA7D23E34E03371F8E8C376C9",
               "E26BA806A59B0330DE40CA38E77A3E494BE2B212F6DD624B",
               "E26BA806A59B03307DE2BCC25A08BA40A8BA335F5D604C62",
               "E26BA806A59B03303C62C2EFF32D3ACDD5D5F35EBCC53371");
    
    cipherKat(af, "AES-128",
               "2B7E151628AED2A6ABF7158809CF4F3C",
               "000102030405060708090A0B0C0D0E0F",
               "6BC1BEE22E409F96E93D7E117393172A"
               ~ "AE2D8A571E03AC9C9EB76FAC45AF8E51",
               "3AD77BB40D7A3660A89ECAF32466EF97"
               ~ "F5D3D58503B9699DE785895A96FDBAAF",
               "7649ABAC8119B246CEE98E9B12E9197D"
               ~ "5086CB9B507219EE95DB113A917678B2",
               "3B3FD92EB72DAD20333449F8E83CFB4A"
               ~ "C8A64537A0B3A93FCDE3CDAD9F1CE58B",
               "3B3FD92EB72DAD20333449F8E83CFB4A"
               ~ "7789508D16918F03F53C52DAC54ED825",
               "3B3FD92EB72DAD20333449F8E83CFB4A"
               ~ "010C041999E03F36448624483E582D0E");
    
    hashTest(af, "SHA-1",
              "", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    
    hashTest(af, "SHA-1",
              "616263", "A9993E364706816ABA3E25717850C26C9CD0D89D");
    
    hashTest(af, "SHA-1",
              "6162636462636465636465666465666765666768666768696768696A"
              ~ "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
              "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
    
    macTest(af, "HMAC(SHA-1)",
             "4869205468657265",
             "B617318655057264E28BC0B6FB378C8EF146BE00",
             "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    
    hashTest(af, "SHA-256",
              "",
              "E3B0C44298FC1C149AFBF4C8996FB924"
              ~ "27AE41E4649B934CA495991B7852B855");
    
    hashTest(af, "SHA-256",
              "616263",
              "BA7816BF8F01CFEA414140DE5DAE2223"
              ~ "B00361A396177A9CB410FF61F20015AD");
    
    hashTest(af, "SHA-256",
              "6162636462636465636465666465666765666768666768696768696A"
              ~ "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
              "248D6A61D20638B8E5C026930C3E6039"
              ~ "A33CE45964FF2167F6ECEDD419DB06C1");
    
    macTest(af, "HMAC(SHA-256)",
             "4869205468657265",
             "198A607EB44BFBC69903A0F1CF2BBDC5"
             ~ "BA0AA3F3D9AE3C1C7A3B1696A0B68CF7",
             "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"
             ~ "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    logInfo("**********************");
    logInfo("*** END SELF TESTS ***");
    logInfo("**********************");
}

/**
* Run a set of self tests on some basic algorithms like AES and SHA-1
* Params:
*  af = an algorithm factory
* Returns:s false if a failure occured, otherwise true
*/
bool passesSelfTests(AlgorithmFactory af)
{
    try
    {
        confirmStartupSelfTests(af);
    }
    catch(SelfTestFailure)
    {
        return false;
    }
    
    return true;
}


/**
* Run a set of algorithm KATs (known answer tests)
* Params:
*  algo_name = the algorithm we are testing
*  vars = a set of input variables for this test, all
            hex encoded. Keys used: "input", "output", "key", and "iv"
*  af = an algorithm factory
* Returns: map from provider name to test result for that provider
*/
HashMapRef!(string, bool)
    algorithmKat(in SCANToken algo_name,
                  in HashMapRef!(string, string) vars,
                  AlgorithmFactory af)
{
    const auto result = algorithmKatDetailed(algo_name, vars, af);
    
    HashMapRef!(string, bool) pass_or_fail;
    
    foreach (const ref string key, const ref string val; result)
        pass_or_fail[key] = (val == "PASSED");
    
    return pass_or_fail;
}

/**
* Run a set of algorithm KATs (known answer tests)
* Params:
*  algo_name = the algorithm we are testing
*  vars = a set of input variables for this test, all
            hex encoded. Keys used: "input", "output", "key", and "iv"
*  af = an algorithm factory
* Returns:s map from provider name to test result for that provider
*/
HashMapRef!(string, string)
    algorithmKatDetailed(in SCANToken algo_name,
                         const ref HashMapRef!(string, string) vars,
                         AlgorithmFactory af)
{
    logTrace("Testing ", algo_name);
    const string algo = algo_name.algoNameAndArgs();
    
    logTrace("algoNameAndArgs: ", algo);
    Vector!string providers = af.providersOf(algo);
    logTrace("Providers: ", providers[]);
    HashMapRef!(string, string) all_results;
    
    if (providers.empty) { // no providers, nothing to do
        logTrace("Warning: ", algo_name.toString(), " has no providers");
        return all_results;
    }
    const string input = vars.get("input");
    const string output = vars.get("output");
    
    SymmetricKey key = SymmetricKey(vars.get("key"));
    InitializationVector iv = InitializationVector(vars.get("iv"));
    
    for (size_t i = 0; i != providers.length; ++i)
    {
        const string provider = providers[i];
        
        if (const HashFunction proto = af.prototypeHashFunction(algo, provider))
        {
            logTrace("Found ", proto.name);
            Filter filt = new HashFilter(proto.clone());
            all_results[provider] = testFilterKat(filt, input, output);
            logInfo(proto.name, " (", provider, ") ... ", all_results[provider]);
        }
        else if (const MessageAuthenticationCode proto = af.prototypeMac(algo, provider))
        {
            logTrace("Found ", proto.name);
            KeyedFilter filt = new MACFilter(proto.clone(), key);
            all_results[provider] = testFilterKat(filt, input, output);
            logInfo(proto.name, " (", provider, ") ... ", all_results[provider]);
        }
        else if (const StreamCipher proto = af.prototypeStreamCipher(algo, provider))
        {
            logTrace("Found ", proto.name);
            KeyedFilter filt = new StreamCipherFilter(proto.clone());
            filt.setKey(key);
            filt.setIv(iv);
            
            all_results[provider] = testFilterKat(filt, input, output);

            
            logInfo(proto.name, " (", provider, ") ... ", all_results[provider]);
        }
        else if (const BlockCipher proto = af.prototypeBlockCipher(algo, provider))
        {
            logTrace("Found ", proto.name);
            KeyedFilter enc = getCipherMode(proto, ENCRYPTION,
                                            algo_name.cipherMode(),
                                            algo_name.cipherModePad());
            
            KeyedFilter dec = getCipherMode(proto, DECRYPTION,
                                            algo_name.cipherMode(),
                                            algo_name.cipherModePad());
            
            if (!enc || !dec)
            {
                logTrace("Enc/dec failure");
                destroy(enc);
                destroy(dec);
                continue;
            }
            
            enc.setKey(key);
            
            if (enc.validIvLength(iv.length))
                enc.setIv(iv);
            else if (!enc.validIvLength(0))
                throw new InvalidIVLength(algo, iv.length);
            
            dec.setKey(key);
            
            if (dec.validIvLength(iv.length))
                dec.setIv(iv);
            else if (!dec.validIvLength(0))
                throw new InvalidIVLength(algo, iv.length);
            
            const Vector!ubyte ad = hexDecode(vars.get("ad"));
            
            if (!ad.empty)
            {
                static if (BOTAN_HAS_AEAD_FILTER) {
                    if (AEADFilter enc_aead = cast(AEADFilter)(enc))
                    {
                        enc_aead.setAssociatedData(ad.ptr, ad.length);
                        
                        if (AEADFilter dec_aead = cast(AEADFilter)(dec))
                            dec_aead.setAssociatedData(ad.ptr, ad.length);
                    }
                }
            }
            
            all_results[provider ~ " (encrypt)"] = testFilterKat(enc, input, output);
            all_results[provider ~ " (decrypt)"] = testFilterKat(dec, output, input);

            logInfo(proto.name, " (", provider, " encrypt) ... ", all_results[provider ~ " (encrypt)"]);
            logInfo(proto.name, " (", provider, " decrypt) ... ", all_results[provider ~ " (decrypt)"]);

        }
    }    

    return all_results;
}

private:

void verifyResults(in string algo, const HashMapRef!(string, string) results)
{
    foreach (const ref string key, const ref string value; *results)
    {
        if (value != "PASSED")
            throw new SelfTestFailure(algo ~ " self-test failed (" ~ value ~ ")" ~
                                        " with provider " ~ key);
    }
}

void hashTest(AlgorithmFactory af, in string name, in string input, in string output)
{
    HashMapRef!(string, string) vars;
    vars["input"] = input;
    vars["output"] = output;
    
    verifyResults(name, algorithmKatDetailed(SCANToken(name), vars, af));
}

void macTest(AlgorithmFactory af,
              in string name,
              in string input,
              in string output,
              in string key)
{
    HashMapRef!(string, string) vars;
    vars["input"] = input;
    vars["output"] = output;
    vars["key"] = key;
    
    verifyResults(name, algorithmKatDetailed(SCANToken(name), vars, af));
}

/*
* Perform a KAT for a cipher
*/
void cipherKat(AlgorithmFactory af,
               in string algo,
               in string key_str,
               in string iv_str,
               in string input,
               in string ecb_out,
               in string cbc_out,
               in string cfb_out,
               in string ofb_out,
               in string ctr_out)
{
    SymmetricKey key = SymmetricKey(key_str);
    InitializationVector iv = InitializationVector(iv_str);
    
    HashMapRef!(string, string) vars;
    vars["key"] = key_str;
    vars["iv"] = iv_str;
    vars["input"] = input;
    
    HashMapRef!(string, bool) results;
    
    vars["output"] = ecb_out;
    verifyResults(algo ~ "/ECB", algorithmKatDetailed(SCANToken(algo ~ "/ECB"), vars, af));
    
    vars["output"] = cbc_out;
    verifyResults(algo ~ "/CBC", algorithmKatDetailed(SCANToken(algo ~ "/CBC/NoPadding"), vars, af));
    
    vars["output"] = cfb_out;
    verifyResults(algo ~ "/CFB", algorithmKatDetailed(SCANToken(algo ~ "/CFB"), vars, af));
    
    vars["output"] = ofb_out;
    verifyResults(algo ~ "/OFB", algorithmKatDetailed(SCANToken(algo ~ "/OFB"), vars, af));
    
    vars["output"] = ctr_out;
    verifyResults(algo ~ "/CTR", algorithmKatDetailed(SCANToken(algo ~ "/CTR-BE"), vars, af));
}


/*
* Perform a Known Answer Test
*/
string testFilterKat(Filter filter,
                     in string input,
                     in string expected)
{
    try
    {
        Pipe pipe = Pipe(new HexDecoder, filter, new HexEncoder);
        pipe.processMsg(input);
        const string got = pipe.toString();
        const bool same = (got == expected);
        
        if (same) {
            return "PASSED";

        } else {
            return "************** FAILED **************** => got " ~ got ~ " expected " ~ expected;
        }
    }
    catch(Exception e)
    {
        return "exception " ~ e.msg;
    }
}