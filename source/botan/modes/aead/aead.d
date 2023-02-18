/**
* Interface for AEAD modes
* 
* Copyright:
* (C) 2013 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.aead;
import botan.constants;
static if (BOTAN_HAS_AEAD_CCM || BOTAN_HAS_AEAD_EAX || BOTAN_HAS_AEAD_GCM || BOTAN_HAS_AEAD_SIV || BOTAN_HAS_AEAD_OCB || BOTAN_HAS_AEAD_CHACHA20_POLY1305):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.libstate.libstate;
import botan.utils.parsing;
static if (BOTAN_HAS_AEAD_CCM) import botan.modes.aead.ccm;
static if (BOTAN_HAS_AEAD_EAX) import botan.modes.aead.eax;
static if (BOTAN_HAS_AEAD_GCM) import botan.modes.aead.gcm;
static if (BOTAN_HAS_AEAD_SIV) import botan.modes.aead.siv;
static if (BOTAN_HAS_AEAD_OCB) import botan.modes.aead.ocb;
static if (BOTAN_HAS_AEAD_CHACHA20_POLY1305) import botan.modes.aead.chacha20poly1305;

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class AEADMode : CipherMode, Transformation
{
public:
    final override bool authenticated() const { return true; }

    /**
    * Set associated data that is not included in the ciphertext but
    * that should be authenticated. Must be called after setKey
    * and before finish.
    *
    * Unless reset by another call, the associated data is kept
    * between messages. Thus, if the AD does not change, calling
    * once (after setKey) is the optimum.
    *
    * Params:
    *  ad = the associated data
    *  ad_len = length of add in bytes
    */
    abstract void setAssociatedData(const(ubyte)* ad, size_t ad_len);

    final void setAssociatedDataVec(Alloc)(const ref Vector!( ubyte, Alloc ) ad)
    {
        setAssociatedData(ad.ptr, ad.length);
    }

    /**
    * Default AEAD nonce size (a commonly supported value among AEAD
    * modes, and large enough that random collisions are unlikely).
    */
    override size_t defaultNonceLength() const { return 12; }

    /**
    * Return the size of the authentication tag used (in bytes)
    */
    abstract size_t tagSize() const;
}

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
AEADMode getAead(in string algo_spec, CipherDir direction)
{
	
	static if (BOTAN_HAS_AEAD_CHACHA20_POLY1305) {
		if (algo_spec == "ChaCha20Poly1305")
		{
			if (direction == ENCRYPTION)
				return new ChaCha20Poly1305Encryption;
			else
				return new ChaCha20Poly1305Decryption;
		}
	}
    AlgorithmFactory af = globalState().algorithmFactory();
    
	static Vector!string last_algo_parts;
	static string last_algo_spec;
	Vector!string algo_parts;
	if (last_algo_spec == algo_spec)
		algo_parts = last_algo_parts.clone;
	else {
		algo_parts = algo_spec.splitter('/');
		last_algo_spec = algo_spec;
		last_algo_parts = algo_parts.clone;
	}
	if (algo_parts.empty)
        throw new InvalidAlgorithmName(algo_spec);
    
    if (algo_parts.length < 2)
        return null;
    
    const string cipher_name = algo_parts[0];
    const BlockCipher cipher = af.prototypeBlockCipher(cipher_name);
    if (!cipher)
        return null;

	static Vector!string last_mode_info;
	static string last_algo_part_1;
	Vector!string mode_info;
	if (last_algo_part_1 == algo_parts[1])
		mode_info = last_mode_info.clone;
	else {
		mode_info = parseAlgorithmName(algo_parts[1]);
		last_mode_info = mode_info.clone;
		last_algo_part_1 = algo_parts[1];
	}

    if (mode_info.empty)
        return null;
    
    const string mode_name = mode_info[0];
    
    const size_t tag_size = (mode_info.length > 1) ? to!uint(mode_info[1]) : cipher.blockSize();
    
    static if (BOTAN_HAS_AEAD_CCM) {
        if (mode_name == "CCM-8")
        {
            if (direction == ENCRYPTION)
                return new CCMEncryption(cipher.clone(), 8, 3);
            else
                return new CCMDecryption(cipher.clone(), 8, 3);
        }
        
        if (mode_name == "CCM" || mode_name == "CCM-8")
        {
            const size_t L = (mode_info.length > 2) ? to!uint(mode_info[2]) : 3;
            
            if (direction == ENCRYPTION)
                return new CCMEncryption(cipher.clone(), tag_size, L);
            else
                return new CCMDecryption(cipher.clone(), tag_size, L);
        }
    }
    
    static if (BOTAN_HAS_AEAD_EAX) {
        if (mode_name == "EAX")
        {
            if (direction == ENCRYPTION)
                return new EAXEncryption(cipher.clone(), tag_size);
            else
                return new EAXDecryption(cipher.clone(), tag_size);
        }
    }
    
    static if (BOTAN_HAS_AEAD_SIV) {
        if (mode_name == "SIV")
        {
            assert(tag_size == 16, "Valid tag size for SIV");
            if (direction == ENCRYPTION)
                return new SIVEncryption(cipher.clone());
            else
                return new SIVDecryption(cipher.clone());
        }
    }
    
    static if (BOTAN_HAS_AEAD_GCM) {
        if (mode_name == "GCM")
        {
            if (direction == ENCRYPTION)
                return new GCMEncryption(cipher.clone(), tag_size);
            else
                return new GCMDecryption(cipher.clone(), tag_size);
        }
    }

    static if (BOTAN_HAS_AEAD_OCB) {
        if (mode_name == "OCB")
        {
            if (direction == ENCRYPTION)
                return new OCBEncryption(cipher.clone(), tag_size);
            else
                return new OCBDecryption(cipher.clone(), tag_size);
        }
    }
    
    return null;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import core.atomic;
shared size_t total_tests;
import memutils.hashmap;

size_t aeadTest(string algo, string input, string expected, string nonce_hex, string ad_hex, string key_hex)
{
    atomicOp!"+="(total_tests, 5);
    const SecureVector!ubyte nonce = hexDecodeLocked(nonce_hex);
    const SecureVector!ubyte ad = hexDecodeLocked(ad_hex);
    const SecureVector!ubyte key = hexDecodeLocked(key_hex);
    Unique!CipherMode enc = getAead(algo, ENCRYPTION);
    Unique!CipherMode dec = getAead(algo, DECRYPTION);
    if (!enc || !dec)
        throw new Exception("Unknown AEAD " ~ algo);
    
    enc.setKey(key);
    dec.setKey(key);
    if (auto aead_enc = cast(AEADMode)(*enc))
        aead_enc.setAssociatedDataVec(ad);
    if (auto aead_dec = cast(AEADMode)(*dec))
        aead_dec.setAssociatedDataVec(ad);
    
    size_t fail = 0;
    
    const SecureVector!ubyte pt = hexDecodeLocked(input);
    const SecureVector!ubyte expected_ct = hexDecodeLocked(expected);
    
    SecureVector!ubyte vec = pt.clone;
    enc.start(nonce);

    // should first update if possible
    enc.finish(vec);
    if (vec != expected_ct)
    {
        logError("1: ", algo ~ " got ct " ~ hexEncode(vec) ~ " expected " ~ expected);
        logError(algo ~ " \n");
        ++fail;
    }
    
    vec = expected_ct.clone;
    
    dec.start(nonce);
    dec.finish(vec);
    
    if (vec != pt)
    {
        logError("2: ", algo ~ " got pt " ~ hexEncode(vec) ~ " expected " ~ input);
        ++fail;
    }
    
    if (enc.authenticated())
    {
        vec = expected_ct.clone;
        vec[0] ^= 1;
        dec.start(nonce);
        try
        {
            dec.finish(vec);
            logError(algo ~ " accepted message with modified message");
            ++fail;
        }
        catch (Exception) {}
        
        if (nonce.length)
        {
            auto bad_nonce = nonce.clone;
            bad_nonce[0] ^= 1;
            vec = expected_ct.clone;
            
            dec.start(bad_nonce);
            
            try
            {
                dec.finish(vec);
                logError(algo ~ " accepted message with modified nonce");
                ++fail;
            }
            catch (Exception) {}
        }
        
        if (auto aead_dec = cast(AEADMode)(*dec))
        {
            SecureVector!ubyte bad_ad = ad.clone;
            
            if (ad.length) {
                bad_ad[0] ^= 1;
            }
            else {
                bad_ad.pushBack(0);
            }
            
            aead_dec.setAssociatedDataVec(bad_ad);
            
            vec = expected_ct.clone;
            dec.start(nonce);
            
            try
            {
                dec.finish(vec);
                logError(algo ~ " accepted message with modified AD");
                ++fail;
            }
            catch (Exception) {}
        }
    }
    return fail;
}

static if (BOTAN_HAS_TESTS && !SKIP_AEAD_TEST) unittest
{
    logDebug("Testing aead.d ...");
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "AEAD", "Out", true,
            (ref HashMap!(string, string) m)
            {
                return aeadTest(m["AEAD"], m["In"], m["Out"], m.get("Nonce"), m.get("AD"), m["Key"]);
            });
    };
    
    size_t fails = runTestsInDir("test_data/aead", test);
    logDebug("Test report");
    testReport("aead", total_tests, fails);
}
