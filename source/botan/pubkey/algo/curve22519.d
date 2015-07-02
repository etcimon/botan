/*
* Curve25519
*
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.pubkey.algo.curve22519;

import botan.constants;

static if (BOTAN_HAS_CURVE22519):
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.curve22519_donna;
import memutils.helpers;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.loadstor;

/**
* This class represents Curve22519 Public Keys.
*/
struct Curve22519PublicKey
{
public:
	this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
	{
		m_owned = true;
		m_pub = new Curve22519PublicKeyImpl(alg_id, key_bits);
	}
	
	this(PrivateKey pkey) { m_pub = cast(Curve22519PublicKeyImpl) pkey; }
	this(PublicKey pkey) { m_pub = cast(Curve22519PublicKeyImpl) pkey; }
	
	mixin Embed!(m_pub, m_owned);
	
	bool m_owned;
	Curve22519PublicKeyImpl m_pub;
}

/**
* This class represents Curve22519 Private Keys.
*/
struct Curve22519PrivateKey
{
public:
	this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
	{
		m_owned = true;
		m_priv = new Curve22519PrivateKeyImpl(alg_id, key_bits, rng);
	}
	
	this(PrivateKey pkey) { m_priv = cast(Curve22519PrivateKeyImpl) pkey; }
	
	mixin Embed!(m_priv, m_owned);
	bool m_owned;
	Curve22519PrivateKeyImpl m_priv;
}

class Curve22519PublicKeyImpl : PublicKey
{
public:
	this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
	{
		BERDecoder(key_bits)
			    .startCons(ASN1Tag.SEQUENCE)
				.decode(m_public, ASN1Tag.OCTET_STRING)
				.verifyEnd()
				.endCons();
		
		sizeCheck(m_public.length, "public key");
	}
	
	/// Used for object casting to the right type in the factory.
	final override @property string algoName() const { return "Curve25519"; }
	
	final override size_t maxInputBits() const { return 256; }
	
	final override size_t messagePartSize() const { return 0; }
	
	final override size_t messageParts() const { return 1; }
	
	final override AlgorithmIdentifier algorithmIdentifier() const
	{
		return AlgorithmIdentifier(getOid(), AlgorithmIdentifierImpl.USE_NULL_PARAM);
	}
	
	final override Vector!ubyte x509SubjectPublicKey() const
	{
		return DEREncoder()
			    .startCons(ASN1Tag.SEQUENCE)
				.encode(m_public, ASN1Tag.OCTET_STRING)
				.endCons()
				.getContentsUnlocked();
	}
	
	Vector!ubyte publicValue() const { return unlock(m_public); }
	
	override bool checkKey(RandomNumberGenerator rng, bool b) const { return true; }
	
	override size_t estimatedStrength() const { return 128; }
	
protected:
	this() { }
	SecureVector!ubyte m_public;
}

/**
* This abstract class represents ECC private keys
*/
final class Curve22519PrivateKeyImpl : Curve22519PublicKeyImpl, PrivateKey, PKKeyAgreementKey
{
public:
	/**
    * ECPrivateKey constructor
    */
	this(RandomNumberGenerator rng) 
	{		
		super();
		m_private = rng.randomVec(32);
		m_public = curve25519Basepoint(m_private);
	}
	
	this(const ref AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
	{
		super();
		BERDecoder(key_bits)
			    .startCons(ASN1Tag.SEQUENCE)
				.decode(m_public, ASN1Tag.OCTET_STRING)
				.decode(m_private, ASN1Tag.OCTET_STRING)
				.verifyEnd()
				.endCons();
		
		sizeCheck(m_public.length, "public key");
		sizeCheck(m_private.length, "private key");
		
		loadCheck(rng);
		
	}
	
	override bool checkKey(RandomNumberGenerator rng, bool b) const
	{
		return curve25519Basepoint(m_private) == m_public;
	}
	
	SecureVector!ubyte pkcs8PrivateKey() const
	{
		return DEREncoder()
			    .startCons(ASN1Tag.SEQUENCE)
				.encode(m_public, ASN1Tag.OCTET_STRING)
				.encode(m_private, ASN1Tag.OCTET_STRING)
				.endCons()
				.getContents();
	}
	
	override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return super.algorithmIdentifier(); }
	
	override Vector!ubyte publicValue() const { return super.publicValue(); }
	
	SecureVector!ubyte agree(const(ubyte)* w, size_t w_len) const {		
		sizeCheck(w_len, "public value");
		return curve25519(m_private, w);
	}
private:
	SecureVector!ubyte m_private;
}
/**
* Curve25519 operation
*/
final class Curve25519KAOperation : KeyAgreement
{
public:
	this(in PrivateKey pkey) {
		this(cast(Curve22519PrivateKeyImpl) pkey);
	}
	this(in Curve22519PrivateKeyImpl pkey) {
		m_key = pkey;
	}
	this(in Curve22519PrivateKey pkey) {
		this(pkey.m_priv);
	}
	
	SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
	{
		return m_key.agree(w, w_len);
	}
private:
	const Curve22519PrivateKeyImpl m_key;
}



private:

void sizeCheck(size_t size, const string str)
{
	if(size != 32)
		throw new DecodingError("Invalid size " ~ size.to!string ~ " for Curve25519 " ~ str);
}

SecureVector!ubyte curve25519(const ref SecureVector!ubyte secret,
	const(ubyte)* pubval)
{
	auto output = SecureVector!ubyte(32);
	const int rc = curve25519Donna(output.ptr, secret.ptr, pubval);
	assert(rc == 0, "Return value of curve25519Donna is ok");
	return output.move();
}

SecureVector!ubyte curve25519Basepoint(const ref SecureVector!ubyte secret)
{
	ubyte[32] basepoint; basepoint[0] = 9;
	return curve25519(secret, cast(const(ubyte)*)basepoint.ptr);
}

static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

private shared size_t total_tests;

size_t curve25519ScalarKat(string secret_h, string basepoint_h,	string out_h)
{
	atomicOp!"+="(total_tests, 1);
	Vector!ubyte secret = hexDecode(secret_h);
	Vector!ubyte basepoint = hexDecode(basepoint_h);
	Vector!ubyte output = hexDecode(out_h);
	
	auto got = Vector!ubyte(32);
	curve25519Donna(got.ptr, secret.ptr, basepoint.ptr);
	
	if(got != output)
	{
		logError("Got " ~ hexEncode(got) ~ " exp " ~ hexEncode(output));
		return 1;
	}
	
	return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_CURVE22519_TEST) unittest
{
	logDebug("Testing curve22519.d ...");
	size_t fails = 0;

	File c25519_scalar = File("../test_data/pubkey/c25519_scalar.vec", "r");
	
	fails += runTestsBb(c25519_scalar, "Curve25519 ScalarMult", "Out", true,
		(ref HashMap!(string, string) m) {
			return curve25519ScalarKat(m["Secret"], m["Basepoint"], m["Out"]);
		});
	
	testReport("curve22519", total_tests, fails);
}

