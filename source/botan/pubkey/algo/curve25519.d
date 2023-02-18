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
module botan.pubkey.algo.curve25519;

import botan.constants;

static if (BOTAN_HAS_CURVE25519):
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.curve25519_donna;
import memutils.helpers;
import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.loadstor;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;

/**
* This class represents Curve25519 Public Keys.
*/
struct Curve25519PublicKey
{
public:
	enum algoName = "Curve25519";

	/// Create a Curve25519 Public Key.
	this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits) 
	{
		m_owned = true;
		m_pub = new Curve25519PublicKeyImpl(alg_id, key_bits);
	}

	/// Create a Curve25519 Public Key.
	this(const ref Vector!ubyte pub) { m_owned = true; m_pub = new Curve25519PublicKeyImpl(pub); }

	/// Create a Curve25519 Public Key.
	this(const ref SecureVector!ubyte pub) { m_owned = true; m_pub = new Curve25519PublicKeyImpl(pub); }

	this(PrivateKey pkey) { m_pub = cast(Curve25519PublicKeyImpl) pkey; }
	this(PublicKey pkey) { m_pub = cast(Curve25519PublicKeyImpl) pkey; }
	
	mixin Embed!(m_pub, m_owned);
	
	bool m_owned;
	Curve25519PublicKeyImpl m_pub;
}

/**
* This class represents Curve25519 Private Keys.
*/
struct Curve25519PrivateKey
{
public:	
	enum algoName = "Curve25519";
	/// Create a new Curve 25519 private key
	this(RandomNumberGenerator rng) 
	{
		m_owned = true;
		m_priv = new Curve25519PrivateKeyImpl(rng);
	}

	/// Load an existing Curve 25519 private key
	this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, RandomNumberGenerator rng) 
	{
		m_owned = true;
		m_priv = new Curve25519PrivateKeyImpl(alg_id, key_bits, rng);
	}
	
	this(PrivateKey pkey) { m_priv = cast(Curve25519PrivateKeyImpl) pkey; }
	
	mixin Embed!(m_priv, m_owned);
	bool m_owned;
	Curve25519PrivateKeyImpl m_priv;
}

class Curve25519PublicKeyImpl : PublicKey
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

	/// Create a Curve25519 Public Key.
	this(const ref Vector!ubyte pub) { m_public = pub.clone(); }

	this(const ref SecureVector!ubyte pub) { m_public = unlock(pub); }

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
	
	Vector!ubyte publicValue() const { return m_public.clone(); }
	
	override bool checkKey(RandomNumberGenerator rng, bool b) const { return true; }
	
	override size_t estimatedStrength() const { return 128; }
	
protected:
	this() { }
	Vector!ubyte m_public;
}

/**
* This abstract class represents ECC private keys
*/
final class Curve25519PrivateKeyImpl : Curve25519PublicKeyImpl, PrivateKey, PKKeyAgreementKey
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
		this(cast(Curve25519PrivateKeyImpl) pkey);
	}
	this(in Curve25519PrivateKeyImpl pkey) {
		m_key = pkey;
	}
	this(in Curve25519PrivateKey pkey) {
		this(pkey.m_priv);
	}
	
	SecureVector!ubyte agree(const(ubyte)* w, size_t w_len)
	{
		return m_key.agree(w, w_len);
	}
private:
	const Curve25519PrivateKeyImpl m_key;
}



private:

void sizeCheck(size_t size, const string str)
{
	if(size != 32)
		throw new DecodingError("Invalid size " ~ size.to!string ~ " for Curve25519 " ~ str);
}

import std.exception : enforce;
SecureVector!ubyte curve25519(const ref SecureVector!ubyte secret,
	const(ubyte)* pubval)
{
	auto output = SecureVector!ubyte(32);
	const int rc = curve25519Donna(output.ptr, secret.ptr, pubval);
	enforce(rc == 0, "Return value of curve25519Donna is ok");
	return output.move();
}

Vector!ubyte curve25519Basepoint(const ref SecureVector!ubyte secret)
{
	ubyte[32] basepoint; basepoint[0] = 9;
	Vector!ubyte ret = Vector!ubyte(32);
	const int rc = curve25519Donna(ret.ptr, secret.ptr, basepoint.ptr);
	enforce(rc == 0, "Return value of curve25519Donna is ok");
	return ret.move();
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
import botan.pubkey.pkcs8;
import std.datetime;
import botan.pubkey.x509_key;

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

size_t c25519Roundtrip()
{
	atomicOp!"+="(total_tests, 1);

	Unique!AutoSeededRNG rng = new AutoSeededRNG;
	
	try
	{
		// First create keys
		auto a_priv_gen = Curve25519PrivateKey(*rng);
		auto b_priv_gen = Curve25519PrivateKey(*rng);
		
		string a_pass = "alice pass";
		string b_pass = "bob pass";

		// Then serialize to encrypted storage
		auto pbe_time = 10.msecs;
		string a_priv_pem = pkcs8.PEM_encode(a_priv_gen, *rng, a_pass, pbe_time);
		string b_priv_pem = pkcs8.PEM_encode(b_priv_gen, *rng, b_pass, pbe_time);
		
		// Reload back into memory
		auto a_priv_ds = cast(DataSource) DataSourceMemory(a_priv_pem);
		auto b_priv_ds = cast(DataSource) DataSourceMemory(b_priv_pem);
		
		Unique!PKKeyAgreementKey a_priv = cast(PKKeyAgreementKey)pkcs8.loadKey(a_priv_ds, *rng, { return a_pass; });
		Unique!PKKeyAgreementKey b_priv = cast(PKKeyAgreementKey)pkcs8.loadKey(b_priv_ds, *rng, b_pass);
		
		// Export public keys as PEM
		string a_pub_pem = x509_key.PEM_encode(*a_priv);
		string b_pub_pem = x509_key.PEM_encode(*b_priv);
		
		auto a_pub_ds = cast(DataSource) DataSourceMemory(a_pub_pem);
		auto b_pub_ds = cast(DataSource) DataSourceMemory(b_pub_pem);
		
		Unique!PublicKey a_pub = x509_key.loadKey(a_pub_ds);
		Unique!PublicKey b_pub = x509_key.loadKey(b_pub_ds);
		
		auto a_pub_key = Curve25519PublicKey(*a_pub);
		auto b_pub_key = Curve25519PublicKey(*b_pub);
		
		auto a_ka = scoped!PKKeyAgreement(*a_priv, "KDF2(SHA-256)");
		auto b_ka = scoped!PKKeyAgreement(*b_priv, "KDF2(SHA-256)");
		
		string context = "shared context value";
		SymmetricKey a_key = a_ka.deriveKey(32, b_pub_key.publicValue(), context);
		SymmetricKey b_key = b_ka.deriveKey(32, a_pub_key.publicValue(), context);
		
		if(a_key != b_key)
			return 1;
	}
	catch(Exception e)
	{
		writeln("C25519 rt fail: ", e.toString());
		return 1;
	}
	
	return 0;
}

static if (BOTAN_HAS_TESTS && !SKIP_CURVE25519_TEST) unittest
{
	logDebug("Testing curve25519.d ...");
	size_t fails = 0;


	File c25519_scalar = File("test_data/pubkey/c25519_scalar.vec", "r");
	
	fails += runTestsBb(c25519_scalar, "Curve25519 ScalarMult", "Out", true,
		(ref HashMap!(string, string) m) {
			return curve25519ScalarKat(m["Secret"], m["Basepoint"], m["Out"]);
		});
	fails += c25519Roundtrip();

	testReport("curve25519", total_tests, fails);
}

