import botan.pubkey.pubkey;
import botan.pubkey.algo.curve25519;
import botan.rng.rng;
import botan.rng.auto_rng;
import std.stdio;
import memutils.unique;
import botan.libstate.lookup;
import botan.asn1.asn1_time;
import botan.codec.hex : hexEncode;
import botan.cert.x509.x509cert;
import botan.cert.x509.x509_crl;
import botan.cert.x509.x509path;
import botan.cert.x509.x509self;
import botan.cert.x509.pkcs10;
import std.datetime;

void main() {
	Unique!AutoSeededRNG rng = new AutoSeededRNG;

	// First create keys
	auto a_priv_gen = Curve25519PrivateKey(*rng);
	auto b_priv_gen = Curve25519PrivateKey(*rng);

	writeln("Generated Public Value A: ", hexEncode(a_priv_gen.publicValue.ptr, a_priv_gen.publicValue.length));
	writeln("Generated Public Value B: ", hexEncode(b_priv_gen.publicValue.ptr, b_priv_gen.publicValue.length));

	string a_pass = "alice pass";
	string b_pass = "bob pass";
	
	// Then serialize to encrypted storage
	auto pbe_time = 10.msecs;
	string a_priv_pem = pkcs8.PEM_encode(a_priv_gen, *rng, a_pass, pbe_time);
	string b_priv_pem = pkcs8.PEM_encode(b_priv_gen, *rng, b_pass, pbe_time);

	writeln("Private Key encoded for storage:\n");
	writeln(a_priv_pem);
	writeln(b_priv_pem);

	// Reload back into memory
	auto a_priv_ds = cast(DataSource) DataSourceMemory(a_priv_pem);
	auto b_priv_ds = cast(DataSource) DataSourceMemory(b_priv_pem);
	
	Unique!PKKeyAgreementKey a_priv = cast(PKKeyAgreementKey)pkcs8.loadKey(a_priv_ds, *rng, { return a_pass; });
	Unique!PKKeyAgreementKey b_priv = cast(PKKeyAgreementKey)pkcs8.loadKey(b_priv_ds, *rng, b_pass);

	writeln("Public key encoded for transmission:\n");
	// Export public keys as PEM
	string a_pub_pem = x509_key.PEM_encode(*a_priv);
	string b_pub_pem = x509_key.PEM_encode(*b_priv);

	writeln(a_pub_pem);
	writeln(b_pub_pem);

	auto a_pub_ds = cast(DataSource) DataSourceMemory(a_pub_pem);
	auto b_pub_ds = cast(DataSource) DataSourceMemory(b_pub_pem);
	
	Unique!PublicKey a_pub = x509_key.loadKey(a_pub_ds);
	Unique!PublicKey b_pub = x509_key.loadKey(b_pub_ds);
	
	auto a_pub_key = Curve25519PublicKey(*a_pub);
	auto b_pub_key = Curve25519PublicKey(*b_pub);

	writeln("Recovered Public Value A: ", hexEncode(a_pub_key.publicValue.ptr, a_pub_key.publicValue.length));
	writeln("Recovered Public Value B: ", hexEncode(b_pub_key.publicValue.ptr, b_pub_key.publicValue.length));

	// Proceed with key agreement
	auto a_ka = scoped!PKKeyAgreement(*a_priv, "KDF2(SHA-256)");
	auto b_ka = scoped!PKKeyAgreement(*b_priv, "KDF2(SHA-256)");
	writeln("\nDeriving key ...");

	// Bob and Alice share a context value and their public keys
	string context = "shared context value";
	SymmetricKey a_key = a_ka.deriveKey(32, b_pub_key.publicValue(), context);
	SymmetricKey b_key = b_ka.deriveKey(32, a_pub_key.publicValue(), context);

	writeln("Derived keys are equal: ", (a_key == b_key)?"Yes":"No");
}
