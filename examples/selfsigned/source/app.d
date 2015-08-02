module app;

import botan.constants;
version = X509;
import botan.cert.x509.certstor;
import botan.cert.x509.x509_crl;
import botan.cert.x509.x509self;
import botan.cert.x509.pkcs10;
import botan.rng.rng;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.pubkey.algo.rsa;
import botan.pubkey.algo.ecdsa;
import memutils.unique;
import std.stdio;
import std.file;
import std.datetime;

const string hash_fn = "SHA-256";

// If CA Key is present, it will be loaded rather than created
const string ca_key_file = "ca.key";
const string ca_cert_file = "ca.crt";

// The CA Certificate can be installed in a machine to trust other certificates signed by it
X509CertOptions caOpts()
{
	// Common Name/Country/Organization/OrgUnit
    X509CertOptions opts = X509CertOptions("GlobecSys CA/CA/GlobecSys Inc/Security");
    
    opts.uri = "http://globecsys.com";
    opts.dns = "globecsys.com";
    opts.email = "etcimon@globecsys.com";
    opts.end = 15.yearsLater();
    opts.CAKey(1);
    
    return opts;
}

// User's signed certificate
const string key_file = "private.pem";
const string pub_file = "public.pem";
const string cert_file = "cert.crt";
const size_t signed_cert_expiration_years = 5; // years

// The certificate request must be signed by a CA Certificate to inherit trust/authority and become a valid certificate
X509CertOptions reqOpts()
{
    X509CertOptions opts = X509CertOptions("GlobecSys.com/CA/GlobecSys Inc/Web Development");
    
    opts.uri = "http://globecsys.com";
    opts.dns = "globecsys.com";
    opts.email = "etcimon@globecsys.com";
    
    opts.addExConstraint("PKIX.EmailProtection");
    opts.addExConstraint("PKIX.ServerAuth");
    //opts.addExConstraint("PKIX.ClientAuth");
    //opts.addExConstraint("PKIX.CodeSigning");
    return opts;
}

X509Time yearsLater(size_t in_years)
{
	return X509Time(Clock.currTime.to!Date().add!"years"(in_years, AllowDayOverflow.no).toISOExtString());
}

void main() {
	Unique!AutoSeededRNG rng = new AutoSeededRNG;
	
	string ca_key_pass_verif = "";
	string ca_key_pass = "";
	do {
		if (std.file.exists(ca_key_file)) {
			assert(std.file.exists(ca_cert_file), "Found CA Private Key but could not find CA Cert file.");
			writeln("Using saved CA Key/CA Cert");
		}
		stdout.writeln("Enter a password for the CA Private Key (default: '')");
		stdout.write("Password: ");
		ca_key_pass = stdin.readln();
		if (!std.file.exists(ca_key_file))
		{
			stdout.write("Verify: ");
			ca_key_pass_verif = stdin.readln();
		} else ca_key_pass_verif = ca_key_pass;
	} while (ca_key_pass_verif != ca_key_pass);
	ca_key_pass = ca_key_pass[0 .. $-1]; // remove \n
	
	string key_pass_verif = "";
	string key_pass = "";
	do {
		stdout.writeln("Enter a password for the Private Key (default: '')");
		stdout.write("Password: ");
		key_pass = stdin.readln();
		stdout.write("Verify: ");
		key_pass_verif = stdin.readln();
	} while (key_pass_verif != key_pass);
	key_pass = key_pass[0 .. $-1]; // remove \n
    // Create the CA's key and self-signed cert
    RSAPrivateKey ca_key;
	X509Certificate ca_cert;
	if (!std.file.exists(ca_key_file))
	{
		ca_key = RSAPrivateKey(*rng, 2048);	
		auto ca_key_enc = pkcs8.PEM_encode(cast(PrivateKey)*ca_key, *rng, ca_key_pass);		
		std.file.write(ca_key_file, ca_key_enc);		
		ca_cert = x509self.createSelfSignedCert(caOpts(), *ca_key, hash_fn, *rng);		
		auto ca_cert_enc = ca_cert.PEM_encode();		
		std.file.write(ca_cert_file, ca_cert_enc);
	}
	else {
		ca_key = RSAPrivateKey(loadKey(ca_key_file, *rng, ca_key_pass));
		ca_cert = X509Certificate(ca_cert_file);
	}
    // Create user's key and cert request
	ECGroup ecc_domain = ECGroup(OID("1.2.840.10045.3.1.7"));
	auto user_key = ECDSAPrivateKey(*rng, ecc_domain);
	
	auto user_key_enc = pkcs8.PEM_encode(cast(PrivateKey)*user_key, *rng, key_pass);
	auto user_pub_enc = x509_key.PEM_encode(cast(PublicKey)*user_key);
	
	std.file.write(key_file, user_key_enc);
	std.file.write(pub_file, user_pub_enc);
	
    PKCS10Request sign_req = x509self.createCertReq(reqOpts(), *user_key, hash_fn, *rng);
    
    // Create the CA object
    X509CA ca = X509CA(ca_cert, *ca_key, hash_fn);
    
    // Sign the requests with the CA object to create the cert
    X509Certificate user_cert = ca.signRequest(sign_req, *rng, X509Time(Clock.currTime().to!Date().toISOExtString()), signed_cert_expiration_years.yearsLater());
   
	std.file.write(cert_file, user_cert.PEM_encode());
	
	writeln(user_cert.toString());
}
