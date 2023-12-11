import botan.pubkey.pubkey;
import botan.pubkey.algo.rsa;
import botan.rng.rng;
import botan.rng.auto_rng;
import std.stdio;
import memutils.unique;
import botan.libstate.lookup;
import botan.codec.hex : hexEncode;
import std.datetime.stopwatch;
void main() {
	StopWatch s;
	s.start();
	for(int i = 0; i < 30; i++) {
	Unique!AutoSeededRNG rng = new AutoSeededRNG;

	const(ubyte)[] message = cast(const(ubyte)[])"Hello, this is a binary message!";
	//writeln("Message: ", cast(string)message);
	auto privkey = RSAPrivateKey(*rng, 1024);
	
	auto pubkey = RSAPublicKey(privkey);
	
	auto enc = scoped!PKEncryptorEME(pubkey, "EME-PKCS1-v1_5");
	auto dec = scoped!PKDecryptorEME(privkey, "EME-PKCS1-v1_5");

	Vector!ubyte encrypted_message = enc.encrypt(message.ptr, message.length, *rng);
	//writeln("Encrypted: ", hexEncode(cast(const(ubyte)*)encrypted_message.ptr, encrypted_message.length));
	SecureVector!ubyte decrypted_message = dec.decrypt(encrypted_message);
	//writeln("Decrypted: ", cast(string)decrypted_message[]);
	}
	s.stop();
	writeln(s.peek().total!"msecs"());


}
