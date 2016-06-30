import std.stdio;
import botan.libstate.global_state;
import botan.constructs.cryptobox;
import botan.rng.rng;
import botan.rng.auto_rng;

void main() {
    auto state = globalState(); // ensure initialized
    Unique!AutoSeededRNG rng = new AutoSeededRNG;
    
    string msg = "Something";
    writeln("Message: ", msg);
	
    string ciphertext = CryptoBox.encrypt(cast(ubyte*)msg.ptr, msg.length, "secret password", *rng);
    writeln(ciphertext);
	
    string plaintext = CryptoBox.decrypt(ciphertext, "secret password");
    writeln("Recovered: ", plaintext);
}
