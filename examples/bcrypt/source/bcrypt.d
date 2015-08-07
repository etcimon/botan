import botan.passhash.bcrypt;
import std.stdio;
import botan.rng.rng;
import botan.rng.auto_rng;
import memutils.unique;
void main() {
	string password = "ObJ_3fjeEtKJzNs135!4384$_29!^  _)";
	Unique!AutoSeededRNG rng = new AutoSeededRNG;

	auto hash = generateBcrypt(password, *rng, 10);
	writeln("Hash: ", hash);
	bool valid = checkBcrypt(password, hash);
	writeln("Valid check OK? ", valid ? "Yes" : "No");
	bool invalid = !checkBcrypt(password[0 .. $-1], hash);
	writeln("Invalid check OK? ", invalid ? "Yes" : "No");
}
