import botan.hash.sha2_32 : SHA256;
import std.stdio;
import std.digest.sha : sha256Of;
void main() {
	import botan.libstate.global_state;
	globalState();
	import botan.libstate.lookup;
	import botan.hash.hash;
	auto sha = retrieveHash("SHA-256").clone();
	string test = "hello";
	sha.update(test);
	writeln(sha.finished()[]);

	writeln(sha256Of(test));
}
