import botan.hash.sha2_32 : SHA256;
import std.stdio;
import std.digest.sha : sha256Of;
import memutils.unique;
import botan.libstate.lookup;

void main() {
	auto sha = retrieveHash("SHA-256").clone(); // on the GC
	string test = "hello";
	sha.update(test);
	writeln(sha.finished()[]); // from botan
	writeln(sha256Of(test)); // from phobos
	
	auto skein = retrieveHash("Skein-512").clone().unique(); // RAII, ie. unique() encapsulates in Unique!HashFunction
	skein.update(test);
	writeln(skein.finished()[]);
	skein.free();
	assert(skein.isEmpty);
}
