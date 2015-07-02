/**
* ChaCha20Poly1305 AEAD
* 
* Copyright:
* (C) 2014 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.modes.aead.chacha20poly1305;
import botan.modes.aead.aead;
import botan.stream.stream_cipher;
import botan.mac.mac;

/**
* Base class
* See draft-irtf-cfrg-chacha20-poly1305-03 for specification
* If a nonce of 64 bits is used the older version described in
* draft-agl-tls-chacha20poly1305-04 is used instead.
*/
class ChaCha20Poly1305Mode : AEADMode
{
public:
	
	override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) {
		if(!validNonceLength(nonce_len))
			throw InvalidIVLength(name, nonce_len);
		
		m_ctext_len = 0;
		m_nonce_len = nonce_len;
		
		m_chacha->setIv(nonce, nonce_len);
		
		ubyte[64] zeros;
		m_chacha.encrypt(zeros.ptr, zeros.length);
		
		m_poly1305.setKey(zeros.ptr, 32);
		// Remainder of output is discard
		
		m_poly1305.update(m_ad);
		
		if(cfrg_version()) {
			auto padding = Vector!ubyte(16 - m_ad.length % 16);
			m_poly1305.update(padding);
		}
		else {
			updateLength(m_ad.length);
		}
		
		return SecureVector!ubyte();
	}
	override void setAssociatedData(const(ubyte)* ad, size_t ad_len) {
		if(m_ctext_len)
			throw new Exception("Too late to set AD for ChaCha20Poly1305");
		m_ad = ad[0 .. length];
	}
	
	override @property string name() const { return "ChaCha20Poly1305"; }
	override size_t updateGranularity() const { return 64; }
	override KeyLengthSpecification keySpec() const { return Key_Length_Specification(32); }
	override bool validNonceLength(size_t n) const { return (n == 8 || n == 12); }
	override size_t tagSize() const { return 16; }
	
	override void clear() {
		m_chacha.clear();
		m_poly1305.clear();
		m_ad.clear();
		m_ctext_len = 0;
	}
	
	override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
	override void keySchedule(const(ubyte)* key, size_t length) {   
		m_chacha.setKey(key, length);
	}
	
	bool valid_nonce_length(size_t n) const override;
	
	size_t tagSize() const override { return 16; }
	
	void clear() override;
protected:
	Unique!StreamCipher m_chacha;
	Unique!MessageAuthenticationCode m_poly1305;
	
	this() {
		m_chacha = makeStreamCipher("ChaCha");
		m_poly1305 = makeMac("Poly1305");
	}
	
	SecureVector!ubyte m_ad;
	size_t m_nonce_len;
	size_t m_ctext_len;
	
	bool cfrg_version() const { return m_nonce_len == 12; }
	void updateLength(size_t len) {		
		ubyte[8] len8;
		storeLittleEndian(cast(ulong)len, len8.ptr);
		m_poly1305.update(len8.ptr, 8);
	}
}

/**
* ChaCha20Poly1305 Encryption
*/
class ChaCha20Poly1305Encryption : ChaCha20Poly1305Mode, Transformation
{
public:
	
	this(BlockCipher cipher, size_t tagSize = 16) 
	{
		super(cipher, tagSize);
	}
	
	override size_t outputLength(size_t input_length) const { return input_length + tagSize(); }
	
	override size_t minimumFinalSize() const { return 0; }
	
	override void update(ref SecureVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = buffer.ptr + offset;
		
		m_chacha.cipher1(buf, sz);
		m_poly1305.update(buf, sz); // poly1305 of ciphertext
		m_ctext_len += sz;
		
	}
	
	override void finish(ref SecureVector!ubyte buffer, size_t offset = 0)
	{
		update(buffer, offset);
		if(cfrg_version())
		{
			auto padding = Vector!ubyte(16 - m_ctext_len % 16);
			m_poly1305.update(padding);
			updateLength(m_ad.size());
		}
		updateLength(m_ctext_len);
		
		const SecureVector!ubyte mac = m_poly1305.finished();
		buffer ~= mac.ptr[0 .. tagSize()];
		m_ctext_len = 0;
		
	}
	
	// Interface fallthrough
	override string provider() const { return "core"; }
	override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
	override size_t updateGranularity() const { return super.updateGranularity(); }
	override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
	override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
	override @property string name() const { return super.name; }
	override void clear() { return super.clear(); }
};

/**
* ChaCha20Poly1305 Decryption
*/
class ChaCha20Poly1305Decryption : ChaCha20Poly1305Mode, Transformation
{
public:
	
	override size_t outputLength(size_t input_length) const { 
		assert(input_length > tagSize(), "Sufficient input");
		return input_length - tagSize(); 
	}
	
	override size_t minimumFinalSize() const { return 0; }
	
	override void update(ref SecureVector!ubyte buffer, size_t offset = 0) {
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = buffer.ptr + offset;
		
		m_poly1305.update(buf, sz); // poly1305 of ciphertext
		m_chacha.cipher1(buf, sz);
		m_ctext_len += sz;
		
	}
	
	override void finish(ref SecureVector!ubyte buffer, size_t offset = 0) {
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = buffer.ptr + offset;
		
		assert(sz >= tagSize(), "Have the tag as part of final input");
		
		const size_t remaining = sz - tagSize();
		
		if(remaining) {
			m_poly1305.update(buf, remaining); // poly1305 of ciphertext
			m_chacha.cipher1(buf, remaining);
			m_ctext_len += remaining;
		}
		
		if(cfrg_version()) {
			for(size_t i = 0; i != 16 - m_ctext_len % 16; ++i)
				m_poly1305.update(0);
			updateLength(m_ad.size());
		}
		
		updateLength(m_ctext_len);
		const SecureVector!ubyte mac = m_poly1305.finished();
		
		const ubyte* included_tag = buf.ptr + remaining;
		
		m_ctext_len = 0;
		
		if(!sameMem(mac.ptr, included_tag, tagSize()))
			throw Integrity_Failure("ChaCha20Poly1305 tag check failed");
		
		buffer.resize(offset + remaining);
	}
	
	// Interface fallthrough
	override string provider() const { return "core"; }
	override SecureVector!ubyte startRaw(const(ubyte)* nonce, size_t nonce_len) { return super.startRaw(nonce, nonce_len); }
	override size_t updateGranularity() const { return super.updateGranularity(); }
	override size_t defaultNonceLength() const { return super.defaultNonceLength(); }
	override bool validNonceLength(size_t nonce_len) const { return super.validNonceLength(nonce_len); }
	override @property string name() const { return super.name; }
	override void clear() { return super.clear(); }
}

