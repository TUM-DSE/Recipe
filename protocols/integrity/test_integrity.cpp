#include "digest_h.h"
int main(void) {

	std::shared_ptr<PacketSsl> cipher;
	uint8_t __key[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
	uint8_t __iv[12] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5,
		0x6, 0x7, 0x8, 0x9, 0xa, 0xb};

	std::shared_ptr<KeyIV> keyIv =
		std::make_shared<KeyIV>(reinterpret_cast<std::byte *>(__key),
				reinterpret_cast<std::byte *>(__iv));
	cipher = std::make_shared<PacketSsl>(keyIv);
	constexpr int kValueSize = 256;
	constexpr int kMetaSize = sizeof(int);
	std::unique_ptr<char[]> payload = std::make_unique<char[]>(kValueSize);
	std::unique_ptr<char[]> metadata = std::make_unique<char[]>(kMetaSize);
	::memset(payload.get(), '1', kValueSize);
	int a = 5;
	for (auto i = 1; i < 10; i++) {
		::memcpy(metadata.get(), &a, kMetaSize);
		auto enc_res = construct(cipher.get(), metadata.get(), kMetaSize, payload.get(), kValueSize);
		auto [h_sz, h] = get_sha256(payload.get(), kValueSize);
		std::cout << h_sz << "\n";
		for (auto i = 0; i < h_sz; i++) {
			std::cout << reinterpret_cast<int*>(h.get())[i] << " ";
		}
		std::cout << "\n";
		std::cout << "encrypted data sz= "<< std::get<0>(enc_res) << "\n";

		auto dec_res = destruct(cipher.get(), std::get<1>(enc_res).get(), std::get<0>(enc_res));
		std::cout << "metadata=" << reinterpret_cast<int*>(metadata.get())[0] << "\n";
		std::cout << "metadata=" << reinterpret_cast<int*>(dec_res.get())[0] << "\n";
		if (::memcmp(dec_res.get() + kMetaSize, h.get(), h_sz) != 0)
		{
			std::cout << __PRETTY_FUNCTION__ << " : error gtm\n";
			exit(128);
		}
		for (auto i = 0; i < (h_sz+kMetaSize); i++) {
			std::cout << reinterpret_cast<int*>(dec_res.get())[i] << " ";
		}
		std::cout << "\n";
		/*
		   int k = 0;
		   ::memcpy(&k, dec_res.get(), kMetaSize);
		   std::cout << k <<  " == " << a << "\n";
		   uint64_t c_h = 0;
		   ::memcpy(&c_h, dec_res.get() + kMetaSize, sizeof(uint64_t));
		   std::cout << c_h <<  " == " << CityHash64(payload.get(), kValueSize) << "\n";
		   a++;
		   */
	}

	return 0;
}

