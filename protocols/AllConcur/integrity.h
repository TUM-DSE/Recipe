#pragma once
#include "encrypt_package.h"
#include <memory>
#include <iostream>
#include <city.h>

#if INTEGRITY_CITYHASH
static std::tuple<size_t, std::unique_ptr<char[]>> construct(PacketSsl* cipher, char* metadata, size_t meta_sz, char* data, size_t data_sz) {
	auto h = CityHash64(data, data_sz);
	// std::cout << __PRETTY_FUNCTION__ << " " << h << "\n";
	std::unique_ptr<char[]> ptr = std::make_unique<char[]>(meta_sz + sizeof(h));
	::memcpy(ptr.get(), metadata, meta_sz);
	::memcpy(ptr.get() + meta_sz, &h, sizeof(h));
	std::unique_ptr<char[]> enc = std::make_unique<char[]>(PacketSsl::get_buffer_size(meta_sz + sizeof(h)));
	bool ok = cipher->encrypt(enc.get(), ptr.get(), meta_sz+sizeof(h));
	if (!ok) 
		std::cout << "error\n";

	return std::make_tuple(PacketSsl::get_buffer_size(meta_sz + sizeof(h)), std::move(enc));
}

static std::unique_ptr<uint8_t[]>  destruct(PacketSsl* cipher, char* enc_data, size_t enc_sz) {
	size_t decrypted_data_sz = PacketSsl::get_message_size(enc_sz);
	std::unique_ptr<uint8_t[]> decrypted_data =
		std::make_unique<uint8_t[]>(decrypted_data_sz);
	bool [[maybe_unused]] success =
		cipher->decrypt(decrypted_data.get(), enc_data, enc_sz);
	if (!success)
		std::cout << "error\n";
	return std::move(decrypted_data);
}
#endif

#if 0
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
	int a = 1;
	for (auto i = 1; i < 10; i++) {
		payload.get()[10] = a;
	::memcpy(metadata.get(), &a, kMetaSize);
	auto enc_res = construct(cipher.get(), metadata.get(), kMetaSize, payload.get(), kValueSize);

	auto dec_res = destruct(cipher.get(), std::get<1>(enc_res).get(), std::get<0>(enc_res));
	int k = 0;
	::memcpy(&k, dec_res.get(), kMetaSize);
	std::cout << k <<  " == " << a << "\n";
	uint64_t c_h = 0;
	::memcpy(&c_h, dec_res.get() + kMetaSize, sizeof(uint64_t));
	std::cout << c_h <<  " == " << CityHash64(payload.get(), kValueSize) << "\n";
	a++;
	}

	return 0;
}
#endif

