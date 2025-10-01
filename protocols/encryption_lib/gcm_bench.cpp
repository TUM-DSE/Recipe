#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <stdlib.h>
#include <sys/time.h>


#include "encrypt_package.h"
inline auto print_buffer_bytes(const unsigned char *data, size_t l) -> void {
	for (size_t i = 0; i < l; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0')
			<< static_cast<int>(data[i]) << " ";
	}
	std::cout << std::dec << std::endl; // Reset stream formatting to decimal
}

static uint64_t get_time_in_ms() {  
	struct timeval tv;

	gettimeofday(&tv, NULL); 
	return (tv.tv_sec * 1000 + tv.tv_usec / 10e6);
}  


// NOLINTEND

int main(int argc, char **argv) {

#if 0
	uint8_t key[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
#endif
	size_t msg_sz = (argc >= 2) ? std::stoi(argv[1]) : 256;
	uint8_t key[] = {0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
		0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb};
	uint8_t iv[] = {0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7,
		0xba, 0x01, 0x36, 0xa7, 0x97, 0xf3};
#if 0
	uint8_t aad[] = {0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
		0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab};
#endif
	std::cout << "msg_sz=" << msg_sz << "\n";
	std::unique_ptr<uint8_t[]> aad = std::make_unique<uint8_t[]>(msg_sz);
	::memset(aad.get(), '0x1', msg_sz);

	uint8_t mac[PacketSsl::MacSize];
	uint8_t iv2[PacketSsl::IvSize];
	uint8_t tag[16] = {/* calculated */};
	uint8_t exp[] = {0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
		0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46};
	CipherSsl crypt(key, iv);
	PacketSsl packet = PacketSsl::create(crypt);

	std::unique_ptr<uint8_t[]> ptr =
		std::make_unique<uint8_t[]>(PacketSsl::get_buffer_size(msg_sz));

	auto start = get_time_in_ms();

	for (auto i = 0; i < 10e6;i++) {
		packet.encrypt(ptr.get(), aad.get(), msg_sz);
		//::memcpy((ptr.get() + PacketSsl::IvSize), aad, sizeof(aad));
		/*
		   std::cout << "ptr=";
		   print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));
		   ::memcpy(mac, ptr.get() + PacketSsl::IvSize + sizeof(aad),
		   PacketSsl::MacSize);

		   std::cout << "iv=";
		   print_buffer_bytes(iv, PacketSsl::IvSize);
		   std::cout << "mac=";
		   print_buffer_bytes(mac, PacketSsl::MacSize);
		   std::cout << "exp=";
		   print_buffer_bytes(exp, PacketSsl::MacSize);
		   */

		std::unique_ptr<uint8_t[]> decrypted = std::make_unique<uint8_t[]>(PacketSsl::get_message_size(PacketSsl::get_buffer_size(msg_sz)));
		bool [[maybe_unused]] ok = packet.decrypt(decrypted.get(), ptr.get(), PacketSsl::get_buffer_size(msg_sz));
		if (!ok) {
			std::cout << "Authentication failed\n";
		}
	}
	auto end = get_time_in_ms();
	std::cout << (end-start) << "\n";

#if 0
	// PacketSsl packet2 = PacketSsl::create(crypt);
	//
	{
		std::unique_ptr<uint8_t[]> payload = std::make_unique<uint8_t[]>(16);
		std::unique_ptr<uint8_t[]> ptr =
			std::make_unique<uint8_t[]>(PacketSsl::get_buffer_size(16));
		::memset(ptr.get(), '0x1', PacketSsl::get_buffer_size(16));

		std::cout << "ptr=";
		print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));

		std::cout << "payload=";
		::memset(payload.get(), '0x2', 16);
		print_buffer_bytes(payload.get(), 16);

		::memcpy((ptr.get() + PacketSsl::IvSize), payload.get(), 16);

		std::cout << "ptr=";
		print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));

		packet.encrypt(ptr.get(), payload.get(), 16);
		::memcpy((ptr.get() + PacketSsl::IvSize), payload.get(), 16);

		std::cout << "\n";
		uint8_t mac[PacketSsl::MacSize];
		uint8_t iv[PacketSsl::IvSize];
		::memcpy(mac, ptr.get() + PacketSsl::IvSize + 16, PacketSsl::MacSize);
		::memcpy(iv, ptr.get(), PacketSsl::IvSize);

		std::cout << "iv(org)=";
		print_buffer_bytes(key, 12);

		std::cout << "payload=";
		print_buffer_bytes(payload.get(), 16);
		std::cout << "payload=";
		std::unique_ptr<uint8_t[]> payload2 = std::make_unique<uint8_t[]>(16);
		::memcpy(payload2.get(), ptr.get() + PacketSsl::IvSize, 16);
		print_buffer_bytes(payload2.get(), 16);

		std::cout << "ptr=";
		print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));

		std::cout << "iv=";
		print_buffer_bytes(iv, PacketSsl::IvSize);
		std::cout << "mac=";
		print_buffer_bytes(mac, PacketSsl::MacSize);

		std::unique_ptr<uint8_t[]> recv_msg =
			std::make_unique<uint8_t[]>(PacketSsl::get_buffer_size(16));
		uint8_t unused;
		packet.decrypt(&unused, ptr.get(), PacketSsl::get_buffer_size(16));
		std::cout << "recv_msg=";
		/*
		   print_buffer_bytes(recv_msg.get(), PacketSsl::get_buffer_size(16));
		   if (::memcmp(recv_msg.get() + PacketSsl::IvSize + 16, ptr.get() +
		   PacketSsl::IvSize + 16, PacketSsl::MacSize) == 0) std::cout << "ola kala
		   1\n"; if (::memcmp(recv_msg.get() + PacketSsl::IvSize + 16, mac,
		   PacketSsl::MacSize) == 0) std::cout << "ola kala 2\n";
		   */
		for (auto i = 0; i < 0; i++) {
			std::cout << "payload=";
			::memset(payload.get(), '0x1' + i, 16);
			print_buffer_bytes(payload.get(), 16);

			::memcpy((ptr.get() + PacketSsl::IvSize), payload.get(), 16);

			std::cout << "ptr=";
			print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));
			{
				std::cout << "ptr=";
				print_buffer_bytes(ptr.get(), PacketSsl::get_buffer_size(16));

				packet.encrypt(ptr.get(), payload.get(), 16);
				::memcpy((ptr.get() + PacketSsl::IvSize), payload.get(), 16);

				std::cout << "\n";
				uint8_t mac[PacketSsl::MacSize];
				uint8_t iv[PacketSsl::IvSize];
				::memcpy(mac, ptr.get() + PacketSsl::IvSize + 16, PacketSsl::MacSize);
				::memcpy(iv, ptr.get(), PacketSsl::IvSize);

				std::cout << "iv(org)=";
				print_buffer_bytes(key, 12);

				std::cout << "payload=";
				print_buffer_bytes(payload.get(), 16);
				std::cout << "payload=";
				std::unique_ptr<uint8_t[]> payload2 = std::make_unique<uint8_t[]>(16);
				::memcpy(payload2.get(), ptr.get() + PacketSsl::IvSize, 16);
				print_buffer_bytes(payload2.get(), 16);

				std::unique_ptr<uint8_t[]> recv_msg =
					std::make_unique<uint8_t[]>(PacketSsl::get_buffer_size(16));
				uint8_t unused;
				packet.decrypt(&unused, ptr.get(), PacketSsl::get_buffer_size(16));
				std::cout << "recv_msg=";
			}
		}
	}
#endif
}
