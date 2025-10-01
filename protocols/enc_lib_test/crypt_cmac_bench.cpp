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
inline auto print_bytes(const unsigned char *data, size_t l) -> void {
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
	std::cout << "msg_sz=" << msg_sz << "\n";
	uint8_t key[] = {0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
		0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb};
	uint8_t iv[] = {0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7,
		0xba, 0x01, 0x36, 0xa7, 0x97, 0xf3};
	
	   uint8_t aad[] = {0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
	   0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab};
	// std::unique_ptr<uint8_t[]> aad = std::make_unique<uint8_t[]>(msg_sz);
	// ::memset(aad.get(), 'd', msg_sz);

	uint8_t mac[PacketSsl::MacSize];
	uint8_t iv2[PacketSsl::IvSize];
	uint8_t tag[16] = {/* calculated */};
	uint8_t exp[] = {0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
		0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46};
	CipherSsl crypt(key, iv);

	crypt.encrypt(tag, aad, sizeof(tag), mac);

	std::cout << "exp=\n";
	print_bytes(exp, sizeof(exp));
	std::cout << "tag=\n";
	print_bytes(tag, sizeof(tag));
	std::cout << "aad=\n";
	print_bytes(aad, sizeof(tag));
	std::cout << "mac=\n";
	print_bytes(mac, sizeof(mac));

	bool ok = crypt.decrypt(tag, aad, sizeof(tag), mac);
	if (!ok)
		std::cout << "Error\n";
}
