#pragma once
#include "generate_traces.h"
#include <set>
#include <vector>
#include <memory>

struct request {
	static constexpr size_t key_sz = ycsb::Trace_cmd::key_size;

	uint32_t batch_sz;
	uint8_t req_owner;
	std::unique_ptr<uint8_t[]> payload;

	request(uint8_t _req_owner, uint32_t _batch_sz, std::unique_ptr<uint8_t[]>&& _payload): req_owner(_req_owner), batch_sz(_batch_sz), payload(_payload.release()) {};

	std::unique_ptr<uint8_t[]> get_next_val(int pos) {
		auto val = std::make_unique<uint8_t[]>(kValueSize);
		// ::memcpy(val.get(), payload.get() + batch_sz*key_sz + kValueSize*pos, kValueSize);
		::memcpy(val.get(), payload.get() + kValueSize*pos, kValueSize);
		return std::move(val);
	}

	void get_next_key(int pos, uint8_t* key_hash) {
		::memcpy(key_hash, (payload.get() + pos*key_sz), key_sz);
#if 0
		for (auto i = 0ULL; i < key_sz; i++) {
			fmt::print("{}", key_hash[i]);
		}
		fmt::print("\n");
#endif
	}
};
