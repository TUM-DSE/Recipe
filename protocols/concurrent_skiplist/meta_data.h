#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fmt/printf.h>
#include <map>
#include <memory>
#include <stdint.h>
//#include "/home/dimitra/secure_replication/CR/common_conf.h"
#include "common_conf.h"

// #include "encryption_lib/encrypt_openssl.h"
#include "encrypt_openssl.h"

#if SCONE_ALLOC
#include "allocator.h"
#endif

#if SHA256_DIGEST
#include "digest_h.h"
#endif

namespace avocado {

#if 0
	template <int key_size> struct Node {
		char key[key_size];

		Node() = default;
		Node(uint8_t const *key) { std::memcpy(this->key, key, key_size); }

		bool operator<(Node const &other) const {
			return std::memcmp(key, other.key, key_size) < 0;
		}
	};
#endif

#if SCONE_ALLOC
	using Ptr_t = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>::Ptr_t;
#endif
	struct MetaData {
		uint64_t h;

#if SHA256_DIGEST
#warning "SHA256 DIGEST"
		uint8_t sha256_digest[kSHA256_SZ];
#endif
		uint8_t mac[CipherSsl::MacSize];
		size_t  data_size = 0;

#if SCONE_ALLOC
		Ptr_t data;
#else
		std::unique_ptr<char[]> data;
#endif
		MetaData() = default;

#if SCONE_ALLOC
#warning "SCONE is ENABLED"
		MetaData(uint8_t* plain_value, size_t sz, Ptr_t&& host_mem) : data_size(sz), data(std::move(host_mem)) {

			// std::cout << __PRETTY_FUNCTION__ << " NEVER EXECUTED\n"; //@dimitra: can be executed here if in CR (update_cmt())
			//todo: just move the ptr for opti
			::memcpy(data.get(), plain_value, sz);
			h = CityHash64(reinterpret_cast<char*>(plain_value), sz);
#if SHA256_DIGEST
			auto [h_sz, sha256_h] = get_sha256(reinterpret_cast<char*>(plain_value), sz);
			::memcpy(sha256_digest, sha256_h.get(), h_sz);
#endif
		}

		MetaData(uint8_t const * plain_value, size_t sz, uint8_t* enc_mac, Ptr_t&& host_mem) : data_size(sz),  data(std::move(host_mem)){
			// data = std::make_unique<char[]>(sz);
			//todo: just move the ptr for opti
			::memcpy(data.get(), plain_value, sz);
			// ::memcpy(data2.get(), plain_value, sz);
			::memcpy(mac, enc_mac, CipherSsl::MacSize);
		}
#endif

		MetaData(uint8_t const * plain_value, size_t sz, uint8_t* enc_mac) : data_size(sz) {
#if SCONE_ALLOC
			//		std::cout << __PRETTY_FUNCTION__ << " should not enter here\n";
#else
			data = std::make_unique<char[]>(sz);
			//todo: just move the ptr for optimization
			::memcpy(data.get(), plain_value, sz);
			::memcpy(mac, enc_mac, CipherSsl::MacSize);
#endif
		}

		MetaData(uint8_t* plain_value, size_t sz) : data_size(sz) {
			// fmt::print("[{}] std::alloc_used\n", __PRETTY_FUNCTION__);
#if SCONE_ALLOC
			//		std::cout << __PRETTY_FUNCTION__ << " should not enter here\n";
#else
#warning "INTEGRITY ONLY HERE (NO SCONE_ALLOC)"
	//		std::cout << __PRETTY_FUNCTION__ << " NEVER EXECUTED\n";
			data = std::make_unique<char[]>(sz);
			//todo: just move the ptr for opti
			::memcpy(data.get(), plain_value, sz);
			h = CityHash64(reinterpret_cast<char*>(plain_value), sz);
#if SHA256_DIGEST
			auto [h_sz, sha256_h] = get_sha256(reinterpret_cast<char*>(plain_value), sz);
			::memcpy(sha256_digest, sha256_h.get(), h_sz);
#endif
#endif
		}
#if 0
		cipher.encrypt(reinterpret_cast<uint8_t*>(this->data.get()), plain_value, data_size, mac); 
		MetaData(CipherSsl const & cipher, size_t data_size, uint8_t const * plain_value, Lamport clock, Ptr_t && data) : data_size(data_size), clock(clock), data(std::move(data)) {
			cipher.encrypt(reinterpret_cast<uint8_t*>(this->data.get()), plain_value, data_size, mac); 
		}
#endif
	};


	struct VarKeySizeNode {
		size_t key_size;
		int next_version = -1;
#ifdef CR_PROTO
#warning "CR benchmakring"
		std::mutex mtx; // locks the versions
		std::map<int, uintptr_t> versions;
#endif

		std::unique_ptr<char[]> key;
		std::shared_ptr<MetaData> meta;

		VarKeySizeNode() = default;
#if 0
		VarKeySizeNode() : next_version(0) {
			versions.insert(std::make_pair(0, reinterpret_cast<uintptr_t>(nullptr)));
		};
#endif

		VarKeySizeNode(VarKeySizeNode &&) = default;
		VarKeySizeNode &operator=(VarKeySizeNode &&) = default;

		VarKeySizeNode(VarKeySizeNode const &other)
			: key_size(other.key_size), key(std::make_unique<char[]>(other.key_size)), meta(other.meta)
#if 0
			  , versions(other.versions), next_version(other.next_version) 
#endif 
		{
			std::memcpy(key.get(), other.key.get(), key_size);
		}

		VarKeySizeNode(size_t key_size, uint8_t const *key)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)) {
				//TODO:
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(kValueSize);
				auto value = ptr_value.get();
				::memset(value, 1, kValueSize);
				auto val_sz = kValueSize;

				meta = std::make_shared<MetaData>(value, val_sz);
				std::memcpy(this->key.get(), key, key_size);
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)) {
				std::memcpy(this->key.get(), key, key_size);
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz);
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, uint8_t* mac)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)) {
				//			fmt::print("[{}] std::alloc_used\n", __PRETTY_FUNCTION__);
				std::memcpy(this->key.get(), key, key_size);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, mac);
			}

#if SCONE_ALLOC
		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, uint8_t* mac, Ptr_t&& host_mem)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)) {
				//			fmt::print("[{}] \n", __PRETTY_FUNCTION__);
				std::memcpy(this->key.get(), key, key_size);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, mac, std::move(host_mem));
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, Ptr_t&& host_mem)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)) {
				std::memcpy(this->key.get(), key, key_size);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, std::move(host_mem));
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, uint8_t* mac, const int& version, Ptr_t&& host_mem)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)), next_version(version) {
				std::memcpy(this->key.get(), key, key_size);
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, mac, std::move(host_mem));
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, const int& version, Ptr_t&& host_mem)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)), next_version(version) {
				std::memcpy(this->key.get(), key, key_size);
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, std::move(host_mem));
			}

#endif

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, uint8_t* mac, const int& version)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)), next_version(version) {
				std::memcpy(this->key.get(), key, key_size);
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz, mac);
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz, const int& version)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)), next_version(version) {
				std::memcpy(this->key.get(), key, key_size);
				//			fmt::print("[{}] std::alloc_used\n", __func__);
				//  fmt::print("[{}] val_sz={}\n", __func__, val_sz);

				meta = std::make_shared<MetaData>(value, val_sz);
			}

		VarKeySizeNode(size_t key_size, uint8_t const *key, const int &version)
			: key_size(key_size), key(std::make_unique<char[]>(key_size)),
			next_version(version) {
#if 0
				//TODO:
				std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(kValueSize);
				auto value = ptr_value.get();
				::memset(value, 1, kValueSize);
				auto val_sz = kValueSize;

				meta = std::make_shared<MetaData>(value, val_sz);
#endif
				std::memcpy(this->key.get(), key, key_size);
			}

		~VarKeySizeNode() {
			/*fmt::print("[{}] size={}, next_version={}\n", __func__, versions.size(),
			  next_version);
			  */
		}

		bool operator<(VarKeySizeNode const &other) const {
			if (key_size < other.key_size)
				return true;
			if (key_size > other.key_size)
				return false;
			return std::memcmp(key.get(), other.key.get(), key_size) < 0;
		}

		int increase_version() {
#ifdef CR_PROTO
			std::lock_guard<std::mutex> g(mtx);
			next_version++;
			versions.insert(
					std::make_pair(next_version, reinterpret_cast<uintptr_t>(nullptr)));
#endif

			//   fmt::print("[{}] size={}, next_version={}\n", __func__,
			//   versions.size(),
			//              next_version);
			return next_version;
		}

		void update_version(int const &version) {
#ifdef CR_PROTO
			std::lock_guard<std::mutex> g(mtx);

			versions.insert(
					std::make_pair(version, reinterpret_cast<uintptr_t>(nullptr)));
			if (versions.size() > 1) {
				auto it = versions.find(version);
				if (it != versions.end()) {
					it = (it != versions.begin()) ? (it--) : it;
					versions.erase(versions.begin(), it);
				}
			}
#endif

			next_version = (next_version < version) ? version : next_version;

			// fmt::print("[{}] size={}, next_version={} cur_version={}\n", __func__,
			// versions.size(),
			//           next_version, version);
		}
	};

} // namespace avocado
