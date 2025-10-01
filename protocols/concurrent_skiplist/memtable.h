#pragma once

#include "common_conf.h"

#include "city.h"
#include "meta_data.h"
#include <memory>

//#include "encryption_lib/encrypt_openssl.h"
#include "encrypt_openssl.h"
#include <folly/ConcurrentSkipList.h>


#if SCONE_ALLOC
#include "alloc/allocator.h"
#endif
namespace avocado {

	class KV_store {
		using Skip_list = folly::ConcurrentSkipList<VarKeySizeNode>;
		using Accessor = Skip_list::Accessor;

		CipherSsl cipher;
		std::shared_ptr<Skip_list> skip_list;
		std::atomic<int64_t> kv_puts;
		mutable std::atomic<int64_t> kv_gets;
		mutable std::atomic<int64_t> kv_failed_gets;
		mutable std::atomic<int64_t> unique_keys;
		std::unique_ptr<uint8_t[]> mock_value;
		std::unique_ptr<uint8_t[]> encrypted_mock_value;
		uint8_t enc_mac[CipherSsl::MacSize];
		uint64 h;

#if SCONE_ALLOC
		using Allocator = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>;
		using Ptr_t = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>::Ptr_t;
#endif

		public:
#if SCONE_ALLOC
		std::shared_ptr<Allocator> my_alloc;
#endif
		size_t VAL_SIZE = kValueSize;
		size_t HASH_SIZE = sizeof(uint64);
		using Node = VarKeySizeNode;
		using CurVersion = int;

		struct Ret_value {
			size_t size;
			std::unique_ptr<uint8_t[]> value;
		};
#if SCONE_ALLOC
		KV_store(CipherSsl &&cipher, std::shared_ptr<Allocator>&& alloc): cipher(cipher), skip_list(Skip_list::createInstance(32)), my_alloc(alloc) {
			mock_value = std::make_unique<uint8_t[]>(VAL_SIZE);
#if ENCRYPTION
			encrypted_mock_value = std::make_unique<uint8_t[]>(VAL_SIZE);
			bool [[maybe_unused]] ok = cipher.encrypt(
					encrypted_mock_value.get(), mock_value.get(), VAL_SIZE, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of mock value failed\n", __func__);
			}
#else
			// fmt::print("[{}] calculate hashes\n", __func__);
			// auto key_hash_ = CityHash64((char *)mock_value.get(), sizeof(HASH_SIZE));
			// h = key_hash_;
#endif

			kv_puts.store(0);
			kv_gets.store(0);
			unique_keys.store(0);
			kv_failed_gets.store(0);

		}
#endif

		KV_store(CipherSsl &&cipher)
			: cipher(cipher), skip_list(Skip_list::createInstance(32)) {
				mock_value = std::make_unique<uint8_t[]>(VAL_SIZE);
#if ENCRYPTION
				encrypted_mock_value = std::make_unique<uint8_t[]>(VAL_SIZE);
				bool [[maybe_unused]] ok = cipher.encrypt(
						encrypted_mock_value.get(), mock_value.get(), VAL_SIZE, enc_mac);
				if (!ok) {
					fmt::print("[{}] encryption of mock value failed\n", __func__);
				}
#else
				// fmt::print("[{}] calculate hashes\n", __func__);
				// auto key_hash_ = CityHash64((char *)mock_value.get(), sizeof(HASH_SIZE));
				// h = key_hash_;
#endif

				kv_puts.store(0);
				kv_gets.store(0);
				unique_keys.store(0);
				kv_failed_gets.store(0);
			}
#if 1
		~KV_store() {
			fmt::print("\n[{}]\tstats\tkv_puts={}\tkv_gets={}\tfailed_gets={}\tunique_"
					"keys={}\n",
					__func__, kv_puts.load(), kv_gets.load(), kv_failed_gets.load(),
					unique_keys.load());
		}
#endif

		Node create_node(size_t key_size, uint8_t const *key) {
			std::cout << __PRETTY_FUNCTION__ << " NOT IN HERE\n";
			std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(kValueSize);
			auto value = ptr_value.get();
			::memset(value, 1, kValueSize);
			auto val_sz = kValueSize;

#if ENCRYPTION
#warning "ENCRYPTION IN PROTOCOL_KV"
			auto encrypted_value = std::make_unique<uint8_t[]>(VAL_SIZE);
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(encrypted_value.get(), value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			return Node(key_size, key, encrypted_value.get(), val_sz, enc_mac);
#else
			return Node(key_size, key, value, val_sz);
#endif
			//		return Node(key_size, key);
		}

		Node create_node(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz) {
			// std::cout << __PRETTY_FUNCTION__ << "\n";
#if ENCRYPTION
#if GMAC
#warning "GMAC FOR KV"
			int unused;
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(&unused, value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = value;
#else
#warning "AES-GCM FOR KV"
			auto encrypted_value = std::make_unique<uint8_t[]>(VAL_SIZE);
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(encrypted_value.get(), value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = encrypted_value.get();
#endif
#if SCONE_ALLOC
#warning "SCONE ALLOC AND ENCRYPTION"
			// auto x = my_alloc->alloc();
			// ::memcpy(x.get(), encrypted_value.get(), val_sz);
			// THIS IS IN AES_GCM: return Node(key_size, key, encrypted_value.get(), val_sz, enc_mac, my_alloc->alloc());
			return Node(key_size, key, put_value, val_sz, enc_mac, my_alloc->alloc());
#else
			return Node(key_size, key, put_value, val_sz, enc_mac);
#endif
#else
#if SCONE_ALLOC
#warning "SCONE ALLOC W/o ENCRYPTION"
			// std::cout << __PRETTY_FUNCTION__ << "\n";
			return Node(key_size, key, value, val_sz, my_alloc->alloc());
#else
			return Node(key_size, key, value, val_sz);
#endif
#endif
		}

		Node create_node(size_t key_size, uint8_t const *key, const int &version) {
			// std::cout << __PRETTY_FUNCTION__ << "\n";
			std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(kValueSize);
			auto value = ptr_value.get();
			::memset(value, 1, kValueSize);
			auto val_sz = kValueSize;
#if ENCRYPTION
#if GMAC
#warning "GMAC FOR KV"
			int unused;
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(&unused, value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = value;
#else
#warning ">>> AES-GCM FOR KV"
			auto encrypted_value = std::make_unique<uint8_t[]>(VAL_SIZE);
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(encrypted_value.get(), value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = encrypted_value.get();
#endif
#if SCONE_ALLOC
#warning "SCONE ALLOC IN CR ENCRYPTION"
			// auto x = my_alloc->alloc();
			// ::memcpy(x.get(), encrypted_value.get(), val_sz);
			return Node(key_size, key, put_value, val_sz, enc_mac, version, my_alloc->alloc());
#else
			return Node(key_size, key, put_value, val_sz, enc_mac, version);
#endif
#else
#if SCONE_ALLOC
#warning "SCONE ALLOC IN CR w/o encryption"
			return Node(key_size, key, value, val_sz, version, my_alloc->alloc());
#else
			return Node(key_size, key, value, val_sz, version);

#endif
#endif
			//			return Node(key_size, key, version);
		}

		Node create_node(size_t key_size, uint8_t const *key, size_t val_size, uint8_t* val, const int &version) {
			// std::cout << __PRETTY_FUNCTION__ << "\n";
			std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(kValueSize);
			auto value = ptr_value.get();
			::memcpy(value, val, val_size);
			auto val_sz = kValueSize;
#if ENCRYPTION
#if GMAC
#warning "GMAC FOR KV"
			int unused;
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(&unused, value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = value;
#else
#warning ">>> AES-GCM FOR KV"
			auto encrypted_value = std::make_unique<uint8_t[]>(VAL_SIZE);
			uint8_t enc_mac[CipherSsl::MacSize];
			bool [[maybe_unused]] ok = cipher.encrypt(encrypted_value.get(), value, val_sz, enc_mac);
			if (!ok) {
				fmt::print("[{}] encryption of failed\n", __func__);
			}
			auto put_value = encrypted_value.get();
#endif
#if SCONE_ALLOC
#warning "SCONE ALLOC IN CR ENCRYPTION"
			// auto x = my_alloc->alloc();
			// ::memcpy(x.get(), encrypted_value.get(), val_sz);
			return Node(key_size, key, put_value, val_sz, enc_mac, version, my_alloc->alloc());
#else
			return Node(key_size, key, put_value, val_sz, enc_mac, version);
#endif
#else
#if SCONE_ALLOC
#warning "SCONE ALLOC IN CR w/o encryption"
			return Node(key_size, key, value, val_sz, version, my_alloc->alloc());
#else
			return Node(key_size, key, value, val_sz, version);

#endif
#endif
			//			return Node(key_size, key, version);
		}

		Ret_value decrypt_node(Node const &node) const;

		CurVersion put(Node &node);
		CurVersion put(size_t key_size, uint8_t const *key);
		CurVersion put(size_t key_size, uint8_t const *key, uint8_t* val, size_t value_sz);
		void put_and_commit(size_t key_size, uint8_t const *key, const int &version);
		void put_and_commit(size_t key_size, uint8_t const *key, size_t val_size, uint8_t* val, const int &version);
		Ret_value get(size_t const key_size, uint8_t const *key) const;
		Ret_value get(Node const &node) const;
		void update_cmt(uint8_t const *key, size_t const &key_sz, int const &version);
	};

} // namespace avocado
