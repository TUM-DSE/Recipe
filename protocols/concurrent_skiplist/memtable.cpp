#include "memtable.h"
// #include "encryption_lib/encrypt_package.h"
#include "encrypt_package.h"

#include <memory>

#include "meta_data.h"
#if SHA256_DIGEST
#include "digest_h.h"
#endif


namespace avocado {

	void KV_store::update_cmt(uint8_t const *key, size_t const &key_sz,
			int const &version) {
		// fmt::print("{}\n", __func__);
		Accessor kv(skip_list);
		auto iter = kv.find(Node(key_sz, key));
		if (iter == kv.end()) {
			//fmt::print("[{}] cmt request for a non-existent key\n", __func__);
			return;
		}
		iter->update_version(version);
	}

	int KV_store::put(VarKeySizeNode &new_node) {
		// FIXME:
#if ENCRYPTION
#warning "ENCRYPTED KV"
#if 0
		// fmt::print("{}\n", __func__);
		auto encrypted_msg_sz = PacketSsl::get_buffer_size(VAL_SIZE);
		auto ptr = std::make_unique<uint8_t[]>(encrypted_msg_sz);
		uint8_t mac[CipherSsl::MacSize];
		bool ok = cipher.encrypt(ptr.get(), mock_value.get(), VAL_SIZE, mac);
		if (!ok) {
			fmt::print("[{}] encryption failed\n", __func__);
			exit(128);
		}
#endif
#else

		//  auto key_hash_ = CityHash64((char *)mock_value.get(), sizeof(HASH_SIZE));
		//  if (key_hash_ != h) {
		//    fmt::print("[{}] hash comparison failed\n", __func__);
		//    exit(128);
		//  }
#endif

		Accessor kv(skip_list);
		auto [node, found] = kv.addOrGetData(new_node);
		if (found)
			unique_keys.fetch_add(1);
#if 0
		if (found) { // There was no node with the same key, we are done here
			return 0;
			// return true;
		}
#endif
#ifdef CR
		auto next_version = node->increase_version();
		return next_version;
#else
		return 1;
#endif
		// return false;
	}

	void KV_store::put_and_commit(size_t key_size, uint8_t const *key,
			const int &version) {
		kv_puts.fetch_add(1);
		// fmt::print("{}\n", __func__);
		auto new_node = create_node(key_size, key, version);
		Accessor kv(skip_list);
		auto [node, found] = kv.addOrGetData(new_node);
		if (found)
			unique_keys.fetch_add(1);
		node->update_version(version);
	}

	void KV_store::put_and_commit(size_t key_size, uint8_t const *key, size_t val_size, uint8_t* val,
			const int &version) {
		kv_puts.fetch_add(1);
		// fmt::print("{}\n", __func__);
		auto new_node = create_node(key_size, key, val_size, val, version);
		Accessor kv(skip_list);
		auto [node, found] = kv.addOrGetData(new_node);
		if (found)
			unique_keys.fetch_add(1);
		node->update_version(version);
	}

	int KV_store::put(size_t key_size, uint8_t const *key) {
		kv_puts.fetch_add(1);
#if 0
		fmt::print("[{}] key=", __func__);
		for (auto i = 0; i < key_size; i++)
			fmt::print("{}", key[i]);
		fmt::print("\n");
#endif
#if 0
		fmt::print("[{}] cnt={}\r", __func__, kv_puts.load());
#endif
		std::unique_ptr<uint8_t[]> ptr_value = std::make_unique<uint8_t[]>(VAL_SIZE);
		auto value = ptr_value.get();
		::memset(value, 1, VAL_SIZE);
		auto val_sz = VAL_SIZE;
	//	fmt::print("[{}] cnt={}\r", __func__, kv_puts.load());
		auto node = create_node(key_size, key, value, val_sz);
		return put(node);
	}

	int KV_store::put(size_t key_size, uint8_t const *key, uint8_t* value, size_t val_sz) {
		kv_puts.fetch_add(1);
#if 0
		fmt::print("[{}] key=", __func__);
		for (auto i = 0; i < key_size; i++)
			fmt::print("{}", key[i]);
		fmt::print("\n");
#endif
#if 0
		fmt::print("[{}] cnt={}\r", __func__, kv_puts.load());
#endif
		auto node = create_node(key_size, key, value, val_sz);
		return put(node);
	}

	KV_store::Ret_value KV_store::decrypt_node(Node const &node) const {
		// FIXME:
#if ENCRYPTION
#warning "decrypt_node = ENCRYPTED KV" 
		if (node.meta->data_size == 0) 
		{
			fmt::print("[{}] no data\n", __func__);
		}
		else if (node.meta->data.get() == nullptr) {
			fmt::print("[{}] nullptr\n", __func__);
		}
		// fmt::print("{} all good here\n", __func__);
		auto dec_ptr = std::make_unique<uint8_t[]>(node.meta->data_size);
		bool [[maybe_unused]] ok2 =
			cipher.decrypt(dec_ptr.get(), node.meta->data.get(), node.meta->data_size, node.meta->mac);
		/*
		   bool [[maybe_unused]] ok2 =
		   cipher.decrypt(dec_ptr.get(), node.meta->data.get(), node.meta->data_size, node.meta->mac);
		   */
		if (ok2)
			return {VAL_SIZE, std::move(dec_ptr)};

		if (!ok2) {
			fmt::print("[{}] decryption failed\n", __func__);
			exit(128);
		}

		std::cout << "I SHOULD NOT BE HERE 1\n";
		auto ptr = std::make_unique<uint8_t[]>(VAL_SIZE);
		bool [[maybe_unused]] ok =
			cipher.decrypt(ptr.get(), encrypted_mock_value.get(), VAL_SIZE, enc_mac);
		if (ok)
			return {VAL_SIZE, std::move(ptr)};

		if (!ok) {
			fmt::print("[{}] decryption failed\n", __func__);
			exit(128);
		}
#else
		if (node.meta->data_size == 0) 
		{
			fmt::print("[{}] no data\n", __func__);
		}
		else if (node.meta->data.get() == nullptr) {
			fmt::print("[{}] nullptr\n", __func__);
		}
#if SHA256_DIGEST
		auto [h_sz, sha256_h] = get_sha256((char*)node.meta->data.get(), node.meta->data_size);
		if (::memcmp(sha256_h.get(), node.meta->sha256_digest, kSHA256_SZ) == 0) {
			// std::cout << "sha256_digest matches\n";
			auto ptr = std::make_unique<uint8_t[]>(node.meta->data_size);
			::memcpy(ptr.get(), node.meta->data.get(), node.meta->data_size);
			return {VAL_SIZE, std::move(ptr)};
		}
		else {
			std::cout << "issue\n";
		}
#endif
		auto cal_hash = CityHash64((char*)node.meta->data.get(), node.meta->data_size);

		if (cal_hash == node.meta->h) {
			// fmt::print("cal_hash == node.meta->h\n");
			auto ptr = std::make_unique<uint8_t[]>(node.meta->data_size);
			::memcpy(ptr.get(), node.meta->data.get(), node.meta->data_size);
			return {VAL_SIZE, std::move(ptr)};
		}
		else {
			fmt::print("{} != {}\n", cal_hash, node.meta->h);
			for (auto i = 0; i < node.meta->data_size; i++)
				fmt::print("{}", (char*)node.meta->data.get()[i]);
		}

		auto key_hash_ = CityHash64((char *)mock_value.get(), sizeof(HASH_SIZE));
		if (key_hash_ == h) {
			auto ptr = std::make_unique<uint8_t[]>(VAL_SIZE);
			::memcpy(ptr.get(), mock_value.get(), VAL_SIZE);
			return {VAL_SIZE, std::move(ptr)};
		}
		if (key_hash_ != h) {
			fmt::print("[{}] hash comparison failed\n", __func__);
			exit(128);
		}
#endif
		return {0, nullptr};
	}

	KV_store::Ret_value KV_store::get(Node const &node) const {
		Accessor kv(skip_list);
		auto iter = kv.find(node);
		if (iter == kv.end()) {
			kv_failed_gets.fetch_add(1);
			return {0, nullptr};
		}

		return decrypt_node(*iter);
	}

	KV_store::Ret_value KV_store::get(size_t const key_size,
			uint8_t const *key) const {
		kv_gets.fetch_add(1);
		return get(Node(key_size, key));
	}

} // namespace avocado
