#pragma once
#include "cipher.h"
#include "integrity.h"
#include "common_conf.h"
#include "concurrent_skiplist/memtable.h"
#include "rate_limiter.h"
#include "state.h"
#include "ycsb_generator/generate_traces.h"
#include <atomic>
#include <memory>
#include <unordered_map>



class AppContext {
	public:
		struct header {
			// consensus sequence number
			uint64_t sqn; 
			// the original sender (request's owner)
			uint8_t req_owner;
			// the sender's id
			uint8_t node_id;
			// batch sz (nb reqs)
			uint32_t batch_sz;
		};

	public:
		AppContext() = default;
		~AppContext() = default;

		// erpc object owned by this thread
		void *rpc;
		int rid;

		using node_identifier = int;
		using session_num = int;
		std::unordered_map<node_identifier, session_num> cluster_info;

		// current node's id
		int node_id;
		int completed_reqs;

		std::shared_ptr<state> ptr_state;

		avocado::KV_store *store = nullptr;

	private:
		//
};

struct request_tag {
	// consensus sequence (request's round)
	uint64_t csqn;
	erpc::MsgBuffer req_buf;
	erpc::MsgBuffer resp_buf;

};

// forward declaration
static void cont_func(void *ctx, void *tag);
static void check_for_termination(const AppContext::header& hdr, AppContext* ctx);

static [[nodiscard]] std::unique_ptr<uint8_t[]> decode_req(char *data,
		size_t data_sz) {
#if INTEGRITY
	// FIXME:: refactoring introduced too many memcpys
	size_t enc_data = PacketSsl::get_buffer_size(kMetaSize + kHashSize);
	auto decrypted_meta = destruct(cipher.get(), reinterpret_cast<char*>(data), enc_data);
	auto calc_sha256 = get_sha256(reinterpret_cast<char*>(data) + enc_data, (data_sz-enc_data));
	if (::memcmp(std::get<1>(calc_sha256).get(), decrypted_meta.get() + kMetaSize, kHashSize) != 0) {
		fmt::print("[{}] Error in verification\n", __func__);
	}
#if INTEGRITY_CITYHASH
	size_t enc_data = PacketSsl::get_buffer_size(kMetaSize + kHashSize);
	auto decrypted_meta = destruct(cipher.get(), data, enc_data);
	uint64_t c_h = 0;
	::memcpy(&c_h, decrypted_meta.get() + kMetaSize, kHashSize);
	if (c_h != CityHash64(reinterpret_cast<char*>(data)+enc_data, data_sz-enc_data)) {
		fmt::print("[{}] Error\n", __func__);
	}
#endif
	std::unique_ptr<uint8_t[]> decrypted_data = std::make_unique<uint8_t[]>(data_sz-enc_data);
	::memcpy(decrypted_data.get(), data + enc_data, data_sz-enc_data);
	return std::move(decrypted_data);
#else
 #if GMAC
 #warning "GMAC ON"
         uint8_t unused;
         size_t dec_size = PacketSsl::get_message_size(data_sz);
         std::unique_ptr<uint8_t[]> ptr =
                 std::make_unique<uint8_t[]>(dec_size);
         ::memcpy(ptr.get(), data + PacketSsl::IvSize, dec_size);
         /*
         std::cout << "decrypted_data=\n";
         for (auto i = 0; i < PacketSsl::get_message_size(data_sz); i++) {
                 fmt::print("{}", decrypted_data.get()[i]);
 
         }       
         std::cout << "\n";
         */
         bool [[maybe_unused]] success = cipher->decrypt(&unused, data, data_sz);
         if (!success) {
                 std::cout << "Authentication failed\n";
                 exit(128);
         }
	 return std::move(ptr);

#else
	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size);

	bool [[maybe_unused]] ok = cipher->decrypt(ptr.get(), data, data_sz);
	return std::move(ptr);
#endif
#endif
}

static void cont_func_default(void *ctx, void *tag) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	struct request_tag* req_tag = reinterpret_cast<request_tag*>(tag);

	rpc->free_msg_buffer(req_tag->req_buf);
	rpc->free_msg_buffer(req_tag->resp_buf);
	delete req_tag;
}

static void cont_func(void *ctx, void *tag) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	struct request_tag* req_tag = reinterpret_cast<request_tag*>(tag);

	auto req_csqn = req_tag->csqn;

	auto data = reinterpret_cast<char *>(req_tag->resp_buf.buf);
	auto data_sz = req_tag->resp_buf.get_data_size();
	auto received_data = decode_req(data, data_sz);

	AppContext::header hdr;
	::memcpy(&hdr, received_data.get(), sizeof(hdr));

	rpc->free_msg_buffer(req_tag->req_buf);
	rpc->free_msg_buffer(req_tag->resp_buf);
	delete req_tag;

#if 0
	// some printing
	static int o = 0;
	o++;
	if (o % 1000 == 0) {
		fmt::print("[{}] received acks for req_csqn={}/{} (req_owner={}) from node_id={}\n", __func__,
				req_csqn, hdr.sqn, hdr.req_owner, hdr.node_id);
	}
#endif

	check_for_termination(hdr, context);
}


// returns true if we have tracked all the messages of the current round
static bool tracked_all_round_messages(int nb_messages) {
	return (nb_messages == kClusterSize);
}

static void apply_kvs_cmds(uint64_t sqn, AppContext* ctx) {
	// apply the updates for that round in deterministic order
	ctx->ptr_state->consensus_sqn.store(sqn);

	// TODO: update the KVs
	auto& reqs = ctx->ptr_state->received_reqs[sqn];
	for (auto& req : reqs) {
		size_t req_batch_sz = req->batch_sz;
		for (int i = 0; i < req->batch_sz; i++) {
			uint8_t key_hash[ycsb::Trace_cmd::key_size];
			// std::unique_ptr<uint8_t[]> key_hash = std::make_unique<uint8_t[]>(ycsb::Trace_cmd::key_size);
			req->get_next_key(i, key_hash);
			auto value = req->get_next_val(i);
#if 0
			fmt::print("[{}] apply for i={}/rnd={}/batch_sz={}\n", __func__, i, sqn, req->batch_sz);
			for (auto k = 0; k < ycsb::Trace_cmd::key_size; k++) {
				fmt::print("{}", key_hash[k]);
			}
			fmt::print("\n");
#endif
			// ctx->store->put(ycsb::Trace_cmd::key_size, key_hash.get());
	//		ctx->store->put(ycsb::Trace_cmd::key_size, key_hash);
			ctx->store->put(ycsb::Trace_cmd::key_size, key_hash, value.get(), kValueSize);
		}
	}
	ctx->ptr_state->remove_req(sqn);
}

static void check_for_termination(const AppContext::header& hdr, AppContext* ctx) {
	// if we have tracked all messages for this round
	auto nb_msgs = ctx->ptr_state->received_reqs_nb(ctx->ptr_state->consensus_sqn.load() + 1);
	if (tracked_all_round_messages(nb_msgs)) {
		// fmt::print("[{}] tracked all messages for round {}\n", __func__, (ctx->ptr_state->consensus_sqn.load() + 1));
		// apply updates in the deterministic order
		apply_kvs_cmds(ctx->ptr_state->consensus_sqn.load()+1, ctx);
		erpc::Rpc<erpc::CTransport> *rpc =
			reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
		// rpc->run_event_loop(3000);
	}
#if 0
	// if we have tracked all messages for this round
	auto nb_msgs = ctx->ptr_state->received_reqs_nb(hdr.sqn);
	if (tracked_all_round_messages(nb_msgs)) {
		// apply updates in the deterministic order
		apply_kvs_cmds(hdr.sqn, ctx);
		erpc::Rpc<erpc::CTransport> *rpc =
			reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
		rpc->run_event_loop(3000);
	}
#endif
}
