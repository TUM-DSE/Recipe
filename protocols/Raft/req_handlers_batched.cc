#include "cipher.h"
#include "common_conf.h"
#include "integrity.h"
#include "context.h"
#include "context_batched.h"
#include "generate_traces.h"
#include "rate_limiter.h"
#include "req_handlers.h"
#include "util.h"
#include <algorithm>
#include <fmt/os.h>
#include <fmt/printf.h>

#if BATCHING
// forward declaration
static std::unique_ptr<uint8_t[]> decode_req(char *data, size_t data_sz);

void req_terminate_followers(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	// decode new commit_index
#if 0
	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	size_t dec_size = PacketSsl::get_message_size(enc_size);
	std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size);
#endif

	// ack that you got the RPC
	auto &resp_buf = req_handle->pre_resp_msgbuf;

	// encrypt response
	auto message_sz = PacketSsl::get_buffer_size(sizeof(int));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(int);
#endif

	int cur_commit_index = 1;
#if INTEGRITY
	char metadata[kMetaSize];
	::memset(metadata, '4', kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(&cur_commit_index), sizeof(int));
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), &cur_commit_index, sizeof(int));
#else

#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
                 ::memcpy(resp_buf.buf+PacketSsl::IvSize, &cur_commit_index, sizeof(int));
 #else
	cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
#endif
#endif
	rpc->resize_msg_buffer(&resp_buf, message_sz);
	rpc->enqueue_response(req_handle, &resp_buf);

	context->terminate.store(true);
}

void req_nb_writes(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	// decode new commit_index
	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	// fmt::print("[{}] enc_size={}\n", __func__, enc_size);
	auto received_data = decode_req(enc_data, enc_size);
	// fmt::print("[{}] end\n", __func__);

	AppContext::header hdr;
	::memcpy(&hdr, received_data.get(), sizeof(hdr));
	int follower_writes = -1;
	::memcpy(&follower_writes, received_data.get() + sizeof(hdr), sizeof(int));

	context->ptr_state->total_write_requests.fetch_add(follower_writes);
	fmt::print("[{}] received from hdr.node_id={}/{} follower_writes={}/{}\n",
			__func__, hdr.node_id, context->RID, follower_writes,
			context->ptr_state->total_write_requests.load());

	// ack that you got the RPC
	auto &resp_buf = req_handle->pre_resp_msgbuf;

	// encrypt response
	auto message_sz = PacketSsl::get_buffer_size(sizeof(int));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(int);
#endif
	int cur_commit_index = 1;
#if INTEGRITY
	char metadata[kMetaSize];
	::memset(metadata, '4', kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(&cur_commit_index), sizeof(int));
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), &cur_commit_index, sizeof(int));
#else
#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
                 ::memcpy(resp_buf.buf+PacketSsl::IvSize, &cur_commit_index, sizeof(int));
 #else

	cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
#endif
#endif
	rpc->resize_msg_buffer(&resp_buf, message_sz);
	rpc->enqueue_response(req_handle, &resp_buf);

	// context->writes[hdr.node_id] = follower_writes;
}

static std::unique_ptr<uint8_t[]> decode_req(char *data, size_t data_sz) {
#if INTEGRITY
	size_t enc_data = PacketSsl::get_buffer_size(kMetaSize + kHashSize);
	auto decrypted_meta = destruct(cipher.get(), reinterpret_cast<char*>(data), enc_data);
	auto calc_sha256 = get_sha256(reinterpret_cast<char*>(data) + enc_data, (data_sz-enc_data));
	if (::memcmp(std::get<1>(calc_sha256).get(), decrypted_meta.get() + kMetaSize, kHashSize) != 0) {
		fmt::print("[{}] Error in verification\n", __func__);
	}

#if INTEGRITY_CITYHASH
	uint64_t c_h = 0;
	::memcpy(&c_h, decrypted_meta.get() + kMetaSize, kHashSize);
	if (c_h != CityHash64(reinterpret_cast<char*>(data)+enc_data, data_sz-enc_data)) {
		fmt::print("[{}] Error data_sz={} enc_data={}\n", __func__, data_sz, enc_data);
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
                  std::cout << __PRETTY_FUNCTION__ << ": Authentication failed\n";
                  exit(128);
          }
          return std::move(ptr);
   
 #else

	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size);

	bool [[maybe_unused]] ok = cipher->decrypt(ptr.get(), data, data_sz);
	if (!ok) {
                  std::cout << __PRETTY_FUNCTION__ << ": Authentication failed (AES_GCM)\n";
		  exit(128);
	}
	return std::move(ptr);
#endif
#endif
}

static void _print_key(uint8_t *key) {
	for (int i = 0; i < ycsb::Trace_cmd::key_size; i++) {
		fmt::print("{}", key[i]);
	}
	fmt::print("\n");
}

static AppContext::header
enqueue_received_req(AppContext *ctx, std::unique_ptr<uint8_t[]> data) {
	// @dimitra: we received a batch here

	AppContext::header hdr;
	::memcpy(&hdr, data.get(), sizeof(hdr));

#if 1
	auto new_req = new batched_request<kReqBatchSz>();
	ctx->ptr_state->uncommitted_reqs.insert({hdr.op_id, new_req});
	// fmt::print("[{}] insert hdr.op_id={}\n", __func__, hdr.op_id);
	new_req->idx = hdr.op_id;
	new_req->nb_batched_reqs = hdr.batch_sz;
	auto &_new_req = ctx->ptr_state->uncommitted_reqs[hdr.op_id];
	size_t offset = sizeof(AppContext::header);
	//	fmt::print("[{}] batch_sz={}/op_id={}\n", __func__, hdr.batch_sz,
	//hdr.op_id);
	for (auto i = 0ULL; i < hdr.batch_sz; i++) {
		//		fmt::print("[{}] for i={}/{}\n", __func__, hdr.op_id, i);
		auto ptr = std::make_unique<uint8_t[]>(ycsb::Trace_cmd::key_size);
		auto ptr_val = std::make_unique<uint8_t[]>(kValueSize);
		::memcpy(ptr.get(), data.get() + offset, ycsb::Trace_cmd::key_size);
		::memcpy(ptr_val.get(), data.get(), kValueSize); // @dimitra (todo): calculate the offset correctly
		offset += ycsb::Trace_cmd::key_size;
		_new_req->keys.emplace_back(std::move(ptr));
		_new_req->values.emplace_back(std::move(ptr_val));
	}

	// fmt::print("[{}] for done\n", __func__);

#endif
	return std::move(hdr);
}

static void enqueue_ack(erpc::ReqHandle *req_handle, AppContext *ctx,
		AppContext::header hdr) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
	// ack that you got the RPC
	auto &resp_buf = req_handle->pre_resp_msgbuf;
	if (resp_buf.buf == nullptr) {
		fmt::print("[{}] error\n", __func__);
	}

	// encrypt response
	hdr.node_id = ctx->node_id;
	hdr.latest_cmt = ctx->ptr_state->commit_index.load();
	auto message_sz = PacketSsl::get_buffer_size(sizeof(AppContext::header));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(AppContext::header);
#endif

	rpc->resize_msg_buffer(&resp_buf, message_sz);
#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &hdr.node_id, kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(&hdr), sizeof(AppContext::header));
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), &hdr, sizeof(AppContext::header));
#else
#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(resp_buf.buf, &hdr, sizeof(AppContext::header));
                 ::memcpy(resp_buf.buf+PacketSsl::IvSize, &hdr, sizeof(AppContext::header));
 #else

	cipher->encrypt(resp_buf.buf, &hdr, sizeof(AppContext::header));
#endif
#endif
	rpc->enqueue_response(req_handle, &resp_buf);
	// fmt::print("[{}] sent ack for hdr.op_id={}\n", __func__, hdr.op_id);
	rpc->run_event_loop_once();
}

static void enqueue_ack_w_reply(erpc::ReqHandle *req_handle, AppContext *ctx,
		std::unique_ptr<uint8_t[]> data,
		size_t data_sz) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
	// ack that you got the RPC
	// TODO: use the dynamic buffer
	// should be executed by leader upon a GET request

	auto &resp_buf = req_handle->pre_resp_msgbuf;

	// encrypt response
	auto message_sz = PacketSsl::get_buffer_size(data_sz);
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + data_sz;
#endif

	if (message_sz > 968) {
		resp_buf = req_handle->dyn_resp_msgbuf;
		resp_buf = rpc->alloc_msg_buffer(message_sz);
	}

	rpc->resize_msg_buffer(&resp_buf, message_sz);
#if INTEGRITY
	char metadata[kMetaSize];
	::memset(metadata, '5', kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), data_sz);
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), data.get(), data_sz);
#else
#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(resp_buf.buf, data.get(), data_sz);
                 ::memcpy(resp_buf.buf+PacketSsl::IvSize, data.get(), data_sz);
 #else

	cipher->encrypt(resp_buf.buf, data.get(), data_sz);
#endif
#endif
	rpc->enqueue_response(req_handle, &resp_buf);
}

// Executed by followers
void req_handler_appendEntries2(erpc::ReqHandle *req_handle, void *ctx) {

	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	context->ptr_state->start_the_workload.store(true);

	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	// fmt::print("[{}] enc_size={}\n", __func__, enc_size);
	auto received_data = decode_req(enc_data, enc_size);
	// fmt::print("[{}] end\n", __func__);
	if (req_handle->get_req_msgbuf()->buf == nullptr) {
		fmt::print("[{}] error, enc_size={}\n", __func__, enc_size);
	}

	auto hdr = enqueue_received_req(context, std::move(received_data));

	// this is for printing
	static int o = 0;
	o++;
	if (o % 10000 == 0)
		fmt::print("[{}] req_id={} (nb of uncommitted_reqs={})\n", __func__,
				hdr.op_id, context->ptr_state->uncommitted_reqs.size());

	enqueue_ack(req_handle, context, std::move(hdr));
}

static int apply_changes(int cmt_idx, AppContext *ctx) {
#if 1
	auto &local_cmt_idx = ctx->ptr_state->commit_index;
	auto &queued_reqs = ctx->ptr_state->uncommitted_reqs;
	auto batched_req = 0;
	int local_idx = local_cmt_idx.load();
	for (auto k = local_cmt_idx.load(); k <= cmt_idx; k++) {
		auto search = queued_reqs.find(k);
		if (search != queued_reqs.end()) {
			auto &reqs = queued_reqs[k];
			if (reqs == nullptr) {
				continue;
			}
			for (int nb_r = 0; nb_r < reqs->nb_batched_reqs; nb_r++) {
//			for (auto &req : reqs->keys)
//				auto key = req.get();
				auto &key = reqs->keys[nb_r];
			        auto& value = reqs->values[nb_r];
				
			//	auto value = req.get_value();
				ctx->store->put(ycsb::Trace_cmd::key_size, key.get(), value.get(), kValueSize);
				// ctx->store->put(ycsb::Trace_cmd::key_size, key);
				local_cmt_idx.fetch_add(1);
				//_print_key(key);
			}

			if (reqs != nullptr) {
				batched_req += reqs->nb_batched_reqs;
				delete queued_reqs[k];
				queued_reqs.erase(k);
				// fmt::print("[{}] cleanup for k={}\n", __func__, k);
				// fmt::print("[{}] breaks here x2 k={}\n", __func__, k);
			}
		}
	}
	// fmt::print("[{}] return here with batched_req={}\n", __func__,
	// batched_req);
	return batched_req;
#endif
}

static auto get_cmt_idx_and_apply(std::unique_ptr<uint8_t[]> data,
		AppContext *ctx) {
	AppContext::header hdr;
	::memcpy(&hdr, data.get(), sizeof(hdr));

	int follower_ops = -1;
	::memcpy(&follower_ops, data.get() + sizeof(hdr), sizeof(int));
	int leader_cmt_idx = hdr.op_id;
	// fmt::print("[{}] for cmt_idx={}\n", __func__, leader_cmt_idx);

	int batch_req = apply_changes(leader_cmt_idx, ctx);

	static int o = 0;
	o++;
	if (o % 10000 == 0)
		fmt::print("[{}] committed op_id={}/{}\n", __func__, leader_cmt_idx,
				ctx->ptr_state->commit_index.load());

	return std::make_tuple(hdr, follower_ops);
}

void req_handler_commitIndex2(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);

	// decode new commit_index
	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	// fmt::print("[{}] enc_size={}\n", __func__, enc_size);
	auto received_data = decode_req(enc_data, enc_size);
	// fmt::print("[{}] end\n", __func__);

	auto [hdr, completed_ops] =
		get_cmt_idx_and_apply(std::move(received_data), context);

	if (context->ptr_state->completed_reqs.load() < completed_ops) {
		// fmt::print("[{}] follower_cmt_idx={}\n", __func__, completed_ops);
		context->ptr_state->completed_reqs.store(completed_ops);
		// rate.release(1);
	}

	// fmt::print("[{}] cmt:", __func__);
	enqueue_ack(req_handle, context, std::move(hdr));
}

void req_handler_forwardGet(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);

	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	// fmt::print("[{}] enc_size={}\n", __func__, enc_size);
	auto received_data = decode_req(enc_data, enc_size);
	// fmt::print("[{}] end\n", __func__, enc_size);

	AppContext::header hdr;
	::memcpy(&hdr, received_data.get(), sizeof(hdr));

	uint8_t key[ycsb::Trace_cmd::key_size];
	::memcpy(key, received_data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);

	auto ret_val = context->store->get(ycsb::Trace_cmd::key_size, key);
	std::unique_ptr<uint8_t[]> data;
	size_t data_sz;
	if (ret_val.value.get() == nullptr) {
		//   fmt::print("[{}] received from {} (key not found)\n", __func__,
		//   hdr.node_id);

		hdr.node_id = context->node_id;
		data_sz = sizeof(hdr);
		data = std::make_unique<uint8_t[]>(sizeof(hdr));
		::memcpy(data.get(), &hdr, sizeof(hdr));
	} else {
		//  fmt::print("[{}] received from {}\n", __func__, hdr.node_id);

		hdr.node_id = context->node_id;
		data = std::make_unique<uint8_t[]>(kValueSize);
		data_sz = kValueSize;
		::memcpy(data.get(), ret_val.value.get(), kValueSize);
	}
	enqueue_ack_w_reply(req_handle, context, std::move(data), data_sz);
}

static void enqueue_put(AppContext *context, const uint8_t *key,
		const int &dest_node) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
	::memset(payload.get(), '0', kMsgSize);

	AppContext::header hdr;
	hdr.node_id = dest_node;
	hdr.op_id = 0;

	struct req_tuple_batched *tag_ptr = new req_tuple_batched();
	::memcpy(tag_ptr->key_hash, key, ycsb::Trace_cmd::key_size);
	tag_ptr->dest_session_nb = hdr.node_id;
	{
		std::lock_guard<std::mutex> l(context->ptr_state->mtx);
		context->ptr_state->concurrent_q->push_back(tag_ptr);
	}
}

void req_handler_forwardPut(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);

	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	// fmt::print("[{}] enc_size={}\n", __func__, enc_size);
	auto received_data = decode_req(enc_data, enc_size);
	// fmt::print("[{}] end\n", __func__);
	AppContext::header hdr;
	::memcpy(&hdr, received_data.get(), sizeof(hdr));
	uint8_t key[ycsb::Trace_cmd::key_size];
	::memcpy(key, received_data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);

	auto dest_node = hdr.node_id;
	// fmt::print("[{}] received from {}\n", __func__, hdr.node_id);

	enqueue_ack(req_handle, context, std::move(hdr));

	enqueue_put(context, key, dest_node);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	rpc->run_event_loop_once();
}
#endif
