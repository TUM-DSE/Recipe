#include "req_handlers.h"
#include "cipher.h"
#include "integrity.h"
#include "common_conf.h"
#include "context.h"
#include "stats.h"
#include "ycsb_generator/generate_traces.h"

static void sanity_check(const int &node_id, const uint8_t *hkey,
		const int &req_type, uint8_t *data) {
#if 1
	AppContext::header hdr;
	::memcpy(&hdr, data, sizeof(AppContext::header));
	if (((node_id != 0) && (node_id != 1) && (node_id != 2)) ||
			(req_type != hdr.req_type)) {
		fmt::print("[{}] fuck you node={}\n", __func__, node_id);
		fmt::print("[{}] {} key=", __func__, req_type);
		for (auto k = 0; k < ycsb::Trace_cmd::key_size; k++)
			fmt::print("{}", hkey[k]);
		fmt::print("\n\n");
		for (auto k = 0; k < kMsgSize; k++)
			fmt::print("{}", data[k]);
		fmt::print("\n\n");
		fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\n", __func__,
				hdr.sender_node, hdr.receiver_node,
				(req_type == kReqPUT) ? "kReqPUT" : "kReqGET");
	}
#endif
}

static std::unique_ptr<uint8_t[]>
decode_request_and_ack(AppContext *ctx, uint8_t *data, size_t data_sz,
		erpc::ReqHandle *req_handle) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
#if 0
	std::cout << "data=\n";
	for (auto i = 0; i < data_sz; i++) {
		fmt::print("{}", data[i]);

	}       
	std::cout << "\n";
	std::cout << "payload=\n";
	for (auto i = 0; i < PacketSsl::get_message_size(data_sz); i++) {
		fmt::print("{}", data[i+PacketSsl::IvSize]);

	}       
	std::cout << "\n";
#endif


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
		fmt::print("[{}] Error\n", __func__);
	}
#endif
	std::unique_ptr<uint8_t[]> decrypted_data = std::make_unique<uint8_t[]>(data_sz-enc_data);
	::memcpy(decrypted_data.get(), data + enc_data, data_sz-enc_data);
#else
#if GMAC
#warning "GMAC ON"
	uint8_t unused;
	size_t decrypted_data_sz = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> decrypted_data =
		std::make_unique<uint8_t[]>(decrypted_data_sz);
	::memcpy(decrypted_data.get(), data + PacketSsl::IvSize, decrypted_data_sz);
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
#else

	size_t decrypted_data_sz = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> decrypted_data =
		std::make_unique<uint8_t[]>(decrypted_data_sz);
	bool [[maybe_unused]] success =
		cipher->decrypt(decrypted_data.get(), data, data_sz);
#endif
#if NO_CIPHER
#else
	if (!success) {
		fmt::print("[{}] decryption failed (RID={})\n", __func__, ctx->RID);
		exit(128);
	}
#endif
#endif

	auto &resp_buf = req_handle->pre_resp_msgbuf;
	auto ack_msg_sz = PacketSsl::get_buffer_size(kAckMsgSize);
	rpc->resize_msg_buffer(&resp_buf, ack_msg_sz);

	rpc->enqueue_response(req_handle, &resp_buf);
	// rpc->run_event_loop_once();

	return std::move(decrypted_data);
}

static void send_kCommitReq(const AppContext::header &hdr, const uint8_t *hkey,
		AppContext *ctx, const int &dest_node) {
	// tail sends commit req for a key to the MIDDLE

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);

	struct req_tuple *tag_ptr = new req_tuple();
	size_t message_sz = PacketSsl::get_buffer_size(kAckMsgSize);
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kAckMsgSize;
#endif

	tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->req_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		fmt::print("[{}] blocked\n", __func__);
	}
	tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->resp_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		fmt::print("[{}] blocked\n", __func__);
	}

	rpc->resize_msg_buffer(&tag_ptr->req_buf, message_sz);
	rpc->resize_msg_buffer(&tag_ptr->resp_buf, message_sz);

	AppContext::header new_hdr;
	new_hdr.sender_node = hdr.sender_node;
	new_hdr.receiver_node = dest_node;
	new_hdr.req_type = kReqCommit;
	new_hdr.rid = ctx->RID;
	new_hdr.key_version = hdr.key_version;
	std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(kAckMsgSize);
	static_assert((sizeof(new_hdr) + ycsb::Trace_cmd::key_size) < kAckMsgSize);
	::memcpy(data.get(), &new_hdr, sizeof(new_hdr));
	::memcpy(data.get() + sizeof(new_hdr), hkey, ycsb::Trace_cmd::key_size);
	// fmt::print("[{}] to new_hdr.sender_node={} dest_node={} version={}\n",
	// __func__, new_hdr.sender_node, dest_node, new_hdr.key_version);

#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &hdr.sender_node, kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), kAckMsgSize);
	::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), data.get(), kAckMsgSize);
#else
#if GMAC
	cipher->encrypt(tag_ptr->req_buf.buf, data.get(), kAckMsgSize);
	::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, data.get(), kAckMsgSize);
#else


	cipher->encrypt(tag_ptr->req_buf.buf, data.get(), kAckMsgSize);
#endif
#endif
	auto session_num = ctx->cluster_info[dest_node];
	rpc->enqueue_request(session_num, kReqCommit, &tag_ptr->req_buf,
			&tag_ptr->resp_buf, cont_func_fw, (void *)tag_ptr);
}

static void send_kCompletedReqsNb_request(int sender_node, AppContext *ctx) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);

	struct req_tuple *tag_ptr = new req_tuple();
	size_t message_sz = PacketSsl::get_buffer_size(kAckMsgSize);
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kAckMsgSize;
#endif
	tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->req_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		fmt::print("[{}] blocked\n", __func__);
	}
	tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->resp_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		fmt::print("[{}] blocked\n", __func__);
	}

	auto num_reqs = ctx->reqs_per_node[sender_node];
	tag_ptr->req_id = num_reqs;
	if (num_reqs == nb_reqs) {
		fmt::print("[{}] sender_node_id={}/{} should now terminate ..\n", __func__,
				sender_node, ctx->RID);
	}
	rpc->resize_msg_buffer(&tag_ptr->req_buf, message_sz);
	rpc->resize_msg_buffer(&tag_ptr->resp_buf, message_sz);

	AppContext::header hdr;
	hdr.sender_node = ctx->node_id;
	hdr.receiver_node = sender_node;
	hdr.req_type = kCompletedReqsNb;
	hdr.rid = ctx->RID;
	std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(kAckMsgSize);
	::memcpy(data.get(), &(num_reqs), sizeof(num_reqs));
	::memcpy(data.get() + sizeof(num_reqs), &hdr, sizeof(hdr));

#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &hdr.sender_node, kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), kAckMsgSize);
	::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), data.get(), kAckMsgSize);
#else
#if GMAC
	cipher->encrypt(tag_ptr->req_buf.buf, data.get(), kAckMsgSize);
	::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, data.get(), kAckMsgSize);
#else


	cipher->encrypt(tag_ptr->req_buf.buf, data.get(), kAckMsgSize);
#endif
#endif
	auto session_num = ctx->cluster_info[sender_node];
	rpc->enqueue_request(session_num, kCompletedReqsNb, &tag_ptr->req_buf,
			&tag_ptr->resp_buf, cont_func_fw, (void *)tag_ptr);
}

static void forward_kReqPUT(AppContext *ctx, uint8_t *data) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);

	struct req_tuple *tag_ptr = new req_tuple();

	auto message_sz = PacketSsl::get_buffer_size(kMsgSize);
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
#endif
	tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->req_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	}
	tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	while (tag_ptr->resp_buf.buf == nullptr) {
		rpc->run_event_loop_once();
		tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
	}
	rpc->resize_msg_buffer(&tag_ptr->req_buf, message_sz);
	rpc->resize_msg_buffer(&tag_ptr->resp_buf, message_sz);

#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data), kMsgSize);
	::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), data, kMsgSize);
#else
#if GMAC
	bool success = cipher->encrypt(tag_ptr->req_buf.buf, data, kMsgSize);
	::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, data, kMsgSize);
#else

	bool [[maybe_unused]] success =
		cipher->encrypt(tag_ptr->req_buf.buf, data, kMsgSize);
#endif
#if NO_CIPHER
#else
	if (!success) {
		fmt::print("[{}] encryption failed\n", __func__);
		exit(128);
	}
#endif
#endif

	AppContext::header hdr;
	::memcpy(&hdr, data, sizeof(AppContext::header));
	/*
	   auto reqs = ctx->reqs_per_node[hdr.sender_node];
	   ctx->reqs_per_node[hdr.sender_node] = reqs + 1;
	   */
	int session_num = -1;
	if (ctx->node_operation == CR::MIDDLE) {
		//    fmt::print("[{}] MIDDLE version={}\n", __func__, hdr.key_version);
		session_num = ctx->cluster_info[kTailNodeId];
	} else if (ctx->node_operation == CR::HEAD) {
		session_num = ctx->cluster_info[kMiddleNodeId1];
		//	fmt::print("[{}] HEAD version={} to {}\n", __func__, hdr.key_version,
		// session_num);
	}
	rpc->enqueue_request(session_num, kReqPUT, &tag_ptr->req_buf,
			&tag_ptr->resp_buf, cont_func_fw, (void *)tag_ptr);
}

void req_handler_terminated_node(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	auto data = decode_request_and_ack(
			context, req_handle->get_req_msgbuf()->buf,
			req_handle->get_req_msgbuf()->get_data_size(), req_handle);

	int node_id;
	::memcpy(&node_id, data.get(), sizeof(node_id));

	fmt::print("[{}] node w/ id={} (ctx_id={}) terminated ..\n", __func__,
			node_id, context->RID);
	if (context->terminated_nodes.find(node_id) ==
			context->terminated_nodes.end())
		context->terminated_nodes.insert(std::make_pair(node_id, 1));
	else {
		fmt::print("[{}] double executed request, please ignore\n", __func__);
	}

	rpc->run_event_loop_once();
}

void req_handler_cmt(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	//  fmt::print("[{}] completed_ops={}\n", __func__, context->completed_reqs);
	auto data = decode_request_and_ack(
			context, req_handle->get_req_msgbuf()->buf,
			req_handle->get_req_msgbuf()->get_data_size(), req_handle);
	AppContext::header hdr;
	uint8_t hkey[ycsb::Trace_cmd::key_size];
	::memcpy(&hdr, data.get(), sizeof(AppContext::header));
	::memcpy(hkey, data.get() + sizeof(AppContext::header),
			ycsb::Trace_cmd::key_size);

	context->store->update_cmt(hkey, ycsb::Trace_cmd::key_size, hdr.key_version);
	if (hdr.sender_node == context->node_id) {
		context->rate.release(1);
		context->completed_reqs++;
	}
	if (context->node_operation == CR::MIDDLE) {
		//   fmt::print("[{}] completed_ops={}\r", __func__,
		//   context->completed_reqs);
		send_kCommitReq(hdr, hkey, context, kHeadNodeId);
	} else {
		context->reqs_per_node[hdr.sender_node]++;
	}
#if 0
	else {
		fmt::print("[{}] completed_reqs={} for hdr.sender_node={}\n", __func__, context->completed_reqs, hdr.sender_node);
	}
#endif
}

void req_handler_put(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	context->start_the_fucking_workload = true;
	std::unique_ptr<uint8_t[]> payload = std::make_unique<uint8_t[]>(kMsgSize);
	::memset(payload.get(), '1', kMsgSize);

	switch (context->node_operation) {
		case CR::MIDDLE: {

					 auto data = decode_request_and_ack(
							 context, req_handle->get_req_msgbuf()->buf,
							 req_handle->get_req_msgbuf()->get_data_size(), req_handle);
					 AppContext::header hdr;
					 ::memcpy(&hdr, data.get(), sizeof(hdr));

					 uint8_t hkey[ycsb::Trace_cmd::key_size];
					 ::memcpy(hkey, data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);
#if KV
#warning "KV OPERATIONS as usual"
					 // context->store->put(ycsb::Trace_cmd::key_size, hkey);
					 ::memcpy(payload.get(), data.get() + sizeof(hdr) + ycsb::Trace_cmd::key_size, req_handle->get_req_msgbuf()->get_data_size()-sizeof(hdr) - ycsb::Trace_cmd::key_size);
					 context->store->put(ycsb::Trace_cmd::key_size, hkey, payload.get(), kMsgSize);
#endif
					 sanity_check(hdr.sender_node, hkey, kReqPUT, data.get());
					 // rpc->run_event_loop_once();

					 // forward the request to the tail
					 forward_kReqPUT(context, data.get());
					 rpc->run_event_loop_once();
					 break;
				 }
		case CR::TAIL: {

				       erpc::Rpc<erpc::CTransport> *rpc =
					       reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
				       auto data = decode_request_and_ack(
						       context, req_handle->get_req_msgbuf()->buf,
						       req_handle->get_req_msgbuf()->get_data_size(), req_handle);

				       AppContext::header hdr;
				       ::memcpy(&hdr, data.get(), sizeof(AppContext::header));
				       uint8_t hkey[ycsb::Trace_cmd::key_size];
				       ::memcpy(hkey, data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);
#if KV
				       // context->store->put_and_commit(ycsb::Trace_cmd::key_size, hkey,
					//	       hdr.key_version);
				       context->store->put_and_commit(ycsb::Trace_cmd::key_size, hkey, kMsgSize, reinterpret_cast<uint8_t*>(payload.get()),
						       hdr.key_version);
#endif

				       send_kCommitReq(hdr, hkey, context, kMiddleNodeId1);

				       // this is for calculating the completed reqs
				       sanity_check(hdr.sender_node, hkey, kReqPUT, data.get());
				       if (hdr.sender_node == context->node_id) {
					       context->rate.release(1);
					       context->completed_reqs++;
					       rpc->run_event_loop_once();
					       return;
				       }

#if 0
				       auto reqs = context->reqs_per_node[hdr.sender_node];
				       context->reqs_per_node[hdr.sender_node] = reqs + 1;

				       if ((context->reqs_per_node[hdr.sender_node] % kBatchSize == 0) ||
						       (context->reqs_per_node[hdr.sender_node] == nb_reqs)) {
					       send_kCompletedReqsNb_request(hdr.sender_node, context);
				       }
#endif
				       rpc->run_event_loop_once();
				       break;
			       }
		case CR::HEAD: {
				       auto data = decode_request_and_ack(
						       context, req_handle->get_req_msgbuf()->buf,
						       req_handle->get_req_msgbuf()->get_data_size(), req_handle);
				       AppContext::header hdr;
				       ::memcpy(&hdr, data.get(), sizeof(hdr));

				       uint8_t hkey[ycsb::Trace_cmd::key_size];
				       ::memcpy(hkey, data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);
#if KV
// 				       auto kversion = context->store->put(ycsb::Trace_cmd::key_size, hkey);
				       ::memcpy(payload.get(), data.get() + sizeof(hdr) + ycsb::Trace_cmd::key_size, req_handle->get_req_msgbuf()->get_data_size()-sizeof(hdr) - ycsb::Trace_cmd::key_size);
				       auto kversion = context->store->put(ycsb::Trace_cmd::key_size, hkey, payload.get(), kMsgSize);

				       hdr.key_version = kversion;
				       ::memcpy(data.get(), &hdr, sizeof(hdr));
#endif
				       sanity_check(hdr.sender_node, hkey, kReqPUT, data.get());
				       // rpc->run_event_loop_once();

				       // forward the request to the tail
				       forward_kReqPUT(context, data.get());
				       rpc->run_event_loop_once();
				       break;
			       }
	}
}

void req_handler_get(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	context->start_the_fucking_workload = true;

	switch (context->node_operation) {
		case CR::MIDDLE: {
					 auto data = decode_request_and_ack(
							 context, req_handle->get_req_msgbuf()->buf,
							 req_handle->get_req_msgbuf()->get_data_size(), req_handle);

					 AppContext::header hdr;
					 ::memcpy(&hdr, data.get(), sizeof(AppContext::header));
					 fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\n", __func__,
							 hdr.sender_node, hdr.receiver_node,
							 (hdr.req_type == kReqPUT) ? "kReqPUT" : "kReqGET");
					 fmt::print("[{}] never called by CR::MIDDLE\n", __func__);
					 exit(128);
				 }
		case CR::TAIL: {
				       erpc::Rpc<erpc::CTransport> *rpc =
					       reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
				       auto data = decode_request_and_ack(
						       context, req_handle->get_req_msgbuf()->buf,
						       req_handle->get_req_msgbuf()->get_data_size(), req_handle);

				       AppContext::header hdr;
				       ::memcpy(&hdr, data.get(), sizeof(AppContext::header));
				       uint8_t hkey[ycsb::Trace_cmd::key_size];
				       ::memcpy(hkey, data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);
#if KV
#warning "KV is ON"
				       context->store->get(ycsb::Trace_cmd::key_size, hkey);
#endif
				       sanity_check(hdr.sender_node, hkey, kReqGET, data.get());
				       if (hdr.sender_node == context->node_id) {
					       fmt::print("[{}] CR::TAIL (RID={}) serves kReqGET locally\n", __func__,
							       context->RID);

					       fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\n",
							       __func__, hdr.sender_node, hdr.receiver_node,
							       (hdr.req_type == kReqPUT) ? "kReqPUT" : "kReqGET");
					       exit(128);
				       }

#if 0
				       auto reqs = context->reqs_per_node[hdr.sender_node];
				       context->reqs_per_node[hdr.sender_node] = reqs + 1;

				       if ((context->reqs_per_node[hdr.sender_node] % kBatchSize == 0) ||
						       (context->reqs_per_node[hdr.sender_node] == nb_reqs)) {
					       send_kCompletedReqsNb_request(hdr.sender_node, context);
				       }
#endif
				       break;
			       }
		case CR::HEAD:
			       auto data = decode_request_and_ack(
					       context, req_handle->get_req_msgbuf()->buf,
					       req_handle->get_req_msgbuf()->get_data_size(), req_handle);

			       AppContext::header hdr;
			       ::memcpy(&hdr, data.get(), sizeof(AppContext::header));
			       fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\n", __func__,
					       hdr.sender_node, hdr.receiver_node,
					       (hdr.req_type == kReqPUT) ? "kReqPUT" : "kReqGET");
			       fmt::print("[{}] never called by CR::HEAD\n", __func__);
			       exit(128);
	}
}

void req_handler_complete_reqs(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	auto data = decode_request_and_ack(
			context, req_handle->get_req_msgbuf()->buf,
			req_handle->get_req_msgbuf()->get_data_size(), req_handle);

	context->completed_reqs = -1;
#if 0
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	auto data = decode_request_and_ack(
			context, req_handle->get_req_msgbuf()->buf,
			req_handle->get_req_msgbuf()->get_data_size(), req_handle);

	int completed_requests;
	::memcpy(&completed_requests, data.get(), sizeof(completed_requests));
#if DEBUG
	if (std::find(context->seen_reqs_nb.begin(), context->seen_reqs_nb.end(),
				completed_requests) != context->seen_reqs_nb.end()) {
		fmt::print("[{}] already seen req {}\t{} (RID={})\n", __func__,
				completed_requests, context->completed_reqs, context->RID);
		AppContext::header hdr;
		::memcpy(&hdr, data.get() + sizeof(completed_requests), sizeof(hdr));
		fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\tRID={}\n",
				__func__, hdr.sender_node, hdr.receiver_node,
				(hdr.req_type == kCompletedReqsNb) ? "kCompletedReqsNb" : "N/A",
				hdr.rid);

	} else {
		context->seen_reqs_nb.push_back(completed_requests);
	}
#endif

	if (completed_requests <= context->completed_reqs) {
#if 0
		fmt::print("[{}] out-of-order {}\t{} (RID={})\n", __func__, completed_requests,
				context->completed_reqs, context->RID);
		AppContext::header hdr;
		::memcpy(&hdr, data.get() + sizeof(completed_requests), sizeof(hdr));
		fmt::print("[{}] sender_node={}\treceiver_node={}\treq_type={}\tRID={}\n", __func__, hdr.sender_node, hdr.receiver_node, (hdr.req_type == kCompletedReqsNb) ? "kCompletedReqsNb" : "N/A", hdr.rid);
#endif
	} else {
		context->completed_reqs = completed_requests;
		//	fmt::print("[{}] RID={} finished {} requests\n", __func__, context->RID,
		// completed_requests);
	}
	if (completed_requests == nb_reqs) {
		fmt::print("[{}] RID={} done {} reqs\n", __func__, context->RID,
				completed_requests);
	}
	context->rate.release(kBatchSize);
	rpc->run_event_loop_once();
#endif
}
