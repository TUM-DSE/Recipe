#pragma once
#include "cipher.h"
#include "integrity.h"
#include "rate_limiter.h"
#include <atomic>
#include <fmt/printf.h>
#include <memory>
#include <sys/time.h>


static void send_termination_req(AppContext *context) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	AppContext::header hdr;

	size_t message_sz = PacketSsl::get_buffer_size(sizeof(hdr));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(hdr);
#endif

	for (auto& connection : context->cluster_info) {
		auto tag = new request_tag();
		tag->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->csqn = context->ptr_state->current_round - 1;

		hdr.sqn = context->ptr_state->current_round - 1;
		hdr.req_owner = context->node_id;
		hdr.node_id = context->node_id;
		hdr.batch_sz = 0;

		auto data = std::make_unique<uint8_t[]>(sizeof(hdr));
		::memcpy(data.get(), &hdr, sizeof(hdr));
#if INTEGRITY
		char metadata[kMetaSize];
		::memcpy(metadata, &(hdr.sqn), kMetaSize);
		auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), sizeof(hdr));
		::memcpy(tag->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
		::memcpy(tag->req_buf.buf + std::get<0>(res), data.get(), sizeof(hdr));
#else

#if GMAC
#warning "GCMAC is ON"
		cipher->encrypt(tag->req_buf.buf, data.get(), sizeof(hdr));
		::memcpy(tag->req_buf.buf+PacketSsl::IvSize, data.get(), sizeof(hdr));
#else 

		cipher->encrypt(tag->req_buf.buf, data.get(), sizeof(hdr));
#endif
#endif
		rpc->enqueue_request(connection.second, kReqTerminateFollowers, &(tag->req_buf), &(tag->resp_buf),
				cont_func_default, (void *)tag);
	}
}

static void create_batch(const uint8_t* key_hash, const size_t& key_size, size_t& offset, std::unique_ptr<uint8_t[]>& payload) {
	::memcpy(payload.get() + offset, key_hash, key_size);
	offset += key_size;
#if 0
	for (auto i = 0; i < key_size; i++) {
		fmt::print("{}", key_hash[i]);
	}
	fmt::print("\n");
#endif
}

static void create_empty_batch(std::unique_ptr<uint8_t[]>& payload, AppContext* context, const uint64_t& current_round) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	AppContext::header hdr;

	// size_t message_sz = PacketSsl::get_buffer_size(kMsgSize*kReqBatchSz + sizeof(hdr));
	size_t message_sz = PacketSsl::get_buffer_size(kMsgSize + sizeof(hdr));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + (kMsgSize + sizeof(hdr));
#endif
	for (auto& connection : context->cluster_info) {
		auto tag = new request_tag();
		tag->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->csqn = current_round;

		hdr.sqn = current_round;
		hdr.req_owner = context->node_id;
		hdr.node_id = context->node_id;
		hdr.batch_sz = 0;

		auto data = std::make_unique<uint8_t[]>(kMsgSize + sizeof(hdr));
		::memcpy(data.get(), &hdr, sizeof(hdr));
		::memcpy(data.get() + sizeof(hdr), payload.get(), kMsgSize);

#if INTEGRITY
		char metadata[kMetaSize];
		::memcpy(metadata, &(hdr.sqn), kMetaSize);
		auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), (sizeof(hdr)+kMsgSize));
		::memcpy(tag->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
		::memcpy(tag->req_buf.buf + std::get<0>(res), data.get(), (sizeof(hdr) + kMsgSize));
#else
#if GMAC
#warning "GCMAC is ON"
		cipher->encrypt(tag->req_buf.buf, data.get(), (kMsgSize + sizeof(hdr)));
		::memcpy(tag->req_buf.buf+PacketSsl::IvSize, data.get(), (kMsgSize+sizeof(hdr)));
#else
		cipher->encrypt(tag->req_buf.buf, data.get(), (kMsgSize + sizeof(hdr)));
#endif
#endif
		rpc->enqueue_request(connection.second, kReqRecvReq, &(tag->req_buf), &(tag->resp_buf),
				cont_func, (void *)tag);
	}

}

static void enqueue_request(std::unique_ptr<uint8_t[]>& payload, AppContext* context, const uint64_t& current_round, const int& batch_sz) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	AppContext::header hdr;

	size_t message_sz = PacketSsl::get_buffer_size(kMsgSize*kReqBatchSz + sizeof(hdr));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + (kMsgSize*kReqBatchSz + sizeof(hdr));
#endif
	for (auto& connection : context->cluster_info) {
		auto tag = new request_tag();
		tag->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
		tag->csqn = current_round;

		hdr.sqn = current_round;
		hdr.req_owner = context->node_id;
		hdr.node_id = context->node_id;
		hdr.batch_sz = batch_sz;

		auto data = std::make_unique<uint8_t[]>(kMsgSize*batch_sz + sizeof(hdr));
		::memcpy(data.get(), &hdr, sizeof(hdr));
		::memcpy(data.get() + sizeof(hdr), payload.get(), kMsgSize*batch_sz);

#if INTEGRITY
		char metadata[kMetaSize];
		::memcpy(metadata, &(hdr.sqn), kMetaSize);
		auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), (sizeof(hdr)+kMsgSize*batch_sz));
		::memcpy(tag->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
		::memcpy(tag->req_buf.buf + std::get<0>(res), data.get(), (sizeof(hdr) + kMsgSize*batch_sz));
#else
#if GMAC
#warning "GCMAC is ON"
		// @dimitra: you can use the batch_sz here but keep in mind to change message_sz accordingly
		cipher->encrypt(tag->req_buf.buf, data.get(), (kMsgSize*kReqBatchSz + sizeof(hdr)));
		::memcpy(tag->req_buf.buf+PacketSsl::IvSize, data.get(), (kMsgSize*kReqBatchSz+sizeof(hdr)));
#else
		cipher->encrypt(tag->req_buf.buf, data.get(), (kMsgSize*kReqBatchSz + sizeof(hdr)));
#endif
#endif
		rpc->enqueue_request(connection.second, kReqRecvReq, &(tag->req_buf), &(tag->resp_buf),
				cont_func, (void *)tag);
		// rpc->run_event_loop(1000);
	}
}

static void generate_workload(AppContext *context,
		thread_args *args) {

	std::unique_ptr<uint8_t[]> payload = std::make_unique<uint8_t[]>(kMsgSize*kReqBatchSz);
	::memset(payload.get(), '0', kMsgSize*kReqBatchSz);
	size_t offset = 0;

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	if (context->node_id != 0) {
		fmt::print("[{}] wait for signal\n", __func__);
		while (!context->ptr_state->start_the_workload.load())
			rpc->run_event_loop_once();
	}
	struct timeval startTV, endTV;
	gettimeofday(&startTV, NULL);
	int i = 0;
	uint64_t current_round = 0;
	auto vector_sz = args->end - args->begin;
	fmt::print(
			"[{}] will execute {} ({}) ops with Value and MSG sizes: {}B {}B\n",
			__func__, (kWorkloadSize / kTraceSize) * vector_sz, nb_reqs, kValueSize,
			kMsgSize);

	fmt::print("[{}] start batching\n", __func__);
	for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
		for (auto it = args->begin; it != args->end; ++it) {
			if (it->op == ycsb::Trace_cmd::Put || i == 0) {
#if FOLLOWER_WORKLOAD || RATELIMITER && 0
				//       rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
#endif

				i++;
				create_batch(it->key_hash, it->key_size, offset, payload);
				if (i%kReqBatchSz == 0) {
					enqueue_request(payload, context, current_round, kReqBatchSz);
					context->ptr_state->enqueue_received_req(current_round, context->node_id, kReqBatchSz, std::move(payload), kMsgSize*kReqBatchSz);
					//     fmt::print("[{}] end batching\n", __func__);
					//     fmt::print("[{}] start batching\n", __func__);
					payload = std::make_unique<uint8_t[]>(kMsgSize*kReqBatchSz);
					args->writes++;
					current_round++;
					context->ptr_state->current_round++;
					offset = 0;
				}
			} else {
				context->store->get(it->key_size, it->key_hash);
				args->reads++;
				if ((args->reads % 1000) == 0)
					rpc->run_event_loop_once();
			}

			if (i % kQueueSize == 0) {
				rpc->run_event_loop_once();
			}
		}
	}
	if (i%kReqBatchSz != 0)
	{
		std::cout << "enqueue last req=" << current_round << "\n";
		// enqeueue the last req
		enqueue_request(payload, context, current_round, (i%kReqBatchSz));
		context->ptr_state->enqueue_received_req(current_round, context->node_id, i%kReqBatchSz, std::move(payload), kMsgSize*kReqBatchSz);
		payload = std::make_unique<uint8_t[]>(kMsgSize*kReqBatchSz);
		args->writes++;
		current_round++;
		context->ptr_state->current_round++;
	}

	fmt::print("[{}] node #{}/{} is waiting for termination (current total writes={}, consensus_round={})\n",
			__func__, context->node_id, context->rid, args->writes, context->ptr_state->consensus_sqn.load());

	::memset(payload.get(), '0', kMsgSize*kReqBatchSz);

	send_termination_req(context);
	while (!context->ptr_state->terminate_execution()) {
		rpc->run_event_loop(2000);
		fmt::print("[{}] create and send empty batch {}\n", __func__, context->ptr_state->consensus_sqn.load());
		create_empty_batch(payload, context, current_round);
		current_round++;
		context->ptr_state->current_round++;
		// TODO: wait until you receive something
	}

	fmt::print("[{}] node #{}/{} terminates with consensus sqn={}\n",
			__func__, context->node_id, context->rid, context->ptr_state->consensus_sqn);

	gettimeofday(&endTV, NULL);

	fmt::print("**time taken = {} {}\n", (endTV.tv_sec - startTV.tv_sec),
			(endTV.tv_usec - startTV.tv_usec));
}

