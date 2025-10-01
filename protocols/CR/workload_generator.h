#pragma once
#include "chain_rep.h"
#include "cipher.h"
#include "integrity.h"
#include "stats.h"
#include "ycsb_generator/generate_traces.h"
#include <memory>
#include <sys/time.h>

static void generate_workload_middle(AppContext *context, thread_args *args) {
	std::unique_ptr<uint8_t[]> payload = std::make_unique<uint8_t[]>(kMsgSize);
	::memset(payload.get(), '1', kMsgSize);

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	// rpc->run_event_loop(10000);
#if 1
	while (!context->start_the_fucking_workload)
		rpc->run_event_loop_once();
#endif

	struct timeval diff, startTV, endTV;
	gettimeofday(&startTV, NULL);
	fmt::print("[{}] RID={} starts the workload\n", __func__, context->RID);
	int i = 0;
	for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
		for (auto it = args->begin; it != args->end; ++it) {
			context->rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
			size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
#if INTEGRITY
			message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
#endif
			struct req_tuple *tag_ptr = new req_tuple();
			AppContext::header hdr;
			hdr.sender_node = context->node_id;
			if (it->op == ycsb::Trace_cmd::Put) {
				hdr.receiver_node = kHeadNodeId;
				hdr.req_type = kReqPUT;
			} else {
				hdr.receiver_node = kTailNodeId;
				hdr.req_type = kReqGET;
			}
			::memcpy(payload.get(), &hdr, sizeof(hdr));

			::memcpy(payload.get() + sizeof(hdr), it->key_hash, it->key_size);
			tag_ptr->req_id = i;
			tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			while (tag_ptr->req_buf.buf == nullptr) {
				// no space left
				rpc->run_event_loop_once();
				tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}
			tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			while (tag_ptr->resp_buf.buf == nullptr) {
				// no space left
				rpc->run_event_loop_once();
				tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}

			rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
			rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);

#if INTEGRITY
			char metadata[kMetaSize];
			::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
			auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
			::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), kMsgSize);
#else
#if GMAC
#warning "GCMAC is ON"
			/*
			std::cout << "Before: \n";
			for (auto i = 0; i < kMsgSize; i++) {
				fmt::print("{}", payload.get()[i]);
			}
			std::cout << "\nAfter\n";
			*/
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), kMsgSize);

			/*
			for (auto i = 0; i < kMsgSize; i++) {
				fmt::print("{}", payload.get()[i]);
			}
			std::cout << "\n";
			for (auto i = 0; i < message_sz; i++) {
				fmt::print("{}", tag_ptr->req_buf.buf[i]);

			}
			std::cout << "\n";
			{
			#include <chrono>
			using namespace std::chrono_literals;
			std::this_thread::sleep_for(2000ms);
			}*/

#else
			// encrypt
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
#endif
#endif
			if (it->op == ycsb::Trace_cmd::Put) {
				auto session_num = context->cluster_info[kHeadNodeId];
				rpc->enqueue_request(session_num, kReqPUT, &tag_ptr->req_buf,
						&tag_ptr->resp_buf, cont_func, (void *)tag_ptr);
				args->writes++;
			} else {
				auto session_num = context->cluster_info[kTailNodeId];
				rpc->enqueue_request(session_num, kReqGET, &tag_ptr->req_buf,
						&tag_ptr->resp_buf, cont_func_get,
						(void *)tag_ptr);
				args->reads++;
			}
			i++;
			rpc->run_event_loop_once();
			if (i % 50000 == 0) {
				fmt::print("[{}] {}\n", __func__, i);
			}
			// fmt::print("[{}]\tRID\t=\t{}\treq\t=\t{}\r", __func__, context->RID,
			// i);
		}
	}

	fmt::print("[CR::MIDDLE] {}/(RID={}): waiting for replies for nb_reqs={}\n",
			__func__, context->RID, nb_reqs);
	// while (context->completed_reqs != nb_reqs) {
	while (context->completed_reqs < nb_reqs) {
		rpc->run_event_loop_once();
#if 0
		fmt::print("[CR::MIDDLE] {}/(RID={}): waiting for replies for completed_reqs={}\n",
				__func__, context->RID, context->completed_reqs);
#endif
	}

	while (context->terminated_nodes.find(kHeadNodeId) ==
			context->terminated_nodes.end()) {
		rpc->run_event_loop_once();
	}

	gettimeofday(&endTV, NULL);

	printf("\n \n \n[CR::MIDDLE] %s all reqs (%d, R=%d, W=%d) acknowledged\n",
			__PRETTY_FUNCTION__, context->completed_reqs, args->reads,
			args->writes);
	printf("**time taken = %ld %ld\n", (endTV.tv_sec - startTV.tv_sec),
			(endTV.tv_usec - startTV.tv_usec));
}

static void generate_workload_head(AppContext *context, thread_args *args) {
	std::unique_ptr<uint8_t[]> payload = std::make_unique<uint8_t[]>(kMsgSize);
	::memset(payload.get(), '1', kMsgSize);

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	struct timeval diff, startTV, endTV;

	rpc->run_event_loop(1000);
	gettimeofday(&startTV, NULL);
	int i = 0;
	for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
		for (auto it = args->begin; it != args->end; ++it) {
			context->rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
			size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
#if INTEGRITY
			message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
#endif
			struct req_tuple *tag_ptr = new req_tuple();
			tag_ptr->req_id = i;
			tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			AppContext::header hdr;
			hdr.sender_node = context->node_id;
			if (it->op == ycsb::Trace_cmd::Put) {
#if KV
				// auto v = context->store->put(it->key_size, it->key_hash);
				auto v = context->store->put(it->key_size, it->key_hash, payload.get(), kMsgSize);
#endif
				hdr.receiver_node = kMiddleNodeId1;
				hdr.req_type = kReqPUT;
#if KV
				hdr.key_version = v;
#endif
			} else {
				hdr.receiver_node = kTailNodeId;
				hdr.req_type = kReqGET;
			}
			::memcpy(payload.get(), &hdr, sizeof(hdr));
			::memcpy(payload.get() + sizeof(hdr), it->key_hash, it->key_size);
			while (tag_ptr->req_buf.buf == nullptr) {
				// no space left
				rpc->run_event_loop_once();
				tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}
			tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			while (tag_ptr->resp_buf.buf == nullptr) {
				// no space left
				rpc->run_event_loop_once();
				tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}

			rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
			rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);

#if INTEGRITY
			char metadata[kMetaSize];
			::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
			auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
			::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), kMsgSize);
#else
#if GMAC
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), kMsgSize);

#else
			// encrypt
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
#endif
#endif
			if (it->op == ycsb::Trace_cmd::Put) {

				rpc->enqueue_request(context->next_node_session_num, kReqPUT,
						&tag_ptr->req_buf, &tag_ptr->resp_buf, cont_func,
						(void *)tag_ptr);
				args->writes++;
			} else {
				rpc->enqueue_request(context->cluster_info[kTailNodeId], kReqGET,
						&tag_ptr->req_buf, &tag_ptr->resp_buf,
						cont_func_get, (void *)tag_ptr);
				args->reads++;
			}
			i++;
			// fmt::print("[{}]\tRID\t=\t{}\treq\t=\t{}\r", __func__, context->RID,
			// tag_ptr->req_id);
			rpc->run_event_loop_once();
			if (i % 50000 == 0) {
				fmt::print("[{}] {}\n", __func__, i);
				for (int k = 0; k < 10; k++)
					rpc->run_event_loop_once();
			}

#if 0
			for (int k = 0; k < 10; k++)
				rpc->run_event_loop_once();
			i++;
#endif
		}
	}

	fmt::print("[CR::HEAD] {} (RID={}): waiting for replies nb_reqs={} {}\n",
			__func__, context->RID, nb_reqs, i);
	while (context->completed_reqs < nb_reqs) {
		rpc->run_event_loop_once();
#if 0
		fmt::print("[CR::HEAD] {}/(RID={}): waiting for replies for completed_reqs={}\n",
				__func__, context->RID, context->completed_reqs);
#endif
	}
	fmt::print("[{}] RID={} completed_reqs={}\n", __func__, context->RID,
			context->completed_reqs);

	gettimeofday(&endTV, NULL);

	printf("\n \n \n[CR::HEAD] %s all reqs (%d, R=%d, W=%d) acknowledged\n",
			__PRETTY_FUNCTION__, context->completed_reqs, args->reads,
			args->writes);
	printf("**time taken = %ld %ld\n", (endTV.tv_sec - startTV.tv_sec),
			(endTV.tv_usec - startTV.tv_usec));
}

static void generate_workload_tail(AppContext *context, thread_args *args) {
	std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
	::memset(payload.get(), '1', kMsgSize);

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	struct timeval diff, startTV, endTV;

	while (!context->start_the_fucking_workload)
		rpc->run_event_loop_once();

	fmt::print("[{}] RID={} starts the workload\n", __func__, context->RID);
	gettimeofday(&startTV, NULL);

	int i = 0;
	for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
		for (auto it = args->begin; it != args->end; ++it) {
			size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
#if INTEGRITY
			message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
#endif
			if (it->op == ycsb::Trace_cmd::Put) {
				context->rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
				struct req_tuple *tag_ptr = new req_tuple();
				tag_ptr->req_id = i;
				tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
				while (tag_ptr->req_buf.buf == nullptr) {
					// no space left
					rpc->run_event_loop_once();
					tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
					printf("[CR::TAIL] %s: no space ", __func__);
				}
				tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
				while (tag_ptr->resp_buf.buf == nullptr) {
					// no space left
					rpc->run_event_loop_once();
					tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
					printf("[CR::TAIL] %s: no space ", __func__);
				}
				AppContext::header hdr;
				hdr.sender_node = context->node_id;
				hdr.receiver_node = kHeadNodeId;
				hdr.req_type = kReqPUT;
				::memcpy(payload.get(), &hdr, sizeof(hdr));
				::memcpy(payload.get() + sizeof(hdr), it->key_hash, it->key_size);

				rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
				rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);

#if INTEGRITY
				char metadata[kMetaSize];
				::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
				auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), kMsgSize);
				::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
				::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), kMsgSize);
#else
#if GMAC
				cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
				::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), kMsgSize);

#else
				// encrypt
				cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
#endif
#endif

				auto session_num = context->cluster_info[kHeadNodeId];

				rpc->enqueue_request(session_num, kReqPUT, &tag_ptr->req_buf,
						&tag_ptr->resp_buf, cont_func, (void *)tag_ptr);
				args->writes++;
				rpc->run_event_loop_once();
				i++;
			} else {
				context->completed_reqs++;
				context->store->get(it->key_size, it->key_hash);
				args->reads++;
				if (args->reads % 10000 == 0) {
					rpc->run_event_loop_once();
				}
			}
			if (kReadPerMille > 900)
				rpc->run_event_loop_once();
		}
	}
	fmt::print("[CR::TAIL] {}: waiting for replies nb_reqs={}\n", __func__,
			nb_reqs);

	// while (context->completed_reqs < nb_reqs) {
	while (context->completed_reqs < nb_reqs) {
		rpc->run_event_loop_once();
	}
	while (context->terminated_nodes.find(kHeadNodeId) ==
			context->terminated_nodes.end()) {
		rpc->run_event_loop_once();
	}

	gettimeofday(&endTV, NULL);

	printf("\n \n \n[CR::TAIL] %s all reqs (%d, R=%d, W=%d) acknowledged\n",
			__PRETTY_FUNCTION__, context->completed_reqs, args->reads,
			args->writes);
	printf("**time taken = %ld %ld\n", (endTV.tv_sec - startTV.tv_sec),
			(endTV.tv_usec - startTV.tv_usec));
}
