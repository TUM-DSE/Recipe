#include "chain_rep.h"
#include "cipher.h"
#include "concurrent_skiplist/memtable.h"
#include "rate_limiter.h"
#include "stats.h"
#include "workload_generator.h"
#include <memory>

static void sent_termination_req(AppContext *context) {
	std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
	::memset(payload.get(), '0', kMsgSize);

	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	for (auto &i : context->cluster_info) {
		if (i.first != context->node_id) {
			fmt::print("[{}] context->RID={} to i.first={}\n", __func__, context->RID,
					i.first);
			// context->rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
			auto message_sz = PacketSsl::get_buffer_size(kMsgSize);
#if SHA256_DIGEST
#warning "SHA256_DIGEST is ON, INTEGRITY FLAG SHOULD BE OFF"
			message_sz = PacketSsl::get_buffer_size(kMetaSize + kSHA256_SZ) + kMsgSize;
#endif
#if INTEGRITY
			message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
#endif

			struct req_tuple *tag_ptr = new req_tuple();
			tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			while (tag_ptr->req_buf.buf == nullptr) {
				// no space left
				fmt::print("[{}] no space left\n");
				rpc->run_event_loop_once();
				tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}
			tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			while (tag_ptr->resp_buf.buf == nullptr) {
				fmt::print("[{}] no space left\n");
				// no space left
				rpc->run_event_loop_once();
				tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
			}

			rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
			rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);

			::memcpy(payload.get(), &(context->node_id), sizeof(int));
#if INTEGRITY
#warning "INTEGRITY is ON"
			char metadata[kMetaSize];
			::memcpy(metadata, &(context->node_id), kMetaSize);
			auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
			::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), kMsgSize);
#elif SHA256
#warning "SHA256_DIGEST is ON, INTEGRITY FLAG SHOULD BE OFF"
#else
#if GMAC
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
			::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), kMsgSize);
#else
			cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
#endif
#endif
			rpc->enqueue_request(i.second, kReqTerminate, &(tag_ptr->req_buf),
					&(tag_ptr->resp_buf), cont_func_fw, (void *)tag_ptr);
			rpc->run_event_loop(1000);
		}
	}
}

void CR_thread_func(void *ptr_nexus, std::unique_ptr<int> ptr_id,
		int cur_node_id, std::string next_connection,
		std::string head_connection, std::string tail_connection,
		thread_args *args, avocado::KV_store *store) {

	erpc::Nexus *nexus = reinterpret_cast<erpc::Nexus *>(ptr_nexus);
	AppContext *context = new AppContext(rate);
	context->RID = *(ptr_id);
	context->node_id = cur_node_id;
	context->store = store;
	context->node_operation =
		(context->node_id == 0)
		? CR::HEAD
		: ((context->node_id == (kClusterSize - 1)) ? CR::TAIL : CR::MIDDLE);
	context->rpc = new erpc::Rpc<erpc::CTransport>(
			nexus, static_cast<void *>(context), context->RID, sm_handler);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	rpc->retry_connect_on_invalid_rpc_id = true;

	switch (context->node_operation) {
		case CR::HEAD: {
				       context->next_node_id = kMiddleNodeId1;
				       context->tail_node_id = kTailNodeId;

				       {
					       std::string uri = tail_connection + ":" + std::to_string(kUDPPort);
					       int session_num = rpc->create_session(uri, context->RID);
					       while (!rpc->is_connected(session_num)) {
						       fmt::print("[{}] trying to connect to {}\n", __func__, uri);
						       rpc->run_event_loop(100);
					       }
					       std::cout << "[CR:HEAD] connected to " << uri
						       << " w/ remote RPC id: " << context->RID << " (TAIL)\n";
					       context->cluster_info.insert(std::make_pair(kTailNodeId, session_num));
				       }

				       {
					       std::string uri = next_connection + ":" + std::to_string(kUDPPort);
					       int session_num = rpc->create_session(uri, context->RID);
					       while (!rpc->is_connected(session_num)) {
						       fmt::print("[{}] trying to connect to {}\n", __func__, uri);
						       rpc->run_event_loop(100);
					       }
					       std::cout << "[CR:HEAD] connected to " << uri
						       << " w/ remote RPC id: " << context->RID << "\n";
					       context->next_node_session_num = session_num;
					       context->cluster_info.insert(
							       std::make_pair(kMiddleNodeId1, context->next_node_session_num));
				       }

				       rpc->run_event_loop(1000);

				       // generate workload
				       generate_workload_head(context, args);

			       } break;
		case CR::TAIL: {
				       context->head_node_id = kHeadNodeId;
				       context->middle_node_id = kMiddleNodeId1;

				       {
					       std::string uri = next_connection + ":" + std::to_string(kUDPPort);
					       int session_num = rpc->create_session(uri, context->RID);
					       while (!rpc->is_connected(session_num))
						       rpc->run_event_loop_once();
					       std::cout << "[CR::TAIL] connected to " << uri
						       << " w/ remote RPC id: " << context->RID
						       << " MIDDLE (session_num=" << session_num << ")\n";
					       context->next_node_session_num = session_num;
					       context->cluster_info.insert(std::make_pair(kMiddleNodeId1, session_num));
				       }

				       {
					       std::string uri = head_connection + ":" + std::to_string(kUDPPort);
					       int session_num = rpc->create_session(uri, context->RID);
					       while (!rpc->is_connected(session_num))
						       rpc->run_event_loop_once();
					       std::cout << "[CR:TAIL] connected to " << uri
						       << " w/ remote RPC id: " << context->RID
						       << " HEAD (session_num=" << session_num << ")\n";
					       context->cluster_info.insert(std::make_pair(kHeadNodeId, session_num));
				       }

				       generate_workload_tail(context, args);

			       } break;
		case CR::MIDDLE: {

					 {
						 std::string uri = next_connection + ":" + std::to_string(kUDPPort);
						 int session_num = rpc->create_session(uri, context->RID);
						 while (!rpc->is_connected(session_num)) {
							 rpc->run_event_loop_once();
						 }
						 std::cout << "[CR::MIDDLE] connected to " << uri
							 << " w/ remote RPC id: " << context->RID << " (TAIL)\n";
						 context->cluster_info.insert(std::make_pair(kTailNodeId, session_num));

						 if (next_connection != tail_connection) {
							 std::cout << "[CR::MIDDLE] needs to connect w/ CR::TAIL\n";
						 }
					 }

					 {
						 std::string uri = head_connection + ":" + std::to_string(kUDPPort);
						 int session_num = rpc->create_session(uri, context->RID);
						 while (!rpc->is_connected(session_num))
							 rpc->run_event_loop_once();
						 std::cout << "[CR:MIDDLE] connected to " << uri
							 << " w/ remote RPC id: " << context->RID << " (HEAD)\n";
						 context->cluster_info.insert(std::make_pair(kHeadNodeId, session_num));
					 }

					 generate_workload_middle(context, args);

				 } break;
		default:
				 std::cerr << __PRETTY_FUNCTION__
					 << " node's operation is not one of HEAD,TAIL or MIDDLE\n";
				 exit(128);
	}

	sent_termination_req(context);
	while (context->terminated_nodes.size() != (kClusterSize - 1)) {
		rpc->run_event_loop_once();
	}
	fmt::print("[{}] waiting a bit and exiting afterwards ..\n", __func__);

	rpc->run_event_loop(1000);

	for (auto &elem : context->reqs_per_node)
		fmt::print("[{}] node_id={} reqs={} \n", __func__, elem.first, elem.second);
	fmt::print("[{}] deleting context ..\n", __func__);
	delete rpc;
	delete context;
	return;
}
