#include "allconcur_func.h"

void allconcur_thread_func(void *ptr_nexus, std::unique_ptr<int> tid,
		thread_args *args,
		std::shared_ptr<state> ptr_state, int cur_node_id,
		avocado::KV_store *store) {

	erpc::Nexus *nexus = reinterpret_cast<erpc::Nexus *>(ptr_nexus);
	AppContext *context = new AppContext();
	context->rid = *(tid.get());
	context->node_id = cur_node_id;
	context->ptr_state = ptr_state;
	context->store = store;

	context->rpc = new erpc::Rpc<erpc::CTransport>(
			nexus, static_cast<void *>(context), context->rid, sm_handler);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
	rpc->retry_connect_on_invalid_rpc_id = true;

	for (auto& item : cluster_config) {
		if (item.first != cur_node_id) 
		{
			const std::string& uri = item.second + ":" + std::to_string(kUDPPort);
			int session_num = rpc->create_session(uri, context->rid);
			while (!rpc->is_connected(session_num)) {
				rpc->run_event_loop_once();
			}
			fmt::print("[{}] connected to uri={} w/ remote RPC_id={} session_num={}\n",
					__func__, uri, context->rid, session_num);
			context->cluster_info.insert({item.first, session_num});
		}

	}
	// while (cur_node_id != 0)
	// rpc->run_event_loop(2000);

	generate_workload(context, args);

	fmt::print(
			"[{}] (node_id={}, thread_id={}) finishes successfully ..\n",
			__func__, context->node_id, context->rid);

	rpc->run_event_loop(10000);
	delete rpc;
	delete context;
}

