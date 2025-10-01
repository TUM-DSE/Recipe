#include "../ycsb_generator/workload_generator.h"
#include "cipher.h"
#include "concurrent_skiplist/memtable.h"
#include "context.h"
#include "context_batched.h"
#include "raft_thread_func.h"
#include "util.h"
#include "workload_generator_batching.h"
#include "workload_generator.h"
#include <chrono>
#include <fmt/printf.h>

void raft_follower_thread_func(void *ptr_nexus, std::unique_ptr<int> tid,
                               thread_args *args,
                               std::shared_ptr<state> ptr_state,
                               int cur_node_id, avocado::KV_store *store) {

  erpc::Nexus *nexus = reinterpret_cast<erpc::Nexus *>(ptr_nexus);
  AppContext *context = new AppContext();
  context->RID = *(tid.get());
  context->node_id = cur_node_id;
  context->ptr_state = ptr_state;
  context->store = store;

  context->rpc = new erpc::Rpc<erpc::CTransport>(
      nexus, static_cast<void *>(context), context->RID, sm_handler);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  rpc->retry_connect_on_invalid_rpc_id = true;

  std::string uri = leader_address + ":" + std::to_string(kUDPPort);
  int session_num = rpc->create_session(uri, context->RID);
  while (!rpc->is_connected(session_num))
    rpc->run_event_loop_once();
  fmt::print("[{}] connected to uri={} w/ remote RPC_id={}\n", __func__, uri,
             context->RID);
  context->leader_session_num = session_num;

#if FOLLOWER_WORKLOAD
  generate_workload_follower(context, args);
#endif
  while (true && !context->terminate.load()) {
    rpc->run_event_loop_once();
  }

  fmt::print("[{}] will terminate\n", __func__);
  int reqs = context->ptr_state->uncommitted_reqs.size();
  fmt::print("[{}] follower queued_reqs={}, cmt_idx={}\n", __func__, reqs,
             context->ptr_state->commit_index.load());

  rpc->run_event_loop(1000);
  delete rpc;
  delete context;
}

void raft_follower_worker(void *ptr_nexus, std::unique_ptr<int> tid,
                          std::shared_ptr<state> ptr_state, int cur_node_id,
                          avocado::KV_store *store) {

  erpc::Nexus *nexus = reinterpret_cast<erpc::Nexus *>(ptr_nexus);
  AppContext *context = new AppContext();
  context->RID = *(tid.get());
  context->node_id = cur_node_id;
  context->ptr_state = ptr_state;
  context->store = store;

  context->rpc = new erpc::Rpc<erpc::CTransport>(
      nexus, static_cast<void *>(context), context->RID, sm_handler);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  rpc->retry_connect_on_invalid_rpc_id = true;

  std::string uri = leader_address + ":" + std::to_string(kUDPPort);
  int session_num = rpc->create_session(uri, context->RID);
  while (!rpc->is_connected(session_num))
    rpc->run_event_loop_once();
  fmt::print("[{}] connected to uri={} w/ remote RPC_id={}\n", __func__, uri,
             context->RID);
  context->leader_session_num = session_num;

  // follower_worker_thread(context);
  auto static o = 0;
  while (true && !context->terminate.load()) {
    rpc->run_event_loop_once();
#if 0
    o++;
     if (o%1000000 == 0)
       print_uncommitted_reqs(context->ptr_state->uncommitted_reqs, context);
#endif
  }

  int reqs = context->ptr_state->uncommitted_reqs.size();
  fmt::print("[{}] follower worker thread queued_reqs={}, cmt_idx={}\n",
             __func__, reqs, context->ptr_state->commit_index.load());

  for (auto &r : context->ptr_state->uncommitted_reqs) {
    fmt::print("[{}] reqs.i={}\n",
               __func__, r.first);
	}

  rpc->run_event_loop(1000);
  delete rpc;
  delete context;
}
