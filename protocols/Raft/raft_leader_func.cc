#include "../ycsb_generator/workload_generator.h"
#include "concurrent_skiplist/memtable.h"
#include "context.h"
#include "context_batched.h"
#include "raft_thread_func.h"
#include "workload_generator_batching.h"
#include "workload_generator.h"
#include <fmt/printf.h>

void raft_leader_thread_func(void *ptr_nexus, std::unique_ptr<int> tid,
                             thread_args *args, std::atomic<int> &sequencer,
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

  {
    std::string uri = follower_address_1 + ":" + std::to_string(kUDPPort);
    int session_num = rpc->create_session(uri, context->RID);
    while (!rpc->is_connected(session_num)) {
      rpc->run_event_loop_once();
    }
    fmt::print("[{}] connected to uri={} w/ remote RPC_id={} session_num={}\n",
               __func__, uri, context->RID, session_num);
    context->follower_session_nums.insert({1, session_num});
  }

  {
    std::string uri = follower_address_2 + ":" + std::to_string(kUDPPort);
    int session_num = rpc->create_session(uri, context->RID);
    while (!rpc->is_connected(session_num)) {
      rpc->run_event_loop_once();
    }
    fmt::print("[{}] connected to uri={} w/ remote RPC_id={} session_num={}\n",
               __func__, uri, context->RID, session_num);
    context->follower_session_nums.insert({2, session_num});
  }

  // rpc->run_event_loop(1000);
#if NO_BATCHING
  generate_workload_leader(context, args, sequencer);
#else
  generate_workload_leader_batching(context, args, sequencer);
#endif
  /*
  while(true)
  rpc->run_event_loop_once();
  */
  fmt::print(
      "[{}] leader (node_id={}, thread_id={}) finishes successfully ..\n",
      __func__, context->node_id, context->RID);
  sent_termination_req(context);
  rpc->run_event_loop(10000);
  delete rpc;
  delete context;
}

void raft_leader_worker(void *ptr_nexus, std::unique_ptr<int> tid,
                        std::atomic<int> &sequencer,
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

  {
    std::string uri = follower_address_1 + ":" + std::to_string(kUDPPort);
    int session_num = rpc->create_session(uri, context->RID);
    while (!rpc->is_connected(session_num))
      rpc->run_event_loop_once();
    fmt::print("[{}] connected to uri={} w/ remote RPC_id={}\n", __func__, uri,
               context->RID);
    context->follower_session_nums.insert({1, session_num});
  }

  {
    std::string uri = follower_address_2 + ":" + std::to_string(kUDPPort);
    int session_num = rpc->create_session(uri, context->RID);
    while (!rpc->is_connected(session_num))
      rpc->run_event_loop_once();
    fmt::print("[{}] connected to uri={} w/ remote RPC_id={}\n", __func__, uri,
               context->RID);
    context->follower_session_nums.insert({2, session_num});
  }
#if NO_BATCHING
  leader_worker_thread(context, sequencer);
#else
  leader_worker_thread_batching(context, sequencer);
#endif

  fmt::print(
      "[{}] leader (node_id={}, thread_id={}) finishes successfully ..\n",
      __func__, context->node_id, context->RID);
  sent_termination_req(context);
  rpc->run_event_loop(10000);
  delete rpc;
  delete context;
}
