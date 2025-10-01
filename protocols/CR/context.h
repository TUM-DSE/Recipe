#pragma once
#include "common_conf.h"
#include "concurrent_skiplist/memtable.h"
#include "rate_limiter.h"
#include "stats.h"
#include "ycsb_generator/generate_traces.h"
#include <atomic>
#include <memory>
#include <unordered_map>

class CR {
public:
  enum { HEAD = 0, MIDDLE, TAIL };
};

class AppContext {

public:
  AppContext(struct RateLimit &rate) : rate(rate) {
    reqs_per_node.insert(std::make_pair(kHeadNodeId, 0));
    reqs_per_node.insert(std::make_pair(kMiddleNodeId1, 0));
    reqs_per_node.insert(std::make_pair(kTailNodeId, 0));
    completed_reqs = 0;
  }
  ~AppContext() = default;

  // erpc object owned by this thread
  void *rpc;

  int node_operation;
  using cluster_node_id = int;
  using session_num = int;
  std::unordered_map<cluster_node_id, session_num> cluster_info;
  std::unordered_map<cluster_node_id, int> reqs_per_node;
  std::vector<int> seen_reqs_nb;
  struct header {
    int sender_node;
    int receiver_node;
    int req_type;
    int rid;
    int key_version;
  };

  struct Req {
    int node_id;
    int req_type;
    uint8_t hkey[ycsb::Trace_cmd::key_size];
  };
  std::vector<Req> fw_reqs;

  int node_id, next_node_id, tail_node_id, head_node_id, middle_node_id;
  int next_node_session_num;
  int RID;
  int completed_reqs;
  avocado::KV_store *store = nullptr;

  std::map<int, int> terminated_nodes;
  bool start_the_fucking_workload = false;
  struct RateLimit &rate;

private:
  //
};

struct req_tuple {
  erpc::MsgBuffer req_buf;
  erpc::MsgBuffer resp_buf;
  int req_id = -1;
};

static std::string print_node_operation(int node_operation) {
  switch (node_operation) {
  case CR::HEAD:
    return "[CR::HEAD]";
    break;
  case CR::MIDDLE:
    return "[CR::MIDDLE]";
    break;
  case CR::TAIL:
    return "[CR::TAIL]";
    break;
  }
  return "nullptr";
}

static void cont_func(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);
  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;
}

static void cont_func_fw(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);
  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;
}

static void cont_func_get(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);
  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);
  context->completed_reqs++;
  context->rate.release(1);

  delete tag_ptr;
}
