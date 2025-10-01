#pragma once
#include "cipher.h"
#include "common_conf.h"
#include "concurrent_skiplist/memtable.h"
#include "rate_limiter.h"
#include "state.h"
#include "ycsb_generator/generate_traces.h"
#include <atomic>
#include <memory>
#include <unordered_map>

#if NO_BATCHING
// forward declaration
static void cont_func(void *ctx, void *tag);
static void cont_func_cmt(void *ctx, void *tag);
static void cont_func_default(void *ctx, void *tag);

class AppContext {
public:
  struct header {
    int node_id;
    int op_id;
    int latest_cmt = -1;
  };

public:
  AppContext() {
    completed_reqs = 0;
    start_the_workload = false;
    terminate.store(false);
    writes.insert(std::make_pair(1, 0));
    writes.insert(std::make_pair(2, 0));
  };
  ~AppContext() = default;

  // erpc object owned by this thread
  void *rpc;

  int node_operation;
  using NodeId = int;
  using SessionNum = int;
  std::unordered_map<NodeId, SessionNum> cluster_info;
  std::map<int, int> writes;

  int node_id;
  int leader_session_num;
  std::unordered_map<int, int> follower_session_nums;
  int RID;
  int completed_reqs;

  std::shared_ptr<state> ptr_state;

  avocado::KV_store *store = nullptr;
  std::atomic<bool> terminate;
  bool start_the_workload;

private:
  //
};

struct req_tuple_batched {
  int dest_session_nb;
  uint8_t key_hash[ycsb::Trace_cmd::key_size];
};

struct req_tuple {
  erpc::MsgBuffer req_buf;
  erpc::MsgBuffer resp_buf;
  int req_id;
  int dest_session_nb;
};

static [[nodiscard]] std::unique_ptr<uint8_t[]> _decode_req(char *data,
                                                            size_t data_sz) {
  size_t dec_size = PacketSsl::get_message_size(data_sz);
  std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size);

  bool [[maybe_unused]] ok = cipher->decrypt(ptr.get(), data, data_sz);
  return std::move(ptr);
}

static void sent_commit_idx_req(AppContext *context,
                                AppContext::header const &hdr) {

  static int o = 0;
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  AppContext::header h;

  h.node_id = context->node_id;
  h.op_id = context->ptr_state->leader_commit_index.load();
  auto follower_cmt_idx = -1;
  size_t message_sz =
      PacketSsl::get_buffer_size(sizeof(h) + sizeof(follower_cmt_idx));
    #if INTEGRITY
        message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(h) + sizeof(follower_cmt_idx);
  #endif

  // fmt::print("[{}] cmt_idx={}\n", __func__, h.op_id);
  for (auto &k : context->follower_session_nums) {
#if FOLLOWER_WORKLOAD
    o++;
    follower_cmt_idx = context->ptr_state->follower_cmt_idx[k.first];
    if (o % 25000 == 0)
      fmt::print("[{}] cmt_idx={}/lcmt={}\n", __func__, follower_cmt_idx,
                 h.op_id);
#endif
    struct req_tuple *tag_ptr = new req_tuple();
    tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
    while (tag_ptr->req_buf.buf == nullptr) {
      // no space left
      fmt::print("[{}] no space left\n", __func__);
      rpc->run_event_loop_once();
      tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
    }
    tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
    while (tag_ptr->resp_buf.buf == nullptr) {
      // no space left
      fmt::print("[{}] no space left\n", __func__);
      rpc->run_event_loop_once();
      tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(message_sz);
    }

    rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
    rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);

    // encrypt
    auto data =
        std::make_unique<uint8_t[]>(sizeof(h) + sizeof(follower_cmt_idx));
    ::memcpy(data.get(), &h, sizeof(h));
    ::memcpy(data.get() + sizeof(h), &follower_cmt_idx,
             sizeof(follower_cmt_idx));
  #if INTEGRITY
        char metadata[kMetaSize];
        ::memcpy(metadata, &h.op_id, kMetaSize);
        auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), (sizeof(h) + sizeof(follower_cmt_idx)));
        ::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
        ::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), data.get(), (sizeof(h) + sizeof(follower_cmt_idx)));
  #else
#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(tag_ptr->req_buf.buf, data.get(), sizeof(follower_cmt_idx) + sizeof(h));
                 ::memcpy(tag->req_buf.buf+PacketSsl::IvSize, data.get(), sizeof(follower_cmt_idx) + sizeof(h));
 #else

    cipher->encrypt(tag_ptr->req_buf.buf, data.get(),
                    sizeof(h) + sizeof(follower_cmt_idx));
#endif
#endif

    rpc->enqueue_request(k.second, kReqUpdateCommitIndex, &tag_ptr->req_buf,
                         &tag_ptr->resp_buf, cont_func_cmt, (void *)tag_ptr);
  }
}

static void print_uncommitted_reqs(std::unordered_map<int, request *> &reqs,
                                   AppContext *context) {
  fmt::print("[{}] uncommitted_reqs={}\n", __func__, reqs.size());
  for (auto &r : reqs) {
    fmt::print("[{}] reqs.i={}/leader_cmt={}/follower_cmt={} "
               "req_owner={}/acked by {} followers",
               __func__, r.first,
               context->ptr_state->leader_commit_index.load(),
               context->ptr_state->commit_index.load(), r.second->req_owner,
               r.second->recv_acks.size());
    for (auto &f : r.second->recv_acks)
      fmt::print("\t{}", f);
    fmt::print("\n");
  }
}

static void sent_new_commit_index(AppContext *context,
                                  AppContext::header const &hdr) {

  int idx = context->ptr_state->leader_commit_index.load() + 1;

  if (context->ptr_state->uncommitted_reqs.size() == 0)
    return;
  // FIXME: we can fix that
  if (context->ptr_state->uncommitted_reqs.find(idx) ==
      context->ptr_state->uncommitted_reqs.end()) {
    print_uncommitted_reqs(context->ptr_state->uncommitted_reqs, context);
  }

#if 0
  if ((context->ptr_state->uncommitted_reqs[hdr.op_id]->recv_acks.size() >=
        state::nb_followers) || (context->ptr_state->uncommitted_reqs[idx]->recv_acks.size() >= state::nb_followers))
#endif
  if ((context->ptr_state->uncommitted_reqs[idx]->recv_acks.size() >=
       state::nb_followers)) {
    auto &queued_reqs = context->ptr_state->uncommitted_reqs;
    auto flag = false;
    for (auto i = (idx); i <= hdr.op_id; i++) {
      auto &req = queued_reqs[i];
      if (req == nullptr) {
        fmt::print("[{}] nullptr for i={}\n", __func__, i);
        break;
      }
      if (req->recv_acks.size() >= state::nb_followers) {

        context->store->put(ycsb::Trace_cmd::key_size, req->key);
        // increase leader_commit_idx
        context->ptr_state->leader_commit_index.fetch_add(1);
        rate.release(1);
        flag = true;
#if FOLLOWER_WORKLOAD || RATELIMITER
        if (req->req_owner != 0) {
          context->ptr_state->follower_cmt_idx[req->req_owner]++;
        }
#if 0
        else 
          rate.release(1);
#endif
#endif
      } else {
        break;
      }
    }

    // enqueue to commit req
    if (flag)
      sent_commit_idx_req(context, hdr);

    // clean up
    int end_idx = context->ptr_state->leader_commit_index.load();
    while (idx <= end_idx) {
      // fmt::print("[{}] cleaning up from idx={} to end_idx={}\n", __func__,
      // idx, end_idx);
      delete queued_reqs[idx];
      queued_reqs.erase(idx);
      idx++;
    }
  }
}

static void sent_new_commit_index_if_any(AppContext *context) {

  int idx = context->ptr_state->leader_commit_index.load() + 1;
  auto flag = false;

  // FIXME: we can fix that
  // print_uncommitted_reqs(context->ptr_state->uncommitted_reqs, context);
  if (idx <= context->ptr_state->biggest_id) {
    auto search = context->ptr_state->uncommitted_reqs.find(idx);
    if (search != context->ptr_state->uncommitted_reqs.end()) {
      if ((context->ptr_state->uncommitted_reqs[idx]->recv_acks.size() >=
           state::nb_followers)) {
        auto &queued_reqs = context->ptr_state->uncommitted_reqs;
        auto &req = queued_reqs[idx];
        if (req == nullptr) {
          fmt::print("[{}] nullptr for i={}\n", __func__, idx);
          return;
        }
        if (req->recv_acks.size() >= state::nb_followers) {
          context->store->put(ycsb::Trace_cmd::key_size, req->key);
          // increase leader_commit_idx
          context->ptr_state->leader_commit_index.fetch_add(1);
          rate.release(1);
          flag = true;
#if FOLLOWER_WORKLOAD || RATELIMITER
          if (req->req_owner != 0) {
            context->ptr_state->follower_cmt_idx[req->req_owner]++;
            // fmt::print("[{}] follower_cmt_idx={}/req_owner={}\n", __func__,
            // context->ptr_state->follower_cmt_idx[req->req_owner],
            // req->req_owner);
          }
#if 0
          else
            rate.release(1);
#endif
#endif
        } else {
          return;
        }
      }
    }

    // enqueue to commit req
    if (flag) {
      AppContext::header hdr;
      sent_commit_idx_req(context, hdr);
      auto &queued_reqs = context->ptr_state->uncommitted_reqs;

      // clean up
      int end_idx = context->ptr_state->leader_commit_index.load();
      while (idx <= end_idx) {
        // fmt::print("[{}] cleaning up from idx={} to end_idx={}\n", __func__,
        // idx, end_idx);
        delete queued_reqs[idx];
        queued_reqs.erase(idx);
        idx++;
      }
    }
  }
}

static void cont_func(void *ctx, void *tag) {
  //	fmt::print("[{}] \n", __func__);
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);

  auto data = reinterpret_cast<char *>(tag_ptr->resp_buf.buf);
  auto data_sz = tag_ptr->resp_buf.get_data_size();
  auto received_data = _decode_req(data, data_sz);
  AppContext::header hdr;
  ::memcpy(&hdr, received_data.get(), sizeof(hdr));

  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;

  static int o = 0;
  o++;
  if (o % 25000 == 0) {
    fmt::print("[{}] received acks for op_id={} from node_id={}\n", __func__,
               hdr.op_id, hdr.node_id);
  }

  auto search = context->ptr_state->uncommitted_reqs.find(hdr.op_id);
  if (search != context->ptr_state->uncommitted_reqs.end()) {
    auto ret =
        context->ptr_state->uncommitted_reqs[hdr.op_id]->recv_acks.insert(
            hdr.node_id);
    if (!ret.second) {
      fmt::print("[{}] ... double insertion here for node_id={}\n", __func__,
                 hdr.node_id);
      exit(1);
    }
  }
  search = context->ptr_state->uncommitted_reqs.find(hdr.latest_cmt);
  if (search != context->ptr_state->uncommitted_reqs.end()) {
    context->ptr_state->uncommitted_reqs[hdr.latest_cmt]->recv_acks.insert(
        hdr.node_id);
  }

  sent_new_commit_index(context, hdr);
  // fmt::print("[{}] latest committed_entry={}\n", __func__,
  // context->ptr_state->leader_commit_index.load());
}

static void cont_func_default(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);

  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;
}

/**
 * @dimitra: this is executed from the leader thread (specifically the worker
 * thread)
 */
static void cont_func_cmt(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);

  auto data = reinterpret_cast<char *>(tag_ptr->resp_buf.buf);
  auto data_sz = tag_ptr->resp_buf.get_data_size();
  auto ack = _decode_req(data, data_sz);
  AppContext::header hdr;
  ::memcpy(&hdr, ack.get(), sizeof(hdr));
  if ((hdr.node_id != 1) && (hdr.node_id != 2)) {
    fmt::print("[{}] hdr.node_id={}\n", __func__, hdr.node_id);
  }
  context->ptr_state->commit_acks[hdr.node_id]->fetch_add(1);
  if (context->ptr_state->commit_acks[hdr.node_id]->load() % 25000 == 0)
    fmt::print("[{}] commit_acks for hdr.node_id={}/RID={} is {}\n", __func__,
               hdr.node_id, context->RID,
               context->ptr_state->commit_acks[hdr.node_id]->load());

  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;
}

/*
 * @dimitra: this is executed from the follower threads
 * get() reqs do not pass through the worker-thread
 */
static void cont_func_fw_get(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);

  auto data = reinterpret_cast<char *>(tag_ptr->resp_buf.buf);
  auto data_sz = tag_ptr->resp_buf.get_data_size();
  auto ack = _decode_req(data, data_sz);

  context->ptr_state->commit_acks[0]->fetch_add(1);

  rate.release(1);

  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);
  delete tag_ptr;
}

// executed from the follower
static void cont_func_fw_put(void *ctx, void *tag) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  struct req_tuple *tag_ptr = reinterpret_cast<struct req_tuple *>(tag);

  auto data = reinterpret_cast<char *>(tag_ptr->resp_buf.buf);
  auto data_sz = tag_ptr->resp_buf.get_data_size();
  auto ack = _decode_req(data, data_sz);

  rpc->free_msg_buffer(tag_ptr->req_buf);
  rpc->free_msg_buffer(tag_ptr->resp_buf);

  delete tag_ptr;
}
#endif
