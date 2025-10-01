#include "req_handlers.h"
#include "cipher.h"
#include "common_conf.h"
#include "context.h"
#include "generate_traces.h"
#include "rate_limiter.h"
#include "util.h"
#include <algorithm>
#include <fmt/os.h>
#include <fmt/printf.h>

#if NO_BATCHING
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
  int cur_commit_index = 1;
  cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
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
  auto received_data = decode_req(enc_data, enc_size);

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
  int cur_commit_index = 1;
  cipher->encrypt(resp_buf.buf, &cur_commit_index, sizeof(int));
  rpc->resize_msg_buffer(&resp_buf, message_sz);
  rpc->enqueue_response(req_handle, &resp_buf);

  // context->writes[hdr.node_id] = follower_writes;
}

static std::unique_ptr<uint8_t[]> decode_req(char *data, size_t data_sz) {
  size_t dec_size = PacketSsl::get_message_size(data_sz);
  std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size);

  bool [[maybe_unused]] ok = cipher->decrypt(ptr.get(), data, data_sz);
  return std::move(ptr);
}

static AppContext::header
enqueue_received_req(AppContext *ctx, std::unique_ptr<uint8_t[]> data) {
#if 0
  assert(ctx->node_id !=
         0); /* leader should never execute this piece of code */
#endif
  AppContext::header hdr;
  ::memcpy(&hdr, data.get(), sizeof(hdr));
  uint8_t hkey[ycsb::Trace_cmd::key_size];
  ::memcpy(hkey, data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);
  auto new_req = new request();
  new_req->req_id = hdr.op_id;
  ::memcpy(&(new_req->key), hkey, ycsb::Trace_cmd::key_size);
  ctx->ptr_state->uncommitted_reqs.insert({hdr.op_id, new_req});
  return std::move(hdr);
}

static void enqueue_ack(erpc::ReqHandle *req_handle, AppContext *ctx,
                        AppContext::header hdr) {
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
  // ack that you got the RPC
  auto &resp_buf = req_handle->pre_resp_msgbuf;

  // encrypt response
  hdr.node_id = ctx->node_id;
  hdr.latest_cmt = ctx->ptr_state->commit_index.load();
  auto message_sz = PacketSsl::get_buffer_size(sizeof(AppContext::header));
  rpc->resize_msg_buffer(&resp_buf, message_sz);

  cipher->encrypt(resp_buf.buf, &hdr, sizeof(AppContext::header));
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
  rpc->resize_msg_buffer(&resp_buf, message_sz);
  cipher->encrypt(resp_buf.buf, data.get(), data_sz);
  rpc->enqueue_response(req_handle, &resp_buf);
}

// Executed by followers
void req_handler_appendEntries2(erpc::ReqHandle *req_handle, void *ctx) {

  AppContext *context = reinterpret_cast<AppContext *>(ctx);
  context->ptr_state->start_the_workload.store(true);

  char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
  size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
  auto received_data = decode_req(enc_data, enc_size);

  auto hdr = enqueue_received_req(context, std::move(received_data));

  // this is for printing
  static int o = 0;
  o++;
  if (o % 10000 == 0)
    fmt::print("[{}] req_id={} (nb of uncommitted_reqs={})\n", __func__,
               hdr.op_id, context->ptr_state->uncommitted_reqs.size());

  enqueue_ack(req_handle, context, std::move(hdr));
}

#if NO_BATCHING
static void apply_changes(int cmt_idx, AppContext *ctx) {
  auto &local_cmt_idx = ctx->ptr_state->commit_index;
  auto &queued_reqs = ctx->ptr_state->uncommitted_reqs;

  int local_idx = local_cmt_idx.load();
  for (auto k = local_cmt_idx.load(); k <= cmt_idx; k++) {
    auto &req = queued_reqs[k];
    ctx->store->put(ycsb::Trace_cmd::key_size, req->key);
    local_cmt_idx.fetch_add(1);

    delete queued_reqs[k];
    queued_reqs.erase(k);
  }

#if 0
  for (auto k = local_idx; k <= cmt_idx; k++) {
    delete queued_reqs[k];
    queued_reqs.erase(k);
  }
#endif
}
#else
static void apply_changes(int cmt_idx, AppContext *ctx) {
  auto &local_cmt_idx = ctx->ptr_state->commit_index;
  auto &queued_reqs = ctx->ptr_state->uncommitted_reqs;

  int local_idx = local_cmt_idx.load();
  for (auto k = local_cmt_idx.load(); k <= cmt_idx; k++) {
    auto &reqs = queued_reqs[k];
    for (auto req : reqs) {
      auto key = req->keys.back();

      ctx->store->put(ycsb::Trace_cmd::key_size, key);
      local_cmt_idx.fetch_add(1);
    }

    delete queued_reqs[k];
    queued_reqs.erase(k);
  }
}
#if 0
  for (auto k = local_idx; k <= cmt_idx; k++) {
    delete queued_reqs[k];
    queued_reqs.erase(k);
  }
#endif
}
#endif

static auto get_cmt_idx_and_apply(std::unique_ptr<uint8_t[]> data,
                                  AppContext *ctx) {
  AppContext::header hdr;
  ::memcpy(&hdr, data.get(), sizeof(hdr));

  int follower_ops = -1;
  ::memcpy(&follower_ops, data.get() + sizeof(hdr), sizeof(int));
  int leader_cmt_idx = hdr.op_id;

  apply_changes(leader_cmt_idx, ctx);

  static int o = 0;
  o++;
  if (o % 57500 == 0)
    fmt::print("[{}] committed op_id={}/{}\n", __func__, leader_cmt_idx,
               ctx->ptr_state->commit_index.load());

  return std::make_tuple(hdr, follower_ops);
}

void req_handler_commitIndex2(erpc::ReqHandle *req_handle, void *ctx) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
#if 0
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
#endif

  // decode new commit_index
  char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
  size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
  auto received_data = decode_req(enc_data, enc_size);

  auto [hdr, completed_ops] =
      get_cmt_idx_and_apply(std::move(received_data), context);

  if (context->ptr_state->completed_reqs.load() < completed_ops) {
    // fmt::print("[{}] follower_cmt_idx={}\n", __func__, completed_ops);
    context->ptr_state->completed_reqs.store(completed_ops);
    // rate.release(1);
  }

  enqueue_ack(req_handle, context, std::move(hdr));
}

void req_handler_forwardGet(erpc::ReqHandle *req_handle, void *ctx) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);

  char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
  size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
  auto received_data = decode_req(enc_data, enc_size);

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

static void execute_fw_put(AppContext *context, const uint8_t *key,
                           const int &dest_node) {
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  auto op_id = context->ptr_state->sequencer.fetch_add(1);

  std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
  ::memset(payload.get(), '0', kMsgSize);

  AppContext::header hdr;
  hdr.node_id = dest_node;
  hdr.op_id = op_id;

  for (auto &i : context->follower_session_nums) {
    ::memcpy(payload.get(), &hdr, sizeof(hdr));
    ::memcpy(payload.get() + sizeof(hdr), key, ycsb::Trace_cmd::key_size);
    size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
    struct req_tuple *tag_ptr = new req_tuple();
    tag_ptr->req_id = op_id;
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

    auto on_going_req = new request();
    on_going_req->req_id = op_id;
    on_going_req->req_owner = dest_node;
    ::memcpy(on_going_req->key, key, ycsb::Trace_cmd::key_size);
    context->ptr_state->uncommitted_reqs.insert({op_id, on_going_req});

    // encrypt
    cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
    rpc->enqueue_request(i.second, kReqAppendEntries, &(tag_ptr->req_buf),
                         &(tag_ptr->resp_buf), cont_func, (void *)tag_ptr);
  }
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

  std::vector<void *> v;
  v.reserve(2);

  for (auto &i : context->follower_session_nums) {
    ::memcpy(payload.get(), &hdr, sizeof(hdr));
    ::memcpy(payload.get() + sizeof(hdr), key, ycsb::Trace_cmd::key_size);
    size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
    struct req_tuple *tag_ptr = new req_tuple();
    tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
    tag_ptr->dest_session_nb = i.first;
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
    ::memcpy(tag_ptr->resp_buf.buf, payload.get(), kMsgSize);
    v.push_back(tag_ptr);

#if 0
    auto on_going_req = new request();
    on_going_req->req_id = op_id;
    on_going_req->req_owner = dest_node;
    ::memcpy(on_going_req->key, key, ycsb::Trace_cmd::key_size);
    context->ptr_state->uncommitted_reqs.insert({op_id, on_going_req});

    // encrypt
    cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
    rpc->enqueue_request(i.second, kReqAppendEntries, &(tag_ptr->req_buf),
                         &(tag_ptr->resp_buf), cont_func, (void *)tag_ptr);
#endif
  }

#if LF_QUEUE
  while (!context->ptr_state->concurrent_q->enqueue(v)) {
    fmt::print("[{}] .. full\n", __func__);
  }
#elif NO_BATCHING
  {
    std::lock_guard<std::mutex> l(context->ptr_state->mtx);
    context->ptr_state->concurrent_q->push_back(v);
  }
#endif
}

void req_handler_forwardPut(erpc::ReqHandle *req_handle, void *ctx) {
  AppContext *context = reinterpret_cast<AppContext *>(ctx);
#if 0
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
#endif

  char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
  size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
  auto received_data = decode_req(enc_data, enc_size);
  AppContext::header hdr;
  ::memcpy(&hdr, received_data.get(), sizeof(hdr));
  uint8_t key[ycsb::Trace_cmd::key_size];
  ::memcpy(key, received_data.get() + sizeof(hdr), ycsb::Trace_cmd::key_size);

  auto dest_node = hdr.node_id;
  // fmt::print("[{}] received from {}\n", __func__, hdr.node_id);

  enqueue_ack(req_handle, context, std::move(hdr));
#if 0
  execute_fw_put(context, key, dest_node);
#endif
  enqueue_put(context, key, dest_node);
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  rpc->run_event_loop_once();
}
#endif
