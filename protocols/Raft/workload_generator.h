#pragma once
#include "cipher.h"
#include "integrity.h"
#include "rate_limiter.h"
#include <atomic>
#include <fmt/printf.h>
#include <memory>
#include <sys/time.h>

#if NO_BATCHING
static void sent_nb_of_reqs(AppContext *context, const int &writes) {
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

  AppContext::header hdr;
  hdr.node_id = context->node_id;
  size_t message_sz = PacketSsl::get_buffer_size(sizeof(writes) + sizeof(hdr));
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

  auto data = std::make_unique<uint8_t[]>(sizeof(writes) + sizeof(hdr));
  ::memcpy(data.get(), &hdr, sizeof(hdr));
  ::memcpy(data.get() + sizeof(hdr), &writes, sizeof(writes));
  std::cout << "NOT HERE\n";
  // encrypt
  cipher->encrypt(tag_ptr->req_buf.buf, data.get(),
                  sizeof(writes) + sizeof(hdr));
  rpc->enqueue_request(context->leader_session_num, kReqNbReqs,
                       &(tag_ptr->req_buf), &(tag_ptr->resp_buf),
                       cont_func_default, (void *)tag_ptr);
}

std::atomic<int> request::deallocs{0};
static void sent_termination_req(AppContext *context) {
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);
  std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
  ::memset(payload.get(), '0', kMsgSize);

  for (auto &i : context->follower_session_nums) {
    size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
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

  std::cout << "NOT HERE\n";
    // encrypt
    cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
    rpc->enqueue_request(i.second, kReqTerminateFollowers, &(tag_ptr->req_buf),
                         &(tag_ptr->resp_buf), cont_func_default,
                         (void *)tag_ptr);
  }
}

static void generate_workload_leader(AppContext *context, thread_args *args,
                                     std::atomic<int> &sequencer) {
  std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
  ::memset(payload.get(), '0', kMsgSize);

  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

  rpc->run_event_loop(1000);
  struct timeval startTV, endTV;
  gettimeofday(&startTV, NULL);
  int i = 0;
  auto vector_sz = args->end - args->begin;
  fmt::print(
      "[{}] will execute {} ({}) ops with Value and MSG sizes: {}B {}B\n",
      __func__, (kWorkloadSize / kTraceSize) * vector_sz, nb_reqs, kValueSize,
      kMsgSize);
  for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
    for (auto it = args->begin; it != args->end; ++it) {
      if (it->op == ycsb::Trace_cmd::Put || i == 0) {
#if FOLLOWER_WORKLOAD || RATELIMITER && 0
        //       rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
#endif
#if 0 /* @dimitra: we enqueue at the worker thread */
        auto op_id = sequencer.fetch_add(1);
#else

        auto op_id = -1;
#endif
        AppContext::header hdr;
        hdr.node_id = context->node_id;
        hdr.op_id = op_id;

        std::vector<void *> v;
        v.reserve(2);
        for (auto &i : context->follower_session_nums) {
          ::memcpy(payload.get(), &hdr, sizeof(hdr));
          ::memcpy(payload.get() + sizeof(hdr), it->key_hash, it->key_size);
          size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
          struct req_tuple *tag_ptr = new req_tuple();
          tag_ptr->req_id = op_id;
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
        }
#if LF_QUEUE
        while (!context->ptr_state->concurrent_q->enqueue(v)) {
          fmt::print("[{}] full\n", __func__);
        };
#elif NO_BATCHING
        {
          std::lock_guard<std::mutex> l(context->ptr_state->mtx);
          context->ptr_state->concurrent_q->push_back(v);
        }
#endif
        args->writes++;
      } else {
        context->store->get(it->key_size, it->key_hash);
        args->reads++;
        if ((args->reads % 1000) == 0)
          rpc->run_event_loop_once();
      }

      i++;
      if (i % kQueueSize == 0) {
        rpc->run_event_loop_once();
      }
    }
  }

  context->ptr_state->leader_local_tot_writes.fetch_add(args->writes);
  fmt::print("[{}] leader is waiting for replies (current total writes={})\n",
             __func__, context->ptr_state->leader_local_tot_writes.load());
  auto local_ws = context->ptr_state->leader_local_tot_writes.load();
  auto followers_ws = context->ptr_state->total_write_requests.load();

#if FOLLOWER_WORKLOAD
  while ((context->ptr_state->commit_acks[1]->load() !=
          (local_ws + followers_ws)) ||
         (context->ptr_state->commit_acks[2]->load() !=
          (local_ws + followers_ws))) {
#else
  /*
     while (context->ptr_state->commit_acks[1]->load() != args->writes ||
     context->ptr_state->commit_acks[2]->load() != args->writes)
     */

#endif
#if 0
    fmt::print("[{}] leader received {}/{} leader_cmt={} out of {}/tot={}\n",
        __func__, context->ptr_state->commit_acks[1]->load(),
        context->ptr_state->commit_acks[2]->load(),
        context->ptr_state->leader_commit_index.load(), context->ptr_state->leader_local_tot_writes.load(), context->ptr_state->total_write_requests.load());
#endif

    rpc->run_event_loop_once();
    local_ws = context->ptr_state->leader_local_tot_writes.load();
    followers_ws = context->ptr_state->total_write_requests.load();
  }

  int reqs = context->ptr_state->uncommitted_reqs.size();
  fmt::print("[{}] leader received {}/{} leader_cmt={} out of {}/tot={}\n",
             __func__, context->ptr_state->commit_acks[1]->load(),
             context->ptr_state->commit_acks[2]->load(),
             context->ptr_state->leader_commit_index.load(),
             context->ptr_state->leader_local_tot_writes.load(),
             context->ptr_state->total_write_requests.load());
  fmt::print("[{}] leader received {}/{} replies queued_reqs={} deallocs={}\n",
             __func__, context->ptr_state->commit_acks[1]->load(),
             context->ptr_state->commit_acks[2]->load(), reqs,
             request::deallocs.load());

  gettimeofday(&endTV, NULL);

  fmt::print(
      "\n \n \n[{}] all reqs commit_index={} ({}, R={}, W={}) acknowledged\n",
      __func__, context->ptr_state->leader_commit_index.load(),
      context->ptr_state->completed_reqs.load(), args->reads, args->writes);
  fmt::print("**time taken = {} {}\n", (endTV.tv_sec - startTV.tv_sec),
             (endTV.tv_usec - startTV.tv_usec));
}

static void leader_worker_thread(AppContext *ctx, std::atomic<int> &sequencer) {
  auto p1 = std::make_shared<std::atomic<int>>(0);
  auto p2 = std::make_shared<std::atomic<int>>(0);
  ctx->ptr_state->commit_acks.insert({1, p1});
  ctx->ptr_state->commit_acks.insert({2, p2});

  int i = 0;
  std::vector<void *> v;
  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
  auto static o = 0;
  while (!ctx->ptr_state->terminate) {

#if LF_QUEUE
    while (ctx->ptr_state->concurrent_q->try_dequeue(v)) {
#elif NO_BATCHING
    bool is_empty = true;
    {
      std::lock_guard<std::mutex> l(ctx->ptr_state->mtx);
      is_empty = ctx->ptr_state->concurrent_q->empty();
      if (!is_empty) {
        v = ctx->ptr_state->concurrent_q->back();
        ctx->ptr_state->concurrent_q->pop_back();
      }
    }
    while (!is_empty) {
#endif
      i++;
      auto op_id = sequencer.fetch_add(1);
      // rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
      for (auto &ptr : v) {
        auto req = reinterpret_cast<struct req_tuple *>(ptr);
        AppContext::header hdr;
        ::memcpy(&hdr, req->resp_buf.buf, sizeof(hdr));
        hdr.op_id = op_id;
        ::memcpy(req->resp_buf.buf, &hdr, sizeof(hdr));
        uint8_t key[ycsb::Trace_cmd::key_size];
        auto on_going_req = new request();
        on_going_req->req_id = op_id;
        on_going_req->req_owner = hdr.node_id;
        ::memcpy(on_going_req->key, req->resp_buf.buf + sizeof(hdr),
                 ycsb::Trace_cmd::key_size);
        ctx->ptr_state->uncommitted_reqs.insert({op_id, on_going_req});
        ctx->ptr_state->biggest_id = op_id;
        // encrypt
  std::cout << "NOT HERE\n";
        cipher->encrypt(req->req_buf.buf, req->resp_buf.buf, kMsgSize);
        rpc->enqueue_request(ctx->follower_session_nums[req->dest_session_nb],
                             kReqAppendEntries, &(req->req_buf),
                             &(req->resp_buf), cont_func, (void *)req);
        // fmt::print("[{}] sent req to hdr.sender_node={} op_id={}\n",
        // __func__, req->dest_session_nb, hdr.op_id);
      }

      if (i % 37500 == 0) {
        fmt::print("[{}] sent req with id={} (size={}B)\n", __func__, op_id,
                   ctx->ptr_state->uncommitted_reqs.size() *
                       (sizeof(struct request)));
      }
      //@dimitra: you might want to batch here?
      if (op_id % 5 == 0)
        rpc->run_event_loop_once();

        // TODO:
        // 1) add a sequencer
        // 2) enqueue the PUT req
#if LF_QUEUE
#elif NO_BATCHING
      is_empty = true;
#endif
    }
    // we check if we can commit something
    sent_new_commit_index_if_any(ctx);
    o++;
#if 0
      if (o%100000 == 0)
        fmt::print("[{}] {} nb of uncommitted_reqs\n", __func__, ctx->ptr_state->uncommitted_reqs.size());
#endif

    rpc->run_event_loop_once();
  }
  fmt::print("[{}] the leader worker thread will terminate w/ cmt_index={} "
             "(sequencer={})\n",
             __func__, ctx->ptr_state->leader_commit_index.load(),
             sequencer.load());
}
#endif

static void generate_workload_follower(AppContext *context, thread_args *args) {

  std::unique_ptr<char[]> payload = std::make_unique<char[]>(kMsgSize);
  ::memset(payload.get(), '0', kMsgSize);

  erpc::Rpc<erpc::CTransport> *rpc =
      reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

  auto p = std::make_shared<std::atomic<int>>(0);
  context->ptr_state->commit_acks.insert({0, p});

  struct timeval startTV, endTV;

  while (!context->ptr_state->start_the_workload.load())
    rpc->run_event_loop_once();

  gettimeofday(&startTV, NULL);
  int i = 0;
  auto vector_sz = args->end - args->begin;
  fmt::print(
      "[{}] will execute {} ({}) ops with Value and MSG sizes: {}B {}B\n",
      __func__, (kWorkloadSize / kTraceSize) * vector_sz, nb_reqs, kValueSize,
      kMsgSize);

  uint64_t op_id = 0;
  for (uint64_t j = 0; j < (kWorkloadSize / kTraceSize); j++) {
    for (auto it = args->begin; it != args->end; ++it) {
      AppContext::header hdr;
      hdr.node_id = context->node_id;
      hdr.op_id = op_id;
      ::memcpy(payload.get(), &hdr, sizeof(hdr));
      ::memcpy(payload.get() + sizeof(hdr), it->key_hash, it->key_size);

      size_t message_sz = PacketSsl::get_buffer_size(kMsgSize);
   #if INTEGRITY
          message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + kMsgSize;
    #endif

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
  #if INTEGRITY
          char metadata[kMetaSize];
          ::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
          auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), kMsgSize);
          ::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
          ::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), kMsgSize);
  #else

#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
                 ::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), kMsgSize);
 #else
      // encrypt
      cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), kMsgSize);
#endif
#endif
      if (it->op == ycsb::Trace_cmd::Put) {
        rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
        rpc->enqueue_request(context->leader_session_num, kForwardPut,
                             &(tag_ptr->req_buf), &(tag_ptr->resp_buf),
                             cont_func_fw_put, (void *)tag_ptr);
        args->writes++;
      } else {
        rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
        rpc->enqueue_request(context->leader_session_num, kForwardGet,
                             &(tag_ptr->req_buf), &(tag_ptr->resp_buf),
                             cont_func_fw_get, (void *)tag_ptr);
        args->reads++;
      }

      // if (i % kQueueSize == 0)
      rpc->run_event_loop_once();
      i++;
      op_id++;
    }
  }

  auto static o = 0;
  sent_nb_of_reqs(context, args->writes);
  fmt::print("[{}] follower is waiting for replies\n", __func__);
  while ((context->ptr_state->commit_acks[0]->load() +
          context->ptr_state->completed_reqs.load()) != nb_reqs * kNumThreads) {
    rpc->run_event_loop(2000);
    fmt::print("[{}] cmt_acks={}\tcompleted_reqs={}\n", __func__, context->ptr_state->commit_acks[0]->load(), context->ptr_state->completed_reqs.load());
#if 0
    o++;
    if (o%10000000 == 0)
      print_uncommitted_reqs(context->ptr_state->uncommitted_reqs, context);
#endif
  }

  int reqs = context->ptr_state->uncommitted_reqs.size();
  fmt::print("[{}]>>> follower received {} replies queued_reqs={} deallocs={}\n",
             __func__, context->ptr_state->commit_acks[0]->load(), reqs,
             request::deallocs.load());

  gettimeofday(&endTV, NULL);

  fmt::print("\n \n \n[{}] all reqs commit_index={} "
             "(total_completed_reqs={}\tcommit_acks[0]={}\tlocal R={}\tlocal "
             "W={}) acknowledged\n",
             __func__, context->ptr_state->commit_index.load(),
             context->ptr_state->completed_reqs.load(),
             context->ptr_state->commit_acks[0]->load(), args->reads,
             args->writes);
  fmt::print("**time taken = {} {}\n", (endTV.tv_sec - startTV.tv_sec),
             (endTV.tv_usec - startTV.tv_usec));
}

static void follower_worker_thread(AppContext *ctx) {}
