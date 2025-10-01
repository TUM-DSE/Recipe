#pragma once
#include "cipher.h"
#include "rate_limiter.h"
#include "integrity.h"
#include <atomic>
#include <fmt/printf.h>
#include <memory>
#include <sys/time.h>

#if BATCHING

static void sent_nb_of_reqs(AppContext *context, const int &writes) {
  erpc::Rpc<erpc::CTransport> *rpc =
    reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

  AppContext::header hdr;
  hdr.node_id = context->node_id;
  size_t message_sz = PacketSsl::get_buffer_size(sizeof(writes) + sizeof(hdr));
    #if INTEGRITY
        message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + (sizeof(writes) + sizeof(hdr));
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

  auto data = std::make_unique<uint8_t[]>(sizeof(writes) + sizeof(hdr));
  ::memcpy(data.get(), &hdr, sizeof(hdr));
  ::memcpy(data.get() + sizeof(hdr), &writes, sizeof(writes));
#if INTEGRITY
        char metadata[kMetaSize];
        ::memcpy(metadata, &hdr.node_id, kMetaSize);
        auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(data.get()), (sizeof(writes) + sizeof(hdr)));
        ::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
        ::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), data.get(), (sizeof(writes) + sizeof(hdr)));
#else
#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(tag_ptr->req_buf.buf, data.get(), sizeof(writes) + sizeof(hdr));
                 ::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, data.get(), sizeof(writes) + sizeof(hdr));
 #else

  // encrypt
  cipher->encrypt(tag_ptr->req_buf.buf, data.get(),
      sizeof(writes) + sizeof(hdr));
#endif
#endif
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

#if INTEGRITY
        char metadata[kMetaSize];
        ::memset(metadata, '4', kMetaSize);
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
    rpc->enqueue_request(i.second, kReqTerminateFollowers, &(tag_ptr->req_buf),
        &(tag_ptr->resp_buf), cont_func_default,
        (void *)tag_ptr);
  }
}

static void generate_workload_leader_batching(AppContext *context,
    thread_args *args,
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

        auto op_id = -1;
        AppContext::header hdr;
        hdr.node_id = context->node_id;
        hdr.op_id = op_id;
        struct req_tuple_batched *tag_ptr = new req_tuple_batched();
        tag_ptr->dest_session_nb = context->node_id;
        ::memcpy(tag_ptr->key_hash, it->key_hash, it->key_size);

        {
          std::lock_guard<std::mutex> l(context->ptr_state->mtx);
          context->ptr_state->concurrent_q->push_back(tag_ptr);
          //	  fmt::print("[{}] put here
          //context->ptr_state->concurrent_q->size()={}\n", __func__,
          //context->ptr_state->concurrent_q->size());
        }
        args->writes++;
#if 0
        if (args->writes % 2 == 0) {
          for (int l = 0; l < 10; l++)
            rpc->run_event_loop_once();
        }
#endif
      } else {
        context->store->get(it->key_size, it->key_hash);
        args->reads++;
        if ((args->reads % 10) == 0)
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

    rpc->run_event_loop(1000);
    local_ws = context->ptr_state->leader_local_tot_writes.load();
    followers_ws = context->ptr_state->total_write_requests.load();
    fmt::print("[{}] local_ws={}\tfollowers_ws={}\tlcmt={}\tcmt_acks[1]={}\tcmt_acks[2]={}\t\n", __func__, local_ws, followers_ws, context->ptr_state->leader_commit_index.load(),
        context->ptr_state->commit_acks[1]->load(),
       context->ptr_state->commit_acks[2]->load());
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

static void leader_worker_thread_batching(AppContext *ctx,
    std::atomic<int> &sequencer) {
  auto p1 = std::make_shared<std::atomic<int>>(0);
  auto p2 = std::make_shared<std::atomic<int>>(0);
  ctx->ptr_state->commit_acks.insert({1, p1});
  ctx->ptr_state->commit_acks.insert({2, p2});

  int i = 0;
  erpc::Rpc<erpc::CTransport> *rpc =
    reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
  auto static o = 0;
  while (!ctx->ptr_state->terminate) {
    int qsize = 0;
    {
      std::lock_guard<std::mutex> l(ctx->ptr_state->mtx);
      qsize = ctx->ptr_state->concurrent_q->size();
      if (qsize != 0) {

        auto batch = (qsize > kReqBatchSz) ? kReqBatchSz : qsize;
        // fmt::print("[{}] qsize={}/batch={}\n", __func__, qsize, batch);
        qsize = batch;
      }
    }
    if (qsize != 0) {
      // fmt::print("[{}] qsize={}\n", __func__, qsize);
      i++;
      auto op_id = sequencer.fetch_add(qsize);
      // rate.acquire([&rpc]() { rpc->run_event_loop_once(); });
      auto batched_msg_size = sizeof(AppContext::header) + kMsgSize * qsize;
      auto payload = std::make_unique<char[]>(batched_msg_size);
      size_t offset = sizeof(AppContext::header);
      auto on_going_req = new batched_request<kReqBatchSz>();
      on_going_req->nb_batched_reqs = qsize;

      on_going_req->idx = op_id;

      ctx->ptr_state->uncommitted_reqs.insert({op_id, on_going_req});
      ctx->ptr_state->biggest_id = op_id;
      auto &_on_going_req = ctx->ptr_state->uncommitted_reqs[op_id];
      {
        std::lock_guard<std::mutex> l(ctx->ptr_state->mtx);
        // fmt::print("[{}] size of queue={}\n", __func__,
        // ctx->ptr_state->concurrent_q->size());
        for (size_t r = 0; r < qsize; r++) {
          auto req = reinterpret_cast<struct req_tuple_batched *>(
              ctx->ptr_state->concurrent_q->back());
          ::memcpy(payload.get() + offset, req->key_hash,
              ycsb::Trace_cmd::key_size);
          offset += ycsb::Trace_cmd::key_size;
          auto _k = std::make_unique<uint8_t[]>(ycsb::Trace_cmd::key_size);
          auto _k_val = std::make_unique<uint8_t[]>(kValueSize);
          ::memcpy(_k.get(), req->key_hash, ycsb::Trace_cmd::key_size);
          ::memcpy(_k_val.get(), payload.get(), kValueSize);
          _on_going_req->keys.push_back(std::move(_k));
          _on_going_req->values.push_back(std::move(_k_val));
          _on_going_req->reqs_owners.push_back(req->dest_session_nb);
          // fmt::print("[{}] added req={}\n", __func__, req->dest_session_nb);
          ctx->ptr_state->concurrent_q->pop_back();
        }
      }

      size_t message_sz = PacketSsl::get_buffer_size(batched_msg_size);
#if INTEGRITY
        message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + batched_msg_size;
#endif

      auto resp_msg_size = kMsgSize;
      for (auto &follower : ctx->follower_session_nums) {
        AppContext::header hdr;
        hdr.op_id = op_id;
        hdr.batch_sz = qsize;
        ::memcpy(payload.get(), &hdr, sizeof(hdr));

        struct req_tuple *tag_ptr = new req_tuple();
        tag_ptr->req_id = op_id;
        tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
        tag_ptr->dest_session_nb = follower.first;
        while (tag_ptr->req_buf.buf == nullptr) {
          // no space left
          fmt::print("[{}] no space left\n");
          rpc->run_event_loop_once();
          tag_ptr->req_buf = rpc->alloc_msg_buffer_or_die(message_sz);
        }

        tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(resp_msg_size);
        while (tag_ptr->resp_buf.buf == nullptr) {
          fmt::print("[{}] no space left\n");
          // no space left
          rpc->run_event_loop_once();
          tag_ptr->resp_buf = rpc->alloc_msg_buffer_or_die(resp_msg_size);
        }

        rpc->resize_msg_buffer(&(tag_ptr->req_buf), message_sz);
        // rpc->resize_msg_buffer(&(tag_ptr->resp_buf), message_sz);
        rpc->resize_msg_buffer(&(tag_ptr->resp_buf), resp_msg_size);
  #if INTEGRITY
        char metadata[kMetaSize];
        ::memcpy(metadata, &tag_ptr->req_id, kMetaSize);
        auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(payload.get()), batched_msg_size);
        ::memcpy(tag_ptr->req_buf.buf, std::get<1>(res).get(), std::get<0>(res));
        ::memcpy(tag_ptr->req_buf.buf + std::get<0>(res), payload.get(), batched_msg_size);
  #else

#if GMAC
 #warning "GCMAC is ON"
                 cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), batched_msg_size);
                 ::memcpy(tag_ptr->req_buf.buf+PacketSsl::IvSize, payload.get(), batched_msg_size);
 #else
        // encrypt
        cipher->encrypt(tag_ptr->req_buf.buf, payload.get(), batched_msg_size);
#endif
#endif
        // fmt::print("[{}] sent req={} to i.second={}\n", __func__, hdr.op_id, follower.second);
        rpc->enqueue_request(follower.second, kReqAppendEntries,
            &(tag_ptr->req_buf), &(tag_ptr->resp_buf),
            cont_func, (void *)tag_ptr);
      }

      if (i % 100000 == 0) {
        fmt::print("[{}] sent req with id={} (size={})\n", __func__, op_id,
            ctx->ptr_state->uncommitted_reqs.size());
      }
      //@dimitra: you might want to batch here?
      if (op_id % 1 == 0)
        // rpc->run_event_loop(10000);
        rpc->run_event_loop_once();
    }
    // we check if we can commit something
    // sent_new_commit_index_if_any(ctx);
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
