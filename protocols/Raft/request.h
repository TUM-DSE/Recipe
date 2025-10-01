#pragma once
#include "generate_traces.h"
#include <set>
#include <vector>

struct request {
  static std::atomic<int> deallocs;
  request() : req_id(0), req_owner(0){};
  int req_id;
  uint8_t key[ycsb::Trace_cmd::key_size];
  int req_owner = 0;
  std::set<int> recv_acks;
  ~request() { deallocs.fetch_add(1); }
};

template <size_t batched_reqs> struct batched_request {
  batched_request() : idx(0), nb_batched_reqs(batched_reqs) {
    reqs_owners.reserve(batched_reqs);
  };

  int idx;
  int nb_batched_reqs;
  std::vector<int> reqs_owners;

  std::vector<std::unique_ptr<uint8_t[]>> keys;
  std::vector<std::unique_ptr<uint8_t[]>> values;
  std::set<int> recv_acks;
};
