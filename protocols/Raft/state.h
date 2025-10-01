#pragma once
#include "concurrentqueue/concurrentqueue.h"
#include "request.h"
#include <atomic>
#include <memory>
#include <unordered_map>
#include <vector>

// state is shared by all threads
class state {
public:
  static constexpr int nb_followers = 1;
  state()
      : completed_reqs(0), commit_index(0), leader_commit_index(-1),
        total_write_requests(0), leader_local_tot_writes(0) {
    follower_cmt_idx.insert(std::make_pair(1, 0));
    follower_cmt_idx.insert(std::make_pair(2, 0));
  };
  std::atomic<int>
      commit_index; // index of the highest entry known to be committed
  std::atomic<int> leader_commit_index;
  std::atomic<int> sequencer{0};
  std::atomic<bool> terminate{false};
  std::atomic<bool> start_the_workload{false};

  /* @dimitra: needs to be atomic as the worker thread writes it and
   * the other threads are reading this
   */
  std::atomic<int> completed_reqs;
  std::atomic<int> total_write_requests;
  std::atomic<int> leader_local_tot_writes;
  std::unordered_map<int, std::shared_ptr<std::atomic<int>>> commit_acks;

  /*
   * @dimitra: only accessed by the worker-thread
   */
  std::unordered_map<int, int> follower_cmt_idx;
#if NO_BATCHING
  std::unordered_map<int, request *> uncommitted_reqs;
#else
  std::unordered_map<int, batched_request<kReqBatchSz> *> uncommitted_reqs;
#endif
  int biggest_id = -1;

  /*
   * @dimitra: accessed by both worker/workload threads
   */
#if LF_QUEUE
#warning "we are using the LF_QUEUE option"
  std::shared_ptr<moodycamel::ConcurrentQueue<std::vector<void *>>>
      concurrent_q;
#elif NO_BATCHING
  std::shared_ptr<std::vector<std::vector<void *>>> concurrent_q;
  std::mutex mtx;
#else
  std::shared_ptr<std::vector<void *>> concurrent_q;
  std::mutex mtx;
#endif
private:
};
