#include "concurrent_skiplist/memtable.h"
#include "state.h"
#include <memory>

void raft_follower_thread_func(void *, std::unique_ptr<int>, thread_args *,
                               std::shared_ptr<state>, int,
                               avocado::KV_store *);
void raft_leader_thread_func(void *, std::unique_ptr<int>, thread_args *,
                             std::atomic<int> &, std::shared_ptr<state>, int,
                             avocado::KV_store *);

void raft_leader_worker(void *, std::unique_ptr<int>, std::atomic<int> &,
                        std::shared_ptr<state>, int, avocado::KV_store *);

void raft_follower_worker(void *, std::unique_ptr<int>, std::shared_ptr<state>,
                          int, avocado::KV_store *);
