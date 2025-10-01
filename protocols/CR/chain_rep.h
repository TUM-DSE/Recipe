#include <memory>
#include <stdio.h>
#include <thread>
#include <vector>

#include "../ycsb_generator/workload_generator.h"
#include "common_conf.h"
#include "concurrent_skiplist/memtable.h"
#include "context.h"
#include "req_handlers.h"

void CR_thread_func(void *ptr_nexus, std::unique_ptr<int> ptr_id,
                    int cur_node_id, std::string, std::string, std::string,
                    thread_args *args, avocado::KV_store *);
