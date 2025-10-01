
#include "../ycsb_generator/workload_generator.h"
#include "concurrent_skiplist/memtable.h"
#include "context.h"
#include "workload_generator.h"
#include <fmt/printf.h>

void allconcur_thread_func(void *ptr_nexus, std::unique_ptr<int> tid,
		thread_args *args, std::shared_ptr<state> ptr_state, int cur_node_id,
		avocado::KV_store *store);
