#include <iostream>
#include <memory>
#include <thread>
#include <vector>

 #include "allocator.h"
#include "encrypt_package.h"
#include "generate_traces.h"
#include "memtable.h"
#include <fmt/printf.h>
#include <sys/time.h>
#include <inttypes.h>

#if 0
static int kNumThreads = 8;
static uint64_t kTraceSize = 1000000;
static uint64_t kWorkloadSize =
    100e6; // this is the workload size -- threads will replay same trace size
static size_t kValueSize = 16;
static int kReadPerMille = 500;
static std::string kValue = "IaMDimitraGiants";
#endif

std::vector<::ycsb::Trace_cmd> traces;

class thread_args {
  using Traces = std::vector<::ycsb::Trace_cmd>;

public:
  thread_args(int id, std::shared_ptr<avocado::KV_store> kv_ptr, Traces::iterator b,
              Traces::iterator e)
      : thread_id(id), store(kv_ptr), begin(b), end(e) {
    assert(id < kNumThreads);
    assert(kv_ptr != nullptr);
  }

  int thread_id;
  uint64_t operations = 0, reads = 0, writes = 0;
  ;
  std::shared_ptr<avocado::KV_store> store;
  Traces::iterator begin, end;
  long int start_time, end_time;
};

static uint64_t get_time_in_ms() {
  struct timeval tv;

  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000 + tv.tv_usec / 10e6);
}

void thread_func(thread_args *args) {
  fmt::print("[{}] thread={}\n", __func__, args->thread_id);
  bool ok = false;
  args->start_time = get_time_in_ms();
  std::unique_ptr<uint8_t[]> val = std::make_unique<uint8_t[]>(256);
  ::memset(val.get(), 1, 256);
  for (uint64_t i = 0; i < (kWorkloadSize / kTraceSize); i++) {
    for (auto it = args->begin; it != args->end; it++) {
      const uint8_t *ptr = reinterpret_cast<const uint8_t *>(it->key_hash);
      if (it->op == ycsb::Trace_cmd::Put) {
        fmt::print("[{}] put={}\n", __func__, args->writes);
        // ok = args->store->put(it->key_size, ptr, val.get(), 256);
        ok = args->store->put(it->key_size, ptr);
	// fmt::print("[{}]\n", __func__);
        args->operations++;
        args->writes++;
#ifndef BENCHMARKING
        // assert(ok);
#endif
      } else {
        // fmt::print("[{}] get={}\n", __func__, args->reads);
        avocado::KV_store::Ret_value ret = args->store->get(it->key_size, ptr);
        args->operations++;
        args->reads++;
#ifndef BENCHMARKING
        // assert(ret.value.get() != nullptr);
#endif
      }
    }
  }
  args->end_time = get_time_in_ms();
  fmt::print("[{}] thread={} finished ..\n", __func__, args->thread_id);

  return;
}

int main(int argc, char **argv) {
  // the file should be generated used the python script
  // Warning: if program arguments do not match the size of the
  // trace file something might go wrong.
  std::string file = "/home/dimitra/secure_replication/ycsb_generator/"
                     "traces_files/1M_traces.txt";
  // reserve space for the vector --
  traces.reserve(1000000);
  traces = ::ycsb::trace_init(file, kReadPerMille);
  if (traces.size() == 0) {
    return -1;
  }

#if SCONE_ALLOC
	auto alloc = avocado::create_allocator(kValueSize*kTraceSize, kValueSize, true);

	if (alloc == nullptr) {
		std::cout << "[error] alloc is null..\n";
		return -1;
	}
#endif

  uint8_t key[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
  CipherSsl crypt(key, key);
  PacketSsl packet = PacketSsl::create(crypt);

#if SCONE_ALLOC
  std::shared_ptr<avocado::KV_store> store = std::make_shared<avocado::KV_store>(std::move(crypt), std::move(alloc));
#else
  std::shared_ptr<avocado::KV_store> store = std::make_shared<avocado::KV_store>(std::move(crypt));
#endif

  std::vector<std::thread> threads(kNumThreads);
  std::vector<std::unique_ptr<class thread_args>> arguments(kNumThreads);

  auto step_size = kTraceSize / kNumThreads;
  for (int i = 0; i < kNumThreads; i++) {
    auto begin = traces.begin();
    std::advance(begin, i * step_size);
    auto end = begin;
    std::advance(end, step_size);

    arguments[i] = std::make_unique<class thread_args>(i, store, begin, end);
    threads[i] = std::thread(thread_func, arguments[i].get());
  }

  for (auto &t : threads) {
    t.join();
  }

  long int start = arguments[0]->start_time;
  long int end = arguments[0]->end_time;

  // find the earliest start time and the latest end time
  for (auto &i : arguments) {
    fmt::print("[{}] operations={} (reads={}, writes={}) in {} ms\n", __func__,
               i->operations, i->reads, i->writes,
               (i->end_time - i->start_time));

    if (i->start_time < start)
      start = i->start_time;
    if (i->end_time > end)
      end = i->end_time;
  }

  fmt::print("[{}] total operations={} in {} ms kOp/s={}\n", __func__,
             kWorkloadSize, (end - start),
             (kWorkloadSize / ((end - start) / 1000)) / 1000);

  return 0;
}
