#include <memory>
#include <stdio.h>
#include <thread>
#include <vector>

#include "../ycsb_generator/workload_generator.h"
#include "chain_rep.h"
#include "cipher.h"
#include "common_conf.h"
#include "context.h"
#include "req_handlers.h"
  #if SCONE_ALLOC
  #include "allocator.h"
  #endif


int main(int args, char *argv[]) {
  uint8_t __key[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                       0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
  uint8_t __iv[12] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5,
                      0x6, 0x7, 0x8, 0x9, 0xa, 0xb};

  std::shared_ptr<KeyIV> keyIv =
      std::make_shared<KeyIV>(reinterpret_cast<std::byte *>(__key),
                              reinterpret_cast<std::byte *>(__iv));
  cipher = std::make_shared<PacketSsl>(keyIv);

  std::string server_uri = kmarthaHostname + ":" + std::to_string(kUDPPort);
  int cur_node_id = 1;
  erpc::Nexus nexus(server_uri, 0, 0);
  nexus.register_req_func(kReqPUT, req_handler_put);
  nexus.register_req_func(kReqGET, req_handler_get);
  nexus.register_req_func(kReqCommit, req_handler_cmt);
  nexus.register_req_func(kCompletedReqsNb, req_handler_complete_reqs);
  nexus.register_req_func(kReqTerminate, req_handler_terminated_node);

  std::vector<std::thread> threads;
  std::vector<::ycsb::Trace_cmd> traces;
  std::string file = "/home/dimitra/secure_replication/ycsb_generator/"
                     "traces_files/1M_traces.txt";
  traces.reserve(1000000);
  traces = ::ycsb::trace_init(file, kReadPerMille);
  std::vector<std::unique_ptr<class thread_args>> arguments(kNumThreads);
  uint8_t key[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
  CipherSsl crypt(key, key);
  PacketSsl packet = PacketSsl::create(crypt);

//  avocado::KV_store store(std::move(crypt));
    #if SCONE_ALLOC
            auto alloc = avocado::create_allocator(kValueSize*kTraceSize, kValueSize, true);
     
             if (alloc == nullptr) {
                     std::cout << "[error] alloc is null..\n";
                     return -1;
             }
      avocado::KV_store store(std::move(crypt), std::move(alloc));
    #else
   avocado::KV_store store(std::move(crypt));
    #endif


  auto step_size = kTraceSize / kNumThreads;
  for (size_t i = 0; i < kNumThreads; i++) {
    auto begin = traces.begin();
    std::advance(begin, i * step_size);
    auto end = begin;
    std::advance(end, step_size);
    arguments[i] = std::make_unique<class thread_args>(i, begin, end);

    auto ptr_id = std::make_unique<int>(i);
    threads.push_back(std::thread(CR_thread_func, &nexus, std::move(ptr_id),
                                  cur_node_id, kroseHostname, kdonnaHostname,
                                  kroseHostname, arguments[i].get(), &store));
  }

  for (auto &t : threads)
    t.join();

  return 0;
}
