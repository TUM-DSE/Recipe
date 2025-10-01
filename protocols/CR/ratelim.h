#pragma once
#include "common_conf.h"
#include "fmt/printf.h"
#include <atomic>
#include <cstddef>

#define RATELIMITER 1

struct RateLimit {
  std::atomic<size_t> n_aquire{0};
  std::atomic<size_t> n_release{0};
  std::atomic<int> request{0};
  // size_t max_request{1024}; /* 256 for SCONE w/ 1024B and 4096B */
  // size_t max_request{30 * kBatchSize};
  size_t max_request{10 * kBatchSize};
  static constexpr size_t print_request = 200000ULL;

  void release(int batch_size) {
    request.fetch_add((-1) * batch_size, std::memory_order_relaxed);
    auto n = n_release.fetch_add(1, std::memory_order_relaxed);
    if (n % print_request == 0) {
      fmt::print("Release nr:\t{}\n", n);
    }
  }

  template <class F> void acquire(F const &f) {

    auto n = n_aquire.fetch_add(1, std::memory_order_relaxed);
    if (n % print_request == 0) {
      fmt::print("Request nr:\t{}\n", n);
      f();
    }
#if RATELIMITER
    for (;;) {
      auto r = request.load(std::memory_order_relaxed);
      while (r < max_request &&
             !request.compare_exchange_weak(r, r + 1, std::memory_order_release,
                                            std::memory_order_relaxed)) {
#if 0
	      fmt::print("[{}] r={}\tmax_request={}\trequest={}\n",
        __func__, r, max_request, request.load());
#endif

        f();
      }
      if (r < max_request) {
        return;
      }
      f();
    }
#else
    f();
#endif
  }
};
