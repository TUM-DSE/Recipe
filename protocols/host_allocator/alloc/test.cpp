#include "allocator.h"

#include <cstring>

#include <iostream>
#include <sys/mman.h>

#include <fcntl.h>

struct S {
    char t[128];
};

class KV_store {
  using Allocator = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>;
  using Ptr_t = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>::Ptr_t;
  std::shared_ptr<Allocator> alloc;
};

class data {
    public:
  using Allocator = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>;
  using Ptr_t = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>::Ptr_t;
  Ptr_t data2;
  data(Ptr_t&& d) : data2(std::move(d)) {
      std::cout << __PRETTY_FUNCTION__ << "\n";
  }

};


int main() {
    // using namespace slab;
    using Ptr_t = slab::UniquePtrWrap<slab::DynamicLockLessAllocator>::Ptr_t;
   // Ptr_t data;
    auto alloc = avocado::create_allocator(256*3, 256, true);
    auto x = alloc->alloc();
#if 1
    std::cout << sizeof(x) << std::endl;
    std::cout << sizeof(std::byte) << std::endl;
    std::unique_ptr<char[]> k = std::make_unique<char[]>(257);
    ::memset(k.get(), '1', 256);
    auto ptr = std::make_shared<data>(alloc->alloc());
    ::memcpy(ptr->data2.get(), k.get(), 256);
    
    std::cout << reinterpret_cast<char*>(ptr->data2.get())[0] << "\n";
    ::memcpy(x.get(), k.get(), 256);
    for (auto i = 0; i < 256; i++) {
        std::cout << reinterpret_cast<char*>(x.get())[i] << "\n";

    }
    auto x2 = alloc->alloc();
    ::memset(x2.get(), '2', 256);
    for (auto i = 0; i < 256; i++) {
        std::cout << reinterpret_cast<char*>(x2.get())[i] << "\n";

    }
    for (auto i = 0; i < 256; i++) {
        std::cout << reinterpret_cast<char*>(x.get())[i] << "\n";

    }
#endif

}
