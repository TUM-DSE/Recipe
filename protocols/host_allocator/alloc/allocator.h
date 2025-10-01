#pragma once

#include <memory>
#include "../allocator.h"
#include <stdlib.h>

namespace avocado {

  struct AllocatorDeleter {
    void operator()(slab::UniquePtrWrap<slab::DynamicLockLessAllocator> * ptr);
  };

 std::unique_ptr<slab::UniquePtrWrap<slab::DynamicLockLessAllocator>, AllocatorDeleter> create_allocator(size_t size, size_t element_size, bool warmup = true);

} //avocado
