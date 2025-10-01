#include "concurrentqueue.h"
#include <fmt/printf.h>
using namespace moodycamel;

int main(int args, char* argv[]) {
	ConcurrentQueue<int> q;
	int dequeued[300] = { 0 };
	std::thread threads[20];

	// Producers
	for (int i = 0; i != 19; ++i) {
		threads[i] = std::thread([&](int i) {
				int items;
				for (int j = 0; j != 10; ++j) {
				items = i * 10 + j;
				q.enqueue(items);
				}
				}, i);
	}

	// Consumers
	for (int i = 19; i != 20; ++i) {
		threads[i] = std::thread([&]() {
				int item;
				for (std::size_t count = q.try_dequeue(item); count != 0; --count) {
				++dequeued[item];
				}
				});
	}

	fmt::print("[{}] here 1\n", __func__);
	// Wait for all threads
	for (int i = 0; i != 20; ++i) {
		threads[i].join();
	}
	fmt::print("[{}] here 2\n", __func__);

	// Collect any leftovers (could be some if e.g. consumers finish before producers)
	int item;
	std::size_t count;
	while ((count = q.try_dequeue(item)) != 0) {
		fmt::print("[{}] item={}\n", __func__, item);
			++dequeued[item];
	}

	fmt::print("[{}] here 3\n", __func__);

	// Make sure everything went in and came back out!
	for (int i = 0; i != 100; ++i) {
		assert(dequeued[i] == 1);
	}
}
