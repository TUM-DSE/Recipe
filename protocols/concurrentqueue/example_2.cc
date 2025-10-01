#include "concurrentqueue.h"
#include <fmt/printf.h>
using namespace moodycamel;

struct req_tuple {
	void* req_buf;
	void* resp_buf;
	int req_id;
};

constexpr int nb_ops = 100000;

int main(int args, char* argv[]) {
	ConcurrentQueue<struct req_tuple*> q;
	std::thread threads[8];
	// Consumers
	int nb = 0;
	bool stop = false;
	for (int i = 7; i != 8; ++i) {
		threads[i] = std::thread([&]() {
				struct req_tuple* ptr;
				while (!stop) {
				while (q.try_dequeue(ptr)) {
					// fmt::print("[{}] dequeue ptr={} ptr->req_buf={}\n", __func__, reinterpret_cast<void*>(ptr), *reinterpret_cast<int*>(ptr->req_buf));
					auto ptr_int = reinterpret_cast<int*>(ptr->req_buf);
					delete ptr_int;
					delete ptr;
					nb++;
				}
				}
				});
	}

	std::atomic<int> nb_enq{0};
	// Producers
	for (int i = 0; i != 7; ++i) {
		threads[i] = std::thread([&](int i) {
				struct req_tuple* ptr;
				for (int j = 0; j != nb_ops; ++j) {
				ptr = new req_tuple();
				ptr->req_buf = new int(i*nb_ops + j);
				q.enqueue(ptr);
				nb_enq.fetch_add(1);
				}
				}, i);
	}


	fmt::print("[{}] here 1\n", __func__);
	// Wait for all threads
	for (int i = 0; i != 7; ++i) {
		threads[i].join();
	}

	fmt::print("[{}] here 2\n", __func__);
	stop = true;
	threads[7].join();

	// Collect any leftovers (could be some if e.g. consumers finish before producers)
	struct req_tuple* item;
	while (q.try_dequeue(item)) {
		fmt::print("[{}] item={}/{}\n", __func__, reinterpret_cast<void*>(item), *reinterpret_cast<int*>(item->req_buf));
		nb++;
	}

	fmt::print("[{}] we have nb={} dequeues and nb={} enqueues\n", __func__, nb, nb_enq.load());

}
