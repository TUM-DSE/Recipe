#pragma once
#include "concurrentqueue/concurrentqueue.h"
#include "request.h"
#include "common_conf.h"
#include <atomic>
#include <memory>
#include <unordered_map>
#include <vector>
#include <array>

// state is shared by all threads
class state {
	public:
		state() = default;
		~state() {
			fmt::print("[{}] consensus_applied={}, current round={}\n", __func__, consensus_sqn.load(), current_round);
		}

		// latest consensus sqn applied
		std::atomic<uint64_t> consensus_sqn{0};
		std::atomic<bool> start_the_workload{false};
		uint64_t current_round = 0;
		uint64_t max_remote_rnd = -1;



		// @dimitra: mutex might be useful in multithreaded env
		std::mutex mtx;
		using consensus_round = uint64_t;
		using received_messages = std::vector<std::unique_ptr<request>>;
		std::unordered_map<consensus_round, received_messages> received_reqs;

		int received_reqs_nb(uint64_t rnd) {
			std::lock_guard<std::mutex> l(mtx);
			if (received_reqs.find(rnd) != received_reqs.end()) {
        return received_reqs[rnd].size();
#if 0
				return (received_reqs[rnd].size() + ((current_round >= rnd) ? 1 : 0));
#endif
			}
			return 0;
		}

		template<typename T>
			static void update_maximum(std::atomic<T>& maximum_value, T const& value) noexcept
			{
				T prev_value = maximum_value;
				while(prev_value < value &&
						!maximum_value.compare_exchange_weak(prev_value, value))
				{}
			}

		bool terminate_execution() {
			if (max_remote_rnd < 0) return false;
			static int o = 0;
			o++;
			if (o%25000 == 0) fmt::print("[{}] consensus_sqn={}, max_remote_rnd={}\n", __func__, consensus_sqn.load(), max_remote_rnd);
			return (max_remote_rnd <= consensus_sqn.load());
		}

    void remove_req(uint64_t rnd) {
			std::lock_guard<std::mutex> l(mtx);
			received_reqs.erase(rnd);
    }

		void enqueue_received_req(const uint64_t& round, const uint8_t& req_owner, const uint32_t& batch_sz, std::unique_ptr<uint8_t[]> payload_data, size_t payload_sz) {
			if (round <= consensus_sqn.load()) return;

			// fmt::print("[{}] batch_sz={}, payload_sz={}\n", __func__, batch_sz, payload_sz);
			auto recv_request = std::make_unique<request>(req_owner, batch_sz, std::move(payload_data));

			std::lock_guard<std::mutex> l(mtx);
			auto it = received_reqs.find(round);
			if (it != received_reqs.end())
			{
				// this specific request might already have been received
				for (auto& req : received_reqs[round]) {
					if (req->req_owner == req_owner)
						return;
				}
				received_reqs[round].emplace_back(std::move(recv_request));
			}
			else if (consensus_sqn.load() < round) {
				std::vector<std::unique_ptr<request>> vec;
				vec.emplace_back(std::move(recv_request));
				received_reqs.insert({round, std::move(vec)});
			}
		}
};
