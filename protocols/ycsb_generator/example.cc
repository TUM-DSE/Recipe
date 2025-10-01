#include "generate_traces.h"
#include <iostream>
#include <thread>
#include <vector>
#include <memory>
#include "workload_generator.h"

static int      kNumThreads     = 8;
static uint64_t kTraceSize      = 1000000;
static uint64_t kWorkloadSize   = 5e6;        // this is the workload size -- threads will replay same trace size
static size_t   kValueSize      = 16;
static int      kReadPerMille   = 900;
static std::string kValue       = "IaMDimitraGiants";

std::vector<::ycsb::Trace_cmd> traces;


void thread_func(thread_args* args) {
	std::cout << __func__ << ": thread " << args->thread_id << " starts ..\n";
	bool ok = false;
	for (uint64_t i = 0; i < (kWorkloadSize/kTraceSize); i++) {
		for (auto it = args->begin; it != args->end; ++it) {
			const uint8_t* ptr = reinterpret_cast<const uint8_t*>(it->key_hash);
			if (it->op == ycsb::Trace_cmd::Put) {
				args->operations++;
				args->writes++;
			}
			else {
				args->operations++;
				args->reads++;
			}

		//	std::cout << "nb Put\t=" << args->writes<<"\tnb Read\t=" << args->reads <<  "\tTotal ops\t="<< args->operations << "\r";
		}
	}
	std::cout << "\n" << __func__ << ": thread " << args->thread_id << " ends .. (R/W ratio=" << (args->reads*1.0)/(args->writes*1.0) << ") total_ops=" << args->operations <<  "\n";
	return;
}



int main(int argc, char ** argv) {
	// the file should be generated used the python script
	// Warning: if program arguments do not match the size of the 
	// trace file something might go wrong.
	std::string file = "traces_files/1M_traces.txt";
	// reserve space for the vector -- 
	traces.reserve(1000000);
	traces = ::ycsb::trace_init(file, kReadPerMille);


	std::vector<std::thread> threads(kNumThreads);
	std::vector<std::unique_ptr<class thread_args>> arguments(kNumThreads);

	auto step_size = kTraceSize/kNumThreads;
	for (int i = 0; i < kNumThreads; i++) {
		auto begin = traces.begin();
		std::advance(begin, i * step_size);
		auto end = begin;
		std::advance(end, step_size);
		arguments[i] = std::make_unique<class thread_args>(i, begin, end);
                  threads[i] = std::thread(thread_func, arguments[i].get());
	}

	for (auto & t : threads) {
                  t.join();   
          }

	return 0;
}
