#pragma once
#include "generate_traces.h"
#include <iostream>
#include <thread>
#include <vector>
#include <memory>

class thread_args {
	using Traces = std::vector<::ycsb::Trace_cmd>;
	public:
	thread_args(int id, Traces::iterator b, Traces::iterator e)
		: thread_id(id), begin(b), end(e) 
	{}

	int thread_id;
	uint64_t operations = 0, reads = 0, writes = 0;;
	Traces::iterator begin, end;
	long int start_time, end_time;

};
