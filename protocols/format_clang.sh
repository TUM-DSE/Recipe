#!/bin/env sh

clang-format -i CR/*.cc CR/*.h
clang-format -i Raft/*.cc Raft/*.h
clang-format -i encryption_lib/*.h
clang-format -i concurrent_skiplist/*.h
clang-format -i concurrent_skiplist/*.cpp
