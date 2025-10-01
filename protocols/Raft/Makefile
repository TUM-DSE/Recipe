export project_dir = $(realpath $(shell pwd)/..)
export eRPC_dir = $(realpath $(shell pwd)/../eRPC)
export YCSB 	= $(realpath $(shell pwd)/../ycsb_generator)
export KV	= $(realpath $(shell pwd)/../concurrent_skiplist)
export APP 	= $(realpath $(shell pwd))
export DPDK 	= ${eRPC_dir}/dpdk/x86_64-native-linuxapp-gcc
export fmt	= ${project_dir}/fmt
export alloc_dir= ${project_dir}/host_allocator
MODE ?= AES_GCM

ifeq ($(MODE), AES_GCM)
INCLUDES_PATH 	= -I${project_dir}/Raft -I/usr/local/include -I${alloc_dir} -I${project_dir}/openssl/include -I${project_dir}/encryption_lib -I${eRPC_dir}/src -I${DPDK}/include -I${fmt}/include -I${KV} -I${project_dir} -I${YCSB} -I${project_dir}/integrity

CXXFLAGS 	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-attributes -Wno-unused-parameter -Wno-unused-variable -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DFOLLOWER_WORKLOAD -DNSHA256_DIGEST -DNINTEGRITY -DENCRYPTION -DKV -DBATCHING #-DSCONE_ALLOC #-fsanitize=address

else
INCLUDES_PATH 	= -I${project_dir}/Raft -I/usr/local/include -I${alloc_dir} -I${project_dir}/openssl/include -I${project_dir}/enc_lib_test -I${eRPC_dir}/src -I${DPDK}/include -I${fmt}/include -I${KV} -I${project_dir} -I${YCSB} -I${project_dir}/integrity

CXXFLAGS 	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-attributes -Wno-unused-parameter -Wno-unused-variable -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DFOLLOWER_WORKLOAD -DNSHA256_DIGEST -DNINTEGRITY -DGMAC -DENCRYPTION -DKV -DBATCHING -DSCONE_ALLOC #-fsanitize=address
endif

#LDFLAGS_PATH 	= -L${eRPC_dir}/build -L/usr/local/lib64 -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build
LDFLAGS_PATH 	= -L${eRPC_dir}/build -L${project_dir}/openssl/lib -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build

LD_FLAGS	= -lcrypto -ldl -lrt -lpthread -lcityhash -lfmt -lglog -lfolly #-fsanitize=address
LIBS 		= -lerpc_nat -lnuma -Wl,--whole-archive -ldpdk -Wl,--no-whole-archive -lrte_ethdev -Wl,-lrte_port


SRC_FILES_L 	= ${APP}/req_handlers.cc \
		  ${APP}/req_handlers_batched.cc \
		  ${APP}/cipher.cc	 \
		  ${APP}/raft_leader_func.cc	 \
		  ${YCSB}/generate_traces.cc	\
		  ${KV}/memtable.cpp	\
		  ${APP}/rate_limiter.cc \
		   ${alloc_dir}/alloc/create_allocator.cpp
		


SRC_FILES_F 	= ${APP}/req_handlers_batched.cc \
		  ${APP}/cipher.cc	 \
		  ${APP}/raft_follower_func.cc	 \
		  ${YCSB}/generate_traces.cc	\
		  ${KV}/memtable.cpp	\
		  ${APP}/rate_limiter.cc \
		   ${alloc_dir}/alloc/create_allocator.cpp

.PHONY 		= all


all: target

target: leader follower_1 follower_2 

leader:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES_L} ${APP}/leader.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o leader_${MODE}

follower_1:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES_F} ${APP}/follower_1.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o follower_amy_${MODE}

follower_2:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES_F} ${APP}/follower_2.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o follower_martha_${MODE}

clean: 
	rm -f leader_AES_GCM leader_GMAC follower_amy_GMAC follower_amy_AES_GCM follower_martha_GMAC follower_martha_AES_GCM
