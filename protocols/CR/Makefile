export project_dir = $(realpath $(shell pwd)/..)
export eRPC_dir = $(realpath $(shell pwd)/../eRPC)
export YCSB 	= $(realpath $(shell pwd)/../ycsb_generator)
export KV 	= $(realpath $(shell pwd)/../concurrent_skiplist)
export APP 	= $(realpath $(shell pwd))
export DPDK 	= ${eRPC_dir}/dpdk/x86_64-native-linuxapp-gcc
export fmt	= ${project_dir}/fmt
export alloc_dir= ${project_dir}/host_allocator
MODE ?= AES_GCM

#INCLUDES_PATH 	= -I${project_dir}/CR -I/usr/local/include -I${alloc_dir} -I${project_dir}/openssl/include -I${project_dir}/encryption_lib -I${eRPC_dir}/src -I${DPDK}/include -I${fmt}/include -I${project_dir} -I${project_dir}/integrity

ifeq ($(MODE),GMAC)
INCLUDES_PATH 	= -I${project_dir}/CR -I/usr/local/include -I${alloc_dir} -I${project_dir}/openssl/include -I${project_dir}/enc_lib_test -I${eRPC_dir}/src -I${DPDK}/include -I${fmt}/include -I${project_dir} -I${project_dir}/integrity

CXXFLAGS 	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-unused-parameter -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D  RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DKV -DNSHA256_DIGEST -DNINTEGRITY -DGMAC -DENCRYPTION -DNSCONE_ALLOC -DCR_PROTO #-DNO_CIPHER -fsanitize=address -DINTEGRITY
else
INCLUDES_PATH 	= -I${project_dir}/CR -I/usr/local/include -I${alloc_dir} -I${project_dir}/openssl/include -I${project_dir}/encryption_lib -I${eRPC_dir}/src -I${DPDK}/include -I${fmt}/include -I${project_dir} -I${project_dir}/integrity

CXXFLAGS 	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-unused-parameter -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D  RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DKV -DNSHA256_DIGEST -DNINTEGRITY -DNGMAC -DENCRYPTION -DNSCONE_ALLOC -DCR_PROTO #-DNO_CIPHER -fsanitize=address -DINTEGRITY

#CXXFLAGS 	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-unused-parameter -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D  RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DKV -DNSHA256_DIGEST -DNINTEGRITY -DGMAC -DENCRYPTION -DNSCONE_ALLOC -DCR_PROTO #-DNO_CIPHER -fsanitize=address -DINTEGRITY
endif

LDFLAGS_PATH 	= -L${eRPC_dir}/build -L${project_dir}/openssl/lib -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build
#LDFLAGS_PATH 	= -L${eRPC_dir}/build -L/usr/local/lib64 -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build

LD_FLAGS	= -lcrypto -ldl -lrt -lpthread -lcityhash -lfmt -lglog -lfolly #-fsanitize=address
LIBS 		= -lerpc_nat -lnuma -Wl,--whole-archive -ldpdk -Wl,--no-whole-archive -lrte_ethdev -Wl,-lrte_port


SRC_FILES 	= ${APP}/req_handlers.cc \
		  ${APP}/stats.cc	 \
		  ${APP}/cipher.cc	 \
		  ${APP}/rate_limiter.cc	 \
		  ${APP}/chain_rep.cc	 \
		  ${YCSB}/generate_traces.cc	\
		  ${KV}/memtable.cpp	\
		  ${alloc_dir}/alloc/create_allocator.cpp



.PHONY 		= all


all: head middle tail

head:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES} ${APP}/head.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o head_${MODE}

middle:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES} ${APP}/middle.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o middle_${MODE}

tail:
	g++ -DERPC_DPDK=true ${CXXFLAGS} ${INCLUDES_PATH} ${SRC_FILES} ${APP}/tail.cc ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o tail_${MODE}

integrity:
	g++  ${CXXFLAGS} ${INCLUDES_PATH} test_integrity.cpp ${LDFLAGS_PATH} ${LIBS} ${LD_FLAGS} -o integrity

clean:
	rm -f head_AES_GCM middle_AES_GCM tail_AES_GCM
	rm -f head_GMAC middle_GMAC tail_GMAC
