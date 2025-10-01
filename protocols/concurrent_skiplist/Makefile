export project_dir = $(realpath $(shell pwd)/..)
export eRPC_dir = $(realpath $(shell pwd)/../eRPC)
export YCSB     = $(realpath $(shell pwd)/../ycsb_generator)
export APP      = $(realpath $(shell pwd))
export DPDK     = ${eRPC_dir}/dpdk/x86_64-native-linuxapp-gcc
export fmt      = ${project_dir}/fmt
export alloc_dir= ${project_dir}/host_allocator
MODE?=AES_GCM

ifeq ($(MODE), GMAC)
INCLUDES_PATH   = -I${project_dir}  -I${eRPC_dir}/src -I${alloc_dir} -I${project_dir}/integrity -I/usr/local/include -I${project_dir}/openssl/include -I${project_dir}/enc_lib_test -I${DPDK}/include -I${fmt}/include -I${KV} -I${project_dir} -I${YCSB} -I${eRPC_dir}/src -I./ -I${fmt}/include -DGMAC -DENCRYPTION -DNSHA256_DIGEST -DSCONE_ALLOC#-fsanitize=address

CXX_FLAGS	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-attributes -Wno-unused-parameter -Wno-unused-variable -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
else
INCLUDES_PATH   = -I${project_dir}  -I${eRPC_dir}/src -I${alloc_dir} -I${project_dir}/integrity -I/usr/local/include -I${project_dir}/openssl/include -I${project_dir}/encryption_lib -I${DPDK}/include -I${fmt}/include -I${KV} -I${project_dir} -I${YCSB} -I${eRPC_dir}/src -I./ -I${fmt}/include -DENCRYPTION -DNSHA256_DIGEST -DSCONE_ALLOC#-fsanitize=address

CXX_FLAGS	= -g -O3 -std=c++17 -fno-omit-frame-pointer -Wno-attributes -Wno-unused-parameter -Wno-unused-variable -Wno-pedantic -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -D RTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
endif

LDFLAGS_PATH    = -L${eRPC_dir}/build -L${project_dir}/openssl/lib -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build #-fsanitize=address
#LDFLAGS_PATH    = -L${eRPC_dir}/build -L/usr/local/lib64 -L${DPDK}/lib -L/usr/local/lib -L${fmt}/build #-fsanitize=address
all:
	g++ ${CXX_FLAGS} ${INCLUDES_PATH} ${YCSB}/generate_traces.cc ${alloc_dir}/alloc/create_allocator.cpp memtable.cpp skiplist_bench.cpp -o skiplist_${MODE} -lpthread  -ldl -lglog -lgflags -lfolly ${LDFLAGS_PATH} -lcrypto -lcityhash -lrt -lfmt

clean:
	-rm -f skiplist
