#pragma once
#include "rpc.h"
  #if SHA256_DIGEST
  #include "digest_h.h"
  #endif


const std::string kdonnaHostname = "129.215.165.54";
// const std::string kdonnaHostname = "129.215.91.68";
// const std::string kmarthaHostname = "129.215.165.53";
const std::string kmarthaHostname = "129.215.165.53";
const std::string kroseHostname = "129.215.165.57";
const std::string node0 = kdonnaHostname;
const std::string node1 = kroseHostname;
const std::string node2 = kmarthaHostname;
const std::map<int, std::string> cluster_config = {{0, node0}, {1, node1}, {2, node2}};

constexpr uint16_t kUDPPort = 31850;
constexpr uint16_t kNumThreads = 1;
constexpr uint16_t kClusterSize = 3;

constexpr int kReqRecvReq = 1;
constexpr int kReqUpdateCommitIndex = 2;
constexpr int kReqTerminateFollowers = 3;
constexpr int kForwardPut = 4;
constexpr int kForwardGet = 5;
constexpr int kReqNbReqs = 6;

constexpr int kQueueSize = 2;
constexpr int kBatchSize = 200000;
constexpr int kReqBatchSz = 2;
static constexpr int kMsgSize = 4096; //256; //4096;
constexpr int kValueSize = kMsgSize;
constexpr int kMetaSize = sizeof(int); //dimitra: depends on the protocol

#if SHA256_DIGEST
#warning "SHA256_DIGEST IS ON"
constexpr int kHashSize = kSHA256_SZ; // dimitra: we use Sha256 so 64-bit for the hash
#else
constexpr int kHashSize = sizeof(uint64_t); // dimitra: we use CityHash64 so 64-bit for the hash
#endif


static uint64_t kTraceSize = 1000000;
static uint64_t kWorkloadSize = 20e6;
//    40e6; // this is the workload size -- threads will replay same trace size
static int kReadPerMille = 900;

static int64_t nb_reqs = (kWorkloadSize / kNumThreads);

static void sm_handler(int local_session, erpc::SmEventType, erpc::SmErrType,
                       void *) {}
