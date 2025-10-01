#pragma once
#include "rpc.h"
#if SHA256_DIGEST
#include "digest_h.h"
#endif

const std::string kdonnaHostname = "129.215.165.54";
const int kHeadNodeId = 0;
// const std::string kmarthaHostname = "129.215.165.53";
const std::string kmarthaHostname =
    "129.215.165.53"; // this is because we ran on clara
                      // "129.215.165.57"; // this is because we ran on amy
const int kMiddleNodeId1 = 1;
const std::string kroseHostname = "129.215.165.57";
const int kTailNodeId = 2;

constexpr uint16_t kUDPPort = 31850;
constexpr uint16_t kNumThreads = 8;
constexpr uint16_t kClusterSize = 3;

constexpr int kReqPUT = 1;
constexpr int kReqGET = 2;
constexpr int kReqCommit = 5;
constexpr int kCompletedReqsNb = 3;
constexpr int kReqTerminate = 4;

constexpr int kQueueSize = 1;
// constexpr int kBatchSize = 3000;
constexpr int kBatchSize = 1000;
/**
 * Note #1: kBatchSize of 1000 finished the exp in 74sec (~800Kops)
 *          - kMsgSize=256, kWorloadSize=20e6, kReadPerMille=500
 */
// constexpr int kQueueSize = 10;
// constexpr int kBatchSize = 1000;
static constexpr int kMsgSize = 256; //256;
static constexpr int kAckMsgSize = 64;
constexpr int kValueSize = kMsgSize;
constexpr int kMetaSize = sizeof(int); //dimitra: depends on the protocol
#if SHA256_DIGEST
#warning "SHA256_DIGEST IS ON"
constexpr int kHashSize = kSHA256_SZ; // dimitra: we use Sha256 so 64-bit for the hash
#else
constexpr int kHashSize = sizeof(uint64_t); // dimitra: we use CityHash64 so 64-bit for the hash
#endif

static constexpr uint64_t kTraceSize = 1000000;
static constexpr uint64_t kWorkloadSize = 30e6;
    // 100e6; // this is the workload size -- threads will replay same trace
    // size
//    100e6; // this is the workload size -- threads will replay same trace size
static int kReadPerMille = 500;

static int64_t nb_reqs = (kWorkloadSize / kNumThreads);
constexpr int mod_1 = kWorkloadSize % kNumThreads;
constexpr int mod_2 = kTraceSize % kNumThreads;
static_assert(mod_1 == 0);
static_assert(mod_2 == 0);

static void sm_handler(int local_session, erpc::SmEventType, erpc::SmErrType,
                       void *) {}
