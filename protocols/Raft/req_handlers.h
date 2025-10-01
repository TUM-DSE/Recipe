#pragma once
#include "rpc.h"

void req_handler_appendEntries(erpc::ReqHandle *, void *);
void req_handler_commitIndex(erpc::ReqHandle *, void *);
void req_terminate_followers(erpc::ReqHandle *, void *);
void req_handler_appendEntries2(erpc::ReqHandle *, void *);
void req_handler_commitIndex2(erpc::ReqHandle *, void *);
void req_handler_forwardGet(erpc::ReqHandle *, void *);
void req_handler_forwardPut(erpc::ReqHandle *, void *);
void req_nb_writes(erpc::ReqHandle *req_handle, void *);
