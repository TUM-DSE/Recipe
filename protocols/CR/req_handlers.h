#pragma once

#include "rpc.h"

void req_handler_put(erpc::ReqHandle *req_handle, void *context);
void req_handler_get(erpc::ReqHandle *req_handle, void *context);
void req_handler_cmt(erpc::ReqHandle *req_handle, void *context);
void req_handler_complete_reqs(erpc::ReqHandle *req_handle, void *context);

void req_handler_terminated_node(erpc::ReqHandle *, void *);
