#pragma once

#include "context.h"

void req_terminate_followers(erpc::ReqHandle *req_handle, void *ctx);
void req_handler_recv_req(erpc::ReqHandle *req_handle, void *ctx);

