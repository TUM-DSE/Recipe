#include "context.h"
#include "common_conf.h"
#include "generate_traces.h"
#include "rate_limiter.h"
#include "util.h"
#include <algorithm>
#include <fmt/os.h>
#include <fmt/printf.h>
#include "req_handlers.h"
#include "cipher.h"

void req_terminate_followers(erpc::ReqHandle *req_handle, void *ctx) {
	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(context->rpc);

	char *data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t data_sz = req_handle->get_req_msgbuf()->get_data_size();


#if INTEGRITY
	size_t enc_data = PacketSsl::get_buffer_size(kMetaSize + kHashSize);
	auto decrypted_meta = destruct(cipher.get(), reinterpret_cast<char*>(data), enc_data);
	auto calc_sha256 = get_sha256(reinterpret_cast<char*>(data) + enc_data, (data_sz-enc_data));
	if (::memcmp(std::get<1>(calc_sha256).get(), decrypted_meta.get() + kMetaSize, kHashSize) != 0) {
		fmt::print("[{}] Error in verification\n", __func__);
	}

#if INTEGRITY_CITYHASH

	uint64_t c_h = 0;
	::memcpy(&c_h, decrypted_meta.get() + kMetaSize, kHashSize);
	if (c_h != CityHash64(reinterpret_cast<char*>(data)+enc_data, data_sz-enc_data)) {
		fmt::print("[{}] Error\n", __func__);
	}
#endif
	//  std::unique_ptr<uint8_t[]> decrypted_data = std::make_unique<uint8_t[]>(data_sz-enc_data - sizeof(AppContext::header);
	AppContext::header hdr;
	//   ::memcpy(decrypted_data.get(), data + enc_data + sizeof(hdr), data_sz-enc_data-sizeof(hdr));
	::memcpy(&hdr, data + enc_data, sizeof(hdr));
#else
#if GMAC
#warning "GMAC ON"
	uint8_t unused;
	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> temp =
		std::make_unique<uint8_t[]>(dec_size);
	::memcpy(temp.get(), data + PacketSsl::IvSize, dec_size);
	/*
	   std::cout << "decrypted_data=\n";
	   for (auto i = 0; i < PacketSsl::get_message_size(data_sz); i++) {
	   fmt::print("{}", decrypted_data.get()[i]);

	   }       
	   std::cout << "\n";
	   */
	bool [[maybe_unused]] success = cipher->decrypt(&unused, data, data_sz);
	if (!success) {
		std::cout << __PRETTY_FUNCTION__ << " Authentication failed\n";
		exit(128);
	}
	AppContext::header hdr;
	::memcpy(&hdr, temp.get(), sizeof(hdr));

#else	

	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> temp = std::make_unique<uint8_t[]>(dec_size);

	bool [[maybe_unused]] ok = cipher->decrypt(temp.get(), data, data_sz);
	AppContext::header hdr;
	::memcpy(&hdr, temp.get(), sizeof(hdr));
#endif
#endif

	fmt::print("[{}] node={} terminated w/ consensus round={}\n", __func__, hdr.node_id, hdr.sqn);
	context->ptr_state->max_remote_rnd = (context->ptr_state->max_remote_rnd == -1) ? hdr.sqn : ((context->ptr_state->max_remote_rnd < hdr.sqn) ? hdr.sqn : context->ptr_state->max_remote_rnd);
	// ack that you got the RPC
	auto &resp_buf = req_handle->pre_resp_msgbuf;

	// encrypt response
	uint32_t foo = 1;
	auto message_sz = PacketSsl::get_buffer_size(sizeof(foo));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(foo);
#endif
#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &foo, sizeof(foo));
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(&foo), sizeof(foo));
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), &foo, sizeof(foo));
#else
#if GMAC
#warning "GCMAC is ON"
	cipher->encrypt(resp_buf.buf, &foo, sizeof(foo));
	::memcpy(resp_buf.buf+PacketSsl::IvSize, &foo, sizeof(foo));
#else
	cipher->encrypt(resp_buf.buf, &foo, sizeof(foo));
#endif
#endif
	rpc->resize_msg_buffer(&resp_buf, message_sz);
	rpc->enqueue_response(req_handle, &resp_buf);
}


static void
enqueue_received_req(AppContext *ctx, const AppContext::header& hdr, std::unique_ptr<uint8_t[]> data, size_t data_sz) {

#if 0
	fmt::print("[{}] for round={} ..", __func__, hdr.sqn);
	for (auto i = 0; i < 8; i++)
		fmt::print("{}", data.get()[i]);
	fmt::print("\n");
#endif
	ctx->ptr_state->enqueue_received_req(hdr.sqn, hdr.req_owner, hdr.batch_sz, std::move(data), data_sz);
}

static void enqueue_ack(erpc::ReqHandle *req_handle, AppContext *ctx,
		AppContext::header hdr) {
	erpc::Rpc<erpc::CTransport> *rpc =
		reinterpret_cast<erpc::Rpc<erpc::CTransport> *>(ctx->rpc);
	// ack that you got the RPC
	auto &resp_buf = req_handle->pre_resp_msgbuf;

	// encrypt response
	hdr.node_id = ctx->node_id;
	auto message_sz = PacketSsl::get_buffer_size(sizeof(AppContext::header));
#if INTEGRITY
	message_sz =  PacketSsl::get_buffer_size(kMetaSize + kHashSize) + sizeof(AppContext::header);
#endif

	rpc->resize_msg_buffer(&resp_buf, message_sz);
#if INTEGRITY
	char metadata[kMetaSize];
	::memcpy(metadata, &hdr.node_id, kMetaSize);
	auto res = construct(cipher.get(), metadata, kMetaSize, reinterpret_cast<char*>(&hdr), sizeof(AppContext::header));
	::memcpy(resp_buf.buf, std::get<1>(res).get(), std::get<0>(res));
	::memcpy(resp_buf.buf + std::get<0>(res), &hdr, sizeof(AppContext::header));
#else
#if GMAC
#warning "GCMAC is ON"
	cipher->encrypt(resp_buf.buf, &hdr, sizeof(AppContext::header));
	::memcpy(resp_buf.buf+PacketSsl::IvSize, &hdr, sizeof(AppContext::header));
#else
	cipher->encrypt(resp_buf.buf, &hdr, sizeof(AppContext::header));
#endif
#endif
	rpc->enqueue_response(req_handle, &resp_buf);
	rpc->run_event_loop_once();
}

static std::tuple<AppContext::header, std::unique_ptr<uint8_t[]>, size_t> decode_received_request(char *data,
		size_t data_sz) {
#if INTEGRITY
	size_t enc_data = PacketSsl::get_buffer_size(kMetaSize + kHashSize);
	auto decrypted_meta = destruct(cipher.get(), reinterpret_cast<char*>(data), enc_data);
	auto calc_sha256 = get_sha256(reinterpret_cast<char*>(data) + enc_data, (data_sz-enc_data));
	if (::memcmp(std::get<1>(calc_sha256).get(), decrypted_meta.get() + kMetaSize, kHashSize) != 0) {
		fmt::print("[{}] Error in verification\n", __func__);
	}


#if INTEGRITY_CITYHASH
	uint64_t c_h = 0;
	::memcpy(&c_h, decrypted_meta.get() + kMetaSize, kHashSize);
	if (c_h != CityHash64(reinterpret_cast<char*>(data)+enc_data, data_sz-enc_data)) {
		fmt::print("[{}] Error in hdr.sqn={}\n", __func__, hdr.sqn);
	}
#endif
	std::unique_ptr<uint8_t[]> decrypted_data = std::make_unique<uint8_t[]>(data_sz-enc_data - sizeof(AppContext::header));
	AppContext::header hdr;
	::memcpy(decrypted_data.get(), data + enc_data + sizeof(hdr), data_sz-enc_data-sizeof(hdr));
	::memcpy(&hdr, data + enc_data, sizeof(hdr));
	return {hdr, std::move(decrypted_data), (data_sz-enc_data - sizeof(AppContext::header))};
#else
#if GMAC
#warning "GMAC ON"
	uint8_t unused;
	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size - sizeof(AppContext::header));
	AppContext::header hdr;
	::memcpy(&hdr, data + PacketSsl::IvSize, sizeof(hdr));
	::memcpy(ptr.get(), data + PacketSsl::IvSize + sizeof(hdr), dec_size - sizeof(hdr));
	/*
	   std::cout << "decrypted_data=\n";
	   for (auto i = 0; i < PacketSsl::get_message_size(data_sz); i++) {
	   fmt::print("{}", decrypted_data.get()[i]);

	   }       
	   std::cout << "\n";
	   */
	bool [[maybe_unused]] success = cipher->decrypt(&unused, data, data_sz);
	if (!success) {
		std::cout << __PRETTY_FUNCTION__ << " Authentication failed\n";
		std::cout << " hdr.sqn=" << hdr.sqn << " hdr.req_owner=" << hdr.req_owner << " hdr.node_id=" << hdr.node_id << " data_sz " << data_sz << "\n";

		// exit(128);
	}
	return {hdr, std::move(ptr), (dec_size - sizeof(AppContext::header))};

#else	

	size_t dec_size = PacketSsl::get_message_size(data_sz);
	std::unique_ptr<uint8_t[]> temp = std::make_unique<uint8_t[]>(dec_size);
	std::unique_ptr<uint8_t[]> ptr = std::make_unique<uint8_t[]>(dec_size - sizeof(AppContext::header));

	bool [[maybe_unused]] ok = cipher->decrypt(temp.get(), data, data_sz);
	if (!ok) {
		std::cout << __PRETTY_FUNCTION__ << " Authentication failed\n";
	}
	AppContext::header hdr;
	::memcpy(&hdr, temp.get(), sizeof(hdr));
	::memcpy(ptr.get(), temp.get() + sizeof(hdr), dec_size - sizeof(hdr));
	return {hdr, std::move(ptr), dec_size - sizeof(AppContext::header)};
#endif
#endif
}

void req_handler_recv_req(erpc::ReqHandle *req_handle, void *ctx) {

	AppContext *context = reinterpret_cast<AppContext *>(ctx);
	context->ptr_state->start_the_workload.store(true);

	char *enc_data = reinterpret_cast<char *>(req_handle->get_req_msgbuf()->buf);
	size_t enc_size = req_handle->get_req_msgbuf()->get_data_size();
	auto [hdr, payload_data, payload_data_sz] = decode_received_request(enc_data, enc_size);

	enqueue_received_req(context, hdr, std::move(payload_data), payload_data_sz);
	check_for_termination(hdr, context);
#if 0
	// this is for printing
	static int o = 0;
	o++;
	if (o % 2500 == 0)
		fmt::print("[{}] received req for csqn={} (req_owner={}) from node_id={}\n", __func__,
				hdr.sqn, hdr.req_owner, hdr.node_id);
#endif

	enqueue_ack(req_handle, context, std::move(hdr));
}

