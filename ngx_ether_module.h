#ifndef _NGX_ETHER_MODULE_H_INCLUDED_
#define _NGX_ETHER_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_ether.h>

#include <msgpack.h>

#include "protocol_binary.h"

#include <openssl/aes.h>

typedef enum {
	NGX_ETHER_WAITING = 0,
	NGX_ETHER_HANDSHAKING,
	NGX_ETHER_AUTHENTICATING,
	NGX_ETHER_STREAM_KEY_EVSUB,
	NGX_ETHER_RETRIEVE_KEYS,
	NGX_ETHER_STREAM_MEMBER_EVSUB,
	NGX_ETHER_LISTING_MEMBERS,
	NGX_ETHER_RESPOND_LIST_KEYS_QUERY
} ngx_ether_state_et;

typedef struct {
	uint32_t hash;
	void *data;
} ngx_ether_chash_point_st;

typedef struct ngx_ether_memc_server_st {
	union {
		struct sockaddr addr;
		struct sockaddr_in sin;
#if NGX_HAVE_INET6
		struct sockaddr_in6 sin6;
#endif /* NGX_HAVE_INET6 */
	};
	size_t addr_len;

	ngx_str_t name;

	int udp;

	ngx_pool_t *pool;
	ngx_log_t *log;

	ngx_connection_t *c;

	ngx_atomic_uint_t id;

	ngx_queue_t recv_ops;
	ngx_queue_t send_ops;

	ngx_buf_t tmp_recv;

	ngx_queue_t queue;
} ngx_ether_memc_server_st;

typedef struct ngx_ether_memc_op_st {
	uint16_t id0;
	uint32_t id1;

	int is_quiet;

	ngx_ether_memc_op_handler handler;
	void *handler_data;

	const ngx_ether_memc_server_st *server;

	ngx_log_t *log;

	ngx_buf_t send;
	ngx_buf_t recv;

	ngx_queue_t recv_queue;
	ngx_queue_t send_queue;
} ngx_ether_memc_op_st;

typedef struct ngx_ether_peer_st {
	struct {
		ngx_peer_connection_t pc;

		ngx_buf_t send;
		ngx_buf_t recv;

		int has_send:1;

		int pc_connect:1;

		/* conf directives */
		ngx_str_t address;
		ngx_str_t auth;
		ngx_str_t prefix;

		ngx_ether_state_et state;

		uint64_t seq;

		uint64_t listing_keys_id;
	} serf;

	struct {
		/* conf directives */
		ngx_flag_t hex;
		ngx_str_t prefix;

		ngx_queue_t servers;

		ngx_uint_t npoints;
		ngx_ether_chash_point_st *points;
	} memc;

	ngx_pool_t *pool;
	ngx_log_t *log;

	ngx_queue_t keys;
	ngx_ether_key_st *default_key;
} ngx_ether_peer_st;

typedef void (*ngx_ether_add_serf_req_body_pt)(msgpack_packer *pk, ngx_ether_peer_st *peer);
typedef ngx_int_t (*ngx_ether_handle_serf_resp_pt)(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);

typedef struct {
	ngx_ether_state_et state;

	ngx_str_t name;

	ngx_ether_add_serf_req_body_pt add_serf_req_body;
	ngx_ether_handle_serf_resp_pt handle_serf_resp;
} ngx_ether_serf_cmd_st;

typedef enum {
	NGX_ETHER_HANDLE_LIST_MEMBERS,
	NGX_ETHER_HANDLE_ADD_MEMBER,
	NGX_ETHER_HANDLE_REMOVE_MEMBER,
	NGX_ETHER_HANDLE_UPDATE_MEMBER,
} ngx_ether_handle_member_resp_body_et;

#define NGX_ETHER_FOREACH_MEMC_OP(MACRO) \
	MACRO(GET, get) \
	MACRO(SET, set) \
	MACRO(ADD, add) \
	MACRO(REPLACE, replace) \
	MACRO(DELETE, delete) \
	MACRO(INCREMENT, increment) \
	MACRO(DECREMENT, decrement) \
	MACRO(QUIT, quit) \
	MACRO(FLUSH, flush) \
	MACRO(GETQ, getq) \
	MACRO(NOOP, noop) \
	MACRO(VERSION, version) \
	MACRO(GETK, getk) \
	MACRO(GETKQ, getkq) \
	MACRO(APPEND, append) \
	MACRO(PREPEND, prepend) \
	MACRO(STAT, stat) \
	MACRO(SETQ, setq) \
	MACRO(ADDQ, addq) \
	MACRO(REPLACEQ, replaceq) \
	MACRO(DELETEQ, deleteq) \
	MACRO(INCREMENTQ, incrementq) \
	MACRO(DECREMENTQ, decrementq) \
	MACRO(QUITQ, quitq) \
	MACRO(FLUSHQ, flushq) \
	MACRO(APPENDQ, appendq) \
	MACRO(PREPENDQ, prependq) \
	MACRO(TOUCH, touch) \
	MACRO(GAT, gat) \
	MACRO(GATQ, gatq) \
	MACRO(GATK, gatk) \
	MACRO(GATKQ, gatkq) \
	MACRO(SASL_LIST_MECHS, mechs) \
	MACRO(SASL_AUTH, auth) \
	MACRO(SASL_STEP, step) \
	MACRO(RGET, rget) \
	MACRO(RSET, rset) \
	MACRO(RSETQ, rsetq) \
	MACRO(RAPPEND, rappend) \
	MACRO(RAPPENDQ, rappendq) \
	MACRO(RPREPEND, rprepend) \
	MACRO(RPREPENDQ, rprependq) \
	MACRO(RDELETE, rdelete) \
	MACRO(RDELETEQ, rdeleteq) \
	MACRO(RINCR, rincrement) \
	MACRO(RINCRQ, rincrementq) \
	MACRO(RDECR, rdecrement) \
	MACRO(RDECRQ, rdecrementq)

#endif /* _NGX_ETHER_MODULE_H_INCLUDED_ */
