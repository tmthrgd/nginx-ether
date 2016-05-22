#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>

#include "ngx_ether_module.h"

#include <ngx_http_lua_api.h>
#ifndef DDEBUG
#	define DDEBUG 0
#endif
#include "../ddebug.h"
#include "../ngx_http_lua_common.h"
#include "../ngx_http_lua_util.h"
#include "../ngx_http_lua_contentby.h"

#include <lua.h>
#include <lauxlib.h>

#define NGX_ETHER_FOREACH_RESTY_MEMC_OP(MACRO) \
	NGX_ETHER_FOREACH_MEMC_OP(MACRO) \
	MACRO(REPLACE, rep) \
	MACRO(DELETE, del) \
	MACRO(INCREMENT, incr) \
	MACRO(DECREMENT, decr) \
	MACRO(REPLACEQ, repq) \
	MACRO(DELETEQ, delq) \
	MACRO(INCREMENTQ, incrq) \
	MACRO(DECREMENTQ, decrq) \
	MACRO(RDELETE, rdel) \
	MACRO(RDELETEQ, rdelq) \
	MACRO(RINCR, rincr) \
	MACRO(RINCRQ, rincrq) \
	MACRO(RDECR, rdecr) \
	MACRO(RDECRQ, rdecrq) \
	MACRO(RGET, range_get) \
	MACRO(RSET, range_set) \
	MACRO(RSETQ, range_setq) \
	MACRO(RAPPEND, range_append) \
	MACRO(RAPPENDQ, range_appendq) \
	MACRO(RPREPEND, range_prepend) \
	MACRO(RPREPENDQ, range_prependq) \
	MACRO(RDELETE, range_del) \
	MACRO(RDELETE, range_delete) \
	MACRO(RDELETEQ, range_delq) \
	MACRO(RDELETEQ, range_deleteq) \
	MACRO(RINCR, range_incr) \
	MACRO(RINCR, range_increment) \
	MACRO(RINCRQ, range_incrq) \
	MACRO(RINCRQ, range_incrementq) \
	MACRO(RDECR, range_decr) \
	MACRO(RDECR, range_decrement) \
	MACRO(RDECRQ, range_decrq) \
	MACRO(RDECRQ, range_decrementq)

typedef struct {
	ngx_ether_peer_st peer;
} ngx_http_ether_lua_userdata_st;

typedef struct {
	ngx_ether_memc_op_st *op;
	ngx_http_request_t *r;
} ngx_http_ether_lua_memc_op_data_st;

#define ngx_http_ether_lua_get_str(L, idx, pool, str) \
	(str)->data = (u_char *)luaL_checklstring(L, -1, &(str)->len); \
	(str)->data = ngx_pstrdup((pool), (str)); \
	if (!(str)->data) { \
		luaL_error(L, "ngx_pstrdup failed"); \
	}

static ngx_int_t ngx_http_ether_lua_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_ether_lua_memc_resume(ngx_http_request_t *r);
static void ngx_http_ether_lua_memc_handler(ngx_ether_memc_op_st *op, void *data);
static void ngx_http_ether_lua_memc_op_cleanup(void *data);

static int ngx_http_ether_lua_new(lua_State *L);
static int ngx_http_ether_lua_default_key(lua_State *L);
static int ngx_http_ether_lua_get_key(lua_State *L);
static int ngx_http_ether_lua_has_default_key(lua_State *L);
static int ngx_http_ether_lua_memc_op_cmd(lua_State *L, protocol_binary_command cmd);
static int ngx_http_ether_lua_memc_op(lua_State *L);
#define DECLARE_RESTY_ETHER_MEMC_OP(op, name) \
	static int ngx_http_ether_lua_memc_##name(lua_State *L);
NGX_ETHER_FOREACH_RESTY_MEMC_OP(DECLARE_RESTY_ETHER_MEMC_OP)
static int ngx_http_ether_lua_destroy(lua_State *L);

static int ngx_http_ether_lua_preload(lua_State *L);
static ngx_int_t ngx_http_ether_lua_inject_lua(ngx_conf_t *cf);

static ngx_array_t ngx_ether_peers;
static int ngx_ether_has_init;

static const luaL_Reg ngx_http_ether_lua_meths[] = {
	{ "default_key", ngx_http_ether_lua_default_key },
	{ "get_key", ngx_http_ether_lua_get_key },
	{ "has_default_key", ngx_http_ether_lua_has_default_key },
	{ "memc_op", ngx_http_ether_lua_memc_op },
#define PUSH_FUNC_RESTY_ETHER_MEMC_OP(op, name) \
	{ "memc_" #name, ngx_http_ether_lua_memc_##name },
NGX_ETHER_FOREACH_RESTY_MEMC_OP(PUSH_FUNC_RESTY_ETHER_MEMC_OP)
	{ "__gc", ngx_http_ether_lua_destroy },
	{ NULL, NULL }
};

static const luaL_Reg ngx_http_ether_lua_funcs[] = {
	{ "new", ngx_http_ether_lua_new },
	{ NULL, NULL }
};

static ngx_http_module_t ngx_http_ether_lua_ctx = {
	NULL,                           /* preconfiguration */
	ngx_http_ether_lua_inject_lua,  /* postconfiguration */
	NULL,                           /* create main configuration */
	NULL,                           /* init main configuration */
	NULL,                           /* create server configuration */
	NULL,                           /* merge server configuration */
	NULL,                           /* create location configuration */
	NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_ether_lua_module = {
	NGX_MODULE_V1,
	&ngx_http_ether_lua_ctx,          /* module context */
	NULL,                             /* module directives */
	NGX_HTTP_MODULE,                  /* module type */
	NULL,                             /* init master */
	NULL,                             /* init module */
	ngx_http_ether_lua_init_process,  /* init process */
	NULL,                             /* init thread */
	NULL,                             /* exit thread */
	NULL,                             /* exit process */
	NULL,                             /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_ether_lua_init_process(ngx_cycle_t *cycle)
{
	ngx_ether_peer_st **peer;
	size_t i;

	ngx_ether_has_init = 1;

	peer = ngx_ether_peers.elts;
	for (i = 0; i < ngx_ether_peers.nelts; i++) {
		if (ngx_ether_connect_peer(peer[i]) != NGX_OK) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
				"ngx_ether_connect_peer failed");
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static int ngx_http_ether_lua_new(lua_State *L)
{
	int n;
#if 0
	ngx_http_request_t *r;
#endif
	ngx_http_ether_lua_userdata_st *ud;
	ngx_ether_peer_st *peer, **init_peer;

	n = lua_gettop(L);
	if (n != 0 && n != 1) {
		return luaL_error(L, "attempt to pass %d arguments, but accepted 0 or 1", n);
	}

	ud = lua_newuserdata(L, sizeof(ngx_http_ether_lua_userdata_st));
	ngx_memzero(ud, sizeof(ngx_http_ether_lua_userdata_st));

	luaL_getmetatable(L, "_M");
	lua_setmetatable(L, -2);

	peer = &ud->peer;

#if 0
	r = ngx_http_lua_get_request(L);

	if (r && r->pool) {
		peer->pool = r->pool;
	} else {
		peer->pool = ngx_cycle->pool;
	}

	if (r && r->connection && r->connection->log) {
		peer->log = r->connection->log;
	} else {
		peer->log = ngx_cycle->log;
	}
#else
	peer->pool = ngx_cycle->pool;
	peer->log = ngx_cycle->log;
#endif

	peer->memc.hex = 1;

	if (!n) {
		goto create_peer;
	}

	lua_getfield(L, 1, "serf");
	if (!lua_isnoneornil(L, -1)) {
		luaL_checktype(L, -1, LUA_TTABLE);

		lua_getfield(L, -1, "address");
		if (!lua_isnoneornil(L, -1)) {
			ngx_http_ether_lua_get_str(L, -1, peer->pool, &peer->serf.address);
		}
		lua_remove(L, -1);

		lua_getfield(L, -1, "auth");
		if (!lua_isnoneornil(L, -1)) {
			ngx_http_ether_lua_get_str(L, -1, peer->pool, &peer->serf.auth);
		}
		lua_remove(L, -1);

		lua_getfield(L, -1, "prefix");
		if (!lua_isnoneornil(L, -1)) {
			ngx_http_ether_lua_get_str(L, -1, peer->pool, &peer->serf.prefix);
		}
		lua_remove(L, -1);
	}
	lua_remove(L, -1);

	lua_getfield(L, 1, "memc");
	if (!lua_isnoneornil(L, -1)) {
		luaL_checktype(L, -1, LUA_TTABLE);

		lua_getfield(L, -1, "hex");
		if (!lua_isnoneornil(L, -1)) {
			luaL_checktype(L, -1, LUA_TBOOLEAN);
			peer->memc.hex = lua_toboolean(L, -1);
		}
		lua_remove(L, -1);

		lua_getfield(L, -1, "prefix");
		if (!lua_isnoneornil(L, -1)) {
			ngx_http_ether_lua_get_str(L, -1, peer->pool, &peer->memc.prefix);
		}
		lua_remove(L, -1);
	}
	lua_remove(L, -1);

create_peer:
	if (ngx_ether_create_peer(peer) != NGX_OK) {
		peer->pool = NULL;

		lua_pushnil(L);
		lua_pushliteral(L, "failed to create peer struct");
		return 2;
	}

	if (ngx_ether_has_init) {
		if (ngx_ether_connect_peer(peer) != NGX_OK) {
			ngx_ether_cleanup_peer(peer);

			lua_pushnil(L);
			lua_pushliteral(L, "failed to connect to peer");
			return 2;
		}
	} else {
		init_peer = ngx_array_push(&ngx_ether_peers);
		if (!init_peer) {
			ngx_ether_cleanup_peer(peer);

			return luaL_error(L, "ngx_array_push failed");
		}

		*init_peer = peer;
	}

	return 1;
}

static int ngx_http_ether_lua_return_key(lua_State *L, const ngx_ether_key_st *key)
{
	lua_createtable(L, 0, 4);

	lua_pushliteral(L, "name");
	lua_pushlstring(L, (const char *)key->name, SSL_TICKET_KEY_NAME_LEN);
	lua_settable(L, -3);

	lua_pushliteral(L, "key");
	lua_pushlstring(L, (const char *)key->key, key->key_len);
	lua_settable(L, -3);

	lua_pushliteral(L, "aead");
	lua_pushlightuserdata(L, (void *)key->aead);
	lua_settable(L, -3);

	lua_pushliteral(L, "was_default");
	lua_pushboolean(L, key->was_default);
	lua_settable(L, -3);

	return 1;
}

static int ngx_http_ether_lua_default_key(lua_State *L)
{
	int n;
	const ngx_http_ether_lua_userdata_st *ud;
	const ngx_ether_key_st *key;

	n = lua_gettop(L);
	if (n != 1) {
		return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
	}

	ud = luaL_checkudata(L, 1, "_M");

	key = ud->peer.default_key;
	if (!key) {
		lua_pushnil(L);
		lua_pushliteral(L, "no default key");
		return 2;
	}

	return ngx_http_ether_lua_return_key(L, key);
}

static int ngx_http_ether_lua_get_key(lua_State *L)
{
	int n;
	const ngx_http_ether_lua_userdata_st *ud;
	const ngx_ether_key_st *key;
	const u_char *name;
	size_t len;

	n = lua_gettop(L);
	if (n != 2) {
		return luaL_error(L, "attempt to pass %d arguments, but accepted 2", n);
	}

	ud = luaL_checkudata(L, 1, "_M");

	name = (const u_char *)luaL_checklstring(L, 2, &len);
	if (len != SSL_TICKET_KEY_NAME_LEN) {
		lua_pushnil(L);
		lua_pushliteral(L, "invalid key name length");
		return 2;
	}

	key = ngx_ether_get_key(&ud->peer, name);
	if (!key) {
		lua_pushnil(L);
		lua_pushliteral(L, "unkown key");
		return 2;
	}

	return ngx_http_ether_lua_return_key(L, key);
}

static int ngx_http_ether_lua_has_default_key(lua_State *L)
{
	int n;
	const ngx_http_ether_lua_userdata_st *ud;

	n = lua_gettop(L);
	if (n != 1) {
		return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
	}

	ud = luaL_checkudata(L, 1, "_M");

	lua_pushboolean(L, ud->peer.default_key != NULL);
	return 1;
}

static ngx_int_t ngx_http_ether_lua_memc_resume(ngx_http_request_t *r)
{
	lua_State *vm, *L;
	ngx_connection_t *c;
	ngx_int_t rc;
	ngx_http_lua_ctx_t *ctx;
	ngx_http_lua_co_ctx_t *coctx;
	ngx_http_ether_lua_memc_op_data_st *op_data;
	ngx_ether_memc_op_st *op;
	ngx_str_t value;
	int nret;
	union {
		protocol_binary_response_no_extras base;
		protocol_binary_response_get get;
		protocol_binary_response_incr incr;
	} res;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	if (ctx == NULL) {
		return NGX_ERROR;
	}

	ctx->resume_handler = ngx_http_lua_wev_handler;

	coctx = ctx->cur_co_ctx;
	op_data = coctx->data;
	op = op_data->op;
	L = coctx->co;

	rc = ngx_ether_memc_complete_operation(op, &value, &res.base);
	assert(rc != NGX_AGAIN);

	if (rc == NGX_OK) {
		switch (res.base.message.header.response.opcode) {
			case PROTOCOL_BINARY_CMD_INCREMENT:
			case PROTOCOL_BINARY_CMD_DECREMENT:
			case PROTOCOL_BINARY_CMD_INCREMENTQ:
			case PROTOCOL_BINARY_CMD_DECREMENTQ:
				lua_pushnumber(L, res.incr.message.body.value);
				lua_pushnil(L);
				break;
			case PROTOCOL_BINARY_CMD_GET:
			case PROTOCOL_BINARY_CMD_GETQ:
			case PROTOCOL_BINARY_CMD_GETK:
			case PROTOCOL_BINARY_CMD_GETKQ:
			case PROTOCOL_BINARY_CMD_GAT:
			case PROTOCOL_BINARY_CMD_GATQ:
			case PROTOCOL_BINARY_CMD_GATK:
			case PROTOCOL_BINARY_CMD_GATKQ:
				lua_pushlstring(L, (const char *)value.data, value.len);

				lua_newtable(L);
				lua_pushliteral(L, "flags");
				lua_pushnumber(L, res.get.message.body.flags);
				lua_settable(L, -3);
				break;
			default:
				lua_pushlstring(L, (const char *)value.data, value.len);
				lua_pushnil(L);
				break;
		}

		nret = 2;
	} else {
		/* rc == NGX_ERROR */
		lua_pushnil(L);
		lua_pushnil(L);

		switch (res.base.message.header.response.status) {
			case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
				lua_pushliteral(L, "KEY_ENOENT");
				break;
			case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
				lua_pushliteral(L, "KEY_EEXISTS");
				break;
			case PROTOCOL_BINARY_RESPONSE_E2BIG:
				lua_pushliteral(L, "E2BIG");
				break;
			case PROTOCOL_BINARY_RESPONSE_EINVAL:
				lua_pushliteral(L, "EINVAL");
				break;
			case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
				lua_pushliteral(L, "NOT_STORED");
				break;
			case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
				lua_pushliteral(L, "DELTA_BADVAL");
				break;
			case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
				lua_pushliteral(L, "AUTH_ERROR");
				break;
			case PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE:
				lua_pushliteral(L, "AUTH_CONTINUE");
				break;
			case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
				lua_pushliteral(L, "UNKNOWN_COMMAND");
				break;
			case PROTOCOL_BINARY_RESPONSE_ENOMEM:
				lua_pushliteral(L, "ENOMEM");
				break;
			default:
				lua_pushliteral(L, "unkown error");
				break;
		}

		nret = 3;
	}

	coctx->cleanup = NULL;
	ngx_http_ether_lua_memc_op_cleanup(op_data);

	c = r->connection;
	vm = ngx_http_lua_get_lua_vm(r, ctx);

	rc = ngx_http_lua_run_thread(vm, r, ctx, nret);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"lua run thread returned %d", rc);

	if (rc == NGX_AGAIN) {
		return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
	}

	if (rc == NGX_DONE) {
		ngx_http_lua_finalize_request(r, NGX_DONE);
		return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
	}

	if (ctx->entered_content_phase) {
		ngx_http_lua_finalize_request(r, rc);
		return NGX_DONE;
	}

	return rc;
}

static void ngx_http_ether_lua_memc_handler(ngx_ether_memc_op_st *op, void *data)
{
	ngx_http_lua_ctx_t *ctx;
	ngx_http_log_ctx_t *log_ctx;
	ngx_http_lua_co_ctx_t *coctx = data;
	ngx_http_ether_lua_memc_op_data_st *op_data;
	ngx_http_request_t *r;
	ngx_connection_t *c;

	op_data = coctx->data;
	r = op_data->r;
	c = r->connection;

	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	if (!ctx) {
		// ngx_http_ether_lua_memc_op_cleanup(op_data);
		return;
	}

	if (ngx_ether_memc_peak_operation(op) == NGX_AGAIN) {
		return;
	}

	if (c->fd != (ngx_socket_t) -1) {
		/* not a fake connection */
		log_ctx = c->log->data;
		log_ctx->current_request = r;
	}

	ctx->cur_co_ctx = coctx;

	if (ctx->entered_content_phase) {
		(void) ngx_http_ether_lua_memc_resume(r);
	} else {
		ctx->resume_handler = ngx_http_ether_lua_memc_resume;
		ngx_http_core_run_phases(r);
	}

	ngx_http_run_posted_requests(c);
}

static void ngx_http_ether_lua_memc_op_cleanup(void *data)
{
	ngx_http_ether_lua_memc_op_data_st *op_data = data;

	if (op_data->op) {
		ngx_ether_memc_cleanup_operation(op_data->op);
		op_data->op = NULL;
	}
}

static int ngx_http_ether_lua_memc_op_cmd(lua_State *L, protocol_binary_command cmd)
{
	int n, idx = 1, req_idx = -1;
	ngx_http_request_t *r;
	ngx_http_lua_ctx_t *ctx;
	ngx_http_lua_co_ctx_t *coctx;
	const ngx_http_ether_lua_userdata_st *ud;
	ngx_http_ether_lua_memc_op_data_st *op_data;
	const char *cmd_str;
	ngx_keyval_t kv;
	u_char *buf;
	ngx_ether_memc_server_st *server;
	ngx_ether_memc_op_st *op;
	union {
		protocol_binary_request_no_extras base;
		protocol_binary_request_set set;
		protocol_binary_request_incr incr;
		protocol_binary_request_flush flush;
		protocol_binary_request_touch touch;
		protocol_binary_request_gat gat;
	} req;

	n = lua_gettop(L);

	if (cmd != (protocol_binary_command)-1) {
		n++;
	}

	if (n < 3 || n > 5) {
		return luaL_error(L, "attempt to pass %d arguments, but accepted 3 to 5", n);
	}

	r = ngx_http_lua_get_request(L);
	if (!r) {
		return luaL_error(L, "no request found");
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
	if (!ctx) {
		return luaL_error(L, "no request ctx found");
	}

	ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_REWRITE
		| NGX_HTTP_LUA_CONTEXT_ACCESS
		| NGX_HTTP_LUA_CONTEXT_CONTENT
		| NGX_HTTP_LUA_CONTEXT_TIMER
		| NGX_HTTP_LUA_CONTEXT_SSL_CERT);

	coctx = ctx->cur_co_ctx;
	if (!coctx) {
		return luaL_error(L, "no co ctx found");
	}

	ud = luaL_checkudata(L, idx++, "_M");

	if (cmd == (protocol_binary_command)-1) {
		cmd_str = luaL_checkstring(L, idx++);

#define CHECK_RESTY_ETHER_CMD_STRS(op, name) \
		if (ngx_strcmp(cmd_str, #name) == 0) { \
			cmd = PROTOCOL_BINARY_CMD_##op; \
		} else
NGX_ETHER_FOREACH_RESTY_MEMC_OP(CHECK_RESTY_ETHER_CMD_STRS) {
			lua_pushnil(L);
			lua_pushnil(L);
			lua_pushliteral(L, "unknown command");
			return 3;
		}
	}

	kv.key.data = (u_char *)luaL_checklstring(L, idx++, &kv.key.len);
	ngx_str_null(&kv.value);

	ngx_memzero(&req, sizeof(req));

	switch (cmd) {
		case PROTOCOL_BINARY_CMD_INCREMENT:
		case PROTOCOL_BINARY_CMD_DECREMENT:
		case PROTOCOL_BINARY_CMD_INCREMENTQ:
		case PROTOCOL_BINARY_CMD_DECREMENTQ:
			req.incr.message.body.delta = 1;
			break;
		default:
			break;
	}

	if (n > 3) {
		if (lua_isstring(L, idx)) {
			kv.value.data = (u_char *)luaL_checklstring(L, idx++, &kv.value.len);
		} else if (lua_isnumber(L, idx)) {
			switch (cmd) {
				case PROTOCOL_BINARY_CMD_INCREMENT:
				case PROTOCOL_BINARY_CMD_DECREMENT:
				case PROTOCOL_BINARY_CMD_INCREMENTQ:
				case PROTOCOL_BINARY_CMD_DECREMENTQ:
					req.incr.message.body.delta = lua_tonumber(L, idx++);
					break;
				default:
					return luaL_error(L, "argument 4 must be string, got: number");
			}
		} else if (lua_istable(L, idx)) {
			if (n > 4) {
				return luaL_error(L, "attempt to pass %d arguments, but accepted 4", n);
			}

			req_idx = idx++;
		} else {
			return luaL_error(L, "argument 4 must be string, number or table, got: %s", lua_typename(L, lua_type(L, idx++)));
		}
	}

	if (n > 4) {
		if (req_idx != -1) {
			return luaL_error(L, "attempt to pass %d arguments, but accepted 4", n);
		}

		luaL_checktype(L, idx, LUA_TTABLE);
		req_idx = idx++;
	}

	if (req_idx != -1) {
		switch (cmd) {
			case PROTOCOL_BINARY_CMD_INCREMENT:
			case PROTOCOL_BINARY_CMD_DECREMENT:
			case PROTOCOL_BINARY_CMD_INCREMENTQ:
			case PROTOCOL_BINARY_CMD_DECREMENTQ:
				lua_getfield(L, req_idx, "initial");
				if (!lua_isnoneornil(L, -1)) {
					req.incr.message.body.initial = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);

				lua_getfield(L, req_idx, "expiration");
				if (!lua_isnoneornil(L, -1)) {
					req.incr.message.body.expiration = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);
				break;
			case PROTOCOL_BINARY_CMD_SET:
			case PROTOCOL_BINARY_CMD_ADD:
			case PROTOCOL_BINARY_CMD_REPLACE:
			case PROTOCOL_BINARY_CMD_SETQ:
			case PROTOCOL_BINARY_CMD_ADDQ:
			case PROTOCOL_BINARY_CMD_REPLACEQ:
				lua_getfield(L, req_idx, "flags");
				if (!lua_isnoneornil(L, -1)) {
					req.set.message.body.flags = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);

				lua_getfield(L, req_idx, "expiration");
				if (!lua_isnoneornil(L, -1)) {
					req.set.message.body.expiration = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);
				break;
			case PROTOCOL_BINARY_CMD_FLUSH:
			case PROTOCOL_BINARY_CMD_FLUSHQ:
				lua_getfield(L, req_idx, "expiration");
				if (!lua_isnoneornil(L, -1)) {
					req.flush.message.body.expiration = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);
				break;
			case PROTOCOL_BINARY_CMD_TOUCH:
				lua_getfield(L, req_idx, "expiration");
				if (!lua_isnoneornil(L, -1)) {
					req.touch.message.body.expiration = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);
				break;
			case PROTOCOL_BINARY_CMD_GAT:
			case PROTOCOL_BINARY_CMD_GATK:
			case PROTOCOL_BINARY_CMD_GATQ:
			case PROTOCOL_BINARY_CMD_GATKQ:
				lua_getfield(L, req_idx, "expiration");
				if (!lua_isnoneornil(L, -1)) {
					req.gat.message.body.expiration = luaL_checknumber(L, -1);
				}
				lua_remove(L, -1);
				break;
			default:
				break;
		}
	}

	buf = ngx_palloc(r->pool, NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN + kv.key.len*2);
	if (!buf) {
		return luaL_error(L, "ngx_palloc failed");
	}

	ngx_ether_process_session_key_id(&ud->peer, &kv.key, buf);

	server = ngx_ether_get_memc_server(&ud->peer, &kv.key);
	if (!server) {
		ngx_pfree(r->pool, buf);

		lua_pushnil(L);
		lua_pushnil(L);
		lua_pushliteral(L, "no memcached servers");
		return 3;
	}

	op = ngx_ether_memc_start_operation(server, cmd, &kv, &req.base);

	ngx_pfree(r->pool, buf);

	if (!op) {
		lua_pushnil(L);
		lua_pushnil(L);
		lua_pushliteral(L, "ngx_ether_memc_start_operation failed");
		return 3;
	}

	switch (cmd) {
		case PROTOCOL_BINARY_CMD_SETQ:
		case PROTOCOL_BINARY_CMD_ADDQ:
		case PROTOCOL_BINARY_CMD_REPLACEQ:
		case PROTOCOL_BINARY_CMD_DELETEQ:
		case PROTOCOL_BINARY_CMD_INCREMENTQ:
		case PROTOCOL_BINARY_CMD_DECREMENTQ:
		case PROTOCOL_BINARY_CMD_QUITQ:
		case PROTOCOL_BINARY_CMD_FLUSHQ:
		case PROTOCOL_BINARY_CMD_APPENDQ:
		case PROTOCOL_BINARY_CMD_PREPENDQ:
		case PROTOCOL_BINARY_CMD_RSETQ:
		case PROTOCOL_BINARY_CMD_RAPPENDQ:
		case PROTOCOL_BINARY_CMD_RPREPENDQ:
		case PROTOCOL_BINARY_CMD_RDELETEQ:
		case PROTOCOL_BINARY_CMD_RINCRQ:
		case PROTOCOL_BINARY_CMD_RDECRQ:
			lua_pushliteral(L, "success");
			lua_pushnil(L);
			return 2;
		default:
			break;
	}

#if 0
	if (r->connection && r->connection->log) {
		op->log = r->connection->log;
	}
#endif

	op->handler = ngx_http_ether_lua_memc_handler;
	op->handler_data = coctx;

	op_data = ngx_pcalloc(r->pool, sizeof(ngx_http_ether_lua_memc_op_data_st));
	if (!op_data) {
		return luaL_error(L, "ngx_pcalloc failed");
	}

	op_data->op = op;
	op_data->r = r;

	ngx_http_lua_cleanup_pending_operation(coctx);
	coctx->cleanup = ngx_http_ether_lua_memc_op_cleanup;
	coctx->data = op_data;

	return lua_yield(L, 0);
}

static int ngx_http_ether_lua_memc_op(lua_State *L)
{
	return ngx_http_ether_lua_memc_op_cmd(L, (protocol_binary_command)-1);
}

#define DEFINE_RESTY_ETHER_MEMC_OP(op, name) \
	static int ngx_http_ether_lua_memc_##name(lua_State *L) { \
		return ngx_http_ether_lua_memc_op_cmd(L, PROTOCOL_BINARY_CMD_##op); \
	}
NGX_ETHER_FOREACH_RESTY_MEMC_OP(DEFINE_RESTY_ETHER_MEMC_OP)

static int ngx_http_ether_lua_destroy(lua_State *L)
{
	ngx_http_ether_lua_userdata_st *ud;

	ud = luaL_checkudata(L, 1, "_M");

	if (ud->peer.pool) {
		ngx_ether_cleanup_peer(&ud->peer);
		ud->peer.pool = NULL;
	}

	return 0;
}

static int ngx_http_ether_lua_preload(lua_State *L)
{
	const luaL_Reg *l;

	luaL_newmetatable(L, "_M");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* luaL_setfuncs */
	for (l = ngx_http_ether_lua_meths; l->name != NULL; l++) {
		lua_pushcclosure(L, l->func, 0);
		lua_setfield(L, -2, l->name);
	}

	/* luaL_newlib */
	lua_createtable(L, 0, (sizeof(ngx_http_ether_lua_funcs) / sizeof(luaL_Reg)) - 1 + 1);
	for (l = ngx_http_ether_lua_funcs; l->name != NULL; l++) {
		lua_pushcclosure(L, l->func, 0);
		lua_setfield(L, -2, l->name);
	}

	lua_pushnumber(L, SSL_TICKET_KEY_NAME_LEN);
	lua_setfield(L, -2, "key_name_len");

	return 1;
}

static ngx_int_t ngx_http_ether_lua_inject_lua(ngx_conf_t *cf)
{
	if (!ngx_ether_peers.elts && ngx_array_init(&ngx_ether_peers, cf->cycle->pool, 16,
			sizeof(ngx_ether_peer_st *)) != NGX_OK) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init failed");
		return NGX_ERROR;
	}

	return ngx_http_lua_add_package_preload(cf, "nginx.ether",
		ngx_http_ether_lua_preload);
}
