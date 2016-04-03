#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <msgpack.h>

#include "protocol_binary.h"

#define MEMC_KEYS_ARE_HEX 0

#define INSTALL_KEY_EVENT "install-key"
#define REMOVE_KEY_EVENT "remove-key"
#define SET_DEFAULT_KEY_EVENT "set-default-key"

#define RETRIEVE_KEYS_QUERY "retrieve-keys"

#define STREAM_KEY_EVENTS \
	("user:" INSTALL_KEY_EVENT ",user:" REMOVE_KEY_EVENT ",user:" SET_DEFAULT_KEY_EVENT)

#define MEMC_SERVER_TAG_KEY "role"
#define MEMC_SERVER_TAG_VAL "memc"

#define MEMC_PORT_TAG_KEY "memc_port"

#define MEMBER_JOIN_EVENT "member-join"
#define MEMBER_LEAVE_EVENT "member-leave"
#define MEMBER_FAILED_EVENT "member-failed"
#define MEMBER_UPDATE_EVENT "member-update"

#define STREAM_MEMBER_EVENTS \
	(MEMBER_JOIN_EVENT "," MEMBER_LEAVE_EVENT "," MEMBER_FAILED_EVENT "," MEMBER_UPDATE_EVENT)

#define CHASH_NPOINTS 160

#define REALTIME_MAXDELTA 60*60*24*30

#define SERF_SEQ_STATE_MASK 0x0f

#ifndef HAVE_HTONLL
#if NGX_HAVE_LITTLE_ENDIAN
int64_t htonll(int64_t in);
int64_t ntohll(int64_t in);
#else /* NGX_HAVE_LITTLE_ENDIAN */
#define htonll(n) (n)
#define ntohll(n) (n)
#endif /* NGX_HAVE_LITTLE_ENDIAN */
#endif /* HAVE_HTONLL */

typedef struct _peer_st peer_st;

typedef struct {
	ngx_str_t serf_address;
	ngx_str_t serf_auth;
	ngx_msec_t timeout;
} srv_conf_t;

typedef enum {
	WAITING = 0,
	HANDSHAKING,
	AUTHENTICATING,
	STREAM_KEY_EVSUB,
	RETRIEVE_KEYS,
	STREAM_MEMBER_EVSUB,
	LISTING_MEMBERS
} state_et;

typedef struct {
	uint32_t hash;
	void *data;
} chash_point_st;

typedef struct {
	ngx_ssl_session_ticket_key_t key;

	int was_default;

	ngx_queue_t queue;
} key_st;

typedef struct {
	union {
		struct sockaddr addr;
		struct sockaddr_in sin;
#if NGX_HAVE_INET6
		struct sockaddr_in6 sin6;
#endif /* NGX_HAVE_INET6 */
	};
	size_t addr_len;

	ngx_str_t name;

	ngx_queue_t queue;
} memc_server_st;

typedef struct {
	protocol_binary_command cmd;

	ngx_connection_t *c;

	ngx_event_t *ev;

	peer_st *peer;

	ngx_buf_t send;
	ngx_buf_t recv;
} memc_op_st;

typedef struct _peer_st {
	struct {
		ngx_peer_connection_t pc;

		ngx_buf_t send;
		ngx_buf_t recv;

		ngx_str_t auth;

		state_et state;

		uint64_t seq;

		msgpack_sbuffer sbuf;
		msgpack_packer pk;
	} serf;

	struct {
		ngx_queue_t servers;

		ngx_uint_t npoints;
		chash_point_st *points;
	} memc;

	ngx_msec_t timeout;

	ngx_pool_t *pool;
	ngx_log_t *log;

	ngx_http_ssl_srv_conf_t *ssl;

	ngx_queue_t ticket_keys;
	key_st *default_ticket_key;
} peer_st;

typedef void (*add_serf_req_body_pt)(msgpack_packer *pk, peer_st *peer);
typedef ngx_int_t (*handle_serf_resp_pt)(ngx_connection_t *c, peer_st *peer, ssize_t size);

struct serf_cmd_st {
	state_et state;

	ngx_str_t name;

	add_serf_req_body_pt add_serf_req_body;
	handle_serf_resp_pt handle_serf_resp;
};

enum handle_member_resp_body_et {
	HANDLE_LIST_MEMBERS,
	HANDLE_ADD_MEMBER,
	HANDLE_REMOVE_MEMBER,
	HANDLE_UPDATE_MEMBER,
};

static ngx_int_t init_process(ngx_cycle_t *cycle);
static void exit_process(ngx_cycle_t *cycle);

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void serf_read_handler(ngx_event_t *rev);
static void serf_write_handler(ngx_event_t *wev);

static int serf_cmd_state_cmp(const void *in_a, const void *in_b);

static void add_handshake_req_body(msgpack_packer *pk, peer_st *peer);
static void add_auth_req_body(msgpack_packer *pk, peer_st *peer);
static void add_key_ev_req_body(msgpack_packer *pk, peer_st *peer);
static void add_key_query_req_body(msgpack_packer *pk, peer_st *peer);
static void add_member_ev_req_body(msgpack_packer *pk, peer_st *peer);
static void add_list_members_req_body(msgpack_packer *pk, peer_st *peer);

static ngx_int_t handle_handshake_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);
static ngx_int_t handle_auth_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);
static ngx_int_t handle_key_ev_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);
static ngx_int_t handle_key_query_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);
static ngx_int_t handle_member_ev_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);
static ngx_int_t handle_list_members_resp(ngx_connection_t *c, peer_st *peer, ssize_t size);

static ngx_int_t handle_member_resp_body(ngx_connection_t *c, peer_st *peer, msgpack_object *members,
		enum handle_member_resp_body_et todo);

static ngx_int_t ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size,
		ngx_log_t *log);
static char *ether_msgpack_parse_map(msgpack_object *obj, ...);

static int ngx_libc_cdecl chash_cmp_points(const void *one, const void *two);
static ngx_uint_t find_chash_point(ngx_uint_t npoints, chash_point_st *point, uint32_t hash);

static void memc_read_handler(ngx_event_t *rev);
static void memc_write_handler(ngx_event_t *wev);

static memc_op_st *memc_start_operation(peer_st *peer, protocol_binary_command cmd,
		ngx_str_t *key, ngx_str_t *value, void *data);
static ngx_int_t memc_complete_operation(memc_op_st *op, ngx_str_t *value, void *data);
static void memc_cleanup_operation(memc_op_st *op);
static void memc_cleanup_pool_handler(void *data);

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len,
		int *copy);
static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

static ngx_array_t peers = {0};

static int g_ssl_ctx_exdata_peer_index = -1;
static int g_ssl_exdata_memc_op_index = -1;

static const struct serf_cmd_st kSerfCMDs[] = {
	{ HANDSHAKING,
	  ngx_string("handshake"),
	  add_handshake_req_body,
	  handle_handshake_resp },
	{ AUTHENTICATING,
	  ngx_string("auth"),
	  add_auth_req_body,
	  handle_auth_resp },
	{ STREAM_KEY_EVSUB,
	  ngx_string("stream"),
	  add_key_ev_req_body,
	  handle_key_ev_resp },
	{ RETRIEVE_KEYS,
	  ngx_string("query"),
	  add_key_query_req_body,
	  handle_key_query_resp },
	{ STREAM_MEMBER_EVSUB,
	  ngx_string("stream"),
	  add_member_ev_req_body,
	  handle_member_ev_resp },
	{ LISTING_MEMBERS,
	  ngx_string("members-filtered"),
	  add_list_members_req_body,
	  handle_list_members_resp },
};
static const size_t kNumSerfCMDs = sizeof(kSerfCMDs) / sizeof(kSerfCMDs[0]);

static ngx_command_t module_commands[] = {
	{ ngx_string("ether"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, serf_address),
	  NULL },

	{ ngx_string("ether_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  set_opt_env_str,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, serf_auth),
	  NULL },

	{ ngx_string("ether_timeout"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_msec_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, timeout),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t module_ctx = {
	NULL,            /* preconfiguration */
	NULL,            /* postconfiguration */

	NULL,            /* create main configuration */
	NULL,            /* init main configuration */

	create_srv_conf, /* create server configuration */
	merge_srv_conf,  /* merge server configuration */

	NULL,            /* create location configuration */
	NULL             /* merge location configuration */
};

ngx_module_t ngx_http_ether_module = {
	NGX_MODULE_V1,
	&module_ctx,     /* module context */
	module_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL,            /* init master */
	NULL,            /* init module */
	init_process,    /* init process */
	NULL,            /* init thread */
	NULL,            /* exit thread */
	exit_process,    /* exit process */
	NULL,            /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t init_process(ngx_cycle_t *cycle)
{
	ngx_connection_t *c;
	peer_st *peer;
	ngx_peer_connection_t *pc;
	size_t i;
	ngx_int_t rc;
	ngx_event_t *rev, *wev;

	peer = peers.elts;
	for (i = 0; i < peers.nelts; i++) {
		pc = &peer[i].serf.pc;

		rc = ngx_event_connect_peer(pc);
		if (rc == NGX_ERROR || rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ngx_event_connect_peer failed");
			return NGX_ERROR;
		}

		c = pc->connection;
		c->data = &peer[i];

		rev = c->read;
		wev = c->write;

		c->log = cycle->log;
		rev->log = c->log;
		wev->log = c->log;
		c->pool = cycle->pool;

		rev->handler = serf_read_handler;
		wev->handler = serf_write_handler;

		if (peer[i].timeout) {
			// set timeout
		}

		/* The kqueue's loop interface needs it. */
		if (rc == NGX_OK) {
			c->write->handler(c->write);
		}
	}

	return NGX_OK;
}

static void exit_process(ngx_cycle_t *cycle)
{
	peer_st *peer;
	ngx_peer_connection_t *pc;
	ngx_connection_t *c;
	size_t i;

	peer = peers.elts;
	for (i = 0; i < peers.nelts; i++) {
		pc = &peer[i].serf.pc;

		c = pc->connection;
		if (c) {
			ngx_close_connection(c);
			pc->connection = NULL;
		}
	}
}

static void *create_srv_conf(ngx_conf_t *cf)
{
	srv_conf_t *escf;

	escf = ngx_pcalloc(cf->pool, sizeof(srv_conf_t));
	if (!escf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     escf->serf_address = { 0, NULL };
	 *     escf->serf_auth = { 0, NULL };
	 */

	escf->timeout = NGX_CONF_UNSET_MSEC;

	return escf;
}

static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	srv_conf_t *prev = parent;
	srv_conf_t *conf = child;
	ngx_http_ssl_srv_conf_t *ssl;
	ngx_url_t u;
	peer_st *peer;
	ngx_peer_connection_t *pc;
	union {
		uint64_t u64;
		uint8_t byte[sizeof(uint64_t)];
	} seq;

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	ngx_conf_merge_str_value(conf->serf_address, prev->serf_address, "");
	ngx_conf_merge_str_value(conf->serf_auth, prev->serf_auth, "");
	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, NGX_CONF_UNSET_MSEC);

	if (conf->timeout != NGX_CONF_UNSET_MSEC) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether_timeout directive not implemented");
		return NGX_CONF_ERROR;
	}

	if (!conf->serf_address.len || ngx_strcmp(conf->serf_address.data, "off") == 0) {
		return NGX_CONF_OK;
	}

	if (!ssl->session_tickets) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
			"ether cannot be used without ssl_session_tickets being enabled");
		return NGX_CONF_ERROR;
	}

	if (ssl->session_ticket_keys) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
			"ether cannot be used alongside the ssl_session_ticket_key directive");
		return NGX_CONF_ERROR;
	}

	if (ssl->builtin_session_cache != NGX_SSL_NONE_SCACHE) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
			"ether cannot be used without ssl_session_cache being unset (none)");
		return NGX_CONF_ERROR;
	}

	if (ngx_strcmp(conf->serf_address.data, "on") == 0) {
		ngx_str_set(&conf->serf_address, "127.0.0.1:7373");
	}

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url.len = conf->serf_address.len;
	u.url.data = conf->serf_address.data;
	u.default_port = 7373;
	u.no_resolve = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK || !u.addrs || !u.addrs[0].sockaddr) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid url given in ether directive");
		return NGX_CONF_ERROR;
	}

	if (!peers.elts) {
		if (ngx_array_init(&peers, cf->cycle->pool, 16, sizeof(peer_st)) != NGX_OK) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init failed");
			return NGX_CONF_ERROR;
		}
	}

	peer = ngx_array_push(&peers);
	if (!peer) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(peer, sizeof(peer_st));

	peer->serf.auth.data = conf->serf_auth.data;
	peer->serf.auth.len = conf->serf_auth.len;

	ngx_queue_init(&peer->memc.servers);

	if (conf->timeout != NGX_CONF_UNSET_MSEC) {
		peer->timeout = conf->timeout;
	}

	peer->pool = cf->cycle->pool;
	peer->log = cf->cycle->log;

	peer->ssl = ssl;

	ngx_queue_init(&peer->ticket_keys);

	pc = &peer->serf.pc;

	pc->sockaddr = u.addrs[0].sockaddr;
	pc->socklen = u.addrs[0].socklen;
	pc->name = &conf->serf_address;

	pc->get = ngx_event_get_peer;
	pc->log = cf->log;
	pc->log_error = NGX_ERROR_ERR;

	peer->serf.state = HANDSHAKING;

	do {
		if (RAND_bytes(seq.byte, sizeof(uint64_t)) != 1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "RAND_bytes failed");
			return NGX_CONF_ERROR;
		}

		seq.u64 &= ~(uint64_t)SERF_SEQ_STATE_MASK;
	} while (!seq.u64);

	peer->serf.seq = seq.u64;

	if (g_ssl_ctx_exdata_peer_index == -1) {
		g_ssl_ctx_exdata_peer_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_peer_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (g_ssl_exdata_memc_op_index == -1) {
		g_ssl_exdata_memc_op_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_memc_op_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_peer_index, peer)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data failed");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_options(ssl->ssl.ctx, SSL_OP_NO_TICKET);

	if (!SSL_CTX_set_tlsext_ticket_key_cb(ssl->ssl.ctx, session_ticket_key_handler)) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"nginx was built with Session Tickets support, however, "
			"now it is linked dynamically to an OpenSSL library "
			"which has no tlsext support");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_session_cache_mode(ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

	SSL_CTX_sess_set_new_cb(ssl->ssl.ctx, new_session_handler);
	SSL_CTX_sess_set_get_cb(ssl->ssl.ctx, get_cached_session_handler);
	SSL_CTX_sess_set_remove_cb(ssl->ssl.ctx, remove_session_handler);

	if (ssl->session_timeout > REALTIME_MAXDELTA) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"session_timeout cannot be greater than %d seconds, was %d seconds",
			REALTIME_MAXDELTA, ssl->session_timeout);

		ssl->session_timeout = REALTIME_MAXDELTA;
	}

	return NGX_CONF_OK;
}

static char *set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *p = conf;

	ngx_str_t *field, *value;
	ngx_conf_post_t *post;

	field = (ngx_str_t *)(p + cmd->offset);
	if (field->data) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "is duplicate");
		return NGX_CONF_ERROR;
	}

	value = cf->args->elts;

	if (cf->args->nelts == 3) {
		if (ngx_strcmp(value[2].data, "env") != 0) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "only env flag supported");
			return NGX_CONF_ERROR;
		}

		field->data = (u_char *)getenv((const char *)value[1].data);
		if (field->data) {
			field->len = ngx_strlen(field->data);
		}
	} else {
		*field = value[1];
	}

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, field);
	}

	return NGX_CONF_OK;
}

static ngx_int_t ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size,
		ngx_log_t *log)
{
	size_t off = 0;
	msgpack_unpack_return ret;

	ret = msgpack_unpack_next(und, (char *)recv->pos, recv->last - recv->pos, &off);
	switch (ret) {
		case MSGPACK_UNPACK_EXTRA_BYTES:
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"msgpack_unpack_next succeeded but left trailing bytes");
		case MSGPACK_UNPACK_SUCCESS:
			recv->pos += off;
			return NGX_OK;
		case MSGPACK_UNPACK_CONTINUE:
			if (size == NGX_AGAIN) {
				return NGX_AGAIN;
			}

			recv->pos += off;

			if (recv->pos == recv->last) {
				recv->pos = recv->start;
				recv->last = recv->start;
			}

			ngx_log_error(NGX_LOG_ERR, log, 0,
				"msgpack_unpack_next failed with unexpected eof");
			return NGX_AGAIN;
		case MSGPACK_UNPACK_NOMEM_ERROR:
			ngx_log_error(NGX_LOG_ERR, log, 0,
				"msgpack_unpack_next failed with nomem error");
			return NGX_ABORT;
		default: /* MSGPACK_UNPACK_PARSE_ERROR */
			recv->pos += off;

			if (recv->pos == recv->last) {
				recv->pos = recv->start;
				recv->last = recv->start;
			}

			ngx_log_error(NGX_LOG_ERR, log, 0,
				"msgpack_unpack_next failed with parse error");
			return NGX_ERROR;
	}
}

static char *ether_msgpack_parse_map(msgpack_object *obj, ...)
{
	va_list ap;
	msgpack_object *out;
	msgpack_object_kv *ptr;
	msgpack_object_str *str;
	size_t i;
	int found;
	char *name = NULL;

	if (obj->type != MSGPACK_OBJECT_MAP) {
		return "malformed RPC response, expected a map";
	}

	va_start(ap, obj);
	for (;;) {
		name = va_arg(ap, char *);
		if (!name) {
			break;
		}

		out = va_arg(ap, msgpack_object *);

		found = 0;

		for (i = 0; i < obj->via.map.size; i++) {
			ptr = &obj->via.map.ptr[i];

			if (ptr->key.type != MSGPACK_OBJECT_STR) {
				va_end(ap);
				return "malformed RPC response, expect key to be string";
			}

			str = &ptr->key.via.str;
			if (ngx_strncmp(str->ptr, name, str->size) == 0) {
				found = 1;

				if (out) {
					*out = ptr->val;
				}

				if (out && out->type && ptr->val.type != out->type) {
					va_end(ap);
					return "malformed RPC response, wrong type given";
				}

				break;
			}
		}

		if (!found) {
			va_end(ap);
			return "malformed RPC response, key not found";
		}
	}
	va_end(ap);

	return NULL;
}

static void dummy_write_handler(ngx_event_t *wev) { }

static void serf_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size, n;
	msgpack_unpacked und;
	void *hdr_start;
	u_char *new_buf;
	char *err;
	msgpack_object seq, error;
	struct serf_cmd_st *cmd, b;

	c = rev->data;
	peer = c->data;

	if (!peer->serf.recv.start) {
		/* 1/4 of the page_size, is it enough? */
		peer->serf.recv.start = ngx_palloc(c->pool, ngx_pagesize / 4);
		if (!peer->serf.recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");
			return;
		}

		peer->serf.recv.pos = peer->serf.recv.start;
		peer->serf.recv.last = peer->serf.recv.start;
		peer->serf.recv.end = peer->serf.recv.start + ngx_pagesize / 4;
	}

	while (1) {
		n = peer->serf.recv.end - peer->serf.recv.last;

		/* buffer not big enough? enlarge it by twice */
		if (n == 0) {
			size = peer->serf.recv.end - peer->serf.recv.start;

			new_buf = ngx_palloc(c->pool, size * 2);
			if (!new_buf) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated new recv buffer");
				return;
			}

			ngx_memcpy(new_buf, peer->serf.recv.start, size);

			peer->serf.recv.start = new_buf;
			peer->serf.recv.pos = new_buf;
			peer->serf.recv.last = new_buf + size;
			peer->serf.recv.end = new_buf + size * 2;

			n = peer->serf.recv.end - peer->serf.recv.last;
		}

		size = c->recv(c, peer->serf.recv.last, n);

		if (size > 0) {
			peer->serf.recv.last += size;
			continue;
		} else if (size == 0 || size == NGX_AGAIN) {
			break;
		} else {
			c->error = 1;
			return;
		}
	}

	msgpack_unpacked_init(&und);

	hdr_start = peer->serf.recv.pos;

	switch (ether_msgpack_parse(&und, &peer->serf.recv, size, c->log)) {
		case NGX_OK:
			break;
		case NGX_AGAIN:
			goto cleanup;
		case NGX_ABORT:
			exit(2); // something else?
		default: /* NGX_ERROR */
			goto done;
	}

	seq.type = MSGPACK_OBJECT_POSITIVE_INTEGER;
	error.type = MSGPACK_OBJECT_STR;

	err = ether_msgpack_parse_map(&und.data, "Seq", &seq, "Error", &error, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto done;
	}

	if (error.via.str.size) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ether RPC error: %*s",
			error.via.str.size, error.via.str.ptr);
		goto done;
	}

	if (peer->serf.seq != (seq.via.u64 & ~(uint64_t)SERF_SEQ_STATE_MASK)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"unrecognised RPC seq number: %xd", seq.via.u64);
		goto done;
	}

	b.state = seq.via.u64 & SERF_SEQ_STATE_MASK;
	cmd = bsearch(&b, kSerfCMDs, kNumSerfCMDs, sizeof(struct serf_cmd_st), serf_cmd_state_cmp);
	if (!cmd) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"unrecognised RPC seq number: %xd", seq.via.u64);
		goto done;
	}

	switch (cmd->handle_serf_resp(c, peer, size)) {
		case NGX_AGAIN:
			peer->serf.recv.pos = hdr_start;
			goto cleanup;
		case NGX_ABORT:
			exit(2); // something else?
		default: /* NGX_OK || NGX_ERROR */
			break;
	}

done:
	peer->serf.recv.pos = peer->serf.recv.start;
	peer->serf.recv.last = peer->serf.recv.start;

cleanup:
	msgpack_unpacked_destroy(&und);
}

static void serf_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size;
	msgpack_sbuffer *sbuf;
	msgpack_packer *pk;
	struct serf_cmd_st *cmd, b;

	c = wev->data;
	peer = c->data;

	sbuf = &peer->serf.sbuf;
	pk = &peer->serf.pk;

	if (!peer->serf.send.start) {
		b.state = peer->serf.state;
		cmd = bsearch(&b, kSerfCMDs, kNumSerfCMDs, sizeof(struct serf_cmd_st),
			serf_cmd_state_cmp);
		if (!cmd) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"write_handler called in invalid state");
			return;
		}

		msgpack_sbuffer_init(sbuf);
		msgpack_packer_init(pk, sbuf, msgpack_sbuffer_write);

		// header
		// {"Command": "handshake", "Seq": 0}
		msgpack_pack_map(pk, 2);

		msgpack_pack_str(pk, sizeof("Command") - 1);
		msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
		msgpack_pack_str(pk, cmd->name.len);
		msgpack_pack_str_body(pk, cmd->name.data, cmd->name.len);

		msgpack_pack_str(pk, sizeof("Seq") - 1);
		msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
		msgpack_pack_uint64(pk, peer->serf.seq | peer->serf.state);

		// body
		cmd->add_serf_req_body(pk, peer);

		peer->serf.send.start = (u_char *)sbuf->data;
		peer->serf.send.pos = (u_char *)sbuf->data;
		peer->serf.send.last = (u_char *)sbuf->data + sbuf->size;
		peer->serf.send.end = (u_char *)sbuf->data + sbuf->alloc;
	}

	while (peer->serf.send.pos < peer->serf.send.last) {
		size = c->send(c, peer->serf.send.pos, peer->serf.send.last - peer->serf.send.pos);
		if (size > 0) {
			peer->serf.send.pos += size;
		} else if (size == 0 || size == NGX_AGAIN) {
			return;
		} else {
			c->error = 1;
			return;
		}
	}

	if (peer->serf.send.pos == peer->serf.send.last) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ether send done");

		peer->serf.send.start = NULL;
		peer->serf.send.pos = NULL;
		peer->serf.send.last = NULL;
		peer->serf.send.end = NULL;

		msgpack_sbuffer_destroy(sbuf);

		c->write->handler = dummy_write_handler;
	}
}

static int serf_cmd_state_cmp(const void *in_a, const void *in_b)
{
	const struct serf_cmd_st *a = in_a;
	const struct serf_cmd_st *b = in_b;

	if (a->state > b->state) {
		return 1;
	} else if (a->state < b->state) {
		return -1;
	} else {
		return 0;
	}
}

static void add_handshake_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {"Version": 1}

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Version") - 1);
	msgpack_pack_str_body(pk, "Version", sizeof("Version") - 1);
	msgpack_pack_int32(pk, 1);
}

static void add_auth_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {"AuthKey": "my-secret-auth-token"}

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("AuthKey") - 1);
	msgpack_pack_str_body(pk, "AuthKey", sizeof("AuthKey") - 1);
	msgpack_pack_str(pk, peer->serf.auth.len);
	msgpack_pack_str_body(pk, peer->serf.auth.data, peer->serf.auth.len);
}

static void add_key_ev_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {"Type": "member-join,user:deploy"}`

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Type") - 1);
	msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
	msgpack_pack_str(pk, sizeof(STREAM_KEY_EVENTS) - 1);
	msgpack_pack_str_body(pk, STREAM_KEY_EVENTS, sizeof(STREAM_KEY_EVENTS) - 1);
}

static void add_key_query_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {
	// 	"FilterNodes": ["foo", "bar"],
	// 	"FilterTags": {"role": ".*web.*"},
	// 	"RequestAck": true,
	// 	"Timeout": 0,
	// 	"Name": "load",
	// 	"Payload": "15m",
	// }

	msgpack_pack_map(pk, 6);

	msgpack_pack_str(pk, sizeof("FilterNodes") - 1);
	msgpack_pack_str_body(pk, "FilterNodes", sizeof("FilterNodes") - 1);
	msgpack_pack_array(pk, 0);

	msgpack_pack_str(pk, sizeof("FilterTags") - 1);
	msgpack_pack_str_body(pk, "FilterTags", sizeof("FilterTags") - 1);
	msgpack_pack_map(pk, 0);

	msgpack_pack_str(pk, sizeof("RequestAck") - 1);
	msgpack_pack_str_body(pk, "RequestAck", sizeof("RequestAck") - 1);
	msgpack_pack_false(pk);

	msgpack_pack_str(pk, sizeof("Timeout") - 1);
	msgpack_pack_str_body(pk, "Timeout", sizeof("Timeout") - 1);
	msgpack_pack_int64(pk, 0);

	msgpack_pack_str(pk, sizeof("Name") - 1);
	msgpack_pack_str_body(pk, "Name", sizeof("Name") - 1);
	msgpack_pack_str(pk, sizeof(RETRIEVE_KEYS_QUERY) - 1);
	msgpack_pack_str_body(pk, RETRIEVE_KEYS_QUERY, sizeof(RETRIEVE_KEYS_QUERY) - 1);

	msgpack_pack_str(pk, sizeof("Payload") - 1);
	msgpack_pack_str_body(pk, "Payload", sizeof("Payload") - 1);
	msgpack_pack_bin(pk, 0);
}

static void add_member_ev_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {"Type": "member-join,user:deploy"}`

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Type") - 1);
	msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
	msgpack_pack_str(pk, sizeof(STREAM_MEMBER_EVENTS) - 1);
	msgpack_pack_str_body(pk, STREAM_MEMBER_EVENTS, sizeof(STREAM_MEMBER_EVENTS) - 1);
}

static void add_list_members_req_body(msgpack_packer *pk, peer_st *peer)
{
	// {"Tags": {"key": "val"}, "Status": "alive", "Name": "node1"}

	msgpack_pack_map(pk, 2);

	msgpack_pack_str(pk, sizeof("Tags") - 1);
	msgpack_pack_str_body(pk, "Tags", sizeof("Tags") - 1);
	msgpack_pack_map(pk, 1);
	msgpack_pack_str(pk, sizeof(MEMC_SERVER_TAG_KEY) - 1);
	msgpack_pack_str_body(pk, MEMC_SERVER_TAG_KEY, sizeof(MEMC_SERVER_TAG_KEY) - 1);
	msgpack_pack_str(pk, sizeof(MEMC_SERVER_TAG_VAL) - 1);
	msgpack_pack_str_body(pk, MEMC_SERVER_TAG_VAL, sizeof(MEMC_SERVER_TAG_VAL) - 1);

	msgpack_pack_str(pk, sizeof("Status") - 1);
	msgpack_pack_str_body(pk, "Status", sizeof("Status") - 1);
	msgpack_pack_str(pk, sizeof("alive") - 1);
	msgpack_pack_str_body(pk, "alive", sizeof("alive") - 1);
}

static ngx_int_t handle_handshake_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	if (peer->serf.state != HANDSHAKING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC handshake response");
		return NGX_ERROR;
	}

	if (peer->serf.auth.len) {
		peer->serf.state = AUTHENTICATING;
	} else {
		peer->serf.state = STREAM_KEY_EVSUB;
	}

	c->write->handler = serf_write_handler;
	return NGX_OK;
}

static ngx_int_t handle_auth_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	if (peer->serf.state != AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC auth response");
		return NGX_ERROR;
	}

	peer->serf.state = STREAM_KEY_EVSUB;

	c->write->handler = serf_write_handler;
	return NGX_OK;
}

static ngx_int_t handle_key_ev_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object event, name, payload = {0};
	key_st *key;
	ngx_queue_t *q;
	char *err;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif

	// {
	// 	"Event": "user",
	// 	"LTime": 123,
	// 	"Name": "deploy",
	// 	"Payload": "9c45b87",
	// 	"Coalesce": true,
	// }

	if (peer->serf.state == STREAM_KEY_EVSUB) {
		peer->serf.state = RETRIEVE_KEYS;

		c->write->handler = serf_write_handler;
		return NGX_OK;
	}

	if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	event.type = MSGPACK_OBJECT_STR;
	name.type = MSGPACK_OBJECT_STR;
	payload.type = MSGPACK_OBJECT_BIN;

	err = ether_msgpack_parse_map(&und.data,
		"Event", &event, "Name", &name, "Payload", &payload,
		"LTime", NULL, "Coalesce", NULL,
		NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	if (ngx_strncmp(event.via.str.ptr, "user", event.via.str.size) != 0) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			event.via.str.size, event.via.str.ptr);
		return NGX_ERROR;
	}

	if (ngx_strncmp(name.via.str.ptr, INSTALL_KEY_EVENT, name.via.str.size) == 0) {
		if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN + 32) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
			goto error;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket key install: \"%*s\"",
			ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->key.name,
					SSL_TICKET_KEY_NAME_LEN) == 0) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					INSTALL_KEY_EVENT " event: already have key");
				goto error;
			}
		}

		key = ngx_pcalloc(c->pool, sizeof(key_st)); // is this the right pool?
		if (!key) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
			goto error;
		}

		ngx_memcpy(key->key.name, payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN);
		ngx_memcpy(key->key.aes_key, payload.via.bin.ptr + SSL_TICKET_KEY_NAME_LEN, 16);
		ngx_memcpy(key->key.hmac_key, payload.via.bin.ptr + SSL_TICKET_KEY_NAME_LEN + 16, 16);

		ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);
	} else if (ngx_strncmp(name.via.str.ptr, REMOVE_KEY_EVENT, name.via.str.size) == 0) {
		if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
			goto error;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket key removal: \"%*s\"",
			ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->key.name,
				SSL_TICKET_KEY_NAME_LEN) != 0) {
				continue;
			}

			ngx_queue_remove(q);

			if (key == peer->default_ticket_key) {
				peer->default_ticket_key = NULL;

				SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
				SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					REMOVE_KEY_EVENT " event: "
					"on default key, session ticket and cache support disabled");
			}

			ngx_memzero(&key->key, sizeof(key->key));
			ngx_pfree(c->pool, key); // is this the right pool?
			break;
		}
	} else if (ngx_strncmp(name.via.str.ptr, SET_DEFAULT_KEY_EVENT, name.via.str.size) == 0) {
		if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
			goto error;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket key set default: \"%*s\"",
			ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		if (ngx_queue_empty(&peer->ticket_keys)) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
					SET_DEFAULT_KEY_EVENT " event: without any keys");
			goto error;
		}

		if (peer->default_ticket_key) {
			peer->default_ticket_key->was_default = 1;
			peer->default_ticket_key = NULL;
		}

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->key.name,
						SSL_TICKET_KEY_NAME_LEN) == 0) {
				key->was_default = 0;
				peer->default_ticket_key = key;

				SSL_CTX_clear_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

				if (!ngx_queue_empty(&peer->memc.servers)) {
					SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx,
						SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
				}

				break;
			}
		}

		if (!peer->default_ticket_key) {
			SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
			SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				SET_DEFAULT_KEY_EVENT " event: "
				"on unknown key, session ticket and cache support disabled");
			goto error;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			name.via.str.size, name.via.str.ptr);
		goto error;
	}

#if NGX_DEBUG
	{
	size_t num = 0;

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		num++;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl session ticket key have %d keys", num);
	}
#endif

	if (payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	return NGX_OK;

error:
	if (payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	return NGX_ERROR;
}

static ngx_int_t handle_key_query_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object *ptr, payload = {0}, type, default_key, keys;
	key_st *key;
	ngx_queue_t *q;
	char *err;
	ngx_buf_t dummy_recv;
	size_t i;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif

	// {
	// 	"Type": "response",
	// 	"From": "foo",
	// 	"Payload": "1.02",
	// }

	if (peer->serf.state == RETRIEVE_KEYS) {
		peer->serf.state = STREAM_MEMBER_EVSUB;

		c->write->handler = serf_write_handler;
		return NGX_OK;
	}

	if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	type.type = MSGPACK_OBJECT_STR;

	err = ether_msgpack_parse_map(&und.data, "Type", &type, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	if (ngx_strncmp(type.via.str.ptr, "ack", type.via.str.size) == 0
		|| ngx_strncmp(type.via.str.ptr, "done", type.via.str.size) == 0) {
		return NGX_OK;
	}

	if (ngx_strncmp(type.via.str.ptr, "response", type.via.str.size) != 0) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised query response type from serf: %*s",
			type.via.str.size, type.via.str.ptr);
		return NGX_ERROR;
	}

	payload.type = MSGPACK_OBJECT_BIN;

	err = ether_msgpack_parse_map(&und.data, "From", NULL, "Payload", &payload, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	dummy_recv.start = (u_char *)payload.via.bin.ptr;
	dummy_recv.pos = (u_char *)payload.via.bin.ptr;
	dummy_recv.last = (u_char *)payload.via.bin.ptr + payload.via.bin.size;
	dummy_recv.end = (u_char *)payload.via.bin.ptr + payload.via.bin.size;

	rc = ether_msgpack_parse(&und, &dummy_recv, 0, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	default_key.type = MSGPACK_OBJECT_BIN;
	keys.type = MSGPACK_OBJECT_ARRAY;

	err = ether_msgpack_parse_map(&und.data, "Default", &default_key, "Keys", &keys, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	if (default_key.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid default key size");
		goto error;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"ssl session ticket key set default: \"%*s\"",
		ngx_hex_dump(buf, (u_char *)default_key.via.bin.ptr,
			SSL_TICKET_KEY_NAME_LEN) - buf, buf);

	if (peer->default_ticket_key) {
		peer->default_ticket_key->was_default = 1;
		peer->default_ticket_key = NULL;
	}

	for (i = 0; i < keys.via.array.size; i++) {
		ptr = &keys.via.array.ptr[i];

		if (ptr->type != MSGPACK_OBJECT_BIN) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"malformed RPC response, wrong type given");
			goto error;
		}

		if (ptr->via.bin.size != SSL_TICKET_KEY_NAME_LEN + 32) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid ssl session ticket key size");
			goto error;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket key install: \"%*s\"",
			ngx_hex_dump(buf, (u_char *)ptr->via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, key_st, queue);

			if (ngx_memcmp(ptr->via.bin.ptr, key->key.name,
					SSL_TICKET_KEY_NAME_LEN) == 0) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
					RETRIEVE_KEYS_QUERY " query: already have key");
				goto is_default_key;
			}
		}

		key = ngx_pcalloc(c->pool, sizeof(key_st)); // is this the right pool?
		if (!key) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
			goto error;
		}

		ngx_memcpy(key->key.name, ptr->via.bin.ptr, SSL_TICKET_KEY_NAME_LEN);
		ngx_memcpy(key->key.aes_key, ptr->via.bin.ptr + SSL_TICKET_KEY_NAME_LEN, 16);
		ngx_memcpy(key->key.hmac_key, ptr->via.bin.ptr + SSL_TICKET_KEY_NAME_LEN + 16, 16);

		ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);

	is_default_key:
		if (ngx_memcmp(ptr->via.bin.ptr, default_key.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) == 0) {
			peer->default_ticket_key = key;

			SSL_CTX_clear_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

			if (!ngx_queue_empty(&peer->memc.servers)) {
				SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx,
					SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
			}
		}
	}

	if (!peer->default_ticket_key) {
		SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			RETRIEVE_KEYS_QUERY " query: "
			"no valid default key given, session ticket and cache support disabled");
	}

#if NGX_DEBUG
	{
	size_t num = 0;

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		num++;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl session ticket key have %d keys", num);
	}
#endif

	if (payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	return NGX_OK;

error:
	if (payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	return NGX_ERROR;
}

static ngx_int_t handle_member_ev_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object event, members;
	char *err;
	enum handle_member_resp_body_et todo;

	// {
	// 	"Event": "member-join",
	// 	"Members": [
	// 		{
	// 			"Name": "TestNode"
	// 			"Addr": [127, 0, 0, 1],
	// 			"Port": 5000,
	// 			"Tags": {
	// 				"role": "test"
	// 			},
	// 			"Status": "alive",
	// 			"ProtocolMin": 0,
	// 			"ProtocolMax": 3,
	// 			"ProtocolCur": 2,
	// 			"DelegateMin": 0,
	// 			"DelegateMax": 1,
	// 			"DelegateCur": 1,
	// 		},
	// 		...
	// 	]
	// }

	if (peer->serf.state == STREAM_MEMBER_EVSUB) {
		peer->serf.state = LISTING_MEMBERS;

		c->write->handler = serf_write_handler;
		return NGX_OK;
	}

	if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	event.type = MSGPACK_OBJECT_STR;
	members.type = MSGPACK_OBJECT_ARRAY;

	err = ether_msgpack_parse_map(&und.data, "Event", &event, "Members", &members, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	if (ngx_strncmp(event.via.str.ptr, MEMBER_JOIN_EVENT, event.via.str.size) == 0) {
		todo = HANDLE_ADD_MEMBER;
	} else if (ngx_strncmp(event.via.str.ptr, MEMBER_LEAVE_EVENT, event.via.str.size) == 0
		|| ngx_strncmp(event.via.str.ptr, MEMBER_FAILED_EVENT, event.via.str.size) == 0) {
		todo = HANDLE_REMOVE_MEMBER;
	} else if (ngx_strncmp(event.via.str.ptr, MEMBER_UPDATE_EVENT, event.via.str.size) == 0) {
		todo = HANDLE_UPDATE_MEMBER;
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			event.via.str.size, event.via.str.ptr);
		return NGX_ERROR;
	}

	return handle_member_resp_body(c, peer, &members, todo);
}

static ngx_int_t handle_list_members_resp(ngx_connection_t *c, peer_st *peer, ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object members;
	char *err;

	// {
	// 	"Members": [
	// 		{
	// 			"Name": "TestNode"
	// 			"Addr": [127, 0, 0, 1],
	// 			"Port": 5000,
	// 			"Tags": {
	// 				"role": "test"
	// 			},
	// 			"Status": "alive",
	// 			"ProtocolMin": 0,
	// 			"ProtocolMax": 3,
	// 			"ProtocolCur": 2,
	// 			"DelegateMin": 0,
	// 			"DelegateMax": 1,
	// 			"DelegateCur": 1,
	// 		},
	// 	...]
	// }

	if (peer->serf.state == LISTING_MEMBERS) {
		peer->serf.state = WAITING;
	}

	if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	members.type = MSGPACK_OBJECT_ARRAY;

	err = ether_msgpack_parse_map(&und.data, "Members", &members, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	return handle_member_resp_body(c, peer, &members, HANDLE_LIST_MEMBERS);
}

static ngx_int_t handle_member_resp_body(ngx_connection_t *c, peer_st *peer, msgpack_object *members,
		enum handle_member_resp_body_et todo)
{
	msgpack_object name, addr, tags, status;
	msgpack_object_kv *ptr_kv;
	msgpack_object_str *str;
	ngx_queue_t *q;
	char *err;
	int skip_member, have_changed, add_member, remove_member, update_member;
	memc_server_st *server = NULL;
	unsigned char *s_addr;
	uint32_t hash, base_hash;
	union {
		uint32_t value;
		u_char byte[4];
	} prev_hash;
	ngx_int_t rc;
	unsigned short port;
	u_char str_addr[NGX_SOCKADDR_STRLEN];
	u_char str_port[sizeof("65535") - 1];
	size_t i, j, num;

	have_changed = 0;

	add_member = 0;
	remove_member = 0;
	update_member = 0;

	switch (todo) {
		case HANDLE_LIST_MEMBERS:
		case HANDLE_ADD_MEMBER:
			add_member = 1;
			break;
		case HANDLE_REMOVE_MEMBER:
			remove_member = 1;
			break;
		case HANDLE_UPDATE_MEMBER:
			update_member = 1;
			break;
	}

	for (i = 0; i < members->via.array.size; i++) {
		name.type = MSGPACK_OBJECT_STR;
		addr.type = MSGPACK_OBJECT_BIN;
		tags.type = MSGPACK_OBJECT_MAP;
		status.type = MSGPACK_OBJECT_STR;

		err = ether_msgpack_parse_map(&members->via.array.ptr[i],
			"Name", &name,
			"Addr", &addr,
			"Port", NULL,
			"Tags", &tags,
			"Status", &status,
			"ProtocolMin", NULL,
			"ProtocolMax", NULL,
			"ProtocolCur", NULL,
			"DelegateMin", NULL,
			"DelegateMax", NULL,
			"DelegateCur", NULL,
			NULL);
		if (err) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
			return NGX_ERROR;
		}

		if (todo == HANDLE_LIST_MEMBERS) {
			skip_member = 0;
		} else {
			skip_member = 1;
		}

		port = 11211;

		for (j = 0; j < tags.via.map.size; j++) {
			ptr_kv = &tags.via.map.ptr[j];

			if (ptr_kv->key.type != MSGPACK_OBJECT_STR) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"malformed RPC response, expect key to be string");
				return NGX_ERROR;
			}

			str = &ptr_kv->key.via.str;
			if (skip_member && ngx_strncmp(str->ptr, MEMC_SERVER_TAG_KEY,
					str->size) == 0) {
				if (ptr_kv->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"malformed RPC response, expect value to be string");
					return NGX_ERROR;
				}

				str = &ptr_kv->val.via.str;
				if (ngx_strncmp(str->ptr, MEMC_SERVER_TAG_VAL, str->size) != 0) {
					break;
				}

				skip_member = 0;
				continue;
			}

			if (ngx_strncmp(str->ptr, MEMC_PORT_TAG_KEY, str->size) == 0) {
				if (ptr_kv->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"malformed RPC response, expect value to be string");
					return NGX_ERROR;
				}

				str = &ptr_kv->val.via.str;

				rc = ngx_atoi((u_char *)str->ptr, str->size);
				if (rc == NGX_ERROR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"malformed RPC response, "
						"expect " MEMC_PORT_TAG_KEY " tag to be "
						"a valid number");

					skip_member = 1;
					break;
				}

				port = (unsigned short)rc;
				continue;
			}
		}

		if ((update_member && skip_member) || remove_member) {
			for (q = ngx_queue_head(&peer->memc.servers);
				q != ngx_queue_sentinel(&peer->memc.servers);
				q = ngx_queue_next(q)) {
				server = ngx_queue_data(q, memc_server_st, queue);

				if (server->name.len != name.via.str.size
					|| ngx_memcmp(name.via.str.ptr, server->name.data,
						server->name.len) != 0) {
					continue;
				}

				have_changed = 1;

				ngx_queue_remove(q);
				ngx_pfree(c->pool, server); // is this the right pool?
				break;
			}

			continue;
		}

		if (skip_member) {
			continue;
		}

		for (q = ngx_queue_head(&peer->memc.servers);
			q != ngx_queue_sentinel(&peer->memc.servers);
			q = ngx_queue_next(q)) {
			server = ngx_queue_data(q, memc_server_st, queue);

			if (server->name.len == name.via.str.size
				&& ngx_memcmp(name.via.str.ptr, server->name.data,
					server->name.len) == 0) {
				if (add_member) {
					ngx_log_error(NGX_LOG_INFO, c->log, 0,
						"skipping add of existing memcached server in %s",
						(todo == HANDLE_LIST_MEMBERS) ? "members-filtered"
							: MEMBER_JOIN_EVENT " event");
					skip_member = 1;
					break;
				}

				/* update_member */
				goto update_member;
			}
		}

		if (update_member || skip_member) {
			continue;
		}

		/* add_member */
		server = ngx_pcalloc(c->pool, sizeof(memc_server_st)); // is this the right pool?

	update_member:
		have_changed = 1;

		switch (addr.via.bin.size) {
			case 4:
				server->sin.sin_family = AF_INET;
				server->sin.sin_port = htons(port);
				s_addr = (unsigned char *)&server->sin.sin_addr.s_addr;

				server->addr_len = sizeof(struct sockaddr_in);
				break;
#if NGX_HAVE_INET6
			case 16:
				server->sin6.sin6_family = AF_INET6;
				server->sin6.sin6_port = htons(port);
				s_addr = &server->sin6.sin6_addr.s6_addr[0];

				server->addr_len = sizeof(struct sockaddr_in6);
				break;
#else /* NGX_HAVE_INET6 */
			case 16:
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"member has IPv6 address but nginx built without "
					"IPv6 support, skipping member");
				continue;
#endif /* NGX_HAVE_INET6 */
			default:
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"malformed RPC response, expect Addr to be "
					"an array of length 4 or 16");
				return NGX_ERROR;
			}

		ngx_memcpy(s_addr, addr.via.bin.ptr, addr.via.bin.size);

		if (!add_member) {
			continue;
		}

		server->name.data = ngx_palloc(c->pool, name.via.str.size + 1);
		server->name.len = name.via.str.size;

		ngx_memcpy(server->name.data, name.via.str.ptr, name.via.str.size);
		server->name.data[server->name.len] = '\0';

		ngx_queue_insert_tail(&peer->memc.servers, &server->queue);
	}

	if (!have_changed) {
		return NGX_OK;
	}

	if (peer->memc.points) {
		ngx_pfree(c->pool, peer->memc.points);
	}

	num = 0;

	for (q = ngx_queue_head(&peer->memc.servers);
		q != ngx_queue_sentinel(&peer->memc.servers);
		q = ngx_queue_next(q)) {
		num++;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session cache have %d memcached servers", num);

	peer->memc.npoints = 0;
	peer->memc.points = ngx_palloc(c->pool, sizeof(chash_point_st) * CHASH_NPOINTS * num);
	if (!peer->memc.points) {
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);
		return NGX_ERROR;
	}

	for (q = ngx_queue_head(&peer->memc.servers);
		q != ngx_queue_sentinel(&peer->memc.servers);
		q = ngx_queue_next(q)) {
		server = ngx_queue_data(q, memc_server_st, queue);

		switch (server->addr.sa_family) {
#if NGX_HAVE_INET6
			case AF_INET6:
				s_addr = &server->sin6.sin6_addr.s6_addr[0];
				port = ntohs(server->sin6.sin6_port);
				break;
#endif /* NGX_HAVE_INET6 */
			default: /* AF_INET */
				s_addr = &server->sin6.sin6_addr.s6_addr[0];
				port = ntohs(server->sin.sin_port);
				break;
		}

		ngx_crc32_init(base_hash);
		ngx_crc32_update(&base_hash, str_addr,
			ngx_inet_ntop(server->addr.sa_family, s_addr, str_addr, NGX_SOCKADDR_STRLEN));
		ngx_crc32_update(&base_hash, (u_char *)"", 1);

		if (port == 11211) {
			ngx_crc32_update(&base_hash, (u_char *)"11211", strlen("11211") - 1);
		} else {
			ngx_crc32_update(&base_hash, str_port,
				snprintf((char *)str_port, sizeof("65535") - 1, "%hu", port));
		}

		prev_hash.value = 0;

		for (j = 0; j < CHASH_NPOINTS; j++) {
			hash = base_hash;

			ngx_crc32_update(&hash, prev_hash.byte, 4);
			ngx_crc32_final(hash);

			peer->memc.points[peer->memc.npoints].hash = hash;
			peer->memc.points[peer->memc.npoints].data = server;
			peer->memc.npoints++;

#if NGX_HAVE_LITTLE_ENDIAN
			prev_hash.value = hash;
#else /* NGX_HAVE_LITTLE_ENDIAN */
			prev_hash.byte[0] = (u_char)(hash & 0xff);
			prev_hash.byte[1] = (u_char)((hash >> 8) & 0xff);
			prev_hash.byte[2] = (u_char)((hash >> 16) & 0xff);
			prev_hash.byte[3] = (u_char)((hash >> 24) & 0xff);
#endif /* NGX_HAVE_LITTLE_ENDIAN */
		}
	}

	ngx_qsort(peer->memc.points, peer->memc.npoints, sizeof(chash_point_st), chash_cmp_points);

	for (i = 0, j = 1; j < peer->memc.npoints; j++) {
		if (peer->memc.points[i].hash != peer->memc.points[j].hash) {
			peer->memc.points[++i] = peer->memc.points[j];
		}
	}

	peer->memc.npoints = i + 1;

	if (ngx_queue_empty(&peer->memc.servers)) {
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		ngx_log_error(NGX_LOG_INFO, c->log, 0,
			"no memcached servers known, session cache support disabled");
	} else if (!peer->default_ticket_key) {
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		ngx_log_error(NGX_LOG_INFO, c->log, 0,
			"no default session ticket key, session cache support disabled");
	} else {
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx,
			SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
	}

	return NGX_OK;
}

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
	SSL_CTX *ssl_ctx;
	ngx_connection_t *c;
	peer_st *peer;
	key_st *key;
	ngx_queue_t *q;
#if NGX_DEBUG
	u_char buf[32];
#endif

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return -1;
	}

	if (enc) {
		key = peer->default_ticket_key;
		if (!key) {
			return -1;
		}

		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket encrypt, key: \"%*s\" (%s session)",
			ngx_hex_dump(buf, key->key.name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
			SSL_session_reused(ssl_conn) ? "reused" : "new");

		if (RAND_bytes(iv, 16) != 1) {
			return -1;
		}

		if (!EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key->key.aes_key, iv)) {
			return -1;
		}

		if (!HMAC_Init_ex(hctx, key->key.hmac_key, 16, EVP_sha256(), NULL)) {
			return -1;
		}

		ngx_memcpy(name, key->key.name, SSL_TICKET_KEY_NAME_LEN);

		return 0;
	} else {
		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, key_st, queue);

			if (ngx_memcmp(name, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
				goto found;
			}
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\" not found",
			ngx_hex_dump(buf, name, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		return 0;

	found:
		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\"%s",
			ngx_hex_dump(buf, key->key.name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
			(key == peer->default_ticket_key) ? " (default)" : "");

		if (!HMAC_Init_ex(hctx, key->key.hmac_key, 16, EVP_sha256(), NULL)) {
			return -1;
		}

		if (!EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key->key.aes_key, iv)) {
			return -1;
		}

		if (key->was_default) {
			return 2 /* renew */;
		} else {
			return 1;
		}
	}
}

static int ngx_libc_cdecl chash_cmp_points(const void *one, const void *two)
{
	chash_point_st *first = (chash_point_st *)one;
	chash_point_st *second = (chash_point_st *)two;

	if (first->hash < second->hash) {
		return -1;
	} else if (first->hash > second->hash) {
		return 1;
	} else {
		return 0;
	}
}

static ngx_uint_t find_chash_point(ngx_uint_t npoints, chash_point_st *point, uint32_t hash)
{
	ngx_uint_t i, j, k;

	/* find first point >= hash */

	i = 0;
	j = npoints;

	while (i < j) {
		k = (i + j) / 2;

		if (hash > point[k].hash) {
			i = k + 1;
		} else if (hash < point[k].hash) {
			j = k;
		} else {
			return k;
		}
	}

	return i;
}

static void memc_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	memc_op_st *op;
	ssize_t size, n;
	u_char *new_buf;

	c = rev->data;
	op = c->data;

	if (!op->recv.start) {
		/* 1/4 of the page_size, is it enough? */
		op->recv.start = ngx_palloc(c->pool, ngx_pagesize / 4);
		if (!op->recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");
			return;
		}

		op->recv.pos = op->recv.start;
		op->recv.last = op->recv.start;
		op->recv.end = op->recv.start + ngx_pagesize / 4;
	}

	while (1) {
		n = op->recv.end - op->recv.last;

		/* buffer not big enough? enlarge it by twice */
		if (n == 0) {
			size = op->recv.end - op->recv.start;

			new_buf = ngx_palloc(c->pool, size * 2);
			if (!new_buf) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated new recv buffer");
				return;
			}

			ngx_memcpy(new_buf, op->recv.start, size);

			op->recv.start = new_buf;
			op->recv.pos = new_buf;
			op->recv.last = new_buf + size;
			op->recv.end = new_buf + size * 2;

			n = op->recv.end - op->recv.last;
		}

		size = c->recv(c, op->recv.last, n);

		if (size > 0) {
			op->recv.last += size;
			continue;
		} else if (size == 0 || size == NGX_AGAIN) {
			break;
		} else {
			c->error = 1;
			return;
		}
	}

	if (op->ev) {
		ngx_post_event(op->ev, &ngx_posted_events);
		return;
	}

	if (memc_complete_operation(op, NULL, NULL) != NGX_AGAIN) {
		memc_cleanup_operation(op);
	}
}

static void memc_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	memc_op_st *op;
	ssize_t size;

	c = wev->data;
	op = c->data;

	while (op->send.pos < op->send.last) {
		size = c->send(c, op->send.pos, op->send.last - op->send.pos);
		if (size > 0) {
			op->send.pos += size;
		} else if (size == 0 || size == NGX_AGAIN) {
			return;
		} else {
			c->error = 1;
			return;
		}
	}

	if (op->send.pos == op->send.last) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "memc send done");

		ngx_pfree(c->pool, op->send.start);

		op->send.start = NULL;
		op->send.pos = NULL;
		op->send.last = NULL;
		op->send.end = NULL;

		c->write->handler = dummy_write_handler;
	}
}

static memc_op_st *memc_start_operation(peer_st *peer, protocol_binary_command cmd,
		ngx_str_t *key, ngx_str_t *value, void *in_data)
{
	memc_op_st *op = NULL;
	unsigned char *data = NULL;
	size_t len, hdr_len, ext_len = 0, body_len;
	int sock = -1;
	ngx_connection_t *c = NULL;
	memc_server_st *server;
	ngx_event_t *rev, *wev;
	ngx_int_t event;
	uint32_t hash;
	protocol_binary_request_header *req_hdr;
	protocol_binary_request_no_extras *in_req = in_data;
	protocol_binary_request_set *reqs, *in_reqs = in_data;
#if NGX_DEBUG
	const char *cmd_str;
#if !MEMC_KEYS_ARE_HEX
	u_char buf[64];
#endif /* !MEMC_KEYS_ARE_HEX */
#endif /* NGX_DEBUG */

	if (!peer->memc.npoints) {
		return NULL;
	}

	len = 8;

	switch (cmd) {
		case PROTOCOL_BINARY_CMD_GET:
			len += sizeof(protocol_binary_request_get);

#if NGX_DEBUG
			cmd_str = "GET";
#endif
			break;
		case PROTOCOL_BINARY_CMD_SET:
			len += sizeof(protocol_binary_request_set);
			ext_len = sizeof(((protocol_binary_request_set *)NULL)->message.body);

#if NGX_DEBUG
			cmd_str = "SET";
#endif
			break;
		case PROTOCOL_BINARY_CMD_DELETE:
			len += sizeof(protocol_binary_request_delete);

#if NGX_DEBUG
			cmd_str = "DELETE";
#endif
			break;
		default:
			goto error;
	}

#if MEMC_KEYS_ARE_HEX
	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, peer->log, 0,
		"memcached operation: %s \"%*s\"", cmd_str, key->len, key->data);
#else /* MEMC_KEYS_ARE_HEX */
	ngx_log_debug4(NGX_LOG_DEBUG_EVENT, peer->log, 0,
		"memcached operation: %s \"%*s%s\"",
		cmd_str,
		ngx_hex_dump(buf, key->data, ngx_min(key->len, 32)) - buf, buf,
		key->len > 32 ? "..." : "");
#endif /* MEMC_KEYS_ARE_HEX */

	hdr_len = len;
	body_len = ext_len + key->len;

	if (value) {
		body_len += value->len;
	}

	len += body_len;

	data = ngx_palloc(peer->pool, len);
	if (!data) {
		goto error;
	}

	ngx_memzero(data, hdr_len);

	// data[0..1] = request id
	// data[2..3] = sequence number
	// data[4..5] = total datagrams
	// data[6..7] = reserved

	if (RAND_bytes(&data[0], 2) != 1) {
		goto error;
	}

	data[4] = 0;
	data[5] = 1;

	req_hdr = (protocol_binary_request_header *)&data[8];

	req_hdr->request.magic = PROTOCOL_BINARY_REQ;
	req_hdr->request.opcode = cmd;
	req_hdr->request.keylen = htons(key->len);
	req_hdr->request.extlen = ext_len;
	req_hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
	req_hdr->request.bodylen = htonl(body_len);

	if (in_req) {
		req_hdr->request.opaque = in_req->message.header.request.opaque;
		req_hdr->request.cas = htonll(in_req->message.header.request.cas);

		switch (cmd) {
			case PROTOCOL_BINARY_CMD_SET:
				reqs = (protocol_binary_request_set *)req_hdr;
				reqs->message.body.flags
					= htonl(in_reqs->message.body.flags);
				reqs->message.body.expiration
					= htonl(in_reqs->message.body.expiration);
				break;
			default:
				break;
		}
	}

	ngx_memcpy(&data[hdr_len], key->data, key->len);

	if (value) {
		ngx_memcpy(&data[hdr_len + key->len], value->data, value->len);
	}

	op = ngx_pcalloc(peer->pool, sizeof(memc_op_st));
	if (!op) {
		goto error;
	}

	op->cmd = cmd;

	op->peer = peer;

	op->send.start = data;
	op->send.pos = data;
	op->send.last = data + len;
	op->send.end = data + len;

	hash = ngx_crc32_long(key->data, key->len);
	hash = find_chash_point(peer->memc.npoints, peer->memc.points, hash);
	server = peer->memc.points[hash % peer->memc.npoints].data;

	sock = socket(server->addr.sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		goto error;
	}

	c = ngx_get_connection(sock, peer->log);
	if (!c) {
		goto error;
	}

	c->data = op;
	op->c = c;

	c->recv = ngx_udp_recv;
	c->send = ngx_send;
	c->recv_chain = ngx_recv_chain;
	c->send_chain = ngx_send_chain;

	rev = c->read;
	wev = c->write;

	c->log = peer->log;
	rev->log = c->log;
	wev->log = c->log;
	c->pool = peer->pool;

	c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

	if (connect(sock, &server->addr, server->addr_len) == -1) {
		goto error;
	}

	/* UDP sockets are always ready to write */
	wev->ready = 1;

	if (ngx_add_event) {
		event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
				/* kqueue, epoll */                 NGX_CLEAR_EVENT:
				/* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
				/* eventport event type has no meaning: oneshot only */

		if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
			goto error;
		}
	} else {
		/* rtsig */

		if (ngx_add_conn(c) == NGX_ERROR) {
			goto error;
		}
	}

	rev->handler = memc_read_handler;
	wev->handler = memc_write_handler;

	wev->handler(wev);

	return op;

error:
	if (c) {
		ngx_close_connection(c);
	} else if (sock != -1) {
		close(sock);
	}

	if (data) {
		ngx_pfree(peer->pool, data);
	}

	if (op) {
		ngx_pfree(peer->pool, op);
	}

	return NULL;
}

static ngx_int_t memc_complete_operation(memc_op_st *op, ngx_str_t *value, void *out_data)
{
	ngx_str_t data;
	unsigned short key_len, status;
	unsigned int body_len;
	protocol_binary_response_header *res_hdr;
	ngx_uint_t log_level;
	protocol_binary_response_no_extras *out_res = out_data;
	protocol_binary_response_get *resg, *out_resg = out_data;

	if (op->recv.last - op->recv.pos < 8 + (ssize_t)sizeof(protocol_binary_response_header)) {
		return NGX_AGAIN;
	}

	// op->recv.pos[0..1] = request id
	// op->recv.pos[2..3] = sequence number
	// op->recv.pos[4..5] = total datagrams
	// op->recv.pos[6..7] = reserved

	if (op->recv.pos[4] != 0 || op->recv.pos[5] != 1) {
		return NGX_ERROR;
	}

	res_hdr = (protocol_binary_response_header *)&op->recv.pos[8];

	if (res_hdr->response.magic != PROTOCOL_BINARY_RES || res_hdr->response.opcode != op->cmd) {
		return NGX_ERROR;
	}

	key_len = htons(res_hdr->response.keylen);
	body_len = htonl(res_hdr->response.bodylen);

	if (op->recv.last - op->recv.pos < 8 + (ssize_t)sizeof(protocol_binary_response_header)
			+ body_len) {
		return NGX_ERROR;
	}

	data.data = op->recv.pos + 8
		+ sizeof(protocol_binary_response_header)
		+ res_hdr->response.extlen
		+ key_len;
	data.len = body_len
		- key_len
		- res_hdr->response.extlen;

	status = htons(res_hdr->response.status);

	if (out_res) {
		out_res->message.header.response.status = status;
		out_res->message.header.response.opaque = res_hdr->response.opaque;
		out_res->message.header.response.cas = htonll(res_hdr->response.cas);

		switch (op->cmd) {
			case PROTOCOL_BINARY_CMD_GET:
				resg = (protocol_binary_response_get *)res_hdr;
				out_resg->message.body.flags = htonl(resg->message.body.flags);
				break;
			default:
				break;
		}
	}

	if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
		if (value) {
			*value = data;
		}

		return NGX_OK;
	}

	log_level = NGX_LOG_ERR;

	switch (op->cmd) {
		case PROTOCOL_BINARY_CMD_GET:
			if (status == PROTOCOL_BINARY_RESPONSE_KEY_ENOENT) {
				log_level = NGX_LOG_DEBUG;
			}

			break;
		default:
			break;
	}

	ngx_log_error(log_level, op->c->log, 0,
		"memcached error %hd: %*s", status, data.len, data.data);

	return NGX_ERROR;
}

static void memc_cleanup_operation(memc_op_st *op)
{
	ngx_close_connection(op->c);

	op->c->write->handler = NULL;
	op->c->read->handler = NULL;

	if (op->send.start) {
		ngx_pfree(op->c->pool, op->send.start);
	}

	if (op->recv.start) {
		ngx_pfree(op->c->pool, op->recv.start);
	}

	ngx_pfree(op->c->pool, op);
}

static void memc_cleanup_pool_handler(void *data)
{
	memc_op_st *op = data;

	memc_cleanup_operation(op);
}

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
	SSL_CTX *ssl_ctx;
	ngx_connection_t *c;
	peer_st *peer;
	ngx_str_t key, value = {0};
	unsigned int len;
	u_char *session = NULL;
	size_t session_len;
	EVP_CIPHER_CTX ectx;
	HMAC_CTX hctx;
	u_char name[SSL_TICKET_KEY_NAME_LEN];
	u_char iv[EVP_MAX_IV_LENGTH];
	u_char *p;
	int elen;
	unsigned int hlen;
#if MEMC_KEYS_ARE_HEX
	u_char hex[SSL_MAX_SSL_SESSION_ID_LENGTH*2];
#endif /* MEMC_KEYS_ARE_HEX */
	protocol_binary_request_set req;

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return 0;
	}

#if MEMC_KEYS_ARE_HEX
	key.data = hex;
	key.len = ngx_hex_dump(hex, SSL_SESSION_get_id(sess, &len), len) - hex;
#else /* MEMC_KEYS_ARE_HEX */
	key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	key.len = len;
#endif /* MEMC_KEYS_ARE_HEX */

	EVP_CIPHER_CTX_init(&ectx);
	HMAC_CTX_init(&hctx);

	if (session_ticket_key_handler(ssl_conn, name, iv, &ectx, &hctx, 1) < 0) {
		goto cleanup;
	}

	if (!SSL_SESSION_to_bytes(sess, &session, &session_len)) {
		goto cleanup;
	}

	value.data = OPENSSL_malloc(SSL_TICKET_KEY_NAME_LEN + EVP_CIPHER_CTX_iv_length(&ectx)
		+ EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE + session_len);
	if (!value.data) {
		goto cleanup;
	}

	p = value.data;

	ngx_memcpy(p, name, SSL_TICKET_KEY_NAME_LEN);
	p += SSL_TICKET_KEY_NAME_LEN;

	memcpy(p, iv, EVP_CIPHER_CTX_iv_length(&ectx));
	p += EVP_CIPHER_CTX_iv_length(&ectx);

	if (!EVP_EncryptUpdate(&ectx, p, &elen, session, session_len)) {
		goto cleanup;
	}
	p += elen;

	if (!EVP_EncryptFinal_ex(&ectx, p, &elen)) {
		goto cleanup;
	}
	p += elen;

	if (!HMAC_Update(&hctx, value.data, p - value.data) || !HMAC_Final(&hctx, p, &hlen)) {
		goto cleanup;
	}
	p += hlen;

	value.len = p - value.data;

	ngx_memzero(&req, sizeof(protocol_binary_request_set));
	req.message.body.expiration = peer->ssl->session_timeout;

	(void) memc_start_operation(peer, PROTOCOL_BINARY_CMD_SET, &key, &value, &req);

cleanup:
	if (session) {
		OPENSSL_free(session);
	}

	if (value.data) {
		OPENSSL_free(value.data);
	}

	EVP_CIPHER_CTX_cleanup(&ectx);
	HMAC_CTX_cleanup(&hctx);

	return 0;
}

static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len,
		int *copy)
{
	SSL_CTX *ssl_ctx;
	ngx_connection_t *c;
	memc_op_st *op;
	peer_st *peer;
	ngx_str_t key, value;
	ngx_int_t rc;
	ngx_pool_cleanup_t *cln;
	ngx_ssl_session_t *sess = NULL;
	EVP_CIPHER_CTX ectx;
	HMAC_CTX hctx;
	uint8_t mac[EVP_MAX_MD_SIZE];
	uint8_t *plaintext = NULL;
	size_t iv_len, mac_len, ciphertext_len;
	int len1, len2;
#if MEMC_KEYS_ARE_HEX
	u_char hex[SSL_MAX_SSL_SESSION_ID_LENGTH*2];
#endif /* MEMC_KEYS_ARE_HEX */

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	op = SSL_get_ex_data(ssl_conn, g_ssl_exdata_memc_op_index);
	if (!op) {
		peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
		if (!peer) {
			return NULL;
		}

#if MEMC_KEYS_ARE_HEX
		key.data = hex;
		key.len = ngx_hex_dump(hex, id, len) - hex;
#else /* MEMC_KEYS_ARE_HEX */
		key.data = id;
		key.len = len;
#endif /* MEMC_KEYS_ARE_HEX */

		op = memc_start_operation(peer, PROTOCOL_BINARY_CMD_GET, &key, NULL, NULL);
		if (!op) {
			return NULL;
		}

		op->ev = c->write;

		if (!SSL_set_ex_data(ssl_conn, g_ssl_exdata_memc_op_index, op)) {
			memc_cleanup_operation(op);
			return NULL;
		}

		cln = ngx_pool_cleanup_add(c->pool, 0);
		if (!cln) {
			memc_cleanup_operation(op);
			return NULL;
		}

		cln->handler = memc_cleanup_pool_handler;
		cln->data = op;

		return SSL_magic_pending_session_ptr();
	}

	rc = memc_complete_operation(op, &value, NULL);

	if (rc == NGX_AGAIN) {
		return SSL_magic_pending_session_ptr();
	}

	if (rc == NGX_ERROR) {
		memc_cleanup_operation(op);
		return NULL;
	}

	/* rc == NGX_OK */
	EVP_CIPHER_CTX_init(&ectx);
	HMAC_CTX_init(&hctx);

	if (value.len < SSL_TICKET_KEY_NAME_LEN + EVP_MAX_IV_LENGTH) {
		goto cleanup;
	}

	if (session_ticket_key_handler(ssl_conn, value.data,
		&value.data[SSL_TICKET_KEY_NAME_LEN], &ectx, &hctx, 0) < 0) {
		goto cleanup;
	}

	iv_len = EVP_CIPHER_CTX_iv_length(&ectx);

	/* Check the MAC at the end of the ticket. */
	mac_len = HMAC_size(&hctx);

	if (value.len < SSL_TICKET_KEY_NAME_LEN + iv_len + 1 + mac_len) {
		goto cleanup;
	}

	HMAC_Update(&hctx, value.data, value.len - mac_len);
	HMAC_Final(&hctx, mac, NULL);

	if (CRYPTO_memcmp(mac, value.data + value.len - mac_len, mac_len) != 0) {
		goto cleanup;
	}

	/* Decrypt the session data. */
	ciphertext_len = value.len - SSL_TICKET_KEY_NAME_LEN - iv_len - mac_len;

	if (ciphertext_len >= INT_MAX) {
		goto cleanup;
	}

	plaintext = OPENSSL_malloc(ciphertext_len);
	if (!plaintext) {
		goto cleanup;
	}

	if (!EVP_DecryptUpdate(&ectx, plaintext, &len1,
			&value.data[SSL_TICKET_KEY_NAME_LEN + iv_len], (int)ciphertext_len)
		|| !EVP_DecryptFinal_ex(&ectx, plaintext + len1, &len2)) {
		goto cleanup;
	}

	*copy = 0;
	sess = SSL_SESSION_from_bytes(plaintext, len1 + len2);

cleanup:
	if (plaintext) {
		OPENSSL_free(plaintext);
	}

	EVP_CIPHER_CTX_cleanup(&ectx);
	HMAC_CTX_cleanup(&hctx);

	memc_cleanup_operation(op);
	return sess;
}

static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	peer_st *peer;
	ngx_str_t key;
	unsigned int len;
#if MEMC_KEYS_ARE_HEX
	u_char hex[SSL_MAX_SSL_SESSION_ID_LENGTH*2];
#endif /* MEMC_KEYS_ARE_HEX */

	peer = SSL_CTX_get_ex_data(ssl, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return;
	}

#if MEMC_KEYS_ARE_HEX
	key.data = hex;
	key.len = ngx_hex_dump(hex, SSL_SESSION_get_id(sess, &len), len) - hex;
#else /* MEMC_KEYS_ARE_HEX */
	key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	key.len = len;
#endif /* MEMC_KEYS_ARE_HEX */

	(void) memc_start_operation(peer, PROTOCOL_BINARY_CMD_DELETE, &key, NULL, NULL);
}

#if !defined(HAVE_HTONLL) && NGX_HAVE_LITTLE_ENDIAN
int64_t htonll(int64_t in)
{
	union {
		int64_t i64;
		int32_t i32[2];
	} u;
	u.i64 = in;

	int32_t temp = u.i32[0];
	u.i32[0] = htonl(u.i32[1]);
	u.i32[1] = htonl(temp);
	return u.i64;
}

int64_t ntohll(int64_t in)
{
	union {
		int64_t i64;
		int32_t i32[2];
	} u;
	u.i64 = in;

	int32_t temp = u.i32[0];
	u.i32[0] = ntohl(u.i32[1]);
	u.i32[1] = ntohl(temp);
	return u.i64;
}
#endif /* !defined(HAVE_HTONLL) && NGX_HAVE_LITTLE_ENDIAN */
