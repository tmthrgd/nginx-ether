#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <msgpack.h>

#include "protocol_binary.h"

#define MEMC_KEYS_ARE_HEX 0

#define INSTALL_KEY_EVENT "install-key"
#define REMOVE_KEY_EVENT "remove-key"
#define SET_DEFAULT_KEY_EVENT "set-default-key"

#define STREAM_KEY_EVENTS ("user:" INSTALL_KEY_EVENT ",user:" REMOVE_KEY_EVENT ",user:" SET_DEFAULT_KEY_EVENT)

#define MEMC_SERVER_TAG_KEY "role"
#define MEMC_SERVER_TAG_VAL "memc"

#define MEMC_PORT_TAG_KEY "memc_port"

#define MEMBER_JOIN_EVENT "member-join"
#define MEMBER_LEAVE_EVENT "member-leave"
#define MEMBER_FAILED_EVENT "member-failed"
#define MEMBER_UPDATE_EVENT "member-update"

#define STREAM_MEMBER_EVENTS (MEMBER_JOIN_EVENT "," MEMBER_LEAVE_EVENT "," MEMBER_FAILED_EVENT "," MEMBER_UPDATE_EVENT)

#define CHASH_NPOINTS 160

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
	STREAM_MEMBER_EVSUB,
	LISTING_MEMBERS
} state_et;

typedef struct {
	uint32_t hash;
	void *data;
} chash_point_t;

typedef struct {
	ngx_ssl_session_ticket_key_t key;

	int was_default;

	ngx_queue_t queue;
} key_st;

typedef struct {
	union {
		struct sockaddr addr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
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

		struct {
			uint64_t handshake;
			uint64_t auth;
			uint64_t key_ev;
			uint64_t member_ev;
			uint64_t list;
		} seq;

		msgpack_sbuffer sbuf;
		msgpack_packer pk;
	} serf;

	struct {
		//ngx_queue_t servers;

		ngx_uint_t npoints;
		chash_point_t *points;
	} memc;

	ngx_msec_t timeout;

	ngx_pool_t *pool;
	ngx_log_t *log;

	ngx_http_ssl_srv_conf_t *ssl;

	ngx_queue_t ticket_keys;
	key_st *default_ticket_key;
} peer_st;

static ngx_int_t init_process(ngx_cycle_t *cycle);
static void exit_process(ngx_cycle_t *cycle);

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void serf_read_handler(ngx_event_t *rev);
static void serf_write_handler(ngx_event_t *wev);

static ngx_int_t ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size, ngx_log_t *log);
static char *ether_msgpack_parse_map(msgpack_object *obj, ...);

static int ngx_libc_cdecl chash_cmp_points(const void *one, const void *two);
static ngx_uint_t find_chash_point(ngx_uint_t npoints, chash_point_t *point, uint32_t hash);

static void memc_read_handler(ngx_event_t *rev);
static void memc_write_handler(ngx_event_t *wev);

static memc_op_st *memc_start_operation(peer_st *peer, protocol_binary_command cmd, ngx_str_t *key, ngx_str_t *value);
static ngx_int_t memc_complete_operation(memc_op_st *op, ngx_str_t *value);

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy);
static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

static ngx_array_t peers = {0};

static int g_ssl_ctx_exdata_peer_index = -1;
static int g_ssl_exdata_memc_op_index = -1;

static ngx_command_t module_commands[] = {
	{ ngx_string("ether"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, serf_address),
	  NULL },

	{ ngx_string("ether_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
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

// TODO: support ssl_session_timeout

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

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	ngx_conf_merge_str_value(conf->serf_address, prev->serf_address, "");
	ngx_conf_merge_str_value(conf->serf_auth, prev->serf_auth, "");
	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, NGX_CONF_UNSET_MSEC);

	if (conf->timeout != NGX_CONF_UNSET_MSEC) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether_timeout directive not implemented");
		return NGX_CONF_ERROR;
	}

	if (conf->serf_address.len) {
		if (ngx_strcmp(conf->serf_address.data, "off") == 0) {
			return NGX_CONF_OK;
		}

		if (!ssl->session_tickets) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used without ssl_session_tickets being enabled");
			return NGX_CONF_ERROR;
		}

		if (ssl->session_ticket_keys) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used alongside the ssl_session_ticket_key directive");
			return NGX_CONF_ERROR;
		}

		if (ssl->builtin_session_cache != NGX_SSL_NONE_SCACHE) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used without ssl_session_cache being unset (none)");
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

		if (conf->timeout != NGX_CONF_UNSET_MSEC) {
			peer->timeout = conf->timeout;
		}

		peer->pool = cf->cycle->pool;
		peer->log = cf->cycle->log;

		peer->ssl = ssl;

		ngx_queue_init(&peer->ticket_keys);

		peer->memc.points = ngx_palloc(cf->pool, sizeof(chash_point_t) * CHASH_NPOINTS);
		if (!peer->memc.points) {
			return NGX_CONF_ERROR;
		}

		pc = &peer->serf.pc;

		pc->sockaddr = u.addrs[0].sockaddr;
		pc->socklen = u.addrs[0].socklen;
		pc->name = &conf->serf_address;

		pc->get = ngx_event_get_peer;
		pc->log = cf->log;
		pc->log_error = NGX_ERROR_ERR;

		peer->serf.state = HANDSHAKING;

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

		SSL_CTX_set_session_cache_mode(ssl->ssl.ctx, SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);

		SSL_CTX_sess_set_new_cb(ssl->ssl.ctx, new_session_handler);
		SSL_CTX_sess_set_get_cb(ssl->ssl.ctx, get_cached_session_handler);
		SSL_CTX_sess_set_remove_cb(ssl->ssl.ctx, remove_session_handler);
	}

	return NGX_CONF_OK;
}

static ngx_int_t ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size, ngx_log_t *log)
{
	size_t off = 0;
	msgpack_unpack_return ret;

	ret = msgpack_unpack_next(und, (char *)recv->pos, recv->last - recv->pos, &off);
	switch (ret) {
		case MSGPACK_UNPACK_EXTRA_BYTES:
			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next succeeded but left trailing bytes");
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

			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with unexpected eof");
			return NGX_AGAIN;
		case MSGPACK_UNPACK_NOMEM_ERROR:
			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with nomem error");
			return NGX_ABORT;
		default: /* MSGPACK_UNPACK_PARSE_ERROR */
			recv->pos += off;

			if (recv->pos == recv->last) {
				recv->pos = recv->start;
				recv->last = recv->start;
			}

			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with parse error");
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
	msgpack_object seq, error, event, name, payload = {0}, members, addr, tags, status;
	msgpack_object_kv *ptr_kv;
	msgpack_object_str *str;
	void *hdr_start;
	u_char *new_buf;
	key_st *key;
	ngx_queue_t *q;
	char *err;
	int skip_member;
	memc_server_st *server = NULL;
	unsigned char *s_addr;
	int remove_member = 0, add_member = 0, update_member = 0;
	size_t i, j;
	uint32_t hash, base_hash;
	union {
		uint32_t value;
		u_char byte[4];
	} prev_hash;
	ngx_int_t rc;
	unsigned short port;
	u_char str_addr[NGX_SOCKADDR_STRLEN];
	u_char str_port[sizeof("65535") - 1];
#if NGX_DEBUG
	u_char buf[32];
#endif

	c = rev->data;
	peer = c->data;

	if (!peer->serf.recv.start) {
		/* 1/4 of the page_size, is it enough? */
		peer->serf.recv.start = ngx_palloc(c->pool, ngx_pagesize / 4);
		if (!peer->serf.recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated recv buffer");
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
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated new recv buffer");
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
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ether RPC error: %*s", error.via.str.size, error.via.str.ptr);
		goto done;
	}

	if (!seq.via.u64) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, invalid sequence number");
		goto done;
	}

	if (seq.via.u64 == peer->serf.seq.handshake) {
		// {"Seq": 0, "Error": ""}

		if (peer->serf.state != HANDSHAKING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC handshake response");
			goto done;
		}

		if (peer->serf.auth.len) {
			peer->serf.state = AUTHENTICATING;
		} else {
			peer->serf.state = STREAM_KEY_EVSUB;
		}

		c->write->handler = serf_write_handler;
	} else if (seq.via.u64 == peer->serf.seq.auth) {
		// {"Seq": 0, "Error": ""}

		if (peer->serf.state != AUTHENTICATING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC auth response");
			goto done;
		}

		peer->serf.state = STREAM_KEY_EVSUB;

		c->write->handler = serf_write_handler;
	} else if (seq.via.u64 == peer->serf.seq.key_ev) {
		// {"Seq": 0, "Error": ""}
		// {
		// 	"Event": "user",
		// 	"LTime": 123,
		// 	"Name": "deploy",
		// 	"Payload": "9c45b87",
		// 	"Coalesce": true,
		// }

		if (peer->serf.state == STREAM_KEY_EVSUB) {
			peer->serf.state = STREAM_MEMBER_EVSUB;

			c->write->handler = serf_write_handler;
			goto done;
		}

		if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
			goto done;
		}

		switch (ether_msgpack_parse(&und, &peer->serf.recv, size, c->log)) {
			case NGX_OK:
				break;
			case NGX_AGAIN:
				peer->serf.recv.pos = hdr_start;
				goto cleanup;
			case NGX_ABORT:
				exit(2); // something else?
			default: /* NGX_ERROR */
				goto done;
		}

		event.type = MSGPACK_OBJECT_STR;
		name.type = MSGPACK_OBJECT_STR;
		payload.type = MSGPACK_OBJECT_BIN;

		err = ether_msgpack_parse_map(&und.data, "Event", &event, "Name", &name, "Payload", &payload, "LTime", NULL, "Coalesce", NULL, NULL);
		if (err) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
			goto done;
		}

		if (ngx_strncmp(event.via.str.ptr, "user", event.via.str.size) != 0) {
			goto done;
		}

		if (ngx_strncmp(name.via.str.ptr, INSTALL_KEY_EVENT, name.via.str.size) == 0) {
			if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN + 32) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key install: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

			if (!ngx_queue_empty(&peer->ticket_keys)) {
				for (q = ngx_queue_head(&peer->ticket_keys);
					q != ngx_queue_sentinel(&peer->ticket_keys);
					q = ngx_queue_next(q)) {
					key = ngx_queue_data(q, key_st, queue);

					if (ngx_memcmp(payload.via.bin.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, INSTALL_KEY_EVENT " event: already have key");
						goto done;
					}
				}
			}

			key = ngx_pcalloc(c->pool, sizeof(key_st)); // is this the right pool?
			if (!key) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
				goto done;
			}

			ngx_memcpy(key->key.name, payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN);
			ngx_memcpy(key->key.aes_key, payload.via.bin.ptr + SSL_TICKET_KEY_NAME_LEN, 16);
			ngx_memcpy(key->key.hmac_key, payload.via.bin.ptr + SSL_TICKET_KEY_NAME_LEN + 16, 16);

			ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);
		} else if (ngx_strncmp(name.via.str.ptr, REMOVE_KEY_EVENT, name.via.str.size) == 0) {
			if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key removal: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

			if (ngx_queue_empty(&peer->ticket_keys)) {
				goto done;
			}

			for (q = ngx_queue_head(&peer->ticket_keys);
				q != ngx_queue_sentinel(&peer->ticket_keys);
				q = ngx_queue_next(q)) {
				key = ngx_queue_data(q, key_st, queue);

				if (ngx_memcmp(payload.via.bin.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) != 0) {
					continue;
				}

				ngx_queue_remove(q);

				if (key == peer->default_ticket_key) {
					peer->default_ticket_key = NULL;

					SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

					ngx_log_error(NGX_LOG_ERR, c->log, 0, REMOVE_KEY_EVENT " event: on default key, session ticket support disabled");
				}

				ngx_memzero(&key->key, sizeof(key->key));
				ngx_pfree(c->pool, key); // is this the right pool?
				break;
			}
		} else if (ngx_strncmp(name.via.str.ptr, SET_DEFAULT_KEY_EVENT, name.via.str.size) == 0) {
			if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key set default: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

			if (ngx_queue_empty(&peer->ticket_keys)) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, SET_DEFAULT_KEY_EVENT " event: without any keys");
				goto done;
			}

			if (peer->default_ticket_key) {
				peer->default_ticket_key->was_default = 1;
				peer->default_ticket_key = NULL;
			}

			for (q = ngx_queue_head(&peer->ticket_keys);
				q != ngx_queue_sentinel(&peer->ticket_keys);
				q = ngx_queue_next(q)) {
				key = ngx_queue_data(q, key_st, queue);

				if (ngx_memcmp(payload.via.bin.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
					key->was_default = 0;
					peer->default_ticket_key = key;

					SSL_CTX_clear_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
					break;
				}
			}

			if (!peer->default_ticket_key) {
				SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

				ngx_log_error(NGX_LOG_ERR, c->log, 0, SET_DEFAULT_KEY_EVENT " event: on unknown key, session ticket support disabled");
				goto done;
			}
		} else {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "received unrecognised event from serf: %*s", name.via.str.size, name.via.str.ptr);
			goto done;
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
	} else if (seq.via.u64 == peer->serf.seq.member_ev || seq.via.u64 == peer->serf.seq.list) {
		// seq.via.u64 == peer->serf.seq.member_ev
		//
		// {"Seq": 0, "Error": ""}
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

		// seq.via.u64 == peer->serf.seq.list
		//
		// {"Seq": 0, "Error": ""}
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

		if (seq.via.u64 == peer->serf.seq.member_ev && peer->serf.state == STREAM_MEMBER_EVSUB) {
			peer->serf.state = LISTING_MEMBERS;

			c->write->handler = serf_write_handler;
			goto done;
		}

		if (seq.via.u64 == peer->serf.seq.list && peer->serf.state == LISTING_MEMBERS) {
			peer->serf.state = WAITING;
		}

		if (peer->serf.state == HANDSHAKING || peer->serf.state == AUTHENTICATING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
			goto done;
		}

		switch (ether_msgpack_parse(&und, &peer->serf.recv, size, c->log)) {
			case NGX_OK:
				break;
			case NGX_AGAIN:
				peer->serf.recv.pos = hdr_start;
				goto cleanup;
			case NGX_ABORT:
				exit(2); // something else?
			default: /* NGX_ERROR */
				goto done;
		}

		if (seq.via.u64 == peer->serf.seq.list) {
			members.type = MSGPACK_OBJECT_ARRAY;

			err = ether_msgpack_parse_map(&und.data, "Members", &members, NULL);
			if (err) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
				goto done;
			}

			add_member = 1;
		} else {
			event.type = MSGPACK_OBJECT_STR;
			members.type = MSGPACK_OBJECT_ARRAY;

			err = ether_msgpack_parse_map(&und.data, "Event", &event, "Members", &members, NULL);
			if (err) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
				goto done;
			}

			if (ngx_strncmp(event.via.str.ptr, MEMBER_JOIN_EVENT, event.via.str.size) == 0) {
				add_member = 1;
			} else if (ngx_strncmp(event.via.str.ptr, MEMBER_LEAVE_EVENT, event.via.str.size) == 0
				|| ngx_strncmp(event.via.str.ptr, MEMBER_FAILED_EVENT, event.via.str.size) == 0) {
				remove_member = 1;
			} else if (ngx_strncmp(event.via.str.ptr, MEMBER_UPDATE_EVENT, event.via.str.size) == 0) {
				update_member = 1;
			} else {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "received unrecognised event from serf: %*s", event.via.str.size, event.via.str.ptr);
				goto done;
			}
		}

		for (i = 0; i < members.via.array.size; i++) {
			name.type = MSGPACK_OBJECT_STR;
			addr.type = MSGPACK_OBJECT_BIN;
			tags.type = MSGPACK_OBJECT_MAP;
			status.type = MSGPACK_OBJECT_STR;

			err = ether_msgpack_parse_map(&members.via.array.ptr[i],
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
				goto done;
			}

			if (seq.via.u64 == peer->serf.seq.member_ev) {
				skip_member = 1;
			} else {
				skip_member = 0;
			}

			port = 11211;

			for (j = 0; j < tags.via.map.size; j++) {
				ptr_kv = &tags.via.map.ptr[j];

				if (ptr_kv->key.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, expect key to be string");
					goto done;
				}

				str = &ptr_kv->key.via.str;
				if (skip_member && ngx_strncmp(str->ptr, MEMC_SERVER_TAG_KEY, str->size) == 0) {
					if (ptr_kv->val.type != MSGPACK_OBJECT_STR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, expect value to be string");
						goto done;
					}

					str = &ptr_kv->val.via.str;
					if (ngx_strncmp(str->ptr, MEMC_SERVER_TAG_VAL, str->size) == 0) {
						skip_member = 0;
						continue;
					}

					break;
				}

				if (ngx_strncmp(str->ptr, MEMC_PORT_TAG_KEY, str->size) == 0) {
					if (ptr_kv->val.type != MSGPACK_OBJECT_STR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, expect value to be string");
						goto done;
					}

					str = &ptr_kv->val.via.str;

					rc = ngx_atoi((u_char *)str->ptr, str->size);
					if (rc == NGX_ERROR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, expect " MEMC_PORT_TAG_KEY " tag to be valid number");

						skip_member = 1;
						break;
					}

					port = (unsigned short)rc;
					continue;
				}
			}

			if (skip_member) {
				continue;
			}

			if (remove_member) {
				// remove server here
				continue;
			}

			if (update_member) {
				continue;

				// server = pull old server here

				if (!server) {
					continue;
				}
			}

			if (add_member) {
				server = ngx_pcalloc(c->pool, sizeof(memc_server_st)); // is this the right pool?
			}

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
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "member has IPv6 address but nginx built without IPv6 support, skipping member");
					continue;
#endif /* NGX_HAVE_INET6 */
				default:
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, expect Addr to be an array of length 4 or 16");
					goto done;
			}

			ngx_memcpy(s_addr, addr.via.bin.ptr, addr.via.bin.size);

			if (!add_member) {
				continue;
			}

			server->name.data = ngx_palloc(c->pool, name.via.str.size + 1);
			server->name.len = name.via.str.size;

			ngx_memcpy(server->name.data, name.via.str.ptr, name.via.str.size);
			server->name.data[server->name.len] = '\0';

			ngx_crc32_init(base_hash);
			ngx_crc32_update(&base_hash, str_addr, ngx_inet_ntop(server->addr.sa_family, s_addr, str_addr, NGX_SOCKADDR_STRLEN));
			ngx_crc32_update(&base_hash, (u_char *)"", 1);

			if (port == 11211) {
				ngx_crc32_update(&base_hash, (u_char *)"11211", strlen("11211") - 1);
			} else {
				ngx_crc32_update(&base_hash, str_port, snprintf((char *)str_port, sizeof("65535") - 1, "%hu", port));
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

		if (add_member) {
			ngx_qsort(peer->memc.points, peer->memc.npoints, sizeof(chash_point_t), chash_cmp_points);

			for (i = 0, j = 1; j < peer->memc.npoints; j++) {
				if (peer->memc.points[i].hash != peer->memc.points[j].hash) {
					peer->memc.points[++i] = peer->memc.points[j];
				}
			}

			peer->memc.npoints = i + 1;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unrecognised RPC seq number: %x", seq.via.u64);
	}

done:
	peer->serf.recv.pos = peer->serf.recv.start;
	peer->serf.recv.last = peer->serf.recv.start;

cleanup:
	if (payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	msgpack_unpacked_destroy(&und);
}

static void serf_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size;
	msgpack_sbuffer *sbuf;
	msgpack_packer *pk;
	uint64_t seq;

	c = wev->data;
	peer = c->data;

	sbuf = &peer->serf.sbuf;
	pk = &peer->serf.pk;

	if (!peer->serf.send.start) {
		if (RAND_bytes((uint8_t *)&seq, sizeof(uint64_t)) != 1) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "RAND_bytes failed");
			return;
		}

		msgpack_sbuffer_init(sbuf);
		msgpack_packer_init(pk, sbuf, msgpack_sbuffer_write);

		switch (peer->serf.state) {
			case WAITING:
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "write_handler called in WAITING state");
				return;
			case HANDSHAKING:
				peer->serf.seq.handshake = seq;

				// {"Command": "handshake", "Seq": 0}
				// {"Version": 1}

				// header
				msgpack_pack_map(pk, 2);

				msgpack_pack_str(pk, sizeof("Command") - 1);
				msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
				msgpack_pack_str(pk, sizeof("handshake") - 1);
				msgpack_pack_str_body(pk, "handshake", sizeof("handshake") - 1);

				msgpack_pack_str(pk, sizeof("Seq") - 1);
				msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
				msgpack_pack_uint64(pk, seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("Version") - 1);
				msgpack_pack_str_body(pk, "Version", sizeof("Version") - 1);
				msgpack_pack_int32(pk, 1);
				break;
			case AUTHENTICATING:
				peer->serf.seq.auth = seq;

				// {"Command": "auth", "Seq": 0}
				// {"AuthKey": "my-secret-auth-token"}

				// header
				msgpack_pack_map(pk, 2);

				msgpack_pack_str(pk, sizeof("Command") - 1);
				msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
				msgpack_pack_str(pk, sizeof("auth") - 1);
				msgpack_pack_str_body(pk, "auth", sizeof("auth") - 1);

				msgpack_pack_str(pk, sizeof("Seq") - 1);
				msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
				msgpack_pack_uint64(pk, seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("AuthKey") - 1);
				msgpack_pack_str_body(pk, "AuthKey", sizeof("AuthKey") - 1);
				msgpack_pack_str(pk, peer->serf.auth.len);
				msgpack_pack_str_body(pk, peer->serf.auth.data, peer->serf.auth.len);
				break;
			case STREAM_KEY_EVSUB:
				peer->serf.seq.key_ev = seq;

				// {"Command": "stream", "Seq": 0}
				// {"Type": "member-join,user:deploy"}`

				// header
				msgpack_pack_map(pk, 2);

				msgpack_pack_str(pk, sizeof("Command") - 1);
				msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
				msgpack_pack_str(pk, sizeof("stream") - 1);
				msgpack_pack_str_body(pk, "stream", sizeof("stream") - 1);

				msgpack_pack_str(pk, sizeof("Seq") - 1);
				msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
				msgpack_pack_uint64(pk, seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("Type") - 1);
				msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
				msgpack_pack_str(pk, sizeof(STREAM_KEY_EVENTS) - 1);
				msgpack_pack_str_body(pk, STREAM_KEY_EVENTS, sizeof(STREAM_KEY_EVENTS) - 1);
				break;
			case STREAM_MEMBER_EVSUB:
				peer->serf.seq.member_ev = seq;

				// {"Command": "stream", "Seq": 0}
				// {"Type": "member-join,user:deploy"}`

				// header
				msgpack_pack_map(pk, 2);

				msgpack_pack_str(pk, sizeof("Command") - 1);
				msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
				msgpack_pack_str(pk, sizeof("stream") - 1);
				msgpack_pack_str_body(pk, "stream", sizeof("stream") - 1);

				msgpack_pack_str(pk, sizeof("Seq") - 1);
				msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
				msgpack_pack_uint64(pk, seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("Type") - 1);
				msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
				msgpack_pack_str(pk, sizeof(STREAM_MEMBER_EVENTS) - 1);
				msgpack_pack_str_body(pk, STREAM_MEMBER_EVENTS, sizeof(STREAM_MEMBER_EVENTS) - 1);
				break;
			case LISTING_MEMBERS:
				peer->serf.seq.list = seq;

				// {"Command": "members-filtered", "Seq": 0}
				// {"Tags": {"key": "val"}, "Status": "alive", "Name": "node1"}

				// header
				msgpack_pack_map(pk, 2);

				msgpack_pack_str(pk, sizeof("Command") - 1);
				msgpack_pack_str_body(pk, "Command", sizeof("Command") - 1);
				msgpack_pack_str(pk, sizeof("members-filtered") - 1);
				msgpack_pack_str_body(pk, "members-filtered", sizeof("members-filtered") - 1);

				msgpack_pack_str(pk, sizeof("Seq") - 1);
				msgpack_pack_str_body(pk, "Seq", sizeof("Seq") - 1);
				msgpack_pack_uint64(pk, seq);

				// body
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
				break;
		}

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

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
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
		if (!ngx_queue_empty(&peer->ticket_keys)) {
			for (q = ngx_queue_head(&peer->ticket_keys);
				q != ngx_queue_sentinel(&peer->ticket_keys);
				q = ngx_queue_next(q)) {
				key = ngx_queue_data(q, key_st, queue);

				if (ngx_memcmp(name, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
					goto found;
				}
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
	chash_point_t *first = (chash_point_t *) one;
	chash_point_t *second = (chash_point_t *) two;

	if (first->hash < second->hash) {
		return -1;
	} else if (first->hash > second->hash) {
		return 1;
	} else {
		return 0;
	}
}

static ngx_uint_t find_chash_point(ngx_uint_t npoints, chash_point_t *point, uint32_t hash)
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
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated recv buffer");
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
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated new recv buffer");
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
	} else {
		(void) memc_complete_operation(op, NULL);
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

static memc_op_st *memc_start_operation(peer_st *peer, protocol_binary_command cmd, ngx_str_t *key, ngx_str_t *value)
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
#if NGX_DEBUG
	const char *cmd_str;
#	if !MEMC_KEYS_ARE_HEX
	u_char buf[64];
#	endif /* !MEMC_KEYS_ARE_HEX */
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
	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, peer->log, 0, "memcached operation: %s \"%*s\"", cmd_str, key->len, key->data);
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

static ngx_int_t memc_complete_operation(memc_op_st *op, ngx_str_t *value)
{
	ngx_int_t rc;
	ngx_str_t data;
	unsigned short key_len, status;
	unsigned int body_len;
	protocol_binary_response_header *res_hdr;
	ngx_uint_t log_level;

	if (op->recv.last - op->recv.pos < 8 + (ssize_t)sizeof(protocol_binary_response_header)) {
		return NGX_AGAIN;
	}

	// op->recv.pos[0..1] = request id
	// op->recv.pos[2..3] = sequence number
	// op->recv.pos[4..5] = total datagrams
	// op->recv.pos[6..7] = reserved

	if (op->recv.pos[4] != 0 || op->recv.pos[5] != 1) {
		rc = NGX_ERROR;
		goto cleanup;
	}

	res_hdr = (protocol_binary_response_header *)&op->recv.pos[8];

	if (res_hdr->response.magic != PROTOCOL_BINARY_RES || res_hdr->response.opcode != op->cmd) {
		rc = NGX_ERROR;
		goto cleanup;
	}

	key_len = htons(res_hdr->response.keylen);
	body_len = htonl(res_hdr->response.bodylen);

	if (op->recv.last - op->recv.pos < 8 + (ssize_t)sizeof(protocol_binary_response_header) + body_len) {
		rc = NGX_ERROR;
		goto cleanup;
	}

	data.data = op->recv.pos + 8
		+ sizeof(protocol_binary_response_header)
		+ res_hdr->response.extlen
		+ key_len;
	data.len = body_len
		- key_len
		- res_hdr->response.extlen;

	status = htons(res_hdr->response.status);

	if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
		if (value) {
			*value = data;
		}

		rc = NGX_OK;
	} else {
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

		ngx_log_error(log_level, op->c->log, 0, "memcached error %hd: %*s", status, data.len, data.data);

		rc = NGX_ERROR;
	}

cleanup:
	ngx_close_connection(op->c);

	op->c->write->handler = NULL;
	op->c->read->handler = NULL;

	if (rc == NGX_ERROR) {
		ngx_pfree(op->c->pool, op->recv.start);
	}

	ngx_pfree(op->c->pool, op);

	return rc;
}

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
	peer_st *peer;
	ngx_str_t key, value;
	unsigned int len;
#if MEMC_KEYS_ARE_HEX
	u_char hex[128];
#endif /* MEMC_KEYS_ARE_HEX */
	u_char buf[NGX_SSL_MAX_SESSION_SIZE];
	u_char *p;

	peer = SSL_CTX_get_ex_data(ssl_conn->ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return 0; // -1?
	}

#if MEMC_KEYS_ARE_HEX
	p = (u_char *)SSL_SESSION_get_id(sess, &len);

	if (len > 64) {
		return 0;
	}

	key.data = hex;
	key.len = ngx_hex_dump(hex, p, len) - hex;
#else /* MEMC_KEYS_ARE_HEX */
	key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	key.len = len;
#endif /* MEMC_KEYS_ARE_HEX */

	value.data = buf;
	value.len = i2d_SSL_SESSION(sess, NULL);

	/* do not cache too big session */
	if (value.len > NGX_SSL_MAX_SESSION_SIZE) {
		return 0;
	}

	p = buf;
	i2d_SSL_SESSION(sess, &p);

	(void) memc_start_operation(peer, PROTOCOL_BINARY_CMD_SET, &key, &value);
	return 0;
}

static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy)
{
	memc_op_st *op;
	peer_st *peer;
	ngx_str_t key, value;
	ngx_connection_t *c;
	ngx_int_t rc;
#if MEMC_KEYS_ARE_HEX
	u_char hex[128];

	if (len > 64) {
		return NULL;
	}
#endif /* MEMC_KEYS_ARE_HEX */

	c = ngx_ssl_get_connection(ssl_conn);

	op = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_memc_op_index);
	if (op) {
		rc = memc_complete_operation(op, &value);

		if (rc == NGX_AGAIN) {
			return SSL_magic_pending_session_ptr();
		}

		if (rc == NGX_OK) {
			return d2i_SSL_SESSION(NULL, (const uint8_t **)&value.data, value.len);
		}

		/* rc == NGX_ERROR */
		return NULL;
	}

	peer = SSL_CTX_get_ex_data(ssl_conn->ctx, g_ssl_ctx_exdata_peer_index);
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

	op = memc_start_operation(peer, PROTOCOL_BINARY_CMD_GET, &key, NULL);
	if (!op) {
		return NULL;
	}

	op->ev = c->write;

	if (!SSL_set_ex_data(c->ssl->connection, g_ssl_exdata_memc_op_index, op)) {
		return NULL;
	}

	return SSL_magic_pending_session_ptr();
}

static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	peer_st *peer;
	ngx_str_t key;
	unsigned int len;
#if MEMC_KEYS_ARE_HEX
	u_char hex[128];
	u_char *p;
#endif /* MEMC_KEYS_ARE_HEX */

	peer = SSL_CTX_get_ex_data(ssl, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return;
	}

#if MEMC_KEYS_ARE_HEX
	p = (u_char *)SSL_SESSION_get_id(sess, &len);

	if (len > 64) {
		return;
	}

	key.data = hex;
	key.len = ngx_hex_dump(hex, p, len) - hex;
#else /* MEMC_KEYS_ARE_HEX */
	key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	key.len = len;
#endif /* MEMC_KEYS_ARE_HEX */

	(void) memc_start_operation(peer, PROTOCOL_BINARY_CMD_DELETE, &key, NULL);
}
