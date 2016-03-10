#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <msgpack.h>

#define INSTALL_KEY_EVENT "install-key"
#define REMOVE_KEY_EVENT "remove-key"
#define SET_DEFAULT_KEY_EVENT "set-default-key"

#define SUBSCRIBE_EVENTS "user:" INSTALL_KEY_EVENT ",user:" REMOVE_KEY_EVENT ",user:" SET_DEFAULT_KEY_EVENT

typedef struct {
	ngx_str_t serf_address;
	ngx_str_t serf_auth;
	ngx_msec_t timeout;
} srv_conf_t;

typedef enum {
	WAITING = 0,
	HANDSHAKING,
	AUTHENTICATING,
	SUBSCRIBING
} state_et;

typedef struct {
	ngx_ssl_session_ticket_key_t key;

	int was_default;

	ngx_queue_t queue;
} key_st;

typedef struct {
	struct {
		ngx_peer_connection_t pc;

		ngx_buf_t send;
		ngx_buf_t recv;

		ngx_str_t auth;

		state_et state;

		struct {
			uint64_t handshake;
			uint64_t auth;
			uint64_t stream;
		} seq;

		msgpack_sbuffer sbuf;
		msgpack_packer pk;
	} serf;

	ngx_msec_t timeout;

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

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy);
static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

static ngx_array_t peers = {0};

static int g_ssl_ctx_exdata_peer_index = -1;

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

		if (g_ssl_ctx_exdata_peer_index == -1) {
			g_ssl_ctx_exdata_peer_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
			if (g_ssl_ctx_exdata_peer_index == -1) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_get_ex_new_index failed");
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

static void dummy_write_handler(ngx_event_t *wev) { }

static void serf_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size, n;
	msgpack_unpacked und;
	uint32_t i;
	msgpack_object_str *str;
	uint64_t seq = 0;
	msgpack_object_str event_name = {0};
	msgpack_object_bin payload = {0};
	msgpack_object_kv* ptr;
	void *hdr_start;
	u_char *new_buf;
	key_st *key;
	ngx_queue_t *q;
	int is_user_ev = 0;
#if NGX_DEBUG
	u_char buf[32];
#endif

	c = rev->data;
	peer = c->data;

	if (!peer->serf.recv.start) {
		/* 1/2 of the page_size, is it enough? */
		peer->serf.recv.start = ngx_palloc(c->pool, ngx_pagesize / 2);
		if (!peer->serf.recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated recv buffer");
			return;
		}

		peer->serf.recv.pos = peer->serf.recv.start;
		peer->serf.recv.last = peer->serf.recv.start;
		peer->serf.recv.end = peer->serf.recv.start + ngx_pagesize / 2;
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
		case NGX_ERROR:
			goto done;
		case NGX_ABORT:
			exit(2); // something else?
	}

	if (und.data.type != MSGPACK_OBJECT_MAP) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expected a map");
		goto done;
	}

	for (i = 0; i < und.data.via.map.size; i++) {
		ptr = &und.data.via.map.ptr[i];

		if (ptr->key.type != MSGPACK_OBJECT_STR) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect key to be string");
			goto done;
		}

		str = &ptr->key.via.str;
		if (ngx_strncmp(str->ptr, "Seq", str->size) == 0) {
			if (ptr->val.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect Seq to be positive integer");
				goto done;
			}

			seq = ptr->val.via.u64;
		} else if (ngx_strncmp(str->ptr, "Error", str->size) == 0) {
			if (ptr->val.type != MSGPACK_OBJECT_STR) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect Error to be string");
				goto done;
			}

			str = &ptr->val.via.str;
			if (str->size) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "ether RPC error: %*s", str->size, str->ptr);
				goto done;
			}
		} else {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, unrecognised key: %*s", str->size, str->ptr);
		}
	}

	if (!seq) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, missing sequence number");
		goto done;
	}

	if (peer->serf.seq.handshake && seq == peer->serf.seq.handshake) {
		if (peer->serf.state != HANDSHAKING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC handshake response");
			goto done;
		}

		if (peer->serf.auth.len) {
			peer->serf.state = AUTHENTICATING;
		} else {
			peer->serf.state = SUBSCRIBING;
		}

		c->write->handler = serf_write_handler;
	} else if (peer->serf.seq.auth && seq == peer->serf.seq.auth) {
		if (peer->serf.state != AUTHENTICATING) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC auth response");
			goto done;
		}

		peer->serf.state = SUBSCRIBING;

		c->write->handler = serf_write_handler;
	} else if (peer->serf.seq.stream && seq == peer->serf.seq.stream) {
		if (peer->serf.state == SUBSCRIBING) {
			peer->serf.state = WAITING;
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
			case NGX_ERROR:
				goto done;
			case NGX_ABORT:
				exit(2); // something else?
		}

		if (und.data.type != MSGPACK_OBJECT_MAP) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expected a map");
			goto done;
		}

		for (i = 0; i < und.data.via.map.size; i++) {
			ptr = &und.data.via.map.ptr[i];

			if (ptr->key.type != MSGPACK_OBJECT_STR) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect key to be string");
				goto done;
			}

			str = &ptr->key.via.str;
			if (ngx_strncmp(str->ptr, "Event", str->size) == 0) {
				if (ptr->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect Event to be string");
					goto done;
				}

				str = &ptr->val.via.str;
				if (ngx_strncmp(str->ptr, "user", str->size) == 0) {
					is_user_ev = 1;
				}
			} else if (ngx_strncmp(str->ptr, "Name", str->size) == 0) {
				if (ptr->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect Name to be string");
					goto done;
				}

				event_name.size = ptr->val.via.str.size;
				event_name.ptr = ptr->val.via.str.ptr;
			} else if (ngx_strncmp(str->ptr, "Payload", str->size) == 0) {
				if (ptr->val.type != MSGPACK_OBJECT_BIN && ptr->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect Payload to be byte string");
					goto done;
				}

				payload.size = ptr->val.via.bin.size;
				payload.ptr = ptr->val.via.bin.ptr;
			} else if (ngx_strncmp(str->ptr, "LTime", str->size) == 0) {
				// positive integer, ignored
			} else if (ngx_strncmp(str->ptr, "Coalesce", str->size) == 0) {
				// boolean, ignored
			} else {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, unrecognised key: %*s", str->size, str->ptr);
			}
		}

		if (!is_user_ev) {
			goto done;
		}

		if (ngx_strncmp(event_name.ptr, INSTALL_KEY_EVENT, event_name.size) == 0) {
			if (payload.size != SSL_TICKET_KEY_NAME_LEN + 32) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key install: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

			if (!ngx_queue_empty(&peer->ticket_keys)) {
				for (q = ngx_queue_head(&peer->ticket_keys);
					q != ngx_queue_sentinel(&peer->ticket_keys);
					q = ngx_queue_next(q)) {
					key = ngx_queue_data(q, key_st, queue);

					if (ngx_memcmp(payload.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
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

			memcpy(key->key.name, payload.ptr, SSL_TICKET_KEY_NAME_LEN);
			memcpy(key->key.aes_key, payload.ptr + SSL_TICKET_KEY_NAME_LEN, 16);
			memcpy(key->key.hmac_key, payload.ptr + SSL_TICKET_KEY_NAME_LEN + 16, 16);

			ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);
		} else if (ngx_strncmp(event_name.ptr, REMOVE_KEY_EVENT, event_name.size) == 0) {
			if (payload.size != SSL_TICKET_KEY_NAME_LEN) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key removal: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

			if (ngx_queue_empty(&peer->ticket_keys)) {
				goto done;
			}

			for (q = ngx_queue_head(&peer->ticket_keys);
				q != ngx_queue_sentinel(&peer->ticket_keys);
				q = ngx_queue_next(q)) {
				key = ngx_queue_data(q, key_st, queue);

				if (ngx_memcmp(payload.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
					if (key == peer->default_ticket_key) {
						peer->default_ticket_key->was_default = 1;
						peer->default_ticket_key = NULL;

						SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

						ngx_log_error(NGX_LOG_ERR, c->log, 0, REMOVE_KEY_EVENT " event: on default key, session ticket support disabled");
					}

					ngx_queue_remove(q);

					ngx_memzero(&key->key, sizeof(key->key));
					ngx_pfree(c->pool, key); // is this the right pool?
					break;
				}
			}
		} else if (ngx_strncmp(event_name.ptr, SET_DEFAULT_KEY_EVENT, event_name.size) == 0) {
			if (payload.size != SSL_TICKET_KEY_NAME_LEN) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
				goto done;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"ssl session ticket key set default: \"%*s\"",
				ngx_hex_dump(buf, (u_char *)payload.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

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

				if (ngx_memcmp(payload.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
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
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "received unrecognised event from serf: %*s", event_name.size, event_name.ptr);
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
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unrecognised RPC seq number: %x", seq);
	}

done:
	peer->serf.recv.pos = peer->serf.recv.start;
	peer->serf.recv.last = peer->serf.recv.start;

cleanup:
	if (payload.size) {
		ngx_memzero((char *)payload.ptr, payload.size);
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
			case SUBSCRIBING:
				peer->serf.seq.stream = seq;

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
				msgpack_pack_str(pk, sizeof(SUBSCRIBE_EVENTS) - 1);
				msgpack_pack_str_body(pk, SUBSCRIBE_EVENTS, sizeof(SUBSCRIBE_EVENTS) - 1);
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

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
	// add

	return 0;
}

static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy)
{
#if 0
	if (!started) {
		// get
	}

	if (done) {
		return NULL;
	}

	return SSL_magic_pending_session_ptr();
#else
	return NULL;
#endif
}

static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	// del
}
