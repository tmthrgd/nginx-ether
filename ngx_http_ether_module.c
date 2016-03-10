#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <msgpack.h>

#define INSTALL_KEY_EVENT "install-key"
#define REMOVE_KEY_EVENT "remove-key"
#define SET_DEFAULT_KEY_EVENT "set-default-key"

#define SUBSCRIBE_EVENTS "user:" INSTALL_KEY_EVENT ",user:" REMOVE_KEY_EVENT ",user:" SET_DEFAULT_KEY_EVENT

typedef enum {
	INSTALL_KEY = 1,
	REMOVE_KEY,
	SET_DEFAULT_KEY
} event_type_et;

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
	ngx_peer_connection_t pc;

	ngx_str_t auth;
	ngx_msec_t timeout;

	ngx_http_ssl_srv_conf_t *ssl;

	state_et state;

	uint64_t expected_seq;
	uint64_t ev_seq;

	ngx_buf_t send;
	ngx_buf_t recv;

	msgpack_sbuffer sbuf; // replace with custom buffer
	msgpack_packer pk;

	ngx_queue_t ticket_keys;
	key_st *default_ticket_key;
} peer_st;

static ngx_int_t init_process(ngx_cycle_t *cycle);

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void read_handler(ngx_event_t *rev);
static void write_handler(ngx_event_t *wev);

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
	NULL,            /* exit process */
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

	peer = peers.elts;
	for (i = 0; i < peers.nelts; i++) {
		pc = &peer[i].pc;

		rc = ngx_event_connect_peer(pc);
		if (rc == NGX_ERROR || rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ngx_event_connect_peer failed");
			goto error;
		}

		c = pc->connection;
		c->data = &peer[i];

		c->log = cycle->log;
		c->read->log = c->log;
		c->write->log = c->log;
		c->pool = cycle->pool;

		c->write->handler = write_handler;
		c->read->handler = read_handler;

		if (peer[i].timeout) {
			// set timeout
		}

		// add closer

		/* The kqueue's loop interface needs it. */
		if (rc == NGX_OK) {
			c->write->handler(c->write);
		}
	}

	return NGX_OK;

error:
	for (i = 0; i < peers.nelts; i++) {
		pc = &peer[i].pc;
		c = pc->connection;

		if (c) {
			ngx_close_connection(c);
			pc->connection = NULL;
		}
	}

	return NGX_ERROR;
}

static void *create_srv_conf(ngx_conf_t *cf)
{
	srv_conf_t *escf;

	escf = ngx_pcalloc(cf->pool, sizeof(srv_conf_t));
	if (escf == NULL) {
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

		if (ngx_strcmp(conf->serf_address.data, "off") == 0) {
			return NGX_CONF_OK;
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

		peer->auth.data = conf->serf_auth.data;
		peer->auth.len = conf->serf_auth.len;

		if (conf->timeout != NGX_CONF_UNSET_MSEC) {
			peer->timeout = conf->timeout;
		}

		peer->ssl = ssl;

		ngx_queue_init(&peer->ticket_keys);

		pc = &peer->pc;

		pc->sockaddr = u.addrs[0].sockaddr;
		pc->socklen = u.addrs[0].socklen;
		pc->name = &conf->serf_address;

		pc->get = ngx_event_get_peer;
		pc->log = cf->log;
		pc->log_error = NGX_ERROR_ERR;

		peer->state = HANDSHAKING;

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

		if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ssl.ctx, session_ticket_key_handler) == 0) {
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
			if (size != NGX_AGAIN) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with unexpected eof");

				recv->pos += off;

				if (recv->pos == recv->last) {
					recv->pos = recv->start;
					recv->last = recv->start;
				}
			}

			return NGX_AGAIN;
		case MSGPACK_UNPACK_NOMEM_ERROR:
			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with nomem error");

			return NGX_ABORT;
		default: /* MSGPACK_UNPACK_PARSE_ERROR */
			ngx_log_error(NGX_LOG_ERR, log, 0, "msgpack_unpack_next failed with parse error");

			recv->pos += off;

			if (recv->pos == recv->last) {
				recv->pos = recv->start;
				recv->last = recv->start;
			}

			return NGX_ERROR;
	}
}

static void dummy_write_handler(ngx_event_t *wev) { }

static void read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size, n;
	msgpack_unpacked und;
	uint32_t i;
	msgpack_object_str *str;
	uint64_t seq = 0;
	event_type_et type = 0;
	msgpack_object_bin payload;
	msgpack_object_kv* ptr;
	void *hdr_start;
	u_char *new_buf;
	key_st *key;
	ngx_queue_t *q;
	int have_key = 0, is_user_ev = 0;
#if NGX_DEBUG
	u_char buf[32];
#endif

	c = rev->data;
	peer = c->data;

	if (!peer->recv.start) {
		/* 1/2 of the page_size, is it enough? */
		peer->recv.start = ngx_palloc(c->pool, ngx_pagesize / 2);
		if (!peer->recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated recv buffer");
			return;
		}

		peer->recv.pos = peer->recv.start;
		peer->recv.last = peer->recv.start;
		peer->recv.end = peer->recv.start + ngx_pagesize / 2;
	}

	while (1) {
		n = peer->recv.end - peer->recv.last;

		/* buffer not big enough? enlarge it by twice */
		if (n == 0) {
			size = peer->recv.end - peer->recv.start;

			new_buf = ngx_palloc(c->pool, size * 2);
			if (new_buf == NULL) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_palloc failed to allocated new recv buffer");
				return;
			}

			ngx_memcpy(new_buf, peer->recv.start, size);

			peer->recv.start = new_buf;
			peer->recv.pos = new_buf;
			peer->recv.last = new_buf + size;
			peer->recv.end = new_buf + size * 2;

			n = peer->recv.end - peer->recv.last;
		}

		size = c->recv(c, peer->recv.last, n);

		if (size > 0) {
			peer->recv.last += size;
			continue;
		} else if (size == 0 || size == NGX_AGAIN) {
			break;
		} else {
			c->error = 1;
			return;
		}
	}

	msgpack_unpacked_init(&und);

	hdr_start = peer->recv.pos;

	switch (ether_msgpack_parse(&und, &peer->recv, size, c->log)) {
		case NGX_OK:
			break;
		case NGX_AGAIN:
		case NGX_ERROR:
			msgpack_unpacked_destroy(&und);
			return;
		case NGX_ABORT:
			exit(2); // something else?
	}

	if (und.data.type != MSGPACK_OBJECT_MAP) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expected a map");

		msgpack_unpacked_destroy(&und);
		return;
	}

	for (i = 0; i < und.data.via.map.size; i++) {
		ptr = &und.data.via.map.ptr[i];

		if (ptr->key.type != MSGPACK_OBJECT_STR) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect key to be string");

			msgpack_unpacked_destroy(&und);
			return;
		}

		str = &ptr->key.via.str;

		if (ngx_strncmp(str->ptr, "Seq", str->size) == 0) {
			if (ptr->val.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect seq value to be positive integer");

				msgpack_unpacked_destroy(&und);
				return;
			}

			seq = ptr->val.via.u64;

			if (peer->expected_seq && seq != peer->expected_seq) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC message");

				msgpack_unpacked_destroy(&und);
				return;
			}

			continue;
		}

		if (ngx_strncmp(str->ptr, "Error", str->size) == 0) {
			if (ptr->val.type != MSGPACK_OBJECT_STR) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, expect error value to be string");

				msgpack_unpacked_destroy(&und);
				return;
			}

			str = &ptr->val.via.str;
			if (str->size) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "ether RPC error: %*s", str->size, str->ptr);

				msgpack_unpacked_destroy(&und);
				return;
			}

			continue;
		}
	}

	if (!seq) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response header, missing sequence number");

		msgpack_unpacked_destroy(&und);
		return;
	}

	switch (peer->state) {
		case WAITING:
			peer->expected_seq = 0;

			if (seq != peer->ev_seq) {
				break;
			}

			switch (ether_msgpack_parse(&und, &peer->recv, size, c->log)) {
				case NGX_OK:
					break;
				case NGX_AGAIN:
					peer->recv.pos = hdr_start;
				case NGX_ERROR:
					msgpack_unpacked_destroy(&und);
					return;
				case NGX_ABORT:
					exit(2); // something else?
			}

			if (und.data.type != MSGPACK_OBJECT_MAP) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expected a map");

				msgpack_unpacked_destroy(&und);
				return;
			}

			memset(&payload, 0, sizeof(msgpack_object_bin));

			for (i = 0; i < und.data.via.map.size; i++) {
				ptr = &und.data.via.map.ptr[i];

				if (ptr->key.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect key to be string");

					msgpack_unpacked_destroy(&und);
					return;
				}

				str = &ptr->key.via.str;

				if (ngx_strncmp(str->ptr, "Event", str->size) == 0) {
					if (ptr->val.type != MSGPACK_OBJECT_STR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect key to be string");

						msgpack_unpacked_destroy(&und);
						return;
					}

					str = &ptr->val.via.str;

					if (ngx_strncmp(str->ptr, "user", str->size) == 0) {
						is_user_ev = 1;
						continue;
					}

					// only interested in user events for now
					break;
				}

				if (ngx_strncmp(str->ptr, "Name", str->size) == 0) {
					if (ptr->val.type != MSGPACK_OBJECT_STR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect key to be string");

						msgpack_unpacked_destroy(&und);
						return;
					}

					str = &ptr->val.via.str;

					if (ngx_strncmp(str->ptr, INSTALL_KEY_EVENT, str->size) == 0) {
						type = INSTALL_KEY;
					} else if (ngx_strncmp(str->ptr, REMOVE_KEY_EVENT, str->size) == 0) {
						type = REMOVE_KEY;
					} else if (ngx_strncmp(str->ptr, SET_DEFAULT_KEY_EVENT, str->size) == 0) {
						type = SET_DEFAULT_KEY;
					} else {
						// event not subscribed to
						break;
					}

					continue;
				}

				if (ngx_strncmp(str->ptr, "Payload", str->size) == 0) {
					if (ptr->val.type != MSGPACK_OBJECT_BIN && ptr->val.type != MSGPACK_OBJECT_STR) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response body, expect payload to be byte string");

						msgpack_unpacked_destroy(&und);
						return;
					}

					payload.size = ptr->val.via.bin.size;
					payload.ptr = ptr->val.via.bin.ptr;
					continue;
				}

				/*
				 * ignored key value pairs:
				 * 	- LTime: positive integer
				 * 	- Coalesce: boolean
				 */
			}

			if (!is_user_ev || !type) {
				break;
			}

			switch (type) {
				case INSTALL_KEY:
					if (payload.size != SSL_TICKET_KEY_NAME_LEN + 32) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
						break;
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
								have_key = 1;
								break;
							}
						}

						if (have_key) {
							ngx_log_error(NGX_LOG_ERR, c->log, 0, SET_DEFAULT_KEY_EVENT " event: already have key");
							break;
						}
					}

					key = ngx_pcalloc(c->pool, sizeof(key_st)); // is this the right pool?
					if (!key) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
						break;
					}

					memcpy(key->key.name, payload.ptr, SSL_TICKET_KEY_NAME_LEN);
					memcpy(key->key.aes_key, payload.ptr + SSL_TICKET_KEY_NAME_LEN, 16);
					memcpy(key->key.hmac_key, payload.ptr + SSL_TICKET_KEY_NAME_LEN + 16, 16);

					ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);
					break;
				case REMOVE_KEY:
					if (payload.size != SSL_TICKET_KEY_NAME_LEN) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
						break;
					}

					ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
						"ssl session ticket key removal: \"%*s\"",
						ngx_hex_dump(buf, (u_char *)payload.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

					if (ngx_queue_empty(&peer->ticket_keys)) {
						break;
					}

					for (q = ngx_queue_head(&peer->ticket_keys);
						q != ngx_queue_sentinel(&peer->ticket_keys);
						q = ngx_queue_next(q)) {
						key = ngx_queue_data(q, key_st, queue);

						if (ngx_memcmp(payload.ptr, key->key.name, SSL_TICKET_KEY_NAME_LEN) == 0) {
							ngx_queue_remove(q);

							ngx_memzero(&key->key, sizeof(key->key));
							ngx_pfree(c->pool, key); // is this the right pool?
							break;
						}
					}

					break;
				case SET_DEFAULT_KEY:
					if (payload.size != SSL_TICKET_KEY_NAME_LEN) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
						break;
					}

					ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
						"ssl session ticket key set default: \"%*s\"",
						ngx_hex_dump(buf, (u_char *)payload.ptr, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

					if (ngx_queue_empty(&peer->ticket_keys)) {
						ngx_log_error(NGX_LOG_ERR, c->log, 0, SET_DEFAULT_KEY_EVENT " event: without any keys");
						break;
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
						ngx_log_error(NGX_LOG_ERR, c->log, 0, SET_DEFAULT_KEY_EVENT " event: on unknown key, session ticket support disabled");

						SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
					}

					break;
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

			ngx_memzero((char *)payload.ptr, payload.size);
			break;
		case HANDSHAKING:
			if (peer->auth.len) {
				peer->state = AUTHENTICATING;
			} else {
				peer->state = SUBSCRIBING;
			}

			peer->expected_seq = 0;

			c->write->handler = write_handler;
			break;
		case AUTHENTICATING:
			peer->state = SUBSCRIBING;

			peer->expected_seq = 0;

			c->write->handler = write_handler;
			break;
		case SUBSCRIBING:
			peer->state = WAITING;

			peer->expected_seq = 0;
			break;
	}

	peer->recv.pos = peer->recv.start;
	peer->recv.last = peer->recv.start;

	msgpack_unpacked_destroy(&und);
}

static void write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	peer_st *peer;
	ssize_t size;
	msgpack_sbuffer *sbuf;
	msgpack_packer *pk;

	c = wev->data;
	peer = c->data;

	sbuf = &peer->sbuf;
	pk = &peer->pk;

	if (!peer->send.start) {
		if (RAND_bytes((uint8_t *)&peer->expected_seq, sizeof(peer->expected_seq)) != 1) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "RAND_bytes failed");
			return;
		}

		msgpack_sbuffer_init(sbuf);
		msgpack_packer_init(pk, sbuf, msgpack_sbuffer_write);

		switch (peer->state) {
			case WAITING:
				// should never happen
				return;
			case HANDSHAKING:
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
				msgpack_pack_uint64(pk, peer->expected_seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("Version") - 1);
				msgpack_pack_str_body(pk, "Version", sizeof("Version") - 1);
				msgpack_pack_int32(pk, 1);
				break;
			case AUTHENTICATING:
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
				msgpack_pack_uint64(pk, peer->expected_seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("AuthKey") - 1);
				msgpack_pack_str_body(pk, "AuthKey", sizeof("AuthKey") - 1);
				msgpack_pack_str(pk, peer->auth.len);
				msgpack_pack_str_body(pk, peer->auth.data, peer->auth.len);
				break;
			case SUBSCRIBING:
				peer->ev_seq = peer->expected_seq;

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
				msgpack_pack_uint64(pk, peer->expected_seq);

				// body
				msgpack_pack_map(pk, 1);

				msgpack_pack_str(pk, sizeof("Type") - 1);
				msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
				msgpack_pack_str(pk, sizeof(SUBSCRIBE_EVENTS) - 1);
				msgpack_pack_str_body(pk, SUBSCRIBE_EVENTS, sizeof(SUBSCRIBE_EVENTS) - 1);
				break;
		}

		peer->send.start = (u_char *)sbuf->data;
		peer->send.pos = (u_char *)sbuf->data;
		peer->send.last = (u_char *)sbuf->data + sbuf->size;
		peer->recv.end = (u_char *)sbuf->data + sbuf->alloc;
	}

	while (peer->send.pos < peer->send.last) {
		size = c->send(c, peer->send.pos, peer->send.last - peer->send.pos);
		if (size > 0) {
			peer->send.pos += size;
		} else if (size == 0 || size == NGX_AGAIN) {
			return;
		} else {
			c->error = 1;
			return;
		}
	}

	if (peer->send.pos == peer->send.last) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ether send done");

		peer->send.start = NULL;
		peer->send.pos = NULL;
		peer->send.last = NULL;
		peer->recv.end = NULL;

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
	if (peer == NULL) {
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

		RAND_bytes(iv, 16);
		EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key->key.aes_key, iv);
		HMAC_Init_ex(hctx, key->key.hmac_key, 16, EVP_sha256(), NULL);
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

		HMAC_Init_ex(hctx, key->key.hmac_key, 16, EVP_sha256(), NULL);
		EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key->key.aes_key, iv);

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
