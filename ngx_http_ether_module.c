#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define TIMER_DELAY 15*60*1000

typedef struct {
	ngx_str_t serf_address;
	ngx_str_t serf_auth;
	ngx_msec_t timeout;
} srv_conf_t;

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy);
static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

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
	NULL,            /* init process */
	NULL,            /* init thread */
	NULL,            /* exit thread */
	NULL,            /* exit process */
	NULL,            /* exit master */
	NGX_MODULE_V1_PADDING
};

static void *ngx_http_zircon_create_srv_conf(ngx_conf_t *cf)
{
	srv_conf_t *zscf;

	zscf = ngx_pcalloc(cf->pool, sizeof(srv_conf_t));
	if (zscf == NULL) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     zscf->serf_address = { 0, NULL };
	 *     zscf->serf_auth = { 0, NULL };
	 */

	zscf->timeout = NGX_CONF_UNSET_MSEC;

	return zscf;
}

static char *ngx_http_zircon_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	srv_conf_t *prev = parent;
	srv_conf_t *conf = child;
	ngx_http_ssl_srv_conf_t *ssl;
	ngx_url_t u;
	ngx_peer_connection_t *pc = NULL;
	ngx_connection_t *c;

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	ngx_conf_merge_str_value(conf->serf_address, prev->serf_address, "");
	ngx_conf_merge_str_value(conf->serf_auth, prev->serf_auth, "");
	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, NGX_CONF_UNSET_MSEC);

	if (conf->timeout != NGX_CONF_UNSET_MSEC) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether_timeout directive not implemented");
		goto error;
	}

	if (conf->serf_address.len) {
		if (!ssl->session_tickets) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used without ssl_session_tickets being enabled");
			goto error;
		}

		if (ssl->ssl_session_ticket_key) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used alongside the ssl_session_ticket_key directive");
			goto error;
		}

		if (ssl->builtin_session_cache != NGX_SSL_NO_SCACHE) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ether cannot be used without ssl_session_cache being set to off");
			goto error;
		}

		if (ngx_strcmp(conf->serf_address.data, "on") == 0) {
			ngx_str_set(conf->serf_address, "127.0.0.1:7373");
		}

		// TODO: does this (from here) need to move somewhere else?

		ngx_memzero(&u, sizeof(ngx_url_t));

		u.url.len = conf->serf_address.len;
		u.url.data = conf->serf_address.data;
		u.default_port = 7373;
		u.no_resolve = 1;

		if (ngx_parse_url(cf->pool, &u) != NGX_OK || !u.addrs || !u.addrs[0].sockaddr) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid url given in ether directive");
			goto error;
		}

		pc = ngx_pcalloc(cf->cycle->pool, sizeof(ngx_peer_connection_t));
		if (!pc) {
			goto error;
		}

		pc->log = cf->cycle->log;

		pc->sockaddr = u.addrs[0].sockaddr;
		pc->socklen = u.addrs[0].socklen;
		pc->name = &conf->serf_address;

		pc->get = ngx_event_get_peer;

		if (ngx_event_connect_peer(pc) != NGX_OK) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_event_connect_peer failed");
			goto error;
		}

		c = pc->connection;

		c->data = ssl;

		// c->write->handler = ;
		// c->read->handler = ;

		if (conf->timeout != NGX_CONF_UNSET_MSEC) {
			// set timeout
		}

		// add closer

		// send handshake

		if (conf->serf_auth.len) {
			// send auth
		}

		// subscribe to key event

		// get memcache servers

		if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ssl->ctx, session_ticket_key_handler) == 0) {
			ngx_log_error(NGX_LOG_WARN, cf->log, 0,
				"nginx was built with Session Tickets support, however, "
				"now it is linked dynamically to an OpenSSL library "
				"which has no tlsext support");
			goto error;
		}

		SSL_CTX_set_session_cache_mode(ssl->ssl->ctx, SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);

		SSL_CTX_sess_set_new_cb(ssl->ssl->ctx, new_session_handler);
		SSL_CTX_sess_set_get_cb(ssl->ssl->ctx, get_cached_session_handler);
		SSL_CTX_sess_set_remove_cb(ssl->ssl->ctx, remove_session_handler);
	}

	return NGX_CONF_OK;

error:
	if (pc) {
		if (pc->free) {
			(void) pc->free(pc, pc->data, 0);
		} else {
			ngx_close_connection(pc->connection);
			pc->connection = NULL;
		}
	}

	return NGX_CONF_ERROR;
}

static int session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
	SSL_CTX                       *ssl_ctx;
	ngx_uint_t                     i;
	ngx_array_t                   *keys;
	ngx_connection_t              *c;
	ngx_ssl_session_ticket_key_t  *key;
#if NGX_DEBUG
	u_char                         buf[32];
#endif

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_ticket_keys_index);
	if (keys == NULL) {
		return -1;
	}

	key = keys->elts;

	if (enc == 1) {
		/* encrypt session ticket */

		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket encrypt, key: \"%*s\" (%s session)",
			ngx_hex_dump(buf, key[0].name, 16) - buf, buf,
			SSL_session_reused(ssl_conn) ? "reused" : "new");

		RAND_bytes(iv, 16);
		EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key[0].aes_key, iv);
		HMAC_Init_ex(hctx, key[0].hmac_key, 16, ngx_ssl_session_ticket_md(), NULL);
		ngx_memcpy(name, key[0].name, 16);

		return 0;
	} else {
		/* decrypt session ticket */

		for (i = 0; i < keys->nelts; i++) {
			if (ngx_memcmp(name, key[i].name, 16) == 0) {
				goto found;
			}
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\" not found",
			ngx_hex_dump(buf, name, 16) - buf, buf);

		return 0;
	found:
		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\"%s",
			ngx_hex_dump(buf, key[i].name, 16) - buf, buf,
			(i == 0) ? " (default)" : "");

		HMAC_Init_ex(hctx, key[i].hmac_key, 16, ngx_ssl_session_ticket_md(), NULL);
		EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, key[i].aes_key, iv);

		return (i == 0) ? 1 : 2 /* renew */;
	}
}

static int new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
	// add
}

static ngx_ssl_session_t *get_cached_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id, int len, int *copy)
{
	if (!started) {
		// get
	}

	if (done) {
		return NULL;
	}

	return SSL_magic_pending_session_ptr();
}

static void remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	// del
}
