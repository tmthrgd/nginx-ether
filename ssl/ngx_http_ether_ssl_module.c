#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/aes.h>

#include "ngx_ether_module.h"

typedef struct {
	ngx_ether_peer_st peer;

	ngx_msec_t memc_timeout;

	ngx_http_ssl_srv_conf_t *ssl;
} ngx_http_ether_ssl_srv_conf_st;

typedef struct {
	ngx_ether_memc_op_st *op;
	ngx_event_t ev;
} ngx_http_ether_ssl_get_session_cleanup_st;

static ngx_int_t ngx_http_ether_ssl_init_process(ngx_cycle_t *cycle);

static void *ngx_http_ether_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ether_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_ether_ssl_set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_inline const EVP_AEAD *ngx_http_ether_ssl_select_aead(const ngx_ether_key_st *key);

static int ngx_http_ether_ssl_session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn,
		unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx,
		int enc);
static int ngx_http_ether_ssl_session_ticket_key_enc(ngx_ssl_conn_t *ssl_conn, uint8_t *name,
		uint8_t *nonce, EVP_AEAD_CTX *ctx);
static int ngx_http_ether_ssl_session_ticket_key_dec(ngx_ssl_conn_t *ssl_conn, const uint8_t *name,
		EVP_AEAD_CTX *ctx);

static int ngx_http_ether_ssl_new_session_handler(ngx_ssl_conn_t *ssl_conn,
		ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_http_ether_ssl_get_session_handler(ngx_ssl_conn_t *ssl_conn,
		u_char *id, int len, int *copy);
static void ngx_http_ether_ssl_remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

static void ngx_http_ether_ssl_get_session_memc_op_handler(ngx_ether_memc_op_st *op, void *data);
static void ngx_http_ether_ssl_get_session_cleanup_handler(void *data);
static void ngx_http_ether_ssl_get_session_timeout_handler(ngx_event_t *ev);

static int g_ssl_ctx_exdata_conf_index = -1;
static int g_ssl_exdata_memc_op_index = -1;
static int g_ssl_exdata_get_session_timeout_index = -1;

static ngx_conf_post_t ngx_http_ether_ssl_memc_prefix_check_post = { ngx_ether_memc_prefix_check };
static ngx_conf_post_t ngx_http_ether_ssl_serf_prefix_check_post = { ngx_ether_serf_prefix_check };

static ngx_command_t ngx_http_ether_ssl_module_commands[] = {
	{ ngx_string("ether_ssl"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, peer.serf.address),
	  NULL },

	{ ngx_string("ether_ssl_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_ether_ssl_set_opt_env_str,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, peer.serf.auth),
	  NULL },

	{ ngx_string("ether_ssl_serf_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, peer.serf.prefix),
	  &ngx_http_ether_ssl_serf_prefix_check_post },

	{ ngx_string("ether_ssl_session_id_hex"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, peer.memc.hex),
	  NULL },

	{ ngx_string("ether_ssl_session_id_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, peer.memc.prefix),
	  &ngx_http_ether_ssl_memc_prefix_check_post },

	{ ngx_string("ether_ssl_memc_timeout"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_msec_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ether_ssl_srv_conf_st, memc_timeout),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_ether_ssl_module_ctx = {
	NULL,                               /* preconfiguration */
	NULL,                               /* postconfiguration */

	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */

	ngx_http_ether_ssl_create_srv_conf, /* create server configuration */
	ngx_http_ether_ssl_merge_srv_conf,  /* merge server configuration */

	NULL,                               /* create location configuration */
	NULL                                /* merge location configuration */
};

ngx_module_t ngx_http_ether_ssl_module = {
	NGX_MODULE_V1,
	&ngx_http_ether_ssl_module_ctx,     /* module context */
	ngx_http_ether_ssl_module_commands, /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	ngx_http_ether_ssl_init_process,    /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_ether_ssl_init_process(ngx_cycle_t *cycle)
{
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_http_ether_ssl_srv_conf_st *conf;
	ngx_uint_t i;

	cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

	cscfp = cmcf->servers.elts;
	for (i = 0; i < cmcf->servers.nelts; i++) {
		conf = ngx_http_conf_get_module_srv_conf(cscfp[i], ngx_http_ether_ssl_module);
		if (!conf || !conf->peer.pool) {
			continue;
		}

		if (ngx_ether_connect_peer(&conf->peer) != NGX_OK) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ngx_ether_connect_peer failed");
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static void *ngx_http_ether_ssl_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_ether_ssl_srv_conf_st *escf;

	escf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ether_ssl_srv_conf_st));
	if (!escf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     escf->peer.serf.address = { 0, NULL };
	 *     escf->peer.serf.auth = { 0, NULL };
	 *     escf->peer.serf.prefix = { 0, NULL };
	 *     escf->peer.memc.prefix = { 0, NULL };
	 */

	escf->peer.memc.hex = NGX_CONF_UNSET;
	escf->memc_timeout = NGX_CONF_UNSET_MSEC;

	return escf;
}

static char *ngx_http_ether_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_ether_ssl_srv_conf_st *prev = parent;
	ngx_http_ether_ssl_srv_conf_st *conf = child;
	ngx_http_ssl_srv_conf_t *ssl;
	ngx_pool_cleanup_t *cln;

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	ngx_conf_merge_str_value(conf->peer.serf.address, prev->peer.serf.address, "");
	ngx_conf_merge_str_value(conf->peer.serf.auth, prev->peer.serf.auth, "");
	ngx_conf_merge_value(conf->peer.memc.hex, prev->peer.memc.hex, 1);
	ngx_conf_merge_str_value(conf->peer.serf.prefix, prev->peer.serf.prefix, "ether:");
	ngx_conf_merge_str_value(conf->peer.memc.prefix, prev->peer.memc.prefix,
		"ether:ssl-session-cache:");
	ngx_conf_merge_msec_value(conf->memc_timeout, prev->memc_timeout, 250);

	if (!conf->peer.serf.address.len || ngx_strcmp(conf->peer.serf.address.data, "off") == 0) {
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

	if (ngx_strcmp(conf->peer.serf.address.data, "on") == 0) {
		ngx_str_null(&conf->peer.serf.address);
	}

	conf->ssl = ssl;

	conf->peer.log = cf->log;
	conf->peer.pool = cf->pool;

	if (ngx_ether_create_peer(&conf->peer) != NGX_OK) {
		conf->peer.pool = NULL;
		return NGX_CONF_ERROR;
	}

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (!cln) {
		return NGX_CONF_ERROR;
	}

	cln->handler = (ngx_pool_cleanup_pt)ngx_ether_cleanup_peer;
	cln->data = &conf->peer;

	if (g_ssl_ctx_exdata_conf_index == -1) {
		g_ssl_ctx_exdata_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_conf_index == -1) {
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

	if (g_ssl_exdata_get_session_timeout_index == -1) {
		g_ssl_exdata_get_session_timeout_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_get_session_timeout_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_conf_index, conf)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data failed");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_clear_options(ssl->ssl.ctx, SSL_OP_NO_TICKET);

	if (!SSL_CTX_set_tlsext_ticket_key_cb(ssl->ssl.ctx,
			ngx_http_ether_ssl_session_ticket_key_handler)) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"nginx was built with Session Tickets support, however, "
			"now it is linked dynamically to an OpenSSL library "
			"which has no tlsext support");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_session_cache_mode(ssl->ssl.ctx, SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);

	SSL_CTX_sess_set_new_cb(ssl->ssl.ctx, ngx_http_ether_ssl_new_session_handler);
	SSL_CTX_sess_set_get_cb(ssl->ssl.ctx, ngx_http_ether_ssl_get_session_handler);
	SSL_CTX_sess_set_remove_cb(ssl->ssl.ctx, ngx_http_ether_ssl_remove_session_handler);

	if (ssl->session_timeout > NGX_ETHER_REALTIME_MAXDELTA) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"memcached does not support timeouts greater than %d seconds, " \
			"session_timeout of %d seconds will be capped",
			NGX_ETHER_REALTIME_MAXDELTA, ssl->session_timeout);
	}

	return NGX_CONF_OK;
}

static char *ngx_http_ether_ssl_set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *p = conf;

	ngx_str_t *field;
	const ngx_str_t *value;
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

static ngx_inline const EVP_AEAD *ngx_http_ether_ssl_select_aead(const ngx_ether_key_st *key)
{
	switch (key->len*8) {
		case 128:
			return EVP_aead_aes_128_gcm_siv();
		case 256:
			return EVP_aead_aes_256_gcm_siv();
		default:
			return NULL;
	}
}

static int ngx_http_ether_ssl_session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn,
		unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx,
		int enc)
{
	if (hctx != SSL_magic_tlsext_ticket_key_cb_aead_ptr()) {
		return TLSEXT_TICKET_CB_WANT_AEAD;
	}

	if (enc) {
		return ngx_http_ether_ssl_session_ticket_key_enc(ssl_conn, name, iv,
			(EVP_AEAD_CTX *)ectx);
	} else {
		return ngx_http_ether_ssl_session_ticket_key_dec(ssl_conn, name,
			(EVP_AEAD_CTX *)ectx);
	}
}

static int ngx_http_ether_ssl_session_ticket_key_enc(ngx_ssl_conn_t *ssl_conn, uint8_t *name,
		uint8_t *nonce, EVP_AEAD_CTX *ctx) {
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_http_ether_ssl_srv_conf_st *conf;
	const ngx_ether_key_st *key;
	const EVP_AEAD *aead;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	conf = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		return -1;
	}

	key = conf->peer.default_key;
	if (!key) {
		return -1;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"ssl session ticket encrypt, key: \"%*s\" (%s session)",
		ngx_hex_dump(buf, (u_char *)key->name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
		SSL_session_reused(ssl_conn) ? "reused" : "new");

	aead = ngx_http_ether_ssl_select_aead(key);
	if (!aead) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "invalid key length: %d", key->len);
		return -1;
	}

	if (RAND_bytes(nonce, EVP_AEAD_nonce_length(aead)) != 1) {
		return -1;
	}

	if (!EVP_AEAD_CTX_init(ctx, aead, key->key, key->len, EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
		return -1;
	}

	ngx_memcpy(name, key->name, SSL_TICKET_KEY_NAME_LEN);
	return 1;
}

static int ngx_http_ether_ssl_session_ticket_key_dec(ngx_ssl_conn_t *ssl_conn, const uint8_t *name,
		EVP_AEAD_CTX *ctx) {
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_http_ether_ssl_srv_conf_st *conf;
	const ngx_ether_key_st *key;
	const EVP_AEAD *aead;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	conf = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		return -1;
	}

	key = ngx_ether_get_key(&conf->peer, name);
	if (!key) {
		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\" not found",
			ngx_hex_dump(buf, (uint8_t *)name, SSL_TICKET_KEY_NAME_LEN) - buf, buf);
		return 0;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"ssl session ticket decrypt, key: \"%*s\"%s",
		ngx_hex_dump(buf, (u_char *)key->name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
		(key == conf->peer.default_key) ? " (default)" : "");

	aead = ngx_http_ether_ssl_select_aead(key);
	if (!aead) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "invalid key length: %d", key->len);
		return -1;
	}

	if (!EVP_AEAD_CTX_init(ctx, aead, key->key, key->len, EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
		return -1;
	}

	if (key->was_default) {
		return 2 /* renew */;
	} else {
		return 1;
	}
}

static int ngx_http_ether_ssl_new_session_handler(ngx_ssl_conn_t *ssl_conn,
		ngx_ssl_session_t *sess)
{
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_http_ether_ssl_srv_conf_st *conf;
	ngx_ether_memc_server_st *server;
	ngx_str_t key;
	ngx_keyval_t kv;
	unsigned int len;
	EVP_AEAD_CTX aead_ctx;
	CBB cbb;
	u_char *session = NULL, *name, *nonce, *p;
	size_t session_len, out_len;
	protocol_binary_request_add req;
	u_char buf[NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2];

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	conf = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		return 0;
	}

	kv.key.data = key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	kv.key.len = key.len = len;

	ngx_ether_format_memc_key(&conf->peer, &kv.key, buf);

	server = ngx_ether_get_memc_server(&conf->peer, &kv.key);
	if (!server) {
		return 0;
	}

	ngx_str_null(&kv.value);
	EVP_AEAD_CTX_zero(&aead_ctx);

	if (SSL_SESSION_to_bytes_for_ticket(sess, &session, &session_len)
		&& CBB_init(&cbb, SSL_TICKET_KEY_NAME_LEN + EVP_AEAD_MAX_NONCE_LENGTH + session_len
				+ EVP_AEAD_MAX_OVERHEAD)
		&& CBB_add_space(&cbb, &name, SSL_TICKET_KEY_NAME_LEN)
		&& CBB_reserve(&cbb, &nonce, EVP_AEAD_MAX_NONCE_LENGTH)
		&& ngx_http_ether_ssl_session_ticket_key_enc(ssl_conn, name, nonce, &aead_ctx) >= 0
		&& CBB_did_write(&cbb, EVP_AEAD_nonce_length(aead_ctx.aead))
		&& CBB_reserve(&cbb, &p, session_len + EVP_AEAD_max_overhead(aead_ctx.aead))
		&& EVP_AEAD_CTX_seal(&aead_ctx,
				p, &out_len, session_len + EVP_AEAD_max_overhead(aead_ctx.aead),
				nonce, EVP_AEAD_nonce_length(aead_ctx.aead),
				session, session_len, key.data, key.len)
		&& CBB_did_write(&cbb, out_len)
		&& CBB_finish(&cbb, &kv.value.data, &kv.value.len)) {
		ngx_memzero(&req, sizeof(protocol_binary_request_set));
		req.message.body.expiration =
			ngx_min(SSL_SESSION_get_timeout(sess), NGX_ETHER_REALTIME_MAXDELTA);

		(void) ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_ADDQ, &kv, &req);
	}

	OPENSSL_free(session);
	OPENSSL_free(kv.value.data);
	CBB_cleanup(&cbb);

	EVP_AEAD_CTX_cleanup(&aead_ctx);
	return 0;
}

static ngx_ssl_session_t *ngx_http_ether_ssl_get_session_handler(ngx_ssl_conn_t *ssl_conn,
		u_char *id, int len, int *copy)
{
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	ngx_ether_memc_op_st *op;
	const ngx_http_ether_ssl_srv_conf_st *conf;
	ngx_ether_memc_server_st *server;
	ngx_keyval_t kv;
	ngx_str_t value;
	ngx_int_t rc;
	ngx_pool_cleanup_t *cln;
	ngx_http_ether_ssl_get_session_cleanup_st *cln_data;
	ngx_event_t *ev;
	ngx_ssl_session_t *sess;
	EVP_AEAD_CTX aead_ctx;
	CBS cbs, name, nonce;
	size_t plaintext_len;
	u_char buf[NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2];

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	op = SSL_get_ex_data(ssl_conn, g_ssl_exdata_memc_op_index);
	if (!op) {
		conf = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_conf_index);
		if (!conf) {
			return NULL;
		}

		kv.key.data = id;
		kv.key.len = len;

		ngx_ether_format_memc_key(&conf->peer, &kv.key, buf);

		server = ngx_ether_get_memc_server(&conf->peer, &kv.key);
		if (!server) {
			return NULL;
		}

		ngx_str_null(&kv.value);

		op = ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_GET, &kv, NULL);
		if (!op) {
			return NULL;
		}

		op->handler = ngx_http_ether_ssl_get_session_memc_op_handler;
		op->handler_data = c->write;
		op->log = c->log;

		cln = ngx_pool_cleanup_add(c->pool,
			sizeof(ngx_http_ether_ssl_get_session_cleanup_st));
		if (!cln) {
			ngx_ether_memc_cleanup_operation(op);
			return NULL;
		}

		cln->handler = ngx_http_ether_ssl_get_session_cleanup_handler;

		cln_data = cln->data;
		ngx_memzero(cln_data, sizeof(ngx_http_ether_ssl_get_session_cleanup_st));

		cln_data->op = op;

		if (conf->memc_timeout > 0) {
			ev = &cln_data->ev;

			ev->handler = ngx_http_ether_ssl_get_session_timeout_handler;
			ev->data = c->write;
			ev->log = c->log;

			if (!SSL_set_ex_data(ssl_conn, g_ssl_exdata_get_session_timeout_index, ev)) {
				return NULL;
			}

			ngx_add_timer(ev, conf->memc_timeout);
		}

		if (!SSL_set_ex_data(ssl_conn, g_ssl_exdata_memc_op_index, op)) {
			return NULL;
		}

		return SSL_magic_pending_session_ptr();
	}

	ev = SSL_get_ex_data(ssl_conn, g_ssl_exdata_get_session_timeout_index);

	rc = ngx_ether_memc_complete_operation(op, &value, NULL);

	if (rc == NGX_AGAIN) {
		if (ev && ev->timedout) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "memcached operation timedout");
			return NULL;
		}

		return SSL_magic_pending_session_ptr();
	}

	if (ev) {
		ngx_del_timer(ev);
	}

	if (rc == NGX_ERROR) {
		return NULL;
	}

	/* rc == NGX_OK */
	CBS_init(&cbs, value.data, value.len);
	EVP_AEAD_CTX_zero(&aead_ctx);

	if (!CBS_get_bytes(&cbs, &name, SSL_TICKET_KEY_NAME_LEN)
		|| ngx_http_ether_ssl_session_ticket_key_dec(ssl_conn, CBS_data(&name), &aead_ctx)
			<= 0
		|| !CBS_get_bytes(&cbs, &nonce, EVP_AEAD_nonce_length(aead_ctx.aead))
		|| !EVP_AEAD_CTX_open(&aead_ctx,
				(uint8_t *)CBS_data(&cbs), &plaintext_len, CBS_len(&cbs),
				CBS_data(&nonce), CBS_len(&nonce), CBS_data(&cbs), CBS_len(&cbs),
				id, len)) {
		EVP_AEAD_CTX_cleanup(&aead_ctx);
		return NULL;
	}

	*copy = 0;
	sess = SSL_SESSION_from_bytes(CBS_data(&cbs), plaintext_len);
	if (sess) {
		ngx_memcpy(sess->session_id, id, len);
		sess->session_id_length = len;
	} else {
		ERR_clear_error(); /* Don't leave an error on the queue. */
	}

	EVP_AEAD_CTX_cleanup(&aead_ctx);
	return sess;
}

static void ngx_http_ether_ssl_remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	const ngx_http_ether_ssl_srv_conf_st *conf;
	ngx_ether_memc_server_st *server;
	ngx_keyval_t kv;
	unsigned int len;
	u_char buf[NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2];

	conf = SSL_CTX_get_ex_data(ssl, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		return;
	}

	kv.key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	kv.key.len = len;

	ngx_ether_format_memc_key(&conf->peer, &kv.key, buf);

	server = ngx_ether_get_memc_server(&conf->peer, &kv.key);
	if (!server) {
		return;
	}

	ngx_str_null(&kv.value);

	(void) ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_DELETEQ, &kv, NULL);
}

static void ngx_http_ether_ssl_get_session_memc_op_handler(ngx_ether_memc_op_st *op, void *data)
{
	ngx_event_t *ev = data;

	ngx_post_event(ev, &ngx_posted_events);
}

static void ngx_http_ether_ssl_get_session_cleanup_handler(void *data)
{
	ngx_http_ether_ssl_get_session_cleanup_st *cln = data;

	ngx_ether_memc_cleanup_operation(cln->op);

	if (cln->ev.timer_set) {
		ngx_del_timer(&cln->ev);
	}
}

static void ngx_http_ether_ssl_get_session_timeout_handler(ngx_event_t *ev)
{
	ngx_event_t *wev = ev->data;

	ngx_post_event(wev, &ngx_posted_events);
}
