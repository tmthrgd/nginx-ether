#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_ETHER_MODULE_H
#define NGX_HTTP_ETHER_MODULE_H

typedef struct {
	ngx_str_t serf_address;
	ngx_str_t serf_auth;
	ngx_msec_t timeout;

	int enabled;
} ngx_http_ether_srv_conf_t;

static int ngx_http_ether_session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

static int ngx_http_ether_new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_http_ether_get_cached_session_handler(ngx_ssl_conn_t *ssl_conn,
		u_char *id, int len, int *copy);
static void ngx_http_ether_remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

static int ngx_http_ether_ssl_ctx_peer_index;

#endif /* NGX_HTTP_ETHER_MODULE_H */
