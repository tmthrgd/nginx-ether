#ifndef _NGX_ETHER_H_INCLUDED_
#define _NGX_ETHER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include "protocol_binary.h"

#include <openssl/aes.h>

#define NGX_ETHER_SERF_MAX_KEY_PREFIX_LEN 64
#define NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN 64

#define NGX_ETHER_REALTIME_MAXDELTA 60*60*24*30

typedef struct ngx_ether_peer_st ngx_ether_peer_st;
typedef struct ngx_ether_memc_server_st ngx_ether_memc_server_st;
typedef struct ngx_ether_memc_op_st ngx_ether_memc_op_st;

typedef struct {
	struct {
		ngx_str_t address;
		ngx_str_t auth;
		ngx_str_t prefix;
	} serf;

	struct {
		ngx_flag_t hex;
		ngx_str_t prefix;
	} memc;

	ngx_pool_t *pool;
	ngx_log_t *log;
} ngx_ether_conf_st;

typedef struct {
	u_char name[SSL_TICKET_KEY_NAME_LEN];

	u_char key[EVP_AEAD_MAX_KEY_LENGTH];
	size_t key_len;

	const EVP_AEAD *aead;

	int was_default;

	ngx_queue_t queue;
} ngx_ether_key_st;

typedef void (*ngx_ether_memc_op_handler)(ngx_ether_memc_op_st *op, void *data);

ngx_ether_peer_st *ngx_ether_create_peer(const ngx_ether_conf_st *conf);
ngx_int_t ngx_ether_connect_peer(ngx_ether_peer_st *peer);
void ngx_ether_cleanup_peer(ngx_ether_peer_st *peer);

char *ngx_ether_memc_prefix_check(ngx_conf_t *cf, void *data, void *conf);
char *ngx_ether_serf_prefix_check(ngx_conf_t *cf, void *data, void *conf);

const ngx_ether_key_st *ngx_ether_get_key(const ngx_ether_peer_st *peer,
		const u_char name[SSL_TICKET_KEY_NAME_LEN]);
const ngx_ether_key_st *ngx_ether_get_default_key(const ngx_ether_peer_st *peer);

ngx_ether_memc_server_st *ngx_ether_get_memc_server(const ngx_ether_peer_st *peer,
		const ngx_str_t *key);

void ngx_ether_memc_default_op_handler(ngx_ether_memc_op_st *op, void *data);
void ngx_ether_memc_event_op_handler(ngx_ether_memc_op_st *op, void *data);

ngx_ether_memc_op_st *ngx_ether_memc_start_operation(ngx_ether_memc_server_st *server,
		protocol_binary_command cmd, const ngx_keyval_t *kv, void *data);
ngx_int_t ngx_ether_memc_peak_operation(const ngx_ether_memc_op_st *op);
ngx_int_t ngx_ether_memc_complete_operation(const ngx_ether_memc_op_st *op, ngx_str_t *value,
		void *data);
void ngx_ether_memc_cleanup_operation(ngx_ether_memc_op_st *op);

void ngx_ether_memc_set_log(ngx_ether_memc_op_st *op, ngx_log_t *log);
void ngx_ether_memc_set_handler(ngx_ether_memc_op_st *op, ngx_ether_memc_op_handler handler,
		void *data);

/* buf must be atleast peer->memc.prefix.len + key->len*(peer->memc.hex ? 2 : 1) bytes
 * buf should be MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2 bytes */
void ngx_ether_process_session_key_id(const ngx_ether_peer_st *peer, ngx_str_t *key, u_char *buf);

#endif /* _NGX_ETHER_H_INCLUDED_ */
