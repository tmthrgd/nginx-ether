#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/aes.h>

#include <msgpack.h>

#include "protocol_binary.h"

#define NGX_ETHER_INSTALL_KEY_EVENT "install-key"
#define NGX_ETHER_REMOVE_KEY_EVENT "remove-key"
#define NGX_ETHER_SET_DEFAULT_KEY_EVENT "set-default-key"
#define NGX_ETHER_WIPE_KEYS_EVENT "wipe-keys"
#define NGX_ETHER_LIST_KEYS_QUERY "list-keys"

#define NGX_ETHER_RETRIEVE_KEYS_QUERY "retrieve-keys"

#define NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT "memc"
#define NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT_REGEX ".*memc.*"

#define NGX_ETHER_MEMBER_JOIN_EVENT "member-join"
#define NGX_ETHER_MEMBER_LEAVE_EVENT "member-leave"
#define NGX_ETHER_MEMBER_FAILED_EVENT "member-failed"
#define NGX_ETHER_MEMBER_UPDATE_EVENT "member-update"

#define NGX_ETHER_STREAM_MEMBER_EVENTS \
	(NGX_ETHER_MEMBER_JOIN_EVENT "," NGX_ETHER_MEMBER_LEAVE_EVENT "," \
	NGX_ETHER_MEMBER_FAILED_EVENT "," NGX_ETHER_MEMBER_UPDATE_EVENT)

#define NGX_ETHER_CHASH_NPOINTS 160

#define NGX_ETHER_REALTIME_MAXDELTA 60*60*24*30

#define NGX_ETHER_SERF_SEQ_STATE_MASK 0x0f

#define NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN 64
#define NGX_ETHER_SERF_MAX_KEY_PREFIX_LEN 64

#if !NGX_HTTP_ETHER_HAVE_HTONLL
#	if NGX_HAVE_LITTLE_ENDIAN
#		include <byteswap.h>
#		define htonll(n) bswap_64((n))
#		define ntohll(n) bswap_64((n))
#	else /* NGX_HAVE_LITTLE_ENDIAN */
#		define htonll(n) (n)
#		define ntohll(n) (n)
#	endif /* NGX_HAVE_LITTLE_ENDIAN */
#endif /* !NGX_HTTP_ETHER_HAVE_HTONLL */

typedef struct _ngx_ether_peer_st ngx_ether_peer_st;
typedef struct _ngx_ether_memc_op_st ngx_ether_memc_op_st;

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

typedef struct {
	u_char name[SSL_TICKET_KEY_NAME_LEN];

	u_char key[EVP_AEAD_MAX_KEY_LENGTH];
	size_t key_len;

	const EVP_AEAD *aead;

	ngx_atomic_uint_t nonce_seq;

	int was_default;

	ngx_queue_t queue;
} ngx_ether_key_st;

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

	int udp;

	const ngx_ether_peer_st *peer;

	ngx_connection_t *c;

	ngx_atomic_uint_t id;

	ngx_queue_t recv_ops;
	ngx_queue_t send_ops;

	ngx_buf_t tmp_recv;

	ngx_queue_t queue;
} ngx_ether_memc_server_st;

typedef void (*ngx_ether_memc_op_handler)(ngx_ether_memc_op_st *op, void *data);

typedef struct _ngx_ether_memc_op_st {
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

typedef struct _ngx_ether_peer_st {
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

		ngx_str_t tag_key;

		ngx_ether_state_et state;

		uint64_t seq;

		uint64_t listing_keys_id;
	} serf;

	struct {
		/* conf directives */
		ngx_flag_t hex;
		ngx_str_t prefix;
		ngx_msec_t timeout;

		ngx_queue_t servers;

		ngx_uint_t npoints;
		ngx_ether_chash_point_st *points;
	} memc;

	AES_KEY nonce_key;

	ngx_pool_t *pool;
	ngx_log_t *log;

	ngx_http_ssl_srv_conf_t *ssl;

	ngx_queue_t ticket_keys;
	ngx_ether_key_st *default_ticket_key;
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

typedef struct {
	ngx_ether_memc_op_st *op;
	ngx_event_t *ev;
} ngx_ether_get_session_cleanup_st;

static ngx_int_t ngx_ether_init_process(ngx_cycle_t *cycle);

static void ngx_ether_cleanup_peer(void *data);

static void *ngx_ether_create_srv_conf(ngx_conf_t *cf);
static char *ngx_ether_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_ether_set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_ether_memc_prefix_check(ngx_conf_t *cf, void *data, void *conf);
static char *ngx_ether_serf_prefix_check(ngx_conf_t *cf, void *data, void *conf);

static void ngx_ether_serf_read_handler(ngx_event_t *rev);
static void ngx_ether_serf_write_handler(ngx_event_t *wev);

static int ngx_ether_serf_cmd_state_cmp(const void *in_a, const void *in_b);

static void ngx_ether_add_handshake_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_auth_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_key_ev_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_key_query_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_member_ev_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_list_members_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer);
static void ngx_ether_add_respond_list_keys_body(msgpack_packer *pk, ngx_ether_peer_st *peer);

static ngx_int_t ngx_ether_handle_handshake_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);
static ngx_int_t ngx_ether_handle_auth_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);
static ngx_int_t ngx_ether_handle_key_ev_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);
static ngx_int_t ngx_ether_handle_key_query_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);
static ngx_int_t ngx_ether_handle_member_ev_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);
static ngx_int_t ngx_ether_handle_list_members_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size);

static ngx_int_t ngx_ether_handle_member_resp_body(ngx_connection_t *c, ngx_ether_peer_st *peer,
		const msgpack_object *members, ngx_ether_handle_member_resp_body_et todo);

#if NGX_DEBUG
static void ngx_ether_log_memc_version_handler(ngx_ether_memc_op_st *op, void *data);
#endif /* NGX_DEBUG */

static ngx_int_t ngx_ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size,
		ngx_log_t *log);
static const char *ngx_ether_msgpack_parse_map(const msgpack_object *obj, ...);
static int ngx_ether_msgpack_write(void *data, const char *buf, size_t len);

static int ngx_libc_cdecl ngx_ether_chash_cmp_points(const void *one, const void *two);
static ngx_uint_t ngx_ether_find_chash_point(ngx_uint_t npoints,
		const ngx_ether_chash_point_st *point, uint32_t hash);
static ngx_ether_memc_server_st *ngx_ether_get_memc_server(const ngx_ether_peer_st *peer,
		const ngx_str_t *key);

static void ngx_ether_memc_read_handler(ngx_event_t *rev);
static void ngx_ether_memc_write_handler(ngx_event_t *wev);

static void ngx_ether_memc_default_op_handler(ngx_ether_memc_op_st *op, void *data);
static void ngx_ether_memc_event_op_handler(ngx_ether_memc_op_st *op, void *data);

static ngx_ether_memc_op_st *ngx_ether_memc_start_operation(ngx_ether_memc_server_st *server,
		protocol_binary_command cmd, const ngx_keyval_t *kv, void *data);
static ngx_int_t ngx_ether_memc_complete_operation(const ngx_ether_memc_op_st *op,
		ngx_str_t *value, void *data);
static void ngx_ether_memc_cleanup_operation(ngx_ether_memc_op_st *op);

static int ngx_ether_session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);
static int ngx_ether_session_ticket_key_enc(ngx_ssl_conn_t *ssl_conn, uint8_t *name, uint8_t *nonce,
		EVP_AEAD_CTX *ctx);
static int ngx_ether_session_ticket_key_dec(ngx_ssl_conn_t *ssl_conn, const uint8_t *name,
		EVP_AEAD_CTX *ctx);

static int ngx_ether_new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_ether_get_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id,
		int len, int *copy);
static void ngx_ether_remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess);

/* buf must be atleast peer->memc.prefix.len + key->len*(peer->memc.hex ? 2 : 1) bytes
 * buf should be MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2 bytes */
static inline void ngx_ether_process_session_key_id(const ngx_ether_peer_st *peer, ngx_str_t *key,
		u_char *buf);

static void ngx_ether_get_session_cleanup_handler(void *data);
static void ngx_ether_get_session_timeout_handler(ngx_event_t *ev);

static int g_ssl_ctx_exdata_peer_index = -1;
static int g_ssl_exdata_memc_op_index = -1;
static int g_ssl_exdata_get_session_timeout_index = -1;

static const ngx_ether_serf_cmd_st ngx_ether_serf_cmds[] = {
	{ NGX_ETHER_HANDSHAKING,
	  ngx_string("handshake"),
	  ngx_ether_add_handshake_req_body,
	  ngx_ether_handle_handshake_resp },
	{ NGX_ETHER_AUTHENTICATING,
	  ngx_string("auth"),
	  ngx_ether_add_auth_req_body,
	  ngx_ether_handle_auth_resp },
	{ NGX_ETHER_STREAM_KEY_EVSUB,
	  ngx_string("stream"),
	  ngx_ether_add_key_ev_req_body,
	  ngx_ether_handle_key_ev_resp },
	{ NGX_ETHER_RETRIEVE_KEYS,
	  ngx_string("query"),
	  ngx_ether_add_key_query_req_body,
	  ngx_ether_handle_key_query_resp },
	{ NGX_ETHER_STREAM_MEMBER_EVSUB,
	  ngx_string("stream"),
	  ngx_ether_add_member_ev_req_body,
	  ngx_ether_handle_member_ev_resp },
	{ NGX_ETHER_LISTING_MEMBERS,
	  ngx_string("members-filtered"),
	  ngx_ether_add_list_members_req_body,
	  ngx_ether_handle_list_members_resp },
	{ NGX_ETHER_RESPOND_LIST_KEYS_QUERY,
	  ngx_string("respond"),
	  ngx_ether_add_respond_list_keys_body,
	  NULL },
};
static const size_t ngx_ether_num_serf_cmds =
	sizeof(ngx_ether_serf_cmds) / sizeof(ngx_ether_serf_cmds[0]);

static ngx_conf_post_t ngx_ether_memc_prefix_check_post = { ngx_ether_memc_prefix_check };
static ngx_conf_post_t ngx_ether_serf_prefix_check_post = { ngx_ether_serf_prefix_check };

static ngx_command_t ngx_ether_module_commands[] = {
	{ ngx_string("ether"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, serf.address),
	  NULL },

	{ ngx_string("ether_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_ether_set_opt_env_str,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, serf.auth),
	  NULL },

	{ ngx_string("ether_serf_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, serf.prefix),
	  &ngx_ether_serf_prefix_check_post },

	{ ngx_string("ether_session_id_hex"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, memc.hex),
	  NULL },

	{ ngx_string("ether_session_id_prefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, memc.prefix),
	  &ngx_ether_memc_prefix_check_post },

	{ ngx_string("ether_memc_timeout"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_msec_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_ether_peer_st, memc.timeout),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_ether_module_ctx = {
	NULL,                      /* preconfiguration */
	NULL,                      /* postconfiguration */

	NULL,                      /* create main configuration */
	NULL,                      /* init main configuration */

	ngx_ether_create_srv_conf, /* create server configuration */
	ngx_ether_merge_srv_conf,  /* merge server configuration */

	NULL,                      /* create location configuration */
	NULL                       /* merge location configuration */
};

ngx_module_t ngx_http_ether_module = {
	NGX_MODULE_V1,
	&ngx_ether_module_ctx,     /* module context */
	ngx_ether_module_commands, /* module directives */
	NGX_HTTP_MODULE,           /* module type */
	NULL,                      /* init master */
	NULL,                      /* init module */
	ngx_ether_init_process,    /* init process */
	NULL,                      /* init thread */
	NULL,                      /* exit thread */
	NULL,                      /* exit process */
	NULL,                      /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_ether_init_process(ngx_cycle_t *cycle)
{
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_ether_peer_st *peer;
	ngx_connection_t *c;
	ngx_peer_connection_t *pc;
	ngx_int_t rc;
	ngx_event_t *rev, *wev;
	ngx_uint_t i;

	cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

	cscfp = cmcf->servers.elts;
	for (i = 0; i < cmcf->servers.nelts; i++) {
		peer = ngx_http_conf_get_module_srv_conf(cscfp[i], ngx_http_ether_module);
		if (!peer || !peer->serf.pc_connect) {
			continue;
		}

		pc = &peer->serf.pc;

		rc = ngx_event_connect_peer(pc);
		if (rc == NGX_ERROR || rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ngx_event_connect_peer failed");
			return NGX_ERROR;
		}

		c = pc->connection;
		c->data = peer;

		rev = c->read;
		wev = c->write;

		c->log = cycle->log;
		rev->log = c->log;
		wev->log = c->log;
		c->pool = cycle->pool;

		rev->handler = ngx_ether_serf_read_handler;
		wev->handler = ngx_ether_serf_write_handler;

		peer->serf.pc_connect = 0;

		/* The kqueue's loop interface needs it. */
		if (rc == NGX_OK) {
			wev->handler(wev);
		}
	}

	return NGX_OK;
}

static void ngx_ether_cleanup_peer(void *data)
{
	ngx_ether_peer_st *peer = data;
	ngx_peer_connection_t *pc;
	ngx_connection_t *c;
	ngx_queue_t *q;
	ngx_ether_memc_server_st *server;
	ngx_ether_key_st *key;

	pc = &peer->serf.pc;

	c = pc->connection;
	if (c) {
		ngx_close_connection(c);
		pc->connection = NULL;
	}

	for (q = ngx_queue_head(&peer->memc.servers);
		q != ngx_queue_sentinel(&peer->memc.servers);
		q = ngx_queue_next(q)) {
		server = ngx_queue_data(q, ngx_ether_memc_server_st, queue);

		ngx_close_connection(server->c);
	}

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		key = ngx_queue_data(q, ngx_ether_key_st, queue);

		ngx_memzero(key->key, EVP_AEAD_MAX_KEY_LENGTH);
	}
}

static void *ngx_ether_create_srv_conf(ngx_conf_t *cf)
{
	ngx_ether_peer_st *escf;

	escf = ngx_pcalloc(cf->pool, sizeof(ngx_ether_peer_st));
	if (!escf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     escf->serf.address = { 0, NULL };
	 *     escf->serf.auth = { 0, NULL };
	 *     escf->serf.prefix = { 0, NULL };
	 *     escf->memc.prefix = { 0, NULL };
	 */

	escf->memc.hex = NGX_CONF_UNSET;
	escf->memc.timeout = NGX_CONF_UNSET_MSEC;

	return escf;
}

static char *ngx_ether_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_ether_peer_st *prev = parent;
	ngx_ether_peer_st *peer = child;
	ngx_http_ssl_srv_conf_t *ssl;
	ngx_url_t u;
	ngx_pool_cleanup_t *cln;
	ngx_peer_connection_t *pc;
	union {
		uint64_t u64;
		uint8_t byte[sizeof(uint64_t)];
	} seq;
	uint8_t nonce_key[16];
	u_char c;

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	ngx_conf_merge_str_value(peer->serf.address, prev->serf.address, "");
	ngx_conf_merge_str_value(peer->serf.auth, prev->serf.auth, "");
	ngx_conf_merge_value(peer->memc.hex, prev->memc.hex, 1);
	ngx_conf_merge_str_value(peer->serf.prefix, prev->serf.prefix, "ether:");
	ngx_conf_merge_str_value(peer->memc.prefix, prev->memc.prefix, "ether:ssl-session-cache:");
	ngx_conf_merge_msec_value(peer->memc.timeout, prev->memc.timeout, 250);

	if (!peer->serf.address.len || ngx_strcmp(peer->serf.address.data, "off") == 0) {
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

	if (ngx_strcmp(peer->serf.address.data, "on") == 0) {
		ngx_str_set(&peer->serf.address, "127.0.0.1:7373");
	}

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = peer->serf.address;
	u.default_port = 7373;
	u.no_resolve = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK || !u.addrs || !u.addrs[0].sockaddr) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid url given in ether directive");
		return NGX_CONF_ERROR;
	}

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (!cln) {
		return NGX_CONF_ERROR;
	}

	cln->handler = ngx_ether_cleanup_peer;
	cln->data = peer;

	ngx_queue_init(&peer->memc.servers);

	peer->pool = cf->pool;
	peer->log = cf->log;

	peer->ssl = ssl;

	ngx_queue_init(&peer->ticket_keys);

	pc = &peer->serf.pc;

	pc->sockaddr = u.addrs[0].sockaddr;
	pc->socklen = u.addrs[0].socklen;
	pc->name = &peer->serf.address;

	pc->get = ngx_event_get_peer;
	pc->log = cf->log;
	pc->log_error = NGX_ERROR_ERR;

	peer->serf.has_send = 1;

	peer->serf.state = NGX_ETHER_HANDSHAKING;

	do {
		if (RAND_bytes(seq.byte, sizeof(uint64_t)) != 1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "RAND_bytes failed");
			return NGX_CONF_ERROR;
		}

		seq.u64 &= ~(uint64_t)NGX_ETHER_SERF_SEQ_STATE_MASK;
	} while (!seq.u64);

	peer->serf.seq = seq.u64;

	peer->serf.send.tag = cf->pool;

	if (peer->serf.prefix.len == 0) {
		ngx_str_set(&peer->serf.tag_key, "ether");
	} else {
		c = peer->serf.prefix.data[peer->serf.prefix.len - 1];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			peer->serf.tag_key = peer->serf.prefix;
		} else if (peer->serf.prefix.len == 1) {
			ngx_str_set(&peer->serf.tag_key, "ether");
		} else {
			peer->serf.tag_key.data = ngx_pstrdup(cf->pool, &peer->serf.prefix);
			if (!peer->serf.tag_key.data) {
				return NGX_CONF_ERROR;
			}

			peer->serf.tag_key.len = peer->serf.prefix.len - 1;
			peer->serf.tag_key.data[peer->serf.tag_key.len] = '\0';
		}
	}

	if (RAND_bytes(nonce_key, sizeof(nonce_key)) != 1) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "RAND_bytes failed");
		return NGX_CONF_ERROR;
	}

	if (AES_set_encrypt_key(nonce_key, sizeof(nonce_key)*8, &peer->nonce_key) < 0) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "AES_set_encrypt_key failed");
		return NGX_CONF_ERROR;
	}

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

	if (g_ssl_exdata_get_session_timeout_index == -1) {
		g_ssl_exdata_get_session_timeout_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_get_session_timeout_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_peer_index, peer)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data failed");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_options(ssl->ssl.ctx, SSL_OP_NO_TICKET);

	if (!SSL_CTX_set_tlsext_ticket_key_cb(ssl->ssl.ctx, ngx_ether_session_ticket_key_handler)) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"nginx was built with Session Tickets support, however, "
			"now it is linked dynamically to an OpenSSL library "
			"which has no tlsext support");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_session_cache_mode(ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

	SSL_CTX_sess_set_new_cb(ssl->ssl.ctx, ngx_ether_new_session_handler);
	SSL_CTX_sess_set_get_cb(ssl->ssl.ctx, ngx_ether_get_session_handler);
	SSL_CTX_sess_set_remove_cb(ssl->ssl.ctx, ngx_ether_remove_session_handler);

	if (ssl->session_timeout > NGX_ETHER_REALTIME_MAXDELTA) {
		ngx_log_error(NGX_LOG_WARN, cf->log, 0,
			"memcached does not support timeouts greater than %d seconds, " \
			"session_timeout of %d seconds will be capped",
			NGX_ETHER_REALTIME_MAXDELTA, ssl->session_timeout);
	}

	peer->serf.pc_connect = 1;

	return NGX_CONF_OK;
}

static char *ngx_ether_set_opt_env_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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

static char *ngx_ether_memc_prefix_check(ngx_conf_t *cf, void *data, void *conf)
{
	ngx_str_t *str = conf;

	if (str->len > NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN) {
		return "too long";
	}

	return NGX_CONF_OK;
}

static char *ngx_ether_serf_prefix_check(ngx_conf_t *cf, void *data, void *conf)
{
	ngx_str_t *str = conf;

	if (str->len > NGX_ETHER_SERF_MAX_KEY_PREFIX_LEN) {
		return "too long";
	}

	if (ngx_strchr(str->data, ',')) {
		return "contains invalid character";
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_ether_msgpack_parse(msgpack_unpacked *und, ngx_buf_t *recv, ssize_t size,
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

static const char *ngx_ether_msgpack_parse_map(const msgpack_object *obj, ...)
{
	va_list ap;
	msgpack_object *out;
	msgpack_object_kv *ptr;
	const msgpack_object_str *str;
	size_t i;
	int found;
	const char *name;

	if (obj->type != MSGPACK_OBJECT_MAP) {
		return "malformed RPC response, expected a map";
	}

	va_start(ap, obj);
	for (;;) {
		name = va_arg(ap, const char *);
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

				if (out && out->type && ptr->val.type != out->type) {
					va_end(ap);
					return "malformed RPC response, wrong type given";
				}

				if (out) {
					*out = ptr->val;
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

static int ngx_ether_msgpack_write(void *data, const char *buf, size_t len)
{
	ngx_buf_t *nbuf = data;
	ngx_pool_t *pool = nbuf->tag;
	u_char *new_buf;
	size_t size, nsize;

	if (!nbuf->start || (size_t)(nbuf->end - nbuf->last) < len) {
		if (nbuf->start) {
			size = nbuf->last - nbuf->start;
			nsize = (nbuf->end - nbuf->start) * 2;
		} else {
			size = 0;
			nsize = ngx_pagesize / 4;
		}

		while (nsize < size + len) {
			nsize *= 2;
		}

		new_buf = ngx_palloc(pool, nsize);
		if (!new_buf) {
			return -1;
		}

		if (nbuf->start) {
			ngx_memcpy(new_buf, nbuf->start, size);
			ngx_pfree(pool, nbuf->start);
		}

		nbuf->start = new_buf;
		nbuf->pos = new_buf;
		nbuf->last = new_buf + size;
		nbuf->end = new_buf + nsize;
	}

	nbuf->last = ngx_cpymem(nbuf->last, buf, len);
	return 0;
}

static void ngx_ether_serf_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	ngx_ether_peer_st *peer;
	ssize_t size, n;
	msgpack_unpacked und;
	void *hdr_start;
	u_char *new_buf;
	const char *err;
	msgpack_object seq, error;
	ngx_ether_serf_cmd_st b;
	const ngx_ether_serf_cmd_st *cmd;

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
			ngx_pfree(c->pool, peer->serf.recv.start);

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

	switch (ngx_ether_msgpack_parse(&und, &peer->serf.recv, size, c->log)) {
		case NGX_OK:
			break;
		case NGX_AGAIN:
			goto cleanup;
		case NGX_ABORT:
			assert(!"ether_msgpack_parse returned NGX_ABORT");
			goto done;
		default: /* NGX_ERROR */
			goto done;
	}

	seq.type = MSGPACK_OBJECT_POSITIVE_INTEGER;
	error.type = MSGPACK_OBJECT_STR;

	err = ngx_ether_msgpack_parse_map(&und.data, "Seq", &seq, "Error", &error, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto done;
	}

	if (error.via.str.size) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ether RPC error: %*s",
			error.via.str.size, error.via.str.ptr);
		goto done;
	}

	if (peer->serf.seq != (seq.via.u64 & ~(uint64_t)NGX_ETHER_SERF_SEQ_STATE_MASK)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"unrecognised RPC seq number: %xd", seq.via.u64);
		goto done;
	}

	b.state = seq.via.u64 & NGX_ETHER_SERF_SEQ_STATE_MASK;
	cmd = bsearch(&b, ngx_ether_serf_cmds, ngx_ether_num_serf_cmds,
		sizeof(ngx_ether_serf_cmd_st), ngx_ether_serf_cmd_state_cmp);
	if (!cmd) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"unrecognised RPC seq number: %xd", seq.via.u64);
		goto done;
	}

	if (!cmd->handle_serf_resp) {
		goto done;
	}

	switch (cmd->handle_serf_resp(c, peer, size)) {
		case NGX_AGAIN:
			peer->serf.recv.pos = hdr_start;
			goto cleanup;
		case NGX_ABORT:
			assert(!"cmd->handle_serf_resp returned NGX_ABORT");
			break;
		default: /* NGX_OK || NGX_ERROR */
			break;
	}

done:
	peer->serf.recv.pos = peer->serf.recv.start;
	peer->serf.recv.last = peer->serf.recv.start;

cleanup:
	msgpack_unpacked_destroy(&und);
}

static void ngx_ether_serf_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	ngx_ether_peer_st *peer;
	ssize_t size;
	msgpack_packer pk;
	ngx_ether_serf_cmd_st b;
	const ngx_ether_serf_cmd_st *cmd;

	c = wev->data;
	peer = c->data;

	if (!peer->serf.has_send) {
		return;
	}

	if (peer->serf.send.last == peer->serf.send.start) {
		b.state = peer->serf.state;
		cmd = bsearch(&b, ngx_ether_serf_cmds, ngx_ether_num_serf_cmds,
			sizeof(ngx_ether_serf_cmd_st), ngx_ether_serf_cmd_state_cmp);
		if (!cmd) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"write_handler called in invalid state");
			return;
		}

		msgpack_packer_init(&pk, &peer->serf.send, ngx_ether_msgpack_write);

		// header
		// {"Command": "handshake", "Seq": 0}
		msgpack_pack_map(&pk, 2);

		msgpack_pack_str(&pk, sizeof("Command") - 1);
		msgpack_pack_str_body(&pk, "Command", sizeof("Command") - 1);
		msgpack_pack_str(&pk, cmd->name.len);
		msgpack_pack_str_body(&pk, cmd->name.data, cmd->name.len);

		msgpack_pack_str(&pk, sizeof("Seq") - 1);
		msgpack_pack_str_body(&pk, "Seq", sizeof("Seq") - 1);
		msgpack_pack_uint64(&pk, peer->serf.seq | peer->serf.state);

		// body
		cmd->add_serf_req_body(&pk, peer);
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

		peer->serf.send.pos = peer->serf.send.start;
		peer->serf.send.last = peer->serf.send.start;

		peer->serf.has_send = 0;
	}
}

static int ngx_ether_serf_cmd_state_cmp(const void *in_a, const void *in_b)
{
	const ngx_ether_serf_cmd_st *a = in_a, *b = in_b;

	if (a->state > b->state) {
		return 1;
	} else if (a->state < b->state) {
		return -1;
	} else {
		return 0;
	}
}

static void ngx_ether_add_handshake_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	// {"Version": 1}

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Version") - 1);
	msgpack_pack_str_body(pk, "Version", sizeof("Version") - 1);
	msgpack_pack_int32(pk, 1);
}

static void ngx_ether_add_auth_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	// {"AuthKey": "my-secret-auth-token"}

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("AuthKey") - 1);
	msgpack_pack_str_body(pk, "AuthKey", sizeof("AuthKey") - 1);
	msgpack_pack_str(pk, peer->serf.auth.len);
	msgpack_pack_str_body(pk, peer->serf.auth.data, peer->serf.auth.len);
}

static void ngx_ether_add_key_ev_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	u_char buf[5 * NGX_ETHER_SERF_MAX_KEY_PREFIX_LEN
		+ 4 * (sizeof("user:" /*event name*/ ",") - 1)
		+ sizeof("query:" /*query name*/) - 1
		+ sizeof(NGX_ETHER_INSTALL_KEY_EVENT NGX_ETHER_REMOVE_KEY_EVENT
			NGX_ETHER_SET_DEFAULT_KEY_EVENT NGX_ETHER_WIPE_KEYS_EVENT
			NGX_ETHER_LIST_KEYS_QUERY) - 1
		+ 1];
	u_char *p = buf;

	p = ngx_cpymem(p, "user:", sizeof("user:") - 1);
	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_INSTALL_KEY_EVENT, sizeof(NGX_ETHER_INSTALL_KEY_EVENT) - 1);

	*p++ = ',';

	p = ngx_cpymem(p, "user:", sizeof("user:") - 1);
	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_REMOVE_KEY_EVENT, sizeof(NGX_ETHER_REMOVE_KEY_EVENT) - 1);

	*p++ = ',';

	p = ngx_cpymem(p, "user:", sizeof("user:") - 1);
	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_SET_DEFAULT_KEY_EVENT,
		sizeof(NGX_ETHER_SET_DEFAULT_KEY_EVENT) - 1);

	*p++ = ',';

	p = ngx_cpymem(p, "user:", sizeof("user:") - 1);
	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_WIPE_KEYS_EVENT, sizeof(NGX_ETHER_WIPE_KEYS_EVENT) - 1);

	*p++ = ',';

	p = ngx_cpymem(p, "query:", sizeof("query:") - 1);
	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_LIST_KEYS_QUERY, sizeof(NGX_ETHER_LIST_KEYS_QUERY) - 1);

	*p = '\0';

	// {"Type": "member-join,user:deploy"}

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Type") - 1);
	msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
	msgpack_pack_str(pk, p - buf);
	msgpack_pack_str_body(pk, buf, p - buf);
}

static void ngx_ether_add_key_query_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	u_char buf[NGX_ETHER_SERF_MAX_KEY_PREFIX_LEN + sizeof(NGX_ETHER_RETRIEVE_KEYS_QUERY)];
	u_char *p = buf;

	p = ngx_cpymem(p, peer->serf.prefix.data, peer->serf.prefix.len);
	p = ngx_cpymem(p, NGX_ETHER_RETRIEVE_KEYS_QUERY,
		sizeof(NGX_ETHER_RETRIEVE_KEYS_QUERY) - 1);

	*p = '\0';

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
	msgpack_pack_str(pk, p - buf);
	msgpack_pack_str_body(pk, buf, p - buf);

	msgpack_pack_str(pk, sizeof("Payload") - 1);
	msgpack_pack_str_body(pk, "Payload", sizeof("Payload") - 1);
	msgpack_pack_bin(pk, 0);
}

static void ngx_ether_add_member_ev_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	// {"Type": "member-join,user:deploy"}`

	msgpack_pack_map(pk, 1);

	msgpack_pack_str(pk, sizeof("Type") - 1);
	msgpack_pack_str_body(pk, "Type", sizeof("Type") - 1);
	msgpack_pack_str(pk, sizeof(NGX_ETHER_STREAM_MEMBER_EVENTS) - 1);
	msgpack_pack_str_body(pk, NGX_ETHER_STREAM_MEMBER_EVENTS,
		sizeof(NGX_ETHER_STREAM_MEMBER_EVENTS) - 1);
}

static void ngx_ether_add_list_members_req_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	// {"Tags": {"key": "val"}, "Status": "alive", "Name": "node1"}

	msgpack_pack_map(pk, 2);

	msgpack_pack_str(pk, sizeof("Tags") - 1);
	msgpack_pack_str_body(pk, "Tags", sizeof("Tags") - 1);
	msgpack_pack_map(pk, 1);
	msgpack_pack_str(pk, peer->serf.tag_key.len);
	msgpack_pack_str_body(pk, peer->serf.tag_key.data, peer->serf.tag_key.len);
	msgpack_pack_str(pk, sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT_REGEX) - 1);
	msgpack_pack_str_body(pk, NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT_REGEX,
		sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT_REGEX) - 1);

	msgpack_pack_str(pk, sizeof("Status") - 1);
	msgpack_pack_str_body(pk, "Status", sizeof("Status") - 1);
	msgpack_pack_str(pk, sizeof("alive") - 1);
	msgpack_pack_str_body(pk, "alive", sizeof("alive") - 1);
}

static void ngx_ether_add_respond_list_keys_body(msgpack_packer *pk, ngx_ether_peer_st *peer)
{
	msgpack_sbuffer sbuf;
	msgpack_packer pk2;
	ngx_ether_key_st *key;
	ngx_queue_t *q;
	size_t num = 0;

	msgpack_sbuffer_init(&sbuf);
	msgpack_packer_init(&pk2, &sbuf, msgpack_sbuffer_write);

	msgpack_pack_map(&pk2, 2);

	msgpack_pack_str(&pk2, sizeof("Default") - 1);
	msgpack_pack_str_body(&pk2, "Default", sizeof("Default") - 1);

	if (peer->default_ticket_key) {
		msgpack_pack_bin(&pk2, SSL_TICKET_KEY_NAME_LEN);
		msgpack_pack_bin_body(&pk2, peer->default_ticket_key->name, SSL_TICKET_KEY_NAME_LEN);
	} else {
		msgpack_pack_bin(&pk2, 0);
	}

	msgpack_pack_str(&pk2, sizeof("Keys") - 1);
	msgpack_pack_str_body(&pk2, "Keys", sizeof("Keys") - 1);

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		num++;
	}

	msgpack_pack_array(&pk2, num);

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		key = ngx_queue_data(q, ngx_ether_key_st, queue);

		msgpack_pack_bin(&pk2, SSL_TICKET_KEY_NAME_LEN);
		msgpack_pack_bin_body(&pk2, key->name, SSL_TICKET_KEY_NAME_LEN);
	}

	// {"ID": 1023, "Payload": "my response"}

	msgpack_pack_map(pk, 2);

	msgpack_pack_str(pk, sizeof("ID") - 1);
	msgpack_pack_str_body(pk, "ID", sizeof("ID") - 1);
	msgpack_pack_uint64(pk, peer->serf.listing_keys_id);

	msgpack_pack_str(pk, sizeof("Payload") - 1);
	msgpack_pack_str_body(pk, "Payload", sizeof("Payload") - 1);
	msgpack_pack_bin(pk, sbuf.size);
	msgpack_pack_bin_body(pk, sbuf.data, sbuf.size);

	msgpack_sbuffer_destroy(&sbuf);

	peer->serf.state = NGX_ETHER_WAITING;
	peer->serf.listing_keys_id = 0;
}

static ngx_int_t ngx_ether_handle_handshake_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	if (peer->serf.state != NGX_ETHER_HANDSHAKING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC handshake response");
		return NGX_ERROR;
	}

	if (peer->serf.auth.len) {
		peer->serf.state = NGX_ETHER_AUTHENTICATING;
	} else {
		peer->serf.state = NGX_ETHER_STREAM_KEY_EVSUB;
	}

	peer->serf.has_send = 1;
	return NGX_OK;
}

static ngx_int_t ngx_ether_handle_auth_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	if (peer->serf.state != NGX_ETHER_AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC auth response");
		return NGX_ERROR;
	}

	peer->serf.state = NGX_ETHER_STREAM_KEY_EVSUB;

	peer->serf.has_send = 1;
	return NGX_OK;
}

static ngx_int_t ngx_ether_handle_key_ev_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object event, name, payload = {0}, id;
	ngx_ether_key_st *key;
	ngx_queue_t *q, *prev_q;
	const char *err;
	size_t num;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	// {
	// 	"Event": "user",
	// 	"LTime": 123,
	// 	"Name": "deploy",
	// 	"Payload": "9c45b87",
	// 	"Coalesce": true,
	// }

	if (peer->serf.state == NGX_ETHER_STREAM_KEY_EVSUB) {
		peer->serf.state = NGX_ETHER_RETRIEVE_KEYS;

		peer->serf.has_send = 1;
		return NGX_OK;
	}

	if (peer->serf.state == NGX_ETHER_HANDSHAKING
		|| peer->serf.state == NGX_ETHER_AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ngx_ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	event.type = MSGPACK_OBJECT_STR;
	name.type = MSGPACK_OBJECT_STR;

	err = ngx_ether_msgpack_parse_map(&und.data,
		"Event", &event, "Name", &name, "Payload", &payload,
		"LTime", NULL, /* "Coalesce", NULL, */
		NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	assert(name.via.str.size > peer->serf.prefix.len);
	assert(ngx_strncmp(name.via.str.ptr, peer->serf.prefix.data, peer->serf.prefix.len) == 0);

	if (ngx_strncmp(event.via.str.ptr, "query", event.via.str.size) == 0) {
		id.type = MSGPACK_OBJECT_POSITIVE_INTEGER;

		err = ngx_ether_msgpack_parse_map(&und.data, "ID", &id, NULL);
		if (err) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
			goto error;
		}

		if (ngx_strncmp(name.via.str.ptr + peer->serf.prefix.len,
				NGX_ETHER_LIST_KEYS_QUERY,
				name.via.str.size - peer->serf.prefix.len) == 0) {
			if (peer->serf.state == NGX_ETHER_WAITING) {
				peer->serf.state = NGX_ETHER_RESPOND_LIST_KEYS_QUERY;
				peer->serf.listing_keys_id = id.via.u64;
				peer->serf.has_send = 1;
				return NGX_OK;
			}

			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"received %*s query outside of WAITING state, in state: %xd",
				name.via.str.size, name.via.str.ptr, peer->serf.state);
			goto error;
		} else {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"received unrecognised query from serf: %*s",
				name.via.str.size, name.via.str.ptr);
			goto error;
		}
	}

	if (ngx_strncmp(event.via.str.ptr, "user", event.via.str.size) != 0) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			event.via.str.size, event.via.str.ptr);
		return NGX_ERROR;
	}

	if (ngx_strncmp(name.via.str.ptr + peer->serf.prefix.len, NGX_ETHER_WIPE_KEYS_EVENT,
			name.via.str.size - peer->serf.prefix.len) == 0) {
		num = 0;

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			num++;
		}

		ngx_log_error(NGX_LOG_INFO, c->log, 0, "%*s event: removing %d keys, " \
			"session ticket and cache support disabled",
			name.via.str.size, name.via.str.ptr, num);

		SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		peer->default_ticket_key = NULL;

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, ngx_ether_key_st, queue);

			prev_q = ngx_queue_prev(q);
			ngx_queue_remove(q);
			q = prev_q;

			ngx_memzero(key->key, EVP_AEAD_MAX_KEY_LENGTH);
			ngx_pfree(c->pool, key);
		}

		return NGX_OK;
	}

	if (payload.type != MSGPACK_OBJECT_BIN) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "malformed RPC response, wrong type given");
		goto error;
	}

	if (ngx_strncmp(name.via.str.ptr + peer->serf.prefix.len, NGX_ETHER_INSTALL_KEY_EVENT,
			name.via.str.size - peer->serf.prefix.len) == 0) {
		if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN + 16) {
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
			key = ngx_queue_data(q, ngx_ether_key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->name, SSL_TICKET_KEY_NAME_LEN) == 0) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "%*s event: already have key",
					name.via.str.size, name.via.str.ptr);
				goto error;
			}
		}

		key = ngx_pcalloc(c->pool, sizeof(ngx_ether_key_st));
		if (!key) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
			goto error;
		}

		key->key_len = payload.via.bin.size - SSL_TICKET_KEY_NAME_LEN;

		ngx_memcpy(key->name, payload.via.bin.ptr, SSL_TICKET_KEY_NAME_LEN);
		ngx_memcpy(key->key, payload.via.bin.ptr + SSL_TICKET_KEY_NAME_LEN, key->key_len);

		key->aead = EVP_aead_aes_128_gcm();

		ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);
	} else if (ngx_strncmp(name.via.str.ptr + peer->serf.prefix.len, NGX_ETHER_REMOVE_KEY_EVENT,
			name.via.str.size - peer->serf.prefix.len) == 0) {
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
			key = ngx_queue_data(q, ngx_ether_key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->name, SSL_TICKET_KEY_NAME_LEN) != 0) {
				continue;
			}

			ngx_memzero(key->key, EVP_AEAD_MAX_KEY_LENGTH);

			ngx_queue_remove(q);

			if (key == peer->default_ticket_key) {
				peer->default_ticket_key = NULL;

				SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
				SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

				ngx_log_error(NGX_LOG_ERR, c->log, 0, "%*s event: on default key, " \
					"session ticket and cache support disabled",
					name.via.str.size, name.via.str.ptr);
			}

			ngx_pfree(c->pool, key);
			break;
		}
	} else if (ngx_strncmp(name.via.str.ptr + peer->serf.prefix.len,
			NGX_ETHER_SET_DEFAULT_KEY_EVENT,
			name.via.str.size - peer->serf.prefix.len) == 0) {
		if (payload.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid payload size");
			goto error;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket key set default: \"%*s\"",
			ngx_hex_dump(buf, (u_char *)payload.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) - buf, buf);

		if (ngx_queue_empty(&peer->ticket_keys)) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "%*s event: without any keys",
				name.via.str.size, name.via.str.ptr);
			goto error;
		}

		if (peer->default_ticket_key) {
			peer->default_ticket_key->was_default = 1;
			peer->default_ticket_key = NULL;
		}

		for (q = ngx_queue_head(&peer->ticket_keys);
			q != ngx_queue_sentinel(&peer->ticket_keys);
			q = ngx_queue_next(q)) {
			key = ngx_queue_data(q, ngx_ether_key_st, queue);

			if (ngx_memcmp(payload.via.bin.ptr, key->name, SSL_TICKET_KEY_NAME_LEN) == 0) {
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

			ngx_log_error(NGX_LOG_ERR, c->log, 0, "%*s event: on unknown key, " \
				"session ticket and cache support disabled",
				name.via.str.size, name.via.str.ptr);
			goto error;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			name.via.str.size, name.via.str.ptr);
		goto error;
	}

#if NGX_DEBUG
	num = 0;

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		num++;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl session ticket key have %d keys", num);
#endif /* NGX_DEBUG */

	ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);

	return NGX_OK;

error:
	if (payload.type == MSGPACK_OBJECT_BIN && payload.via.bin.size) {
		ngx_memzero((char *)payload.via.bin.ptr, payload.via.bin.size);
	}

	return NGX_ERROR;
}

static ngx_int_t ngx_ether_handle_key_query_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object *ptr, payload = {0}, type, default_key, keys;
	ngx_ether_key_st *key;
	ngx_queue_t *q;
	const char *err;
	ngx_buf_t dummy_recv;
	size_t i;
	int was_default = 0;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	// {
	// 	"Type": "response",
	// 	"From": "foo",
	// 	"Payload": "1.02",
	// }

	if (peer->serf.state == NGX_ETHER_RETRIEVE_KEYS) {
		peer->serf.state = NGX_ETHER_STREAM_MEMBER_EVSUB;

		peer->serf.has_send = 1;
		return NGX_OK;
	}

	if (peer->serf.state == NGX_ETHER_HANDSHAKING
		|| peer->serf.state == NGX_ETHER_AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ngx_ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	type.type = MSGPACK_OBJECT_STR;

	err = ngx_ether_msgpack_parse_map(&und.data, "Type", &type, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	if (ngx_strncmp(type.via.str.ptr, "ack", type.via.str.size) == 0
		|| ngx_strncmp(type.via.str.ptr, "done", type.via.str.size) == 0) {
		return NGX_OK;
	} else if (ngx_strncmp(type.via.str.ptr, "response", type.via.str.size) != 0) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised query response type from serf: %*s",
			type.via.str.size, type.via.str.ptr);
		return NGX_ERROR;
	}

	payload.type = MSGPACK_OBJECT_BIN;

	err = ngx_ether_msgpack_parse_map(&und.data, "From", NULL, "Payload", &payload, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	dummy_recv.start = (u_char *)payload.via.bin.ptr;
	dummy_recv.pos = (u_char *)payload.via.bin.ptr;
	dummy_recv.last = (u_char *)payload.via.bin.ptr + payload.via.bin.size;
	dummy_recv.end = (u_char *)payload.via.bin.ptr + payload.via.bin.size;

	rc = ngx_ether_msgpack_parse(&und, &dummy_recv, 0, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	default_key.type = MSGPACK_OBJECT_BIN;
	keys.type = MSGPACK_OBJECT_ARRAY;

	err = ngx_ether_msgpack_parse_map(&und.data, "Default", &default_key, "Keys", &keys, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		goto error;
	}

	if (default_key.via.bin.size && default_key.via.bin.size != SSL_TICKET_KEY_NAME_LEN) {
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

		if (ptr->via.bin.size != SSL_TICKET_KEY_NAME_LEN + 16) {
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
			key = ngx_queue_data(q, ngx_ether_key_st, queue);

			if (ngx_memcmp(ptr->via.bin.ptr, key->name,
					SSL_TICKET_KEY_NAME_LEN) == 0) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"%*s" NGX_ETHER_RETRIEVE_KEYS_QUERY " query: " \
					"already have key",
					peer->serf.prefix.len, peer->serf.prefix.data);
				goto is_default_key;
			}
		}

		key = ngx_pcalloc(c->pool, sizeof(ngx_ether_key_st));
		if (!key) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to allocate memory");
			goto error;
		}

		key->key_len = ptr->via.bin.size - SSL_TICKET_KEY_NAME_LEN;

		ngx_memcpy(key->name, ptr->via.bin.ptr, SSL_TICKET_KEY_NAME_LEN);
		ngx_memcpy(key->key, ptr->via.bin.ptr + SSL_TICKET_KEY_NAME_LEN, key->key_len);

		key->aead = EVP_aead_aes_128_gcm();

		key->was_default = was_default;

		ngx_queue_insert_tail(&peer->ticket_keys, &key->queue);

	is_default_key:
		if (default_key.via.bin.size && ngx_memcmp(ptr->via.bin.ptr, default_key.via.bin.ptr,
				SSL_TICKET_KEY_NAME_LEN) == 0) {
			peer->default_ticket_key = key;

			SSL_CTX_clear_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);

			if (!ngx_queue_empty(&peer->memc.servers)) {
				SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx,
					SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
			}

			/* the next key on will all be former defaults */
			was_default = 1;
		}
	}

	if (!peer->default_ticket_key) {
		SSL_CTX_set_options(peer->ssl->ssl.ctx, SSL_OP_NO_TICKET);
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"%*s" NGX_ETHER_RETRIEVE_KEYS_QUERY " query: "
			"no valid default key given, session ticket and cache support disabled",
			peer->serf.prefix.len, peer->serf.prefix.data);
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
#endif /* NGX_DEBUG */

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

static ngx_int_t ngx_ether_handle_member_ev_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object event, members;
	const char *err;
	ngx_ether_handle_member_resp_body_et todo;

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

	if (peer->serf.state == NGX_ETHER_STREAM_MEMBER_EVSUB) {
		peer->serf.state = NGX_ETHER_LISTING_MEMBERS;

		peer->serf.has_send = 1;
		return NGX_OK;
	}

	if (peer->serf.state == NGX_ETHER_HANDSHAKING
		|| peer->serf.state == NGX_ETHER_AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ngx_ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	event.type = MSGPACK_OBJECT_STR;
	members.type = MSGPACK_OBJECT_ARRAY;

	err = ngx_ether_msgpack_parse_map(&und.data, "Event", &event, "Members", &members, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	if (ngx_strncmp(event.via.str.ptr, NGX_ETHER_MEMBER_JOIN_EVENT, event.via.str.size) == 0) {
		todo = NGX_ETHER_HANDLE_ADD_MEMBER;
	} else if (ngx_strncmp(event.via.str.ptr, NGX_ETHER_MEMBER_LEAVE_EVENT,
			event.via.str.size) == 0
		|| ngx_strncmp(event.via.str.ptr, NGX_ETHER_MEMBER_FAILED_EVENT,
			event.via.str.size) == 0) {
		todo = NGX_ETHER_HANDLE_REMOVE_MEMBER;
	} else if (ngx_strncmp(event.via.str.ptr, NGX_ETHER_MEMBER_UPDATE_EVENT,
			event.via.str.size) == 0) {
		todo = NGX_ETHER_HANDLE_UPDATE_MEMBER;
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"received unrecognised event from serf: %*s",
			event.via.str.size, event.via.str.ptr);
		return NGX_ERROR;
	}

	return ngx_ether_handle_member_resp_body(c, peer, &members, todo);
}

static ngx_int_t ngx_ether_handle_list_members_resp(ngx_connection_t *c, ngx_ether_peer_st *peer,
		ssize_t size)
{
	ngx_int_t rc;
	msgpack_unpacked und;
	msgpack_object members;
	const char *err;

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

	if (peer->serf.state == NGX_ETHER_LISTING_MEMBERS) {
		peer->serf.state = NGX_ETHER_WAITING;
	}

	if (peer->serf.state == NGX_ETHER_HANDSHAKING
		|| peer->serf.state == NGX_ETHER_AUTHENTICATING) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "unexpected RPC stream response");
		return NGX_ERROR;
	}

	msgpack_unpacked_init(&und);

	rc = ngx_ether_msgpack_parse(&und, &peer->serf.recv, size, c->log);
	if (rc != NGX_OK) {
		return rc;
	}

	members.type = MSGPACK_OBJECT_ARRAY;

	err = ngx_ether_msgpack_parse_map(&und.data, "Members", &members, NULL);
	if (err) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, err);
		return NGX_ERROR;
	}

	return ngx_ether_handle_member_resp_body(c, peer, &members, NGX_ETHER_HANDLE_LIST_MEMBERS);
}

static ngx_int_t ngx_ether_handle_member_resp_body(ngx_connection_t *c, ngx_ether_peer_st *peer,
		const msgpack_object *members, ngx_ether_handle_member_resp_body_et todo)
{
	msgpack_object name, addr, tags, status;
	const msgpack_object_kv *ptr_kv;
	const msgpack_object_str *str;
	u_char *ether, *p, *semicolon;
	ngx_queue_t *q, *prev_q;
	const char *err;
	int skip_member,
		have_changed,
		add_member, remove_member, update_member, insert_member,
		was_udp, is_udp;
	ngx_ether_memc_server_st *server;
	void *s_addr;
	uint32_t hash, base_hash;
	union {
		uint32_t value;
		u_char byte[sizeof(uint32_t)];
	} prev_hash;
	ngx_int_t rc;
	unsigned short port;
	u_char str_addr[NGX_SOCKADDR_STRLEN];
	u_char str_port[sizeof("65535") - 1];
	size_t i, j, num, len;
	ngx_int_t event;
	ngx_event_t *rev, *wev;
	ngx_socket_t s;
	ngx_connection_t *sc = NULL;
	ngx_peer_connection_t pc;
	ngx_ether_memc_op_st *op;
#if NGX_DEBUG
	ngx_keyval_t kv = {ngx_null_string, ngx_null_string};
#endif /* NGX_DEBUG */

	have_changed = 0;

	add_member = 0;
	remove_member = 0;
	update_member = 0;

	switch (todo) {
		case NGX_ETHER_HANDLE_LIST_MEMBERS:
		case NGX_ETHER_HANDLE_ADD_MEMBER:
			add_member = 1;
			break;
		case NGX_ETHER_HANDLE_REMOVE_MEMBER:
			remove_member = 1;
			break;
		case NGX_ETHER_HANDLE_UPDATE_MEMBER:
			update_member = 1;
			break;
	}

	for (i = 0; i < members->via.array.size; i++) {
		name.type = MSGPACK_OBJECT_STR;
		addr.type = MSGPACK_OBJECT_BIN;
		tags.type = MSGPACK_OBJECT_MAP;
		status.type = MSGPACK_OBJECT_STR;

		err = ngx_ether_msgpack_parse_map(&members->via.array.ptr[i],
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
			goto error;
		}

		skip_member = 1;

		port = 11211;
		is_udp = 0;

		for (j = 0; j < tags.via.map.size; j++) {
			ptr_kv = &tags.via.map.ptr[j];

			if (ptr_kv->key.type != MSGPACK_OBJECT_STR) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"malformed RPC response, expect key to be string");
				goto error;
			}

			str = &ptr_kv->key.via.str;
			if (ngx_strncmp(str->ptr, peer->serf.tag_key.data, str->size) == 0) {
				if (ptr_kv->val.type != MSGPACK_OBJECT_STR) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"malformed RPC response, expect value to be string");
					goto error;
				}

				str = &ptr_kv->val.via.str;

				ether = ngx_palloc(c->pool, str->size + 1);
				if (!ether) {
					goto error;
				}

				*ngx_cpymem(ether, str->ptr, str->size) = '\0';

				p = ether;

				while(1) {
					semicolon = (u_char *)ngx_strchr(p, ';');

					if (semicolon) {
						len = semicolon - p;
						*semicolon = '\0';
					} else {
						len = ether + str->size - p;
					}

					if (ngx_strncmp(p, NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT "=",
							sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT "=")
							- 1) == 0) {
						if (!skip_member) {
							ngx_log_error(NGX_LOG_ERR, c->log, 0,
								"%*s contains duplicate tag \"" \
								NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT \
								"\"",
								peer->serf.tag_key.len,
								peer->serf.tag_key.data);

							skip_member = 1;
							break;
						}

						skip_member = 0;

						p += sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT "=")
							- 1;
						len -= sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT "=")
							- 1;

						if (ngx_strncmp(p, "udp:", sizeof("udp:") - 1) == 0) {
							is_udp = 1;

							p += sizeof("udp:") - 1;
							len -= sizeof("udp:") - 1;
						} else if (ngx_strncmp(p, "tcp:", sizeof("tcp:") - 1) == 0) {
							p += sizeof("tcp:") - 1;
							len -= sizeof("tcp:") - 1;
						} else if (ngx_strncmp(p, "udp", len) == 0) {
							is_udp = 1;

							goto next;
						} else if (ngx_strncmp(p, "tcp", len) == 0) {
							goto next;
						}

						rc = ngx_atoi(p, len);
						if (rc <= 0 || rc > 0xFFFF) {
							ngx_log_error(NGX_LOG_ERR, c->log, 0,
								"malformed RPC response, expect %*s="
								NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT
								"=.. to be a valid number",
								peer->serf.tag_key.len,
								peer->serf.tag_key.data);

							skip_member = 1;
							break;
						}

						port = (unsigned short)rc;
					} else if (ngx_strncmp(p, NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT,
							sizeof(NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT)
							- 1) == 0) {
						if (!skip_member) {
							ngx_log_error(NGX_LOG_ERR, c->log, 0,
								"%*s contains duplicate tag \"" \
								NGX_ETHER_SERF_ETHER_TAG_MEMC_OPT \
								"\"",
								peer->serf.tag_key.len,
								peer->serf.tag_key.data);

							skip_member = 1;
							break;
						}

						skip_member = 0;
					} else {
						ngx_log_error(NGX_LOG_ERR, c->log, 0,
							"unrecognized option %*s", len, p);

						skip_member = 1;
						break;
					}

				next:
					if (!semicolon) {
						break;
					}

					p = semicolon + 1;
				}

				ngx_pfree(c->pool, ether);

				if (skip_member) {
					break;
				}
			}
		}

		insert_member = 1;

		for (q = ngx_queue_head(&peer->memc.servers);
			q != ngx_queue_sentinel(&peer->memc.servers);
			q = ngx_queue_next(q)) {
			server = ngx_queue_data(q, ngx_ether_memc_server_st, queue);

			if (server->name.len != name.via.str.size
				|| ngx_memcmp(name.via.str.ptr, server->name.data,
					server->name.len) != 0) {
				continue;
			}

			if (add_member) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"skipping add of existing memcached server in %s",
					(todo == NGX_ETHER_HANDLE_LIST_MEMBERS) ? "members-filtered"
						: NGX_ETHER_MEMBER_JOIN_EVENT " event");

				skip_member = 1;
			} else if ((update_member && skip_member) || remove_member) {
				have_changed = 1;

				ngx_queue_remove(q);

				ngx_close_connection(server->c);

				for (q = ngx_queue_head(&server->recv_ops);
					q != ngx_queue_sentinel(&server->recv_ops);
					q = ngx_queue_next(q)) {
					op = ngx_queue_data(q, ngx_ether_memc_op_st, recv_queue);

					prev_q = ngx_queue_prev(q);
					ngx_ether_memc_cleanup_operation(op);
					q = prev_q;
				}

				if (server->tmp_recv.start) {
					ngx_pfree(c->pool, server->tmp_recv.start);
				}

				ngx_pfree(c->pool, server);
			} else {
				/* update_member */
				insert_member = 0;
			}

			break;
		}

		if (skip_member || remove_member) {
			continue;
		}

		have_changed = 1;

		if (insert_member) {
			server = ngx_pcalloc(c->pool, sizeof(ngx_ether_memc_server_st));
		}

		if (addr.via.bin.size == 16 && IN6_IS_ADDR_V4MAPPED(addr.via.bin.ptr)) {
			/* strip 12 byte IPv4 in IPv6 prefix: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff */
			addr.via.bin.ptr += 12;
			addr.via.bin.size -= 12;
		}

		switch (addr.via.bin.size) {
			case 4:
				server->sin.sin_family = AF_INET;
				server->sin.sin_port = htons(port);
				s_addr = &server->sin.sin_addr.s_addr;

				server->addr_len = sizeof(struct sockaddr_in);
				break;
#if NGX_HAVE_INET6
			case 16:
				server->sin6.sin6_family = AF_INET6;
				server->sin6.sin6_port = htons(port);
				s_addr = server->sin6.sin6_addr.s6_addr;

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
				goto error;
		}

		ngx_memcpy(s_addr, addr.via.bin.ptr, addr.via.bin.size);

		was_udp = server->udp;
		server->udp = is_udp;

		if (!insert_member) {
			if (was_udp && is_udp) {
				if (connect(server->c->fd, &server->addr, server->addr_len) == -1) {
					ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
						"connect() failed");
					goto error;
				}

				continue;
			}

			ngx_close_connection(server->c);
		}

		if (is_udp) {
			s = ngx_socket(server->addr.sa_family, SOCK_DGRAM, 0);
			ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "UDP socket %d", s);
			if (s == (ngx_socket_t)-1) {
				ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
					ngx_socket_n " failed");
				goto error;
			}

			sc = ngx_get_connection(s, c->log);
			if (!sc) {
				if (ngx_close_socket(s) == -1) {
					ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
						ngx_close_socket_n "failed");
				}

				goto error;
			}

			if (ngx_nonblocking(s) == -1) {
				ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
					ngx_nonblocking_n " failed");
				goto error;
			}
		} else {
			ngx_memzero(&pc, sizeof(ngx_peer_connection_t));

			pc.sockaddr = &server->addr;
			pc.socklen = server->addr_len;
			pc.name = &server->name;

			pc.get = ngx_event_get_peer;
			pc.log = c->log;
			pc.log_error = NGX_ERROR_ERR;

			rc = ngx_event_connect_peer(&pc);
			if (rc == NGX_ERROR || rc == NGX_DECLINED) {
				ngx_log_error(NGX_LOG_EMERG, c->log, 0,
					"ngx_event_connect_peer failed");
				goto error;
			}

			sc = pc.connection;
		}

		server->c = sc;
		sc->data = server;

		if (is_udp) {
			sc->recv = ngx_udp_recv;
			sc->send = ngx_send;
			sc->recv_chain = ngx_recv_chain;
			sc->send_chain = ngx_send_chain;
		}

		rev = sc->read;
		wev = sc->write;

		sc->log = c->log;
		rev->log = sc->log;
		wev->log = sc->log;
		sc->pool = c->pool;

		if (is_udp) {
			sc->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

			if (connect(s, &server->addr, server->addr_len) == -1) {
				ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
					"connect() failed");
				goto error;
			}

			/* UDP sockets are always ready to write */
			wev->ready = 1;

			event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
					/* kqueue, epoll */                 NGX_CLEAR_EVENT:
					/* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
					/* eventport event type has no meaning: oneshot only */

			if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
				goto error;
			}
		}

		rev->handler = ngx_ether_memc_read_handler;
		wev->handler = ngx_ether_memc_write_handler;

		/* don't close the socket on error if we've gotten this far */
		sc = NULL;

		if (!insert_member) {
			continue;
		}

		ngx_queue_init(&server->recv_ops);
		ngx_queue_init(&server->send_ops);

		ngx_atomic_fetch_add(&server->id, 1); /* skip 0 */

		server->name.len = name.via.str.size;
		server->name.data = ngx_palloc(c->pool, name.via.str.size + 1);
		if (!server->name.data) {
			goto error;
		}

		*ngx_cpymem(server->name.data, name.via.str.ptr, name.via.str.size) = '\0';

		server->peer = peer;

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
	peer->memc.points = ngx_palloc(c->pool,
		sizeof(ngx_ether_chash_point_st) * NGX_ETHER_CHASH_NPOINTS * num);
	if (!peer->memc.points) {
		goto error;
	}

	for (q = ngx_queue_head(&peer->memc.servers);
		q != ngx_queue_sentinel(&peer->memc.servers);
		q = ngx_queue_next(q)) {
		server = ngx_queue_data(q, ngx_ether_memc_server_st, queue);

#if NGX_DEBUG
		op = ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_VERSION, &kv, NULL);

		if (op) {
			op->handler = ngx_ether_log_memc_version_handler;
			op->log = c->log;
		} else {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_ether_memc_start_operation(PROTOCOL_BINARY_CMD_VERSION) failed");
		}
#endif /* NGX_DEBUG */

		switch (server->addr.sa_family) {
#if NGX_HAVE_INET6
			case AF_INET6:
				s_addr = server->sin6.sin6_addr.s6_addr;
				port = ntohs(server->sin6.sin6_port);
				break;
#endif /* NGX_HAVE_INET6 */
			default: /* AF_INET */
				s_addr = &server->sin.sin_addr.s_addr;
				port = ntohs(server->sin.sin_port);
				break;
		}

		ngx_crc32_init(base_hash);
		ngx_crc32_update(&base_hash, str_addr,
			ngx_inet_ntop(server->addr.sa_family, s_addr, str_addr, NGX_SOCKADDR_STRLEN));
		ngx_crc32_update(&base_hash, (u_char *)"", 1);

		if (port == 11211) {
			ngx_crc32_update(&base_hash, (u_char *)"11211", sizeof("11211") - 1);
		} else {
			ngx_crc32_update(&base_hash, str_port,
				snprintf((char *)str_port, sizeof("65535") - 1, "%hu", port));
		}

		prev_hash.value = 0;

		for (j = 0; j < NGX_ETHER_CHASH_NPOINTS; j++) {
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

	ngx_qsort(peer->memc.points, peer->memc.npoints, sizeof(ngx_ether_chash_point_st),
		ngx_ether_chash_cmp_points);

	for (i = 0, j = 1; j < peer->memc.npoints; j++) {
		if (peer->memc.points[i].hash != peer->memc.points[j].hash) {
			peer->memc.points[++i] = peer->memc.points[j];
		}
	}

	if (peer->memc.npoints) {
		peer->memc.npoints = i + 1;
	}

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

error:
	if (sc) {
		ngx_close_connection(sc);
	}

	if (have_changed) {
		SSL_CTX_set_session_cache_mode(peer->ssl->ssl.ctx, SSL_SESS_CACHE_OFF);

		peer->memc.npoints = 0;

		if (peer->memc.points) {
			ngx_pfree(c->pool, peer->memc.points);
			peer->memc.points = NULL;
		}

		ngx_log_error(NGX_LOG_INFO, c->log, 0, "error in handle_member_resp_body after " \
			"change, session cache support disabled");
	}

	return NGX_ERROR;
}

#if NGX_DEBUG
static void ngx_ether_log_memc_version_handler(ngx_ether_memc_op_st *op, void *data)
{
	ngx_int_t rc;
	ngx_str_t value;

	rc = ngx_ether_memc_complete_operation(op, &value, NULL);

	if (rc == NGX_AGAIN) {
		return;
	}

	if (rc == NGX_OK) {
		ngx_log_error(NGX_LOG_DEBUG, op->log, 0,
			"memcached server \"%*s\" version: %*s",
			op->server->name.len, op->server->name.data,
			value.len, value.data);
	}

	/* rc == NGX_OK || rc == NGX_ERROR */
	ngx_ether_memc_cleanup_operation(op);
}
#endif /* NGX_DEBUG */

static int ngx_ether_session_ticket_key_handler(ngx_ssl_conn_t *ssl_conn, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
	if (hctx != SSL_magic_tlsext_ticket_key_cb_aead_ptr()) {
		return TLSEXT_TICKET_CB_WANT_AEAD;
	}

	if (enc) {
		return ngx_ether_session_ticket_key_enc(ssl_conn, name, iv, (EVP_AEAD_CTX *)ectx);
	} else {
		return ngx_ether_session_ticket_key_dec(ssl_conn, name, (EVP_AEAD_CTX *)ectx);
	}
}

static int ngx_ether_session_ticket_key_enc(ngx_ssl_conn_t *ssl_conn, uint8_t *name,
		uint8_t *nonce, EVP_AEAD_CTX *ctx) {
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_ether_peer_st *peer;
	ngx_ether_key_st *key;
	union {
		struct {
			uint64_t seq;
			uint8_t rand[EVP_AEAD_MAX_NONCE_LENGTH - sizeof(uint64_t)];
		};
		uint8_t byte[EVP_AEAD_MAX_NONCE_LENGTH];
	} new_nonce;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return -1;
	}

	key = peer->default_ticket_key;
	if (!key) {
		return -1;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"ssl session ticket encrypt, key: \"%*s\" (%s session)",
		ngx_hex_dump(buf, key->name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
		SSL_session_reused(ssl_conn) ? "reused" : "new");

	new_nonce.seq = ngx_atomic_fetch_add(&key->nonce_seq, 1);

	if (RAND_bytes(new_nonce.rand, sizeof(new_nonce.rand)) != 1) {
		return -1;
	}

#if EVP_AEAD_MAX_NONCE_LENGTH != AES_BLOCK_SIZE
#	error EVP_AEAD_MAX_NONCE_LENGTH is not equal to AES_BLOCK_SIZE
#endif /* EVP_AEAD_MAX_NONCE_LENGTH != AES_BLOCK_SIZE */
	AES_ecb_encrypt(new_nonce.byte, nonce, &peer->nonce_key, AES_ENCRYPT);

	if (!EVP_AEAD_CTX_init(ctx, key->aead, key->key, key->key_len,
			EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
		return -1;
	}

	ngx_memcpy(name, key->name, SSL_TICKET_KEY_NAME_LEN);
	return 0;
}

static int ngx_ether_session_ticket_key_dec(ngx_ssl_conn_t *ssl_conn, const uint8_t *name,
		EVP_AEAD_CTX *ctx) {
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_ether_peer_st *peer;
	const ngx_ether_key_st *key;
	ngx_queue_t *q;
#if NGX_DEBUG
	u_char buf[SSL_TICKET_KEY_NAME_LEN*2];
#endif /* NGX_DEBUG */

	c = ngx_ssl_get_connection(ssl_conn);
	ssl_ctx = c->ssl->session_ctx;

	peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return -1;
	}

	for (q = ngx_queue_head(&peer->ticket_keys);
		q != ngx_queue_sentinel(&peer->ticket_keys);
		q = ngx_queue_next(q)) {
		key = ngx_queue_data(q, ngx_ether_key_st, queue);

		if (ngx_memcmp(name, key->name, SSL_TICKET_KEY_NAME_LEN) != 0) {
			continue;
		}

		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"ssl session ticket decrypt, key: \"%*s\"%s",
			ngx_hex_dump(buf, (u_char *)key->name, SSL_TICKET_KEY_NAME_LEN) - buf, buf,
			(key == peer->default_ticket_key) ? " (default)" : "");

		if (!EVP_AEAD_CTX_init(ctx, key->aead, key->key, key->key_len,
				EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
			return -1;
		}

		if (key->was_default) {
			return 2 /* renew */;
		} else {
			return 1;
		}
	}

	ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"ssl session ticket decrypt, key: \"%*s\" not found",
		ngx_hex_dump(buf, (uint8_t *)name, SSL_TICKET_KEY_NAME_LEN) - buf, buf);

	return 0;
}

static int ngx_libc_cdecl ngx_ether_chash_cmp_points(const void *one, const void *two)
{
	const ngx_ether_chash_point_st *first = one, *second = two;

	if (first->hash < second->hash) {
		return -1;
	} else if (first->hash > second->hash) {
		return 1;
	} else {
		return 0;
	}
}

static ngx_uint_t ngx_ether_find_chash_point(ngx_uint_t npoints,
		const ngx_ether_chash_point_st *point, uint32_t hash)
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

static ngx_ether_memc_server_st *ngx_ether_get_memc_server(const ngx_ether_peer_st *peer,
		const ngx_str_t *key)
{
	uint32_t hash;

	if (!peer->memc.npoints) {
		return NULL;
	}

	/* see comment in ngx_crc32.c */
	if (key->len > 64) {
		hash = ngx_crc32_long(key->data, key->len);
	} else {
		hash = ngx_crc32_short(key->data, key->len);
	}

	hash = ngx_ether_find_chash_point(peer->memc.npoints, peer->memc.points, hash);
	return peer->memc.points[hash % peer->memc.npoints].data;
}

static void ngx_ether_memc_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	ngx_ether_memc_server_st *server;
	ngx_ether_memc_op_st *op, quiet_op = {0};
	ngx_queue_t *q;
	ngx_buf_t recv;
	u_char *new_buf;
	size_t n, len = 0 /* maybe-uninitialized in GCC */;
	ssize_t size;
	protocol_binary_response_header *res_hdr;
	union {
		uint16_t u16;
		uint8_t byte[2];
	} id0;

	c = rev->data;
	server = c->data;

	if (server->tmp_recv.start) {
		recv = server->tmp_recv;

		server->tmp_recv.start = NULL;
		server->tmp_recv.pos = NULL;
		server->tmp_recv.last = NULL;
		server->tmp_recv.end = NULL;
	} else {
		/* 1/4 of the page_size, is it enough? */
		recv.start = ngx_palloc(c->pool, ngx_pagesize / 4);
		if (!recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");
			return;
		}

		recv.pos = recv.start;
		recv.last = recv.start;
		recv.end = recv.start + ngx_pagesize / 4;
	}

	do {
		n = recv.end - recv.last;

		/* buffer not big enough? enlarge it by twice */
		if (n == 0) {
			size = recv.end - recv.start;

			new_buf = ngx_palloc(c->pool, size * 2);
			if (!new_buf) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated new recv buffer");
				return;
			}

			ngx_memcpy(new_buf, recv.start, size);
			ngx_pfree(c->pool, recv.start);

			recv.start = new_buf;
			recv.pos = new_buf;
			recv.last = new_buf + size;
			recv.end = new_buf + size * 2;

			n = recv.end - recv.last;
		}

		size = c->recv(c, recv.last, n);

		if (size > 0) {
			recv.last += size;
			continue;
		} else if (size == 0 || size == NGX_AGAIN) {
			break;
		} else {
			c->error = 1;
			return;
		}
	} while (!server->udp);

done_read:
	if (server->udp) {
		if (recv.last - recv.pos < 8 + (ssize_t)sizeof(protocol_binary_response_header)) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "truncated memc packet");
			goto cleanup;
		}

		// op->recv.pos[0..1] = request id
		// op->recv.pos[2..3] = sequence number
		// op->recv.pos[4..5] = total datagrams
		// op->recv.pos[6..7] = reserved

		ngx_memcpy(id0.byte, recv.pos, sizeof(id0.byte));

		if (recv.pos[4] != 0 || recv.pos[5] != 1) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"multipacket udp memcached not supported");
			goto cleanup;
		}

		recv.pos += 8;
		res_hdr = (protocol_binary_response_header *)recv.pos;
	} else {
		if (recv.last - recv.pos < (ssize_t)sizeof(protocol_binary_response_header)) {
			goto store_temp;
		}

		res_hdr = (protocol_binary_response_header *)recv.pos;

		len = sizeof(protocol_binary_response_header) + ntohl(res_hdr->response.bodylen);
		if (recv.last - recv.pos < (ssize_t)len) {
			goto store_temp;
		}

		id0.u16 = 0; /* GCC produces a maybe-uninitialized error without this */
	}

	if (res_hdr->response.magic != PROTOCOL_BINARY_RES) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"invalid memcached magic: %d", res_hdr->response.magic);
		goto process_next;
	}

	switch (res_hdr->response.opcode) {
		case PROTOCOL_BINARY_CMD_ADDQ:
		case PROTOCOL_BINARY_CMD_DELETEQ:
			/* an error has occured */

			quiet_op.id0 = id0.u16;
			quiet_op.id1 = res_hdr->response.opaque;

			quiet_op.is_quiet = 1;

			quiet_op.server = server;

			quiet_op.log = c->log;

			quiet_op.recv = recv;

			assert(ngx_ether_memc_complete_operation(&quiet_op, NULL, NULL)
				== NGX_ERROR);
			goto process_next;
	}

	for (q = ngx_queue_head(&server->recv_ops);
		q != ngx_queue_sentinel(&server->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, ngx_ether_memc_op_st, recv_queue);

		if ((server->udp && op->id0 != id0.u16)
			|| op->id1 != res_hdr->response.opaque) {
			continue;
		}

		ngx_queue_remove(&op->recv_queue);

		if (!server->udp && recv.last - recv.pos > (ssize_t)len) {
			op->recv.start = ngx_palloc(c->pool, len);
			if (!op->recv.start) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated recv buffer");
				return;
			}

			op->recv.pos = op->recv.start;
			op->recv.last = ngx_cpymem(op->recv.pos, recv.pos, len);
			op->recv.end = op->recv.last;
		} else {
			op->recv = recv;
		}

		op->handler(op, op->handler_data);

		if (!server->udp && recv.last - recv.pos > (ssize_t)len) {
			goto process_next;
		} else {
			return;
		}
	}

	if (server->udp) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"invalid memc id: %ud", id0.u16 | (res_hdr->response.opaque << 16));
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"invalid memc id: %ud", res_hdr->response.opaque);
	}

process_next:
	if (!server->udp && recv.last - recv.pos > (ssize_t)len) {
		recv.pos += len;
		goto done_read;
	}

cleanup:
	ngx_pfree(c->pool, recv.start);
	return;

store_temp:
	if (recv.pos != recv.start
		&& recv.end - recv.start > (ssize_t)(ngx_pagesize * 4)
		&& (recv.end - recv.start) - (recv.last - recv.pos) > (ssize_t)ngx_pagesize) {
		server->tmp_recv.start = ngx_palloc(c->pool, recv.last - recv.pos);
		if (!server->tmp_recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");

			server->tmp_recv = recv;
			return;
		}

		server->tmp_recv.pos = server->tmp_recv.start;
		server->tmp_recv.last = ngx_cpymem(server->tmp_recv.pos, recv.pos, recv.last - recv.pos);
		server->tmp_recv.end = server->tmp_recv.last;
		goto cleanup;
	} else {
		server->tmp_recv = recv;
	}
}

static void ngx_ether_memc_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	ngx_ether_memc_server_st *server;
	ngx_ether_memc_op_st *op;
	ngx_queue_t *q;
	ssize_t size;

	c = wev->data;
	server = c->data;

	while (!ngx_queue_empty(&server->send_ops)) {
		q = ngx_queue_head(&server->send_ops);
		op = ngx_queue_data(q, ngx_ether_memc_op_st, send_queue);

		while (op->send.pos < op->send.last) {
			size = c->send(c, op->send.pos, op->send.last - op->send.pos);
			if (size > 0) {
				op->send.pos += size;

				if (server->udp) {
					break;
				}
			} else if (size == 0 || size == NGX_AGAIN) {
				return;
			} else {
				c->error = 1;
				return;
			}
		}

		ngx_queue_remove(&op->send_queue);

		if (server->udp && op->send.pos != op->send.last) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "memc send truncated");
		} else {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, op->log, 0, "memc send done");
		}

		if (op->is_quiet) {
			ngx_ether_memc_cleanup_operation(op);
		} else {
			ngx_pfree(c->pool, op->send.start);

			op->send.start = NULL;
			op->send.pos = NULL;
			op->send.last = NULL;
			op->send.end = NULL;
		}
	}
}

static void ngx_ether_memc_default_op_handler(ngx_ether_memc_op_st *op, void *data)
{
	if (ngx_ether_memc_complete_operation(op, NULL, NULL) != NGX_AGAIN) {
		ngx_ether_memc_cleanup_operation(op);
	}
}

static void ngx_ether_memc_event_op_handler(ngx_ether_memc_op_st *op, void *data)
{
	ngx_event_t *ev = data;

	ngx_post_event(ev, &ngx_posted_events);
}

static ngx_ether_memc_op_st *ngx_ether_memc_start_operation(ngx_ether_memc_server_st *server,
		protocol_binary_command cmd, const ngx_keyval_t *kv, void *in_data)
{
	ngx_ether_memc_op_st *op = NULL;
	unsigned char *data = NULL, *p;
	size_t len, hdr_len, ext_len = 0, body_len;
	uint64_t id;
	union {
		uint16_t u16;
		uint8_t byte[2];
	} id0;
	uint32_t id1;
	int is_quiet = 0;
	protocol_binary_request_header *req_hdr;
	protocol_binary_request_set *reqs;
	const protocol_binary_request_no_extras *in_req = in_data;
	const protocol_binary_request_set *in_reqs = in_data;
#if NGX_DEBUG
	const char *cmd_str;
#endif /* NGX_DEBUG */

	switch (cmd) {
		case PROTOCOL_BINARY_CMD_GET:
#if NGX_DEBUG
			cmd_str = "GET";
#endif /* NGX_DEBUG */
			break;
		case PROTOCOL_BINARY_CMD_ADDQ:
			is_quiet = 1;

			ext_len = sizeof(((protocol_binary_request_set *)NULL)->message.body);

#if NGX_DEBUG
			cmd_str = "ADDQ";
#endif /* NGX_DEBUG */
			break;
		case PROTOCOL_BINARY_CMD_DELETEQ:
			is_quiet = 1;

#if NGX_DEBUG
			cmd_str = "DELETEQ";
#endif /* NGX_DEBUG */
			break;
		case PROTOCOL_BINARY_CMD_VERSION:
#if NGX_DEBUG
			cmd_str = "VERSION";
#endif /* NGX_DEBUG */
			break;
		default:
			goto error;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, server->peer->log, 0,
		"memcached operation: %s \"%*s\"", cmd_str, kv->key.len, kv->key.data);

	hdr_len = sizeof(protocol_binary_request_header);

	if (server->udp) {
		hdr_len = 8 + hdr_len;
	}

	body_len = ext_len + kv->key.len + kv->value.len;
	len = hdr_len + body_len;

	data = ngx_palloc(server->peer->pool, len);
	if (!data) {
		goto error;
	}

	p = data;
	ngx_memzero(p, hdr_len);

	id = ngx_atomic_fetch_add(&server->id, 1);
	if (!id) {
		/* skip 0 */
		id = ngx_atomic_fetch_add(&server->id, 1);
	}

	if (server->udp) {
		// data[0..1] = request id
		// data[2..3] = sequence number
		// data[4..5] = total datagrams
		// data[6..7] = reserved

		id0.u16 = id & 0xffff;
		id1 = id >> 16;

		ngx_memcpy(p, id0.byte, sizeof(id0.byte));

		p[4] = 0;
		p[5] = 1;

		req_hdr = (protocol_binary_request_header *)&p[8];
	} else {
		id0.u16 = 0;
		id1 = id;

		req_hdr = (protocol_binary_request_header *)p;
	}

	p += hdr_len;
	p += ext_len;

	req_hdr->request.magic = PROTOCOL_BINARY_REQ;
	req_hdr->request.opcode = cmd;
	req_hdr->request.keylen = htons(kv->key.len);
	req_hdr->request.extlen = ext_len;
	req_hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
	req_hdr->request.bodylen = htonl(body_len);
	req_hdr->request.opaque = id1;

	if (in_req) {
		req_hdr->request.cas = htonll(in_req->message.header.request.cas);

		if (cmd == PROTOCOL_BINARY_CMD_ADDQ) {
			reqs = (protocol_binary_request_set *)req_hdr;
			reqs->message.body.flags
				= htonl(in_reqs->message.body.flags);
			reqs->message.body.expiration
				= htonl(in_reqs->message.body.expiration);
		}
	}

	p = ngx_cpymem(p, kv->key.data, kv->key.len);

	if (kv->value.len) {
		p = ngx_cpymem(p, kv->value.data, kv->value.len);
	}

	op = ngx_pcalloc(server->peer->pool, sizeof(ngx_ether_memc_op_st));
	if (!op) {
		goto error;
	}

	op->id0 = id0.u16;
	op->id1 = id1;

	op->is_quiet = is_quiet;

	op->handler = ngx_ether_memc_default_op_handler;

	op->server = server;

	op->send.start = data;
	op->send.pos = data;
	op->send.last = data + len;
	op->send.end = data + len;

	op->log = server->c->log;

	if (!is_quiet) {
		ngx_queue_insert_tail(&server->recv_ops, &op->recv_queue);
	}

	ngx_queue_insert_tail(&server->send_ops, &op->send_queue);

	server->c->write->handler(server->c->write);

	return op;

error:
	if (data) {
		ngx_pfree(server->peer->pool, data);
	}

	if (op) {
		ngx_pfree(server->peer->pool, op);
	}

	return NULL;
}

static ngx_int_t ngx_ether_memc_complete_operation(const ngx_ether_memc_op_st *op,
		ngx_str_t *value, void *out_data)
{
	ngx_str_t data;
	unsigned short key_len, status;
	unsigned int body_len;
	protocol_binary_response_header *res_hdr;
	ngx_uint_t log_level;
	protocol_binary_response_no_extras *out_res = out_data;
	protocol_binary_response_get *resg, *out_resg = out_data;

	if (!op->recv.start) {
		/* memc_read_handler has not yet been invoked for this op */
		return NGX_AGAIN;
	}

	if (op->recv.last - op->recv.pos < (ssize_t)sizeof(protocol_binary_response_header)) {
		if (op->server->udp) {
			return NGX_ERROR;
		} else {
			return NGX_AGAIN;
		}
	}

	res_hdr = (protocol_binary_response_header *)op->recv.pos;

	assert(res_hdr->response.magic == PROTOCOL_BINARY_RES);
	assert(op->id1 == res_hdr->response.opaque);

	key_len = ntohs(res_hdr->response.keylen);
	body_len = ntohl(res_hdr->response.bodylen);

	if (res_hdr->response.extlen + key_len > body_len) {
		return NGX_ERROR;
	}

	if (op->recv.last - op->recv.pos < (ssize_t)sizeof(protocol_binary_response_header)
			+ body_len) {
		if (op->server->udp) {
			return NGX_ERROR;
		} else {
			return NGX_AGAIN;
		}
	}

	data.data = op->recv.pos
		+ sizeof(protocol_binary_response_header)
		+ res_hdr->response.extlen
		+ key_len;
	data.len = body_len
		- key_len
		- res_hdr->response.extlen;

	status = ntohs(res_hdr->response.status);

	if (out_res) {
		out_res->message.header.response.status = status;
		out_res->message.header.response.cas = ntohll(res_hdr->response.cas);

		if (res_hdr->response.opcode == PROTOCOL_BINARY_CMD_GET) {
			resg = (protocol_binary_response_get *)res_hdr;
			out_resg->message.body.flags = ntohl(resg->message.body.flags);
		}
	}

	if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
		if (value) {
			*value = data;
		}

		return NGX_OK;
	}

	log_level = NGX_LOG_ERR;

	if (res_hdr->response.opcode == PROTOCOL_BINARY_CMD_GET
		&& status == PROTOCOL_BINARY_RESPONSE_KEY_ENOENT) {
		log_level = NGX_LOG_DEBUG;
	}

	ngx_log_error(log_level, op->log, 0, "memcached error %hd: %*s", status, data.len, data.data);
	return NGX_ERROR;
}

static void ngx_ether_memc_cleanup_operation(ngx_ether_memc_op_st *op)
{
	const ngx_ether_peer_st *peer = op->server->peer;

	if (ngx_queue_prev(&op->recv_queue)
		&& ngx_queue_next(ngx_queue_prev(&op->recv_queue)) == &op->recv_queue) {
		ngx_queue_remove(&op->recv_queue);
	}

	if (ngx_queue_prev(&op->send_queue)
		&& ngx_queue_next(ngx_queue_prev(&op->send_queue)) == &op->send_queue) {
		ngx_queue_remove(&op->send_queue);
	}

	if (op->send.start) {
		ngx_pfree(peer->pool, op->send.start);
	}

	if (op->recv.start) {
		ngx_pfree(peer->pool, op->recv.start);
	}

	ngx_pfree(peer->pool, op);
}

static int ngx_ether_new_session_handler(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	const ngx_ether_peer_st *peer;
	ngx_ether_memc_server_st *server;
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

	peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return 0;
	}

	kv.key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	kv.key.len = len;

	ngx_str_null(&kv.value);
	EVP_AEAD_CTX_zero(&aead_ctx);

#ifndef OPENSSL_NO_FEMTOZIP
	if (SSL_SESSION_to_compressed_bytes_for_ticket(ssl_ctx, sess, &session, &session_len)
#else /* OPENSSL_NO_FEMTOZIP */
	if (SSL_SESSION_to_bytes_for_ticket(sess, &session, &session_len)
#endif /* OPENSSL_NO_FEMTOZIP */
		&& CBB_init(&cbb, SSL_TICKET_KEY_NAME_LEN + EVP_AEAD_MAX_NONCE_LENGTH + session_len
				+ EVP_AEAD_MAX_OVERHEAD)
		&& CBB_add_space(&cbb, &name, SSL_TICKET_KEY_NAME_LEN)
		&& CBB_reserve(&cbb, &nonce, EVP_AEAD_MAX_NONCE_LENGTH)
		&& ngx_ether_session_ticket_key_enc(ssl_conn, name, nonce, &aead_ctx) >= 0
		&& CBB_did_write(&cbb, EVP_AEAD_nonce_length(aead_ctx.aead))
		&& CBB_reserve(&cbb, &p, session_len + EVP_AEAD_max_overhead(aead_ctx.aead))
		&& EVP_AEAD_CTX_seal(&aead_ctx,
				p, &out_len, session_len + EVP_AEAD_max_overhead(aead_ctx.aead),
				nonce, EVP_AEAD_nonce_length(aead_ctx.aead),
				session, session_len, kv.key.data, kv.key.len)
		&& CBB_did_write(&cbb, out_len)
		&& CBB_finish(&cbb, &kv.value.data, &kv.value.len)) {
		ngx_memzero(&req, sizeof(protocol_binary_request_set));
		req.message.body.expiration =
			ngx_min(SSL_SESSION_get_timeout(sess), NGX_ETHER_REALTIME_MAXDELTA);

		ngx_ether_process_session_key_id(peer, &kv.key, buf);
		server = ngx_ether_get_memc_server(peer, &kv.key);
		if (server) {
			(void) ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_ADDQ, &kv, &req);
		}
	}

	OPENSSL_free(session);
	OPENSSL_free(kv.value.data);
	CBB_cleanup(&cbb);

	EVP_AEAD_CTX_cleanup(&aead_ctx);
	return 0;
}

static ngx_ssl_session_t *ngx_ether_get_session_handler(ngx_ssl_conn_t *ssl_conn, u_char *id,
		int len, int *copy)
{
	const SSL_CTX *ssl_ctx;
	const ngx_connection_t *c;
	ngx_ether_memc_op_st *op;
	const ngx_ether_peer_st *peer;
	ngx_ether_memc_server_st *server;
	ngx_keyval_t kv;
	ngx_str_t value;
	ngx_int_t rc;
	ngx_pool_cleanup_t *cln;
	ngx_ether_get_session_cleanup_st *cln_data;
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
		peer = SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_peer_index);
		if (!peer) {
			return NULL;
		}

		kv.key.data = id;
		kv.key.len = len;

		ngx_ether_process_session_key_id(peer, &kv.key, buf);
		server = ngx_ether_get_memc_server(peer, &kv.key);
		if (!server) {
			return NULL;
		}

		ngx_str_null(&kv.value);

		op = ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_GET, &kv, NULL);
		if (!op) {
			return NULL;
		}

		op->handler = ngx_ether_memc_event_op_handler;
		op->handler_data = c->write;

		op->log = c->log;

		cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_ether_get_session_cleanup_st));
		if (!cln) {
			ngx_ether_memc_cleanup_operation(op);
			return NULL;
		}

		cln->handler = ngx_ether_get_session_cleanup_handler;

		cln_data = cln->data;
		cln_data->op = op;
		cln_data->ev = NULL;

		if (peer->memc.timeout > 0) {
			ev = ngx_pcalloc(c->pool, sizeof(ngx_event_t));
			if (!ev) {
				return NULL;
			}
			cln_data->ev = ev;

			ev->handler = ngx_ether_get_session_timeout_handler;
			ev->data = c->write;
			ev->log = c->log;

			if (!SSL_set_ex_data(ssl_conn, g_ssl_exdata_get_session_timeout_index, ev)) {
				return NULL;
			}

			ngx_add_timer(ev, peer->memc.timeout);
		}

		if (!SSL_set_ex_data(ssl_conn, g_ssl_exdata_memc_op_index, op)) {
			return NULL;
		}

		return SSL_magic_pending_session_ptr();
	}

	rc = ngx_ether_memc_complete_operation(op, &value, NULL);

	if (rc == NGX_AGAIN) {
		ev = SSL_get_ex_data(ssl_conn, g_ssl_exdata_get_session_timeout_index);
		if (ev && ev->timedout) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "memcached operation timedout");
			return NULL;
		}

		return SSL_magic_pending_session_ptr();
	}

	if (rc == NGX_ERROR) {
		return NULL;
	}

	/* rc == NGX_OK */
	CBS_init(&cbs, value.data, value.len);
	EVP_AEAD_CTX_zero(&aead_ctx);

	if (!CBS_get_bytes(&cbs, &name, SSL_TICKET_KEY_NAME_LEN)
		|| ngx_ether_session_ticket_key_dec(ssl_conn, CBS_data(&name), &aead_ctx) <= 0
		|| !CBS_get_bytes(&cbs, &nonce, EVP_AEAD_nonce_length(aead_ctx.aead))
		|| !EVP_AEAD_CTX_open(&aead_ctx,
				(uint8_t *)CBS_data(&cbs), &plaintext_len, CBS_len(&cbs),
				CBS_data(&nonce), CBS_len(&nonce), CBS_data(&cbs), CBS_len(&cbs),
				id, len)) {
		EVP_AEAD_CTX_cleanup(&aead_ctx);
		return NULL;
	}

	*copy = 0;
#ifndef OPENSSL_NO_FEMTOZIP
	sess = SSL_SESSION_from_compressed_bytes(ssl_ctx, CBS_data(&cbs), plaintext_len);
#else /* OPENSSL_NO_FEMTOZIP */
	sess = SSL_SESSION_from_bytes(CBS_data(&cbs), plaintext_len);
#endif /* OPENSSL_NO_FEMTOZIP */
	if (sess) {
		ngx_memcpy(sess->session_id, id, len);
		sess->session_id_length = len;
	} else {
		ERR_clear_error(); /* Don't leave an error on the queue. */
	}

	EVP_AEAD_CTX_cleanup(&aead_ctx);
	return sess;
}

static void ngx_ether_remove_session_handler(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
	const ngx_ether_peer_st *peer;
	ngx_ether_memc_server_st *server;
	ngx_keyval_t kv;
	unsigned int len;
	u_char buf[NGX_ETHER_MEMC_MAX_KEY_PREFIX_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH*2];

	peer = SSL_CTX_get_ex_data(ssl, g_ssl_ctx_exdata_peer_index);
	if (!peer) {
		return;
	}

	kv.key.data = (u_char *)SSL_SESSION_get_id(sess, &len);
	kv.key.len = len;

	ngx_ether_process_session_key_id(peer, &kv.key, buf);
	server = ngx_ether_get_memc_server(peer, &kv.key);
	if (!server) {
		return;
	}

	ngx_str_null(&kv.value);

	(void) ngx_ether_memc_start_operation(server, PROTOCOL_BINARY_CMD_DELETEQ, &kv, NULL);
}

static inline void ngx_ether_process_session_key_id(const ngx_ether_peer_st *peer, ngx_str_t *key,
		u_char *buf)
{
	u_char *p;

	if (peer->memc.hex) {
		p = buf + peer->memc.prefix.len;

		key->len = ngx_hex_dump(p, key->data, key->len) - p;
		key->data = p;
	}

	if (peer->memc.prefix.len) {
		p = ngx_cpymem(buf, peer->memc.prefix.data, peer->memc.prefix.len);

		if (!peer->memc.hex) {
			p = ngx_cpymem(p, key->data, key->len);
		}

		key->data = buf;
		key->len += peer->memc.prefix.len;
	}
}

static void ngx_ether_get_session_cleanup_handler(void *data)
{
	ngx_ether_get_session_cleanup_st *cln = data;

	ngx_ether_memc_cleanup_operation(cln->op);

	if (cln->ev && cln->ev->timer_set) {
		ngx_del_timer(cln->ev);
	}
}

static void ngx_ether_get_session_timeout_handler(ngx_event_t *ev)
{
	ngx_event_t *wev = ev->data;

	ngx_post_event(wev, &ngx_posted_events);
}
