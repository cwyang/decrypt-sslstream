/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * decrypt-sslstream
 * 6 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 *
 * TODO: support extended master secret
 * NOTE: TLS 1.3 does not support RSA.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>          // ENOMEM,..
#include <arpa/inet.h>      // ntohl()
#include <openssl/crypto.h> // EVP_PKEY
#include <openssl/bio.h>    // BIO
#include <openssl/pem.h>    // PEM*
#include <openssl/err.h>    // ERR_*()
#include <openssl/ssl.h>
#include <pthread.h>        // PTHREAD_MUTEX
#include "memory.h"
#include "ssl_stub.h"

#define READ_CHUNK 128

#define fatal(X) do {                           \
        fprintf(stderr, "%s\n", X);             \
        abort();                                \
    } while (0)
#define mesg(a...) fprintf(stderr, ##a)
#define print_ssl_error() do {                                          \
        char estr[256];                                                 \
        ERR_error_string_n(ERR_get_error(), estr, sizeof(estr) - 1);    \
        mesg("%s:SSL: %s\n", __FUNCTION__, estr);                       \
    } while (0)

typedef struct st_string {
    unsigned char *buf;
    int len;
} str_t;

void str_new(str_t *s, char *buf, int len) 
{
    s->buf = h2o_mem_alloc(len);
    s->len = len;
    memcpy(s->buf, buf, len);
}
int str_cmp(str_t *s, str_t *t) 
{
    if (s->len != t->len) return 1;
    return strncasecmp(s->buf, t->buf, s->len);
}
void str_free(str_t *s) 
{
    if (s->buf) free(s->buf);
    s->len = 0;
}

str_t str_dup(str_t *s) 
{
    str_t r;
    str_new(&r, s->buf, s->len);
    return r;
}

void mesg_buf(const char *hdr, char *p, int n) 
{
    extern char *hex2buf(const void *vp, int len);
    mesg("%s[%d]:\n", hdr, n); 
    if (n <= 0)
        return;
    
    char *c = hex2buf(p, n);
    mesg("%s\n", c);
    free(c);
}

// RFC5246
#define TLS_H_HELLO_REQUEST       0
#define TLS_H_CLIENT_HELLO        1
#define TLS_H_SERVER_HELLO        2
#define TLS_H_NEW_SESSION_TICKET  4     /* RFC5077 */
#define TLS_H_CERTIFICATE         11
#define TLS_H_SERVER_KEY_EXCHANGE 12
#define TLS_H_CERTIFICATE_REQUEST 13
#define TLS_H_SERVER_HELLO_DONE   14
#define TLS_H_CERTIFICATE_VERIFY  15
#define TLS_H_CLIENT_KEY_EXCHANGE 16
#define TLS_H_FINISHED            20
// record max: 2^14 bytes
#define TLS_R_CHANGE_CIPHER_SPEC  20
#define TLS_R_ALERT               21
#define TLS_R_HANDSHAKE           22
#define TLS_R_APPLICATION_DATA    23

typedef enum enum_state {
    TLS_ST_START = 0,
    TLS_ST_CLIENT_HELLO,
    TLS_ST_SERVER_HELLO,
    TLS_ST_NEW_SESSION_TICKET,
    TLS_ST_CERTIFICATE,
    TLS_ST_SERVER_KEY_EXCHANGE,
    TLS_ST_CERTIFICATE_REQUEST,
    TLS_ST_SERVER_HELLO_DONE,
    TLS_ST_CLIENT_KEY_EXCHANGE,
    TLS_ST_CERTIFICATE_VERIFY,
    TLS_ST_CHANGE_CIPHER_SPEC,
    TLS_ST_FINISHED,
    TLS_ST_DONE
} ssl_state_t;

typedef int (*ssl_decrypt_callback_t)(void *cbarg, const char *plain_msg, size_t len, int is_rev);

#define MASTER_SECRET_LEN   48
typedef struct st_ssl_decrypt_ctx {
    struct st_ssl_peer
    {
        SSL             *ssl;
        h2o_buffer_t    *buf;
        int             state;          // handshake state
    } peer[2];
    SSL_CTX *ssl_ctx;
    const SSL_CIPHER *ssl_cipher;
    struct {
        unsigned        disable:1;
        unsigned        gen_params:1;
        unsigned        client_dir:1;      // dir 0 is client
        unsigned        client_ticket:1;
        unsigned        server_ticket:1;
        unsigned        client_ems:1;
        unsigned        server_ems:1;
    } flag;
    uint16_t    version;
    uint16_t    cipher;
    uint8_t     compression;            /* XXX: HOW? */
    uint8_t     ready;
#define READY(x) (x >= 7)
#define SET_CLIENT_RANDOM(x) do { x |= 1; } while (0)
#define SET_SERVER_RANDOM(x) do { x |= 2; } while (0)
#define SET_PMS(x) do { x |= 4; } while (0)
#define SET_READY(x) do { x |= 8; } while (0)
    str_t       client_random;
    str_t       server_random;
    str_t       client_id;
    str_t       server_id;
    str_t       client_ticket;
    str_t       server_ticket;
    str_t       sni;
    str_t       pms;
    str_t       master_secret;

    EVP_PKEY    *pkey;

    ssl_decrypt_callback_t  decrypt_cb;
    void        *cb_arg;
} SSL_DECRYPT_CTX;

void SSL_DECRYPT_CTX_init(SSL_DECRYPT_CTX *pctx, EVP_PKEY *pkey, ssl_decrypt_callback_t decrypt_cb, void *cb_arg);
void SSL_DECRYPT_CTX_free(SSL_DECRYPT_CTX *pctx);
int decrypt_pms(SSL_DECRYPT_CTX *pctx) ;
int decrypt(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);
int decrypt_record(SSL_DECRYPT_CTX *pctx, int dir, SSL *ssl, h2o_buffer_t **buf, size_t buflen, int is_tls);
int decrypt_handshake(SSL_DECRYPT_CTX *pctx, int dir, SSL *ssl, h2o_buffer_t **buf, size_t buflen, int is_tls);
int decrypt_alert(SSL_DECRYPT_CTX *pctx, int dir, SSL *ssl, h2o_buffer_t **buf, size_t buflen, int is_tls);
int statem(SSL_DECRYPT_CTX *pctx, int dir, h2o_buffer_t **_input);
int do_handshake(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);
static int generate_ssl(SSL_DECRYPT_CTX *pctx);
static void update_session_cache(SSL_DECRYPT_CTX *pctx);
static int retrieve_session_cache(SSL_DECRYPT_CTX *pctx);

#define INITIAL_INPUT_BUFFER_SIZE 4096
h2o_buffer_mmap_settings_t buffer_mmap_settings = {
    32 * 1024 * 1024,
    "/tmp/ssldecrypt.b.XXXXXX"
};
__thread h2o_buffer_prototype_t buffer_prototype = {
    {16},                            /* keep 16 recently used chunks */
    {INITIAL_INPUT_BUFFER_SIZE * 2}, /* minimum initial capacity */
    &buffer_mmap_settings
};

static int test_cb(void *dummy, const char *plain_msg, size_t len,int is_rev)  
{
    static int cnt = 0;

    if (cnt++ >= 4) {
        mesg("--- %s ---\n", is_rev ? "RESP" : "REQ");
        mesg("simulated error\n");
        return -1;
    }
    
    mesg("--- %s ---\n", is_rev ? "RESP" : "REQ");
    mesg_buf("record", (char *) plain_msg, len);
    return 0;
}


static EVP_PKEY *load_private_key(char *pem_file) 
{
    BIO *in;
    EVP_PKEY *pkey;
    RSA *rsa;
    
    in = BIO_new(BIO_s_file());
    if (BIO_read_filename(in, pem_file) <= 0)
        fatal("BIO_read_filename");

    rsa = PEM_read_bio_RSAPrivateKey(in, NULL, 0, NULL);
    if (!rsa)
        fatal("PEM_read_bio_RSAPrivateKey");

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_RSA(pkey, rsa))
        fatal("EVP_PKEY_set1_RSA");

    RSA_free(rsa);

    BIO_free(in);
    return pkey;
}

int main(int argc, char *argv[]) 
{
    char buf[READ_CHUNK];
    size_t n;
    EVP_PKEY *pkey;
    FILE *fp[2];
    int c = 0, argn = argc - 2 ;
    SSL_DECRYPT_CTX ctx = {};
    

    if (argc < 4)
        fatal("usage: decrypt keyfile [sslstream-from-client sslstream-from-server]+");

    mesg("\n# SSL session decryptor\n  by Chul-Woong Yang (cwyang@gmail.com)\n\n");
    
    init_library();
    
    pkey = load_private_key(argv[1]);

    for (int k = 0; k < argn - 1; k += 2) {
        SSL_DECRYPT_CTX_init(&ctx, pkey, NULL, NULL);
        
        fp[0] = fopen(argv[2+k], "rb");
        fp[1] = fopen(argv[3+k], "rb");
        if (!(fp[0] && fp[1]))
            fatal("cannot open sslstreams");
        
//    fclose(fp[1]);
//    fp[1] = NULL;
    
        do {
            int i;
            for (i = 0; i < 2; i ++) {
                if (fp[i] == NULL)
                    continue;
                n = fread(buf, 1, READ_CHUNK, fp[i]);
                if (n == 0) {
                    fclose(fp[i]);
                    fp[i] = NULL;
                    continue;
                }
                if (decrypt(&ctx, i, buf, n) != 0)
                    ctx.flag.disable = 1;
            }
            if ((!fp[0] && !fp[1]))
                break;
        } while (fp[0] || fp[1]);
        SSL_DECRYPT_CTX_free(&ctx);
        mesg("-------------------------------------------------\n");
    }
    EVP_PKEY_free(pkey);
    return 0; 
}

void SSL_DECRYPT_CTX_init(SSL_DECRYPT_CTX *pctx, EVP_PKEY *pkey,
                          ssl_decrypt_callback_t decrypt_cb, void *cb_arg)
{
    *pctx = (SSL_DECRYPT_CTX) {};
    
    h2o_buffer_init(&pctx->peer[0].buf, &buffer_prototype);
    h2o_buffer_init(&pctx->peer[1].buf, &buffer_prototype);
    pctx->pkey = pkey;
    pctx->decrypt_cb = decrypt_cb;
    pctx->cb_arg = cb_arg;
    EVP_PKEY_up_ref(pkey);
}

void SSL_DECRYPT_CTX_free(SSL_DECRYPT_CTX *pctx) 
{
    h2o_buffer_dispose(&pctx->peer[0].buf);
    h2o_buffer_dispose(&pctx->peer[1].buf);
    SSL_free(pctx->peer[0].ssl);
    SSL_free(pctx->peer[1].ssl);
    SSL_CTX_free(pctx->ssl_ctx);
    str_free(&pctx->client_random);
    str_free(&pctx->server_random);
    str_free(&pctx->client_id);
    str_free(&pctx->server_id);
    str_free(&pctx->pms);
    str_free(&pctx->master_secret);
    str_free(&pctx->sni);
    str_free(&pctx->client_ticket);
    str_free(&pctx->server_ticket);
    if (pctx->pkey) EVP_PKEY_free(pctx->pkey);
}

#define DIR_CLI 0
#define DIR_SVR 1
#define READ_BUFSIZE 4096
int decrypt(SSL_DECRYPT_CTX *pctx,
             int dir, char *_buf, size_t _buflen) 
{
    int rc;
    char *hdr = dir ? " <<- " : "->>  ";
    struct st_ssl_peer *peer = &pctx->peer[dir];

    if (pctx->flag.disable) {
        mesg("%s[Raw packet] decrypt disabled, len=%zu\n", hdr, _buflen);
        return EPROTO;
    }
    
    h2o_iovec_t buf = h2o_buffer_reserve(&peer->buf, READ_BUFSIZE);
    if (buf.base == NULL)
        return ENOMEM;
    if (buf.len < _buflen)
        return ENOSPC;
    memcpy(buf.base, _buf, _buflen);
    peer->buf->size += _buflen;

    do {
        rc = statem(pctx, dir, &peer->buf);
    } while (rc == 0);

    // rc == EAGAIN or ERROR
    return rc == EAGAIN ? 0 : rc;
}

static uint8_t get_u8(char *c) 
{
    return (unsigned char)*c;
}
static uint32_t get_u24(char *c) 
{
    uint32_t v = 0;
    memcpy(((char *)&v)+1, c, 3);
    return ntohl(v);
}
static uint16_t get_u16(char *c) 
{
    uint16_t v = 0;
    memcpy(((char *)&v), c, 2);
    return ntohs(v);
}

int statem(SSL_DECRYPT_CTX *pctx, int dir, h2o_buffer_t **_input) 
{
    h2o_buffer_t *input = *_input;
    uint32_t    msg_type = 0, major = 0, minor = 0;
    uint32_t   length = 0;
    char *hdr = dir ? " <<- " : "->>  ";
    int rc = 0;
    
//    if (pctx->peer[dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) { // record
    
    if (input->size < 5)
        return EAGAIN;
    msg_type = get_u8(&input->bytes[0]);
    major = get_u8(&input->bytes[1]);
    minor = get_u8(&input->bytes[2]);
    length = get_u16(&input->bytes[3]);
//    mesg("%s state(block=%zu, record=%d)\n", hdr, input->size, length);

    if (input->size < 5 + length)
        return EAGAIN;

    switch (msg_type) {
    case TLS_R_APPLICATION_DATA:
        mesg("%s[TLS record] application data       len=%u\n", hdr, length);
        if (!READY(pctx->ready)) {
            if (pctx->peer[1-dir].state < TLS_ST_CHANGE_CIPHER_SPEC)
                return EAGAIN;

            mesg("%s[TLS record] missing param, cannot decrypt, len=%u\n", hdr, length);
            rc = EPROTO;
            break;
        }
        
        rc = decrypt_record(pctx, dir, 
                            pctx->peer[dir].ssl, &pctx->peer[dir].buf, length, minor ? 1 : 0);
        if (rc < 0) {
            mesg("%s[TLS record] decrypt record error %d\n", hdr, rc);
            if (rc != -EPIPE)
                rc = EINVAL;
        }
        return rc;
    case TLS_R_HANDSHAKE:
        if (pctx->peer[dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) {
            // encrypted handshake,
            mesg("%s[TLS record] encrypted handshake    len=%u\n", hdr, length);
            rc = decrypt_handshake(pctx, dir,
                                   pctx->peer[dir].ssl, &pctx->peer[dir].buf, length, minor ? 1 : 0);
            if (rc < 0) {
                mesg("%s[TLS record] decrypt handshake error %d\n", hdr, rc);
                rc = EINVAL;
            }
            return rc;
        }
        
        rc = do_handshake(pctx, dir, &input->bytes[5], length);
        if (rc != 0) {
            mesg("%s[TLS record] bad handshake record %d\n", hdr, rc);
            rc = EINVAL;
        }
        break;
    case TLS_R_CHANGE_CIPHER_SPEC:
        mesg("%s[TLS record] CHANGE_CIPHER_SPEC     len=%u\n", hdr, length);
        pctx->peer[dir].state = TLS_ST_CHANGE_CIPHER_SPEC;
        if (!READY(pctx->ready) && pctx->peer[1-dir].state < TLS_ST_CHANGE_CIPHER_SPEC)
            return EAGAIN;
        if (pctx->flag.gen_params == 0) {
            if (!READY(pctx->ready)) {
                if (retrieve_session_cache(pctx) < 0) {
                    mesg("%s[TLS record] CHANGE_CIPHER_SPEC     insufficient handshake params, cannot decrypt\n", hdr);
                    return EPROTO;
                }
            }
            if (generate_ssl(pctx) < 0) {
                mesg("%s[TLS record] CHANGE_CIPHER_SPEC     cannot generate key\n", hdr);
                return EPROTO;
            }
            pctx->flag.gen_params = 1;
            SET_READY(pctx->ready);
        }
        if (!pctx->flag.client_dir) /* server with NEW_SESSION_TICKET mesg */
            update_session_cache(pctx);
        break;
    case TLS_R_ALERT:
        if (pctx->peer[dir].state < TLS_ST_CHANGE_CIPHER_SPEC) {
            mesg("%s[TLS record] alert                  len=%u\n", hdr, length);
            break;
        }
        // encrypted alert
        mesg("%s[TLS record] encrypted alert        len=%u\n", hdr, length);
        rc = decrypt_alert(pctx, dir,
                           pctx->peer[dir].ssl, &pctx->peer[dir].buf, length, minor ? 1 : 0);
        if (rc < 0) {
            mesg("%s[TLS record] decrypt alert error %d\n", hdr, rc);
            rc = EINVAL;
        }
        return rc;
    default:
        mesg("%s[TLS record] bad type=%d version=%d.%d len=%u\n",
             hdr, msg_type, major, minor, length);
        rc = EFAULT;
        break;
    }
    h2o_buffer_consume(_input, 5+length);
    return rc;
}

static int parse_hello(SSL_DECRYPT_CTX *pctx, char *buf, uint32_t len, int is_client) 
{
    struct __attribute ((__packed__)) client_hello {
        uint16_t version;
        uint8_t  random[32];
        uint8_t  len;
        char data[];
    } *p = (struct client_hello *)buf;
    char *pp = &p->data[p->len], *pend = (char *)p + len;
    uint16_t cipherlen, extlen;
    uint8_t complen;
    extern const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p);
    const char *hdr = is_client ? "CLIENT_HELLO" : "SERVER_HELLO";
    
#define CHECK(P,LEN,END) do { if (P+LEN > END) return -EPROTO; } while (0)
    
    if (is_client) {
        CHECK(pp, 3, pend);
        str_new(&pctx->client_random, p->random, 32);
        str_new(&pctx->client_id, p->data, p->len);
        cipherlen = get_u16(pp);
        pp += (2 + cipherlen);
        complen = get_u8(pp);
        pp += (1 + complen);
    } else {
        CHECK(pp, 0, pend);
        pctx->version = p->version;
        str_new(&pctx->server_random, p->random, 32);
        str_new(&pctx->server_id, p->data, p->len);
        pctx->cipher = htons(get_u16(pp));
        pp += 2;
        pctx->compression = get_u8(pp);
        pp++;
        mesg("ver: %02x %02x\n",
             ((unsigned char *)&pctx->version)[0],
             ((unsigned char *)&pctx->version)[1]);
        mesg("cip: %02x %02x\n",
             ((unsigned char *)&pctx->cipher)[0],
             ((unsigned char *)&pctx->cipher)[1]);
        mesg("compr: %02x\n", pctx->compression);
        pctx->ssl_cipher = ssl3_get_cipher_by_char((char *) &pctx->cipher);
        if (pctx->ssl_cipher == NULL) {
            mesg ("bad cipher %x\n", pctx->cipher);        
            return -EINVAL;
        }
    }
    CHECK(pp, 0, pend);
    if (pp == pend) { // no extension
        mesg("%s: no extension", hdr);
        return 0;
    }
    extlen = get_u16(pp);
    if (extlen == 0) {
        mesg("%s: no extension", hdr);
        return 0;
    }
    pp += 2;
    CHECK(pp, extlen, pend);
    int extnum = 0;
    while (1) {
        uint16_t type = get_u16(pp);
        mesg("%s: extension type=%d\n", hdr, type);
        
        pp += 2;
        switch (type) {
        case 0: {
            unsigned char *q = pp + 4;
            if (!is_client)
                break;
            if (*q++ != 0)
                break;
            uint16_t snilen = get_u16(q);
            str_new(&pctx->sni, q + 2, snilen);
            break;
        }
        case 35: {   // session ticket
            uint16_t ticketlen = get_u16(pp);
            if (!is_client)
                break;
            str_new(&pctx->client_ticket, pp + 2, ticketlen);
            pctx->flag.client_ticket = 1;
            break;
        }
        case 0x17:  // EMS
            if (is_client)
                pctx->flag.client_ems = 1;
            else
                pctx->flag.server_ems = 1;
            break;
        default:
            break;
        }
        uint16_t l = get_u16(pp);
        CHECK(pp, 2 + l, pend);
        pp += (2 + l);
        extnum++;
        
        if (pp == pend) {
            mesg("%s: %d extensions processed\n", hdr, extnum);
            break;
        }
    }
    
    pctx->compression = get_u8(&(p->data[p->len+2]));

    return 0;
}

int extract_payload(char *buf, int buflen, int from, int len, str_t *dst) 
{
    if (from + len > buflen)
        return -1;
    dst->buf = h2o_mem_alloc(len);
    dst->len = len;
    memcpy(dst->buf, &buf[from], len);
    return 0;
}

int do_handshake(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen) 
{
    char *hdr = dir ? " <<- " : "->>  ";
    uint32_t msg_type = 0, length = 0;
    int v;
    
    msg_type = get_u8(&buf[0]);
    length = get_u24(&buf[1]);

    if (length > buflen + 4) {
        mesg("%s[TLS handshake] invalid length(%d > %zud + 4), msg_type=%d\n", hdr,
             length, buflen, msg_type);
        return EPROTO;
    }
    
    switch (msg_type) {
    case TLS_H_CLIENT_HELLO:
        mesg("%s[TLS handshake] CLIENT_HELLO        len=%zu\n", hdr, buflen);
        if (dir == 1)
            pctx->flag.client_dir = 1;
        
        if (parse_hello(pctx, &buf[4], length, 1 /* client */) < 0) {
            mesg("%s[TLS handshake] CLIENT_HELLO truncated\n", hdr);
            return EPROTO;
        }
        mesg_buf("client-random", pctx->client_random.buf, pctx->client_random.len);
        mesg_buf("client-id", pctx->client_id.buf, pctx->client_id.len);
        mesg_buf("client-ticket", pctx->client_ticket.buf, pctx->client_ticket.len);
        mesg_buf("sni", pctx->sni.buf, pctx->sni.len);
        SET_CLIENT_RANDOM(pctx->ready);
        break;
    case TLS_H_SERVER_HELLO:
        mesg("%s[TLS handshake] SERVER_HELLO        len=%zu\n", hdr, buflen);
        if (parse_hello(pctx, &buf[4], length, 0 /*server */) < 0) {
            mesg("%s[TLS handshake] SERVER_HELLO truncated\n", hdr);
            return EPROTO;
        }
        mesg ("cipher: %s\n", SSL_CIPHER_get_name(pctx->ssl_cipher));
        mesg_buf("server-id", pctx->server_id.buf, pctx->server_id.len);
        
        if ((v = check_rsa(pctx->ssl_cipher)) < 0) {
            mesg("%s[TLS handshake] non-RSA %s, decryption skipped\n", hdr,
                 v == -1 ? "key exchange algorithm" :
                 "auth algorithm");
            return EPROTONOSUPPORT;
        }
        SET_SERVER_RANDOM(pctx->ready);
        break;
    case TLS_H_CLIENT_KEY_EXCHANGE:
        mesg("%s[TLS handshake] CLIENT_KEY_EXCHANGE len=%zu\n", hdr, buflen);
        extract_payload(&buf[4], length, 0, length, &pctx->pms);
        decrypt_pms(pctx);
        
        SET_PMS(pctx->ready);
        break;
    case TLS_H_HELLO_REQUEST:
        mesg("%s[TLS handshake] HELLO_REQUEST       len=%zu\n", hdr, buflen); break;
    case TLS_H_CERTIFICATE:
        mesg("%s[TLS handshake] CERTIFICATE         len=%zu\n", hdr, buflen); break;
    case TLS_H_SERVER_KEY_EXCHANGE:
        mesg("%s[TLS handshake] SERVER_KEY_EXCHANGE len=%zu\n", hdr, buflen); break;
    case TLS_H_CERTIFICATE_REQUEST:
        mesg("%s[TLS handshake] CERTIFICATE_REQUEST len=%zu\n", hdr, buflen); break;
    case TLS_H_SERVER_HELLO_DONE:
        mesg("%s[TLS handshake] SERVER_HELLO_DONE   len=%zu\n", hdr, buflen); break;
    case TLS_H_CERTIFICATE_VERIFY:
        mesg("%s[TLS handshake] CERTIFICATE_VERIFY  len=%zu\n", hdr, buflen); break;
    case TLS_H_NEW_SESSION_TICKET: {
        mesg("%s[TLS handshake] NEW_SESSION_TICKET  len=%zu\n", hdr, buflen);
        uint16_t tlen = get_u16(&buf[8]);
        if (tlen + 6 != length) {
            mesg("%s[TLS handshake] tlen + 6 (%d) != len (%d)\n", hdr, tlen + 6, length);
            break;
        }
        extract_payload(&buf[8], length-4, 2, tlen, &pctx->server_ticket);
        mesg_buf("server-ticket", pctx->server_ticket.buf, pctx->server_ticket.len);
        pctx->flag.server_ticket = 1;
        break;
    }
    case TLS_H_FINISHED:
        mesg("%s[TLS handshake] FINISHED            len=%zu\n", hdr, buflen); break;
    default:
        mesg("%s[TLS handshake] bad type=%d len=%zu\n", hdr, msg_type, buflen);
        return EFAULT;
    }
    return 0;
}

int decrypt_pms(SSL_DECRYPT_CTX *pctx) 
{
    RSA *rsa;
    int n, i;
    
    if ((rsa = EVP_PKEY_get1_RSA(pctx->pkey)) == NULL)
        return -1;

    RSA_free(rsa);
    uint16_t len = get_u16(pctx->pms.buf);
    if (len + 2 != pctx->pms.len) {
        mesg("%s: invalid pms (%d != %d)\n", __FUNCTION__, len + 2, pctx->pms.len);
        return -1;
    }

    char *p = pctx->pms.buf + 2;
    n = RSA_private_decrypt(len, p, p, rsa, RSA_PKCS1_PADDING);
    if (n != SSL_MAX_MASTER_KEY_LENGTH) {
        mesg("RSA_private_decyprt: error, len=%d\n", pctx->pms.len);
        print_ssl_error();
        return -1;
    }
    pctx->pms.len = n;

    mesg_buf("pms-decrypted", p, n);
    
//    for (i = 0; i < n; i++) mesg("%d: %3d [%c]\n", i + 1, p[i], p[i]);
}

// handle FINISHED mesg
int handshake_cb(SSL *ssl) 
{
    mesg("%s: SSL(%p) received HANDSHAKE record.\n", __FUNCTION__, ssl);
    return 1;
}

static int read_bio(BIO *b, char *out, int len)
{
    struct st_ssl_peer *peer = BIO_get_data(b);
    h2o_buffer_t *buf = peer->buf;

    if (len == 0)
        return 0;

    if (buf->size == 0) {
        BIO_set_retry_read(b);
        return -1;
    }

    mesg("%s: buf = %p, buf_len=%4zu, len=%4d  |  ",
         __FUNCTION__, buf, (buf)->size, len);
    
    if (buf->size < len) {
        len = (int)buf->size;
    }
    memcpy(out, buf->bytes, len);
    {
        unsigned char *p = out;
        mesg("%02x %02x %02x %02x %02x ..\n", p[0], p[1], p[2], p[3], p[4]);
    }
    
    h2o_buffer_consume(&peer->buf, len);

    return len;
}
static long ctrl_bio(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        return BIO_get_shutdown(b);
    case BIO_CTRL_SET_CLOSE:
        BIO_set_shutdown(b, (int) num);
        return 1;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}
static void setup_bio(SSL *ssl, struct st_ssl_peer *peer) 
{
    static BIO_METHOD *bio_methods = NULL;
    if (bio_methods == NULL) {
        static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&init_lock);
        if (bio_methods == NULL) {
            BIO_METHOD *b = BIO_meth_new(BIO_TYPE_FD, "ssl_decrypt");
            BIO_meth_set_read(b, read_bio);
            BIO_meth_set_ctrl(b, ctrl_bio);
            __sync_synchronize();       /* full memory barrier */
            bio_methods = b;
        }
        pthread_mutex_unlock(&init_lock);
    }
/*  old style
    static BIO_METHOD bio_methods = {BIO_TYPE_FD, "ssl_decrypt", NULL, read_bio, NULL,
                                     NULL, ctrl_bio, new_bio, free_bio, NULL};
*/
    BIO *bio = BIO_new(bio_methods);
    if (bio == NULL)
        h2o_fatal("malloc");
    BIO_set_data(bio, peer);
    BIO_set_init(bio, 1);
    SSL_set_bio(ssl, bio, bio);
}

static void ssl_info_cb(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_ALERT == 0)
        return;
    uint16_t alert = htons((uint16_t)ret);
    mesg_buf("alert", (char *)&alert, 2);
}
   
static int generate_ssl(SSL_DECRYPT_CTX *pctx) 
{
    uint8_t major = pctx->version & 0xff;
    uint8_t minor = pctx->version >> 8;
    int rc = 0, rc2 = 0;
    
    mesg("%s: TLS version %d.%d\n", __FUNCTION__, major, minor);

    if (pctx->flag.server_ems) {
        mesg("skipping EMS session\n");
        return -1;
    }
    
    pctx->ssl_ctx = SSL_CTX_new(SSL_method(major, minor));
    if (!pctx->ssl_ctx) {
        print_ssl_error();
        goto error;
    }
	SSL_CTX_set_info_callback(pctx->ssl_ctx, ssl_info_cb);

    for (int i = 0; i < 2; i ++) {
        SSL *s = SSL_new(pctx->ssl_ctx);

        if (!s) {
            print_ssl_error();
        }
        
        s->s3->tmp.new_cipher = pctx->ssl_cipher;
        s->handshake_func = handshake_cb;
        s->version = pctx->version;
        my_ssl_clear_state(s);
        mesg("SSL_new: server=%d\n", s->server);
        memcpy(s->s3->client_random, pctx->client_random.buf, SSL3_RANDOM_SIZE);
        memcpy(s->s3->server_random, pctx->server_random.buf, SSL3_RANDOM_SIZE);
        pctx->peer[i].ssl = s;

        setup_bio(s, &pctx->peer[i]);
        
        ssl_get_new_session(s, 0);
        SSL_SESSION *ss = SSL_get0_session(s);
        ss->cipher = pctx->ssl_cipher;
        my_ssl_session_set_compress_meth(ss, 0);     /* right? */

        int cipher_dir;
        if (i != pctx->flag.client_dir)
            cipher_dir = SSL3_CHANGE_CIPHER_CLIENT_READ;
        else
            cipher_dir = SSL3_CHANGE_CIPHER_SERVER_READ;

        if (minor) { // TLS
            if (pctx->master_secret.len == MASTER_SECRET_LEN) {
                memcpy(ss->master_key, pctx->master_secret.buf, MASTER_SECRET_LEN);
                ss->master_key_length = MASTER_SECRET_LEN;
                
            } else {
                ss->master_key_length =
                    my_tls1_generate_master_secret(s,
                                                   ss->master_key,
                                                   pctx->pms.buf + 2,
                                                   pctx->pms.len);
            }
            rc = tls1_setup_key_block(s);
            rc2 = tls1_change_cipher_state(s, cipher_dir);
        } else {
            if (pctx->master_secret.len) {
                memcpy(ss->master_key, pctx->master_secret.buf, MASTER_SECRET_LEN);
                ss->master_key_length = MASTER_SECRET_LEN;
            } else {
                ss->master_key_length =
                    my_ssl3_generate_master_secret(s,
                                                   ss->master_key,
                                                   pctx->pms.buf + 2,
                                                   pctx->pms.len);
            }
            rc = ssl3_setup_key_block(s);
            rc2 = ssl3_change_cipher_state(s, cipher_dir);
        }
        mesg_buf("master-key", ss->master_key, ss->master_key_length);
        if (pctx->master_secret.buf == NULL)
            str_new(&pctx->master_secret, ss->master_key, ss->master_key_length);
        
        if (rc == 0 ||
            rc2 == 0 ||
            ss->master_key_length <= 0) {
            mesg("%s: setup_key_block failed (%d, %d)\n", __FUNCTION__, rc, rc2);
            print_ssl_error();
            goto error;
        } else
            mesg("%s: setup_key_block ok\n", __FUNCTION__);        
    }
    return 0;
    
error:
    return -1;
}

// temporary check
str_t prev_key;
str_t prev_val;

void cache_put(str_t *k, str_t *v) 
{
    prev_key = str_dup(k);
    prev_val = str_dup(v);
}
int cache_get(str_t *k, str_t *v) 
{
    if (str_cmp(&prev_key, k) != 0) {
        return -1;
    }
    *v = prev_val;
    return 0;
}


static int retrieve_session_cache(SSL_DECRYPT_CTX *pctx) 
{
    // RFC5077 3.4
    if (pctx->client_id.len == 0)
        return -1;
    
    if (str_cmp(&pctx->client_id, &pctx->server_id))
        return -1;
    
    if (pctx->flag.client_ticket) {
        if (cache_get(&pctx->client_ticket, &pctx->master_secret) < 0)
            return -1;
        mesg("Ticket-HIT\n");
    } else if (pctx->client_id.len) {
        if (cache_get(&pctx->client_id, &pctx->master_secret) < 0)
            return -1;
        mesg("ID-Hit\n");
    } else {
        return -1;
    }
    
    return 0;
}

static void update_session_cache(SSL_DECRYPT_CTX *pctx) 
{
    // RFC5077 3.4
    if (pctx->flag.server_ticket) {    // we should discards session id
        // store ticket-key
        cache_put(&pctx->server_ticket, &pctx->master_secret);
        return;
    }
    if (pctx->server_id.len) {
        // store id-key
        cache_put(&pctx->server_id, &pctx->master_secret);
        return;
    }
}

static int _decrypt_record(SSL_DECRYPT_CTX *pctx, int dir, 
                           SSL *ssl, h2o_buffer_t **_input, size_t len, int is_tls, int type)
{
    char buf[2048];
    int n;
    
    mesg("%s: type=%d buf_ptr = %p, buf_len=%zu\n", __FUNCTION__, type, *_input, (*_input)->size);

    switch(type) {
    case TLS_R_HANDSHAKE: 
        n = my_ssl3_read_bytes(ssl, SSL3_RT_HANDSHAKE, buf, 2048, 0);  /* no DTLS */
        mesg("%s:n=%d\n", __FUNCTION__, n);
        
        break;
    case TLS_R_ALERT:
        n = my_ssl3_read_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, 2048, 0);   /* no DTLS */
        print_ssl_error();
        if (n == 0) { // valid alert
            /* char buf[2]; */
            /* buf[0] = ssl->s3->alert_fragment[0]; // alert_level */
            /* buf[1] = ssl->s3->alert_fragment[1]; */
            /* mesg_buf("alert", buf, 2); */
            return 0;
        }
        return 0;
        
        break;
    default:
        n = SSL_read(ssl, buf, 2048);
        break;
    }

    if (type == TLS_R_APPLICATION_DATA && pctx->decrypt_cb) {
        int r = pctx->decrypt_cb(pctx->cb_arg, buf, n, 
                                 (dir == pctx->flag.client_dir) ? 0 : 1);
        if (r < 0) {    // session error
            return -EPIPE;
        }
    } else
        mesg_buf("record", buf, n);
    
    return n <= 0 ? n : 0;
}

int decrypt_record(SSL_DECRYPT_CTX *pctx, int dir,
                   SSL *ssl, h2o_buffer_t **_input, size_t len, int is_tls)  
{
    return _decrypt_record(pctx, dir, ssl, _input, len, is_tls, TLS_R_APPLICATION_DATA);
}
int decrypt_handshake(SSL_DECRYPT_CTX *pctx, int dir,
                      SSL *ssl, h2o_buffer_t **_input, size_t len, int is_tls)  
{
    return _decrypt_record(pctx, dir, ssl, _input, len, is_tls, TLS_R_HANDSHAKE);
}
int decrypt_alert(SSL_DECRYPT_CTX *pctx, int dir,
                  SSL *ssl, h2o_buffer_t **_input, size_t len, int is_tls)  
{
    return _decrypt_record(pctx, dir, ssl, _input, len, is_tls, TLS_R_ALERT);
}
