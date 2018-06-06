/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * decrypt-sslstream
 * 6 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>          // ENOMEM,..
#include <arpa/inet.h>      // ntohl()
#include <openssl/crypto.h> // EVP_PKEY
#include <openssl/bio.h>    // BIO
#include <openssl/pem.h>    // PEM*
#include <openssl/ssl.h>
#include "memory.h"

#define READ_CHUNK 128

#define fatal(X) do {                           \
        fprintf(stderr, "%s\n", X);             \
        abort();                                \
    } while (0)
#define mesg(a...) fprintf(stderr, ##a)

typedef struct st_string {
    char *buf;
    int len;
} str_t;

void str_free(str_t s) 
{
    if (s.buf)
        free(s.buf);
    s.buf = NULL;
}

// RFC5246
#define TLS_H_HELLO_REQUEST       0
#define TLS_H_CLIENT_HELLO        1
#define TLS_H_SERVER_HELLO        2
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
    
#define MASTER_SECRET_LEN   48
typedef struct st_ssl_decrypt_ctx {
    SSL_CTX *ssl_ctx;
    struct st_peer
    {
        SSL             *ssl;
        h2o_buffer_t    *buf;
        int             state;  // handshake state
    } peer[2];
    uint16_t    version;
    uint16_t    cipher;
    uint8_t     compression;    /* XXX: HOW? */
    uint8_t     ready;
#define READY(x) (x == 7)
#define SET_CLIENT_RANDOM(x) do { x |= 1; } while (0)
#define SET_SERVER_RANDOM(x) do { x |= 2; } while (0)
#define SET_PMS(x) do { x |= 4; } while (0)
    str_t       client_random;
    str_t       server_random;
    str_t       pre_master_secret;
    char        master_secret[MASTER_SECRET_LEN];
    EVP_PKEY    *pkey;
    
    /* TODO: session resumption */
    /* TODO: TLS1.3 */
} SSL_DECRYPT_CTX;

void SSL_DECRYPT_CTX_init(SSL_DECRYPT_CTX *pctx);
void SSL_DECRYPT_CTX_free(SSL_DECRYPT_CTX *pctx);
int decrypt(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);
int decrypt_record(SSL *ssl, char *buf, size_t buflen);
int statem(SSL_DECRYPT_CTX *pctx, int dir, h2o_buffer_t **_input);
int do_handshake(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);



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


static void init_library(void) 
{
    ;
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

void main(int argc, char *argv[]) 
{
    char buf[READ_CHUNK];
    size_t n;
    EVP_PKEY *pkey;
    FILE *fp[2];
    int c = 0;
    SSL_DECRYPT_CTX ctx = {};
    
    SSL_DECRYPT_CTX_init(&ctx);

    if (argc != 4)
        fatal("usage: decrypt keyfile sslstream-from-client sslstream-from-server");

    init_library();
    
    ctx.pkey = load_private_key(argv[1]);

    fp[0] = fopen(argv[2], "rb");
    fp[1] = fopen(argv[3], "rb");
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
            }
            decrypt(&ctx, i, buf, n);
        }
        if ((!fp[0] && !fp[1]))
            break;
    } while (fp[0] || fp[1]);

    SSL_DECRYPT_CTX_free(&ctx);
}

void SSL_DECRYPT_CTX_init(SSL_DECRYPT_CTX *pctx) 
{
/*    pctx->ssl_ctx = SSL_CTX_new(TLSv1_2_method());
    pctx->cli = SSL_new(pctx->ssl_ctx);
    pctx->svr = SSL_new(pctx->ssl_ctx);
*/
    h2o_buffer_init(&pctx->peer[0].buf, &buffer_prototype);
    h2o_buffer_init(&pctx->peer[1].buf, &buffer_prototype);
}

void SSL_DECRYPT_CTX_free(SSL_DECRYPT_CTX *pctx) 
{
    h2o_buffer_dispose(&pctx->peer[0].buf);
    h2o_buffer_dispose(&pctx->peer[1].buf);
    SSL_free(pctx->peer[0].ssl);
    SSL_free(pctx->peer[1].ssl);
    SSL_CTX_free(pctx->ssl_ctx);
    str_free(pctx->client_random);
    str_free(pctx->server_random);
    str_free(pctx->pre_master_secret);
    if (pctx->pkey) EVP_PKEY_free(pctx->pkey);
}

#define DIR_CLI 0
#define DIR_SVR 1
#define READ_BUFSIZE 4096
int decrypt(SSL_DECRYPT_CTX *pctx,
             int dir, char *_buf, size_t _buflen) 
{
    int rc;
    struct st_peer *peer = &pctx->peer[dir];
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

static void get_u8(uint32_t *v, char *c) 
{
    *v = (unsigned char)*c;
}
static void get_u24(uint32_t *v, char *c) 
{
    *v = 0;
    memcpy(((char *)v)+1, c, 3);
    *v = ntohl(*v);
}
static void get_u16(uint32_t *v, char *c) 
{
    *v = 0;
    memcpy(((char *)v)+2, c, 2);
    *v = ntohl(*v);
}

int statem(SSL_DECRYPT_CTX *pctx, int dir, h2o_buffer_t **_input) 
{
    h2o_buffer_t *input = *_input;
    uint32_t    msg_type = 0, major = 0, minor = 0;
    uint32_t   length = 0;
    char *hdr = dir ? " <<< " : " >>> ";
    int rc;
    
//    if (pctx->peer[dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) { // record
    
    if (input->size < 5)
        return EAGAIN;
    get_u8(&msg_type, &input->bytes[0]);
    get_u8(&major, &input->bytes[1]);
    get_u8(&minor, &input->bytes[2]);
    get_u16(&length, &input->bytes[3]);
//    mesg("%s state(block=%zu, record=%d)\n", hdr, input->size, length);

    if (input->size < length)
        return EAGAIN;
    
    switch (msg_type) {
    case TLS_R_APPLICATION_DATA:
        if (1 ||  READY(pctx->ready)) {
            rc = decrypt_record(pctx->peer[dir].ssl, input->bytes, length);
            if (rc < 0) {
                mesg("%s[TLS record] decrypt record error %d\n", hdr, rc);
                return EINVAL;
            }
            mesg("%s[TLS record] application data, len=%u\n", hdr, length);
            break;
        }
        
        if (pctx->peer[1-dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) {
            mesg("%s[TLS record] missing param, cannot decrypt\n", hdr);
            return EPROTO;
        }
        
        return EAGAIN; 
    case TLS_R_HANDSHAKE:
        if (pctx->peer[dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) {
            // encrypted handshake
            mesg("%s[TLS record] encrypted handshake, len=%u\n", hdr, length);
            break;
        }
        
        rc = do_handshake(pctx, dir, &input->bytes[5], length);
        if (rc != 0) {
            mesg("%s[TLS record] bad handshake record %d\n", hdr, rc);
            return EINVAL;
        }
        break;
    case TLS_R_CHANGE_CIPHER_SPEC:
        pctx->peer[dir].state = TLS_ST_CHANGE_CIPHER_SPEC;
        mesg("%s[TLS record] change cipher spec, len=%u\n", hdr, length);
        break;
    case TLS_R_ALERT:
        mesg("%s[TLS record] type=%d len=%u\n", hdr, msg_type, length);
        break;
    default:
        mesg("%s[TLS record] bad type=%d version=%d.%d len=%u\n",
             hdr, msg_type, major, minor, length);
        return EFAULT;
    }
    h2o_buffer_consume(_input, 5+length);
//    mesg("%sconsume %d\n", hdr, 5 + length);
    return 0;
}

int do_handshake(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen) 
{
    char *hdr = dir ? " <<< " : " >>> ";
    uint32_t msg_type = 0, length = 0;
    get_u8(&msg_type, &buf[0]);
    get_u24(&length, &buf[1]);

    switch (msg_type) {
    case TLS_H_CLIENT_HELLO:
        // XXX: TODO
        mesg("%s[TLS handshake] CLIENT_HELLO type=%d len=%zu\n", hdr, msg_type, buflen);
        SET_CLIENT_RANDOM(pctx->ready);
        break;
    case TLS_H_SERVER_HELLO:
        // XXX: TODO
        mesg("%s[TLS handshake] SERVER_HELLO type=%d len=%zu\n", hdr, msg_type, buflen);
        SET_SERVER_RANDOM(pctx->ready);
        break;
    case TLS_H_CLIENT_KEY_EXCHANGE:
        // XXX: TODO
        mesg("%s[TLS handshake] CLIENT_KEY_EXCHANGE type=%d len=%zu\n", hdr, msg_type, buflen);
        SET_PMS(pctx->ready);
        break;

    case TLS_H_HELLO_REQUEST:
    case TLS_H_CERTIFICATE:
    case TLS_H_SERVER_KEY_EXCHANGE:
    case TLS_H_CERTIFICATE_REQUEST:
    case TLS_H_SERVER_HELLO_DONE:
    case TLS_H_CERTIFICATE_VERIFY:
        mesg("%s[TLS handshake] type=%d len=%zu\n", hdr, msg_type, buflen);
        break;
    case TLS_H_FINISHED:
        mesg("%s[TLS handshake] FINISHED type=%d len=%zu\n", hdr, msg_type, buflen);
        break;
    default:
        mesg("%s[TLS handshake] bad type=%d len=%zu\n", hdr, msg_type, buflen);
        return EFAULT;
    }
    return 0;
}

int decrypt_record(SSL *ssl, char *buf, size_t buflen)
{
    // XXX: TODO
    return 0;
}

