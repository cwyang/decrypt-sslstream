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
#include <openssl/err.h>    // ERR_*()
#include <openssl/ssl.h>
#include "memory.h"

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
    
#define MASTER_SECRET_LEN   48
typedef struct st_ssl_decrypt_ctx {
    int         disable;
    SSL_CTX *ssl_ctx;
    const SSL_CIPHER *ssl_cipher;
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
    str_t       pms;
    char        master_secret[MASTER_SECRET_LEN];
    EVP_PKEY    *pkey;
    
    /* TODO: session resumption */
    /* TODO: TLS1.3 */
    /* TODO: extended master secret */
} SSL_DECRYPT_CTX;

void SSL_DECRYPT_CTX_init(SSL_DECRYPT_CTX *pctx);
void SSL_DECRYPT_CTX_free(SSL_DECRYPT_CTX *pctx);
int decrypt(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);
int decrypt_record(SSL *ssl, char *buf, size_t buflen);
int statem(SSL_DECRYPT_CTX *pctx, int dir, h2o_buffer_t **_input);
int do_handshake(SSL_DECRYPT_CTX *pctx, int dir, char *buf, size_t buflen);
int decrypt_pms(SSL_DECRYPT_CTX *pctx) ;
static int generate_ssl(SSL_DECRYPT_CTX *pctx);



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
            if (decrypt(&ctx, i, buf, n) != 0)
                ctx.disable = 1;
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
    str_free(pctx->pms);
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
    struct st_peer *peer = &pctx->peer[dir];

    if (pctx->disable) {
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
        if (READY(pctx->ready)) {
            rc = decrypt_record(pctx->peer[dir].ssl, input->bytes, length);
            if (rc < 0) {
                mesg("%s[TLS record] decrypt record error %d\n", hdr, rc);
                rc = EINVAL;
                break;
            }
            mesg("%s[TLS record] application data       len=%u\n", hdr, length);
            break;
        }
        
        if (pctx->peer[1-dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) {
            mesg("%s[TLS record] missing param, cannot decrypt, len=%u\n", hdr, length);
            rc = EPROTO;
            break;
        }
        
        return EAGAIN; 
    case TLS_R_HANDSHAKE:
        if (pctx->peer[dir].state >= TLS_ST_CHANGE_CIPHER_SPEC) {
            // encrypted handshake
            mesg("%s[TLS record] encrypted handshake    len=%u\n", hdr, length);
            break;
        }
        
        rc = do_handshake(pctx, dir, &input->bytes[5], length);
        if (rc != 0) {
            mesg("%s[TLS record] bad handshake record %d\n", hdr, rc);
            rc = EINVAL;
            break;

        }
        break;
    case TLS_R_CHANGE_CIPHER_SPEC:
        pctx->peer[dir].state = TLS_ST_CHANGE_CIPHER_SPEC;
        mesg("%s[TLS record] change cipher spec     len=%u\n", hdr, length);
        break;
    case TLS_R_ALERT:
        mesg("%s[TLS record] alert                  len=%u\n", hdr, length);
        break;
    default:
        mesg("%s[TLS record] bad type=%d version=%d.%d len=%u\n",
             hdr, msg_type, major, minor, length);
        rc = EFAULT;
        break;
    }
    h2o_buffer_consume(_input, 5+length);
//    mesg("%sconsume %d\n", hdr, 5 + length);
    return rc;
}
    
static int parse_server_hello(SSL_DECRYPT_CTX *pctx, char *buf, uint32_t len) 
{
    struct __attribute ((__packed__)) server_hello {
        uint16_t version;
        uint8_t  random[32];
        uint8_t  len;
        char data[];
        // opaque seession id + uint16_t cipher + uint8_t compression
    } *p = (struct server_hello *)buf;
    extern const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p);
    
    if (len < sizeof(struct server_hello) + p->len + 3)
        return -EPROTO;
    pctx->version = p->version;
    pctx->cipher = htons(get_u16(&(p->data[p->len])));
    pctx->compression = get_u8(&(p->data[p->len+2]));

    mesg("ver: %02x %02x\n",
         ((unsigned char *)&pctx->version)[0],
         ((unsigned char *)&pctx->version)[1]);
    mesg("cip: %02x %02x\n",
         ((unsigned char *)&pctx->cipher)[0],
         ((unsigned char *)&pctx->cipher)[1]);
    mesg("compr: %02x\n", pctx->compression);

    pctx->server_random.buf = h2o_mem_alloc(32);
    pctx->server_random.len = 32;
    memcpy(pctx->server_random.buf, p->random, 32);

    pctx->ssl_cipher = ssl3_get_cipher_by_char((char *) &pctx->cipher);
    if (pctx->ssl_cipher == NULL) {
        mesg ("bad cipher %x\n", pctx->cipher);        
        return -EINVAL;
    }

    return 0;
}

int is_rsa (SSL_DECRYPT_CTX *pctx)
{
    const SSL_CIPHER *cipher = pctx->ssl_cipher;
    const char *name = SSL_CIPHER_get_name(cipher);
    int kx_nid = SSL_CIPHER_get_kx_nid(cipher);
    int auth_nid = SSL_CIPHER_get_auth_nid(cipher);
    mesg ("cipher: %s\n", name);
    if (kx_nid != NID_kx_rsa) {
        mesg ("non-RSA key exchange algorithm\n");
        return 0;
    }
    if (auth_nid != NID_auth_rsa) {
        mesg ("non-RSA auth algorithm\n");
        return 0;
    }
    return 1;
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

        if (extract_payload(&buf[4], length, 2, 32,
                            &pctx->client_random) < 0) {
            mesg("%s[TLS handshake] CLIENT_HELLO truncated\n", hdr);
            return EPROTO;
        }
        mesg("%s[TLS handshake] CLIENT_HELLO random: %02x %02x %02x.. \n", hdr,
             pctx->client_random.buf[0],
             pctx->client_random.buf[1],
             pctx->client_random.buf[2]);
        SET_CLIENT_RANDOM(pctx->ready);
        break;
    case TLS_H_SERVER_HELLO:
        mesg("%s[TLS handshake] SERVER_HELLO        len=%zu\n", hdr, buflen);
        if (parse_server_hello(pctx, &buf[4], length) < 0) {
            mesg("%s[TLS handshake] SERVER_HELLO truncated\n", hdr);
            return EPROTO;
        }
        if (!is_rsa(pctx)) {
            mesg("%s[TLS handshake] non-RSA, decryption skipped\n", hdr);
            return EPROTONOSUPPORT;
        }
        SET_SERVER_RANDOM(pctx->ready);
        break;
    case TLS_H_CLIENT_KEY_EXCHANGE:
        mesg("%s[TLS handshake] CLIENT_KEY_EXCHANGE len=%zu\n", hdr, buflen);
        extract_payload(&buf[4], length, 0, length, &pctx->pms);
        mesg("%s[TLS handshake] CLIENT_KEY_EXCHANGE pms: %02x %02x %02x.. \n", hdr,
             pctx->pms.buf[0],
             pctx->pms.buf[1],
             pctx->pms.buf[2]);
        decrypt_pms(pctx);
        
        SET_PMS(pctx->ready);
        break;

    case TLS_H_HELLO_REQUEST:
        mesg("%s[TLS handshake] HELLO_REQUEST       len=%zu\n", hdr, buflen);
        break;
    case TLS_H_CERTIFICATE:
        mesg("%s[TLS handshake] CERTIFICATE         len=%zu\n", hdr, buflen);
        break;
    case TLS_H_SERVER_KEY_EXCHANGE:
        mesg("%s[TLS handshake] SERVER_KEY_EXCHANGE len=%zu\n", hdr, buflen);
        break;
    case TLS_H_CERTIFICATE_REQUEST:
        mesg("%s[TLS handshake] CERTIFICATE_REQUEST len=%zu\n", hdr, buflen);
        break;
    case TLS_H_SERVER_HELLO_DONE:
        mesg("%s[TLS handshake] SERVER_HELLO_DONE   len=%zu\n", hdr, buflen);
        break;
    case TLS_H_CERTIFICATE_VERIFY:
        mesg("%s[TLS handshake] CERTIFICATE_VERIFY  len=%zu\n", hdr, buflen);
        break;
    case TLS_H_NEW_SESSION_TICKET:
        mesg("%s[TLS handshake] NEW_SESSION_TICKET  len=%zu\n", hdr, buflen);
        break;
    case TLS_H_FINISHED:
        mesg("%s[TLS handshake] FINISHED            len=%zu\n", hdr, buflen);
        break;
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
    
    if ((rsa = EVP_PKEY_get0_RSA(pctx->pkey)) == NULL)
        return -1;

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

    mesg("pms decrypted\n");
//    for (i = 0; i < n; i++) mesg("%d: %3d [%c]\n", i + 1, p[i], p[i]);

    generate_ssl(pctx);
    
    
    // XXX: TODO
//    master_key_length = generate_master_secret(s, master_key, p, i);
    
}

static int generate_ssl(SSL_DECRYPT_CTX *pctx) 
{
    uint8_t major = pctx->version & 0xff;
    uint8_t minor = pctx->version >> 8;
    
    mesg("%s: TLS version %d.%d\n", __FUNCTION__, major, minor);
    
    if (!minor /* minor == 0x00 */) { // SSL 3.0
        pctx->ssl_ctx = SSL_CTX_new(SSLv3_method());
    } else {
        pctx->ssl_ctx = SSL_CTX_new(TLS_method());
    }

    for (int i = 0; i < 2; i ++) {
        SSL *s = SSL_new(pctx->ssl_ctx);
#warning TODO
#if 0
        s->s3->tmp.new_cipher = pctx->ssl_cipher;
        memcpy(s->s3->client_random, pctx->client_random.buf, SSL3_RANDOM_SIZE);
        memcpy(s->s3->server_random, pctx->server_random.buf, SSL3_RANDOM_SIZE);
        
        extern int ssl_get_new_session(SSL *s, int session);    /* from ssl_session.c */
        
        ssl_get_new_session(s, 0);
        SSL_SESSION *ss = SSL_get0_session(s);
        pctx->peer[i].ssl = s;
        ss->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        ss->master_key,
                                                        pctx->pms.buf + 2,
                                                        pctx->pms.len);
#endif
    }
    return 0;
    
error:
    return -1;
}

int decrypt_record(SSL *ssl, char *buf, size_t buflen)
{
    // XXX: TODO
    return 0;
}

