/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * ssl_stub.c
 * 14 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 */
#include <openssl/ssl.h>
#include "ssl_stub.h"

#define str(s) xstr(s)
#define xstr(s) #s
#pragma message ("openssl version=" str(OPENSSL_VERSION_NUMBER))

/*
  OPENSSL_VERSION_NUMBER  0x1 00 01 15 fL  // 1.0.1u
  OPENSSL_VERSION_NUMBER  0x1 00 02 0f fL  // 1.0.2o
  OPENSSL_VERSION_NUMBER  0x1 01 00 08 fL  // 1.1.0h
  OPENSSL_VERSION_NUMBER  0x1 01 01 00 7L  // 1.1.1-pre7
*/

#if OPENSSL_VERSION_NUMBER >= 0x1010001fL && NOT_LIBRESSL /* >= 1.1.0.a */
void init_library(void) 
{
    OPENSSL_init_ssl(0, NULL);
}

int check_rsa (const SSL_CIPHER *cipher)
{
    int kx_nid = SSL_CIPHER_get_kx_nid(cipher);
    int auth_nid = SSL_CIPHER_get_auth_nid(cipher);

    if (kx_nid != NID_kx_rsa) {
        return -1;
    }
    if (auth_nid != NID_auth_rsa) {
        return -2;
    }
    return 0;
}
/* allround ssl method */
const SSL_METHOD *SSL_method(uint8_t major, uint8_t minor)
{
    return TLS_method();
}
#else /* < 1.1.0.a */
void init_library(void) 
{
    SSL_library_init();
}

int check_rsa (const SSL_CIPHER *cipher)
{
    unsigned long alg_mkey, alg_auth;

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;

# define SSL_kRSA                0x00000001L
# define SSL_aRSA                0x00000001L
    
    if (alg_mkey != SSL_kRSA) {
        return -1;
    }
    if (alg_auth != SSL_aRSA) {
        return -2;
    }
    return 0;
}
/* allround ssl method */
const SSL_METHOD *SSL_method(uint8_t major, uint8_t minor)
{
    switch(minor) {
    case 0: /* SSL 3.0 */
        return SSLv3_method();
    case 1: /* TLS 1.0 */
        return TLSv1_method();
    case 2: /* TLS 1.1 */
        return TLSv1_1_method();
    case 3: /* TLS 1.2 or greater */
        return TLSv1_2_method();
    default:
        return SSLv23_method();
    }
}

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) 
{
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    if (rsa == NULL)
        return NULL;
    RSA_free(rsa);
    return rsa;
}

#endif

int my_ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek) 
{
#if OPENSSL_VERSION_NUMBER >= 0x10101007L && NOT_LIBRESSL /* >= 1.1.1-pre7 */
    /* from record_layer_s3.c */
    extern int ssl3_read_bytes(SSL *s, int type, int *recvd_type,
                               unsigned char *buf, size_t len, int peek, size_t *readbytes);
    size_t rb=0;
    int n;
    
    if ((n = ssl3_read_bytes(s, type, (int *)NULL, buf, len, peek, &rb)) != 1)
        return -1;
    return rb;
#elif OPENSSL_VERSION_NUMBER >= 0x1010001fL && NOT_LIBRESSL /* >= 1.1.0.a */
    /* from record_layer_s3.c */
    extern int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf, int len, int peek);
    return ssl3_read_bytes(s, type, (int *)NULL, buf, len, peek);
#else
    /* from s3_pkt.c */
    extern int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
    return ssl3_read_bytes(s, type, buf, len, peek);
#endif
}

void my_ssl_clear_state(SSL *s) 
{
#if OPENSSL_VERSION_NUMBER >= 0x1010001fL && NOT_LIBRESSL /* >= 1.1.0.a */
    s->statem.hand_state = TLS_ST_OK;
#else
    s->state = SSL_ST_OK;
#endif
    s->server = 0;  /* to handle alert in >= 1.1.0.a */
}
int my_tls1_generate_master_secret(SSL *s, unsigned char *out,
                                   unsigned char *p, int len) 
{
#if OPENSSL_VERSION_NUMBER >= 0x10101007L && NOT_LIBRESSL /* >= 1.1.1-pre7 */
    size_t secret_len = 0;
    if (tls1_generate_master_secret(s, out, p, len, &secret_len) != 1)
        return -1;
    return secret_len;
#else
    return tls1_generate_master_secret(s, out, p, len);
#endif
}

int my_ssl3_generate_master_secret(SSL *s, unsigned char *out,
                                   unsigned char *p, int len) 
{
#if OPENSSL_VERSION_NUMBER >= 0x10101007L && NOT_LIBRESSL /* >= 1.1.1-pre7 */
    size_t secret_len = 0;
    if (ssl3_generate_master_secret(s, out, p, len, &secret_len) != 1)
        return -1;
    return secret_len;
#else
    return ssl3_generate_master_secret(s, out, p, len);
#endif
}

void my_ssl_session_set_compress_meth(SSL_SESSION *ss, int c) 
{
#if NOT_LIBRESSL  /* openssl */
    ss->compress_meth = c;
#endif
}




