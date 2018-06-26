/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * ssl_stub.h
 * 14 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 */
#ifndef SSL_STUB_H
#define SSL_STUB_H
#include <stdint.h>
#define IS_LIBRESSL (!defined(LIBRESSL_VERSION_NUMBER))
#define NOT_LIBRESSL (!defined(LIBRESSL_VERSION_NUMBER))

void init_library(void);
extern int check_rsa (const SSL_CIPHER *cipher);
extern const SSL_METHOD *SSL_method(uint8_t major, uint8_t minor);

#if OPENSSL_VERSION_NUMBER >= 0x10101007L && NOT_LIBRESSL /* >= 1.1.1-pre7 */
#include <ssl_locl.h>
/* nothing yet */
/* from t1_enc.c */
extern int tls1_generate_master_secret(SSL *s, unsigned char *out,
                                       unsigned char *p, size_t len,
                                       size_t *secret_size);
/* from s3_enc.c */
extern int ssl3_generate_master_secret(SSL *s, unsigned char *out,
                                       unsigned char *p, size_t len,
                                       size_t *secret_size);
#elif OPENSSL_VERSION_NUMBER >= 0x1010001fL && NOT_LIBRESSL  /* >= 1.1.0.a */
#include <ssl_locl.h>
#else
extern RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
#define EVP_PKEY_up_ref(pkey) CRYPTO_add(&(pkey)->references, 1, CRYPTO_LOCK_EVP_PKEY)

#define BIO_get_data(b)             ((b)->ptr)
#define BIO_set_data(b, p)          ((b)->ptr = (p))
#define BIO_get_init(b)             ((b)->init)
#define BIO_set_init(b, i)          ((b)->init = (i))
#define BIO_get_shutdown(b)         ((b)->shutdown)
#define BIO_set_shutdown(b, v)      ((b)->shutdown = (v))
#define BIO_meth_set_read(b, f)     ((b)->bread = f)
#define BIO_meth_set_puts(b, f)     ((b)->bputs = f)
#define BIO_meth_set_ctrl(b, f)     ((b)->ctrl = f)
static inline BIO_METHOD *BIO_meth_new(int type, const char *name)
{
    BIO_METHOD *b = (BIO_METHOD *)malloc(sizeof(*b));
    if (b != NULL) {
        memset(b, 0, sizeof(*b));
        b->type = type;
        b->name = name;
    }
    return b;
}
/* from t1_enc.c */
extern int tls1_generate_master_secret(SSL *s, unsigned char *out,
                                       unsigned char *p, int len);
/* from s3_enc.c */
extern int ssl3_generate_master_secret(SSL *s, unsigned char *out,
                                       unsigned char *p, int len);        
#endif

/* from ssl_session.c */
extern int ssl_get_new_session(SSL *s, int session);
/* from t1_enc.c */
extern int tls1_setup_key_block(SSL *s);
extern int tls1_change_cipher_state(SSL *s, int which);
/* from s3_enc.c */
extern int ssl3_setup_key_block(SSL *s);
extern int ssl3_change_cipher_state(SSL *s, int which);

extern int my_ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
extern void my_ssl_clear_state(SSL *s);
extern int my_tls1_generate_master_secret(SSL *s, unsigned char *out,
                                          unsigned char *p, int len);
extern int my_ssl3_generate_master_secret(SSL *s, unsigned char *out,
                                          unsigned char *p, int len);        
extern void my_ssl_session_set_compress_meth(SSL_SESSION *ss, int c);
#endif

