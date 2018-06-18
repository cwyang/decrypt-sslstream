/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * ssl_stub.h
 * 14 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 */
#ifndef SSL_STUB_H
#define SSL_STUB_H
#include <stdint.h>
void init_library(void);
extern int check_rsa (const SSL_CIPHER *cipher);
extern const SSL_METHOD *SSL_method(uint8_t major, uint8_t minor);
#if OPENSSL_VERSION_NUMBER >= 0x101000afL /* >= 1.1.0.a */
/* nothing yet */
#else
extern RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
#endif
#endif

