/* set ts=4 sw=4 enc=utf-8: -*- Mode: c; tab-width: 4; c-basic-offset:4; coding: utf-8 -*- */
/*
 * util.c
 * 18 June 2018, Chul-Woong Yang (cwyang@gmail.com)
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static const char *hex = "0123456789abcdef";

static const char printable[257] = {
	"................"	/* 0x */
	"................"	/* 1x */
	" !\"#$%&'()*+,-./"	/* 2x */
	"0123456789:;<=>?"	/* 3x */
	"@ABCDEFGHIJKLMNO"	/* 4x */
	"PQRSTUVWXYZ[\\]^_"	/* 5x */
	"`abcdefghijklmno"	/* 6x */
	"pqrstuvwxyz{|}~."	/* 7x */
	"................"	/* 8x */
	"................"	/* 9x */
	"................"	/* ax */
	"................"	/* bx */
	"................"	/* cx */
	"................"	/* dx */
	"................"	/* ex */
	"................"	/* fx */
};

// return buf should be freed by caller
char *hex2buf(const void *vp, int len)
{
    const unsigned char *cp = (const unsigned char *)vp;
    char *buf;
    size_t buflen = ((len+15)/16) * 73;
    char *bp, *sp, *ap;
    int index= 0;

    // 0123456789012345678901234567890123456789012345678901234567890123456
    // 0032: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff   0123456789ABCDEFn
    // 73 byte per 16 byte
    assert(len > 0);
    
    buf = malloc(buflen);

    if (!buf) 
        return NULL;
    
    memset(buf, ' ', buflen);
    sp = bp = buf;
    *bp++ = hex[((index/256) >> 4) & 0xf];
    *bp++ = hex[((index/256)) & 0xf];
    *bp++ = hex[((index%256) >> 4) & 0xf];
    *bp++ = hex[((index%256)) & 0xf];
    *bp++ = ':';
    bp++;

    ap = bp + 50;
    while (--len >= 0) {
        unsigned char ch = *cp++;
        *bp++ = hex[(ch >> 4) & 0xf];
        *bp++ = hex[ch & 0xf];
        *bp++ = ' ';
        *ap++ = printable[ch];
        if (ap - sp >= 72) {
            *ap = '\n';
            if (len == 0)
                break;
            index += 16;
            sp = bp = ap + 1;
            *bp++ = hex[((index/256) >> 4) & 0xf];
            *bp++ = hex[((index/256)) & 0xf];
            *bp++ = hex[((index%256) >> 4) & 0xf];
            *bp++ = hex[((index%256)) & 0xf];
            *bp++ = ':';
            bp++;
            ap = bp + 50;
        }
    }
    *ap = 0;

    return buf;
}
