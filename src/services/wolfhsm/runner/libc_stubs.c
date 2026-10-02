/* libc_stubs.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Minimal freestanding implementations of the C string/memory functions
 * that wolfSSL/wolfHSM call by name.  We build with -nostdlib -fno-builtin
 * so the toolchain provides none of these.  memcpy/memset already live in
 * runtime.c — do NOT redefine them here.
 *
 * The ctype table _ctype_ + the __ctype_ptr__ pointer satisfy the
 * <ctype.h> macros that newlib's ctype.h expands to. wolfSSL's XTOUPPER /
 * XTOLOWER / XISALPHA / XISDIGIT call sites all bottom out here.
 */

#include <stddef.h>

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++; pb++;
    }
    return 0;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { ++a; ++b; --n; }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* -------------------------------------------------------------------------
 * ctype: newlib-compatible _ctype_ table.
 *
 * The 257-byte form indexes by (c + 1) so that EOF (-1) reads byte 0.
 * Bit values match newlib's ctype_.h.
 * ---------------------------------------------------------------------- */

#define _U 0x01
#define _L 0x02
#define _N 0x04
#define _S 0x08
#define _P 0x10
#define _C 0x20
#define _X 0x40
#define _B 0x80

const char _ctype_[257] = {
    0,                                                       /* EOF       */
    /* 0x00..0x07 */ _C, _C, _C, _C, _C, _C, _C, _C,
    /* 0x08..0x0F */ _C, _C|_S, _C|_S, _C|_S, _C|_S, _C|_S, _C, _C,
    /* 0x10..0x17 */ _C, _C, _C, _C, _C, _C, _C, _C,
    /* 0x18..0x1F */ _C, _C, _C, _C, _C, _C, _C, _C,
    /* 0x20..0x27 */ _S|_B, _P, _P, _P, _P, _P, _P, _P,
    /* 0x28..0x2F */ _P, _P, _P, _P, _P, _P, _P, _P,
    /* 0x30..0x37 */ _N|_X, _N|_X, _N|_X, _N|_X, _N|_X, _N|_X, _N|_X, _N|_X,
    /* 0x38..0x3F */ _N|_X, _N|_X, _P, _P, _P, _P, _P, _P,
    /* 0x40..0x47 */ _P, _U|_X, _U|_X, _U|_X, _U|_X, _U|_X, _U|_X, _U,
    /* 0x48..0x4F */ _U, _U, _U, _U, _U, _U, _U, _U,
    /* 0x50..0x57 */ _U, _U, _U, _U, _U, _U, _U, _U,
    /* 0x58..0x5F */ _U, _U, _U, _P, _P, _P, _P, _P,
    /* 0x60..0x67 */ _P, _L|_X, _L|_X, _L|_X, _L|_X, _L|_X, _L|_X, _L,
    /* 0x68..0x6F */ _L, _L, _L, _L, _L, _L, _L, _L,
    /* 0x70..0x77 */ _L, _L, _L, _L, _L, _L, _L, _L,
    /* 0x78..0x7F */ _L, _L, _L, _P, _P, _P, _P, _C,
    /* 0x80..0xFF */ 0
};

/* Never reassigned, so it links read-only like the table it points at. */
const char *__ctype_ptr__ __attribute__((section(".rodata.__ctype_ptr__"))) =
    _ctype_;

/* Out-of-line ctype function forms — wolfSSL may take the address of
 * tolower/toupper, in which case the macro form does not apply. */

int tolower(int c)
{
    if ((unsigned)c < 256u && (_ctype_[c + 1] & _U)) return c + ('a' - 'A');
    return c;
}

int toupper(int c)
{
    if ((unsigned)c < 256u && (_ctype_[c + 1] & _L)) return c - ('a' - 'A');
    return c;
}

int isspace(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & _S); }
int isdigit(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & _N); }
int isalpha(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & (_U | _L)); }
int isalnum(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & (_U | _L | _N)); }
int isxdigit(int c) { return (unsigned)c < 256u && (_ctype_[c + 1] & _X); }
int isupper(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & _U); }
int islower(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & _L); }
int iscntrl(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & _C); }
int isprint(int c)  { return (unsigned)c < 256u && (_ctype_[c + 1] & (_P | _U | _L | _N | _B)); }

int strcasecmp(const char *a, const char *b)
{
    int ca, cb;
    do {
        ca = tolower((unsigned char)*a++);
        cb = tolower((unsigned char)*b++);
    } while (ca != 0 && ca == cb);
    return ca - cb;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    char *d = dst;
    while (n && (*d = *src) != '\0') { ++d; ++src; --n; }
    while (n--) *d++ = '\0';
    return dst;
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    int ca = 0, cb = 0;
    while (n--) {
        ca = tolower((unsigned char)*a++);
        cb = tolower((unsigned char)*b++);
        if (ca == 0 || ca != cb) break;
    }
    return ca - cb;
}
