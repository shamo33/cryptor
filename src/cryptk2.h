/**
 *  CryptK2 Library - KCipher-2(R) Implementation for C/C++
 *  Copyright (c) 2015-2022 Mystia.org Project. All rights reserved.
 */

#ifndef LIBCRYPTK2_CRYPTK2_H_
#define LIBCRYPTK2_CRYPTK2_H_

// for size_t
#include <stddef.h>
// for uint8_t
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


// we always use dll in this version
//#ifndef CRYPTK2_DLL
//#  define CRYPTK2_DLL
//#endif


#ifdef _WIN32
#  ifdef CRYPTK2_DLL
#    ifdef CRYPTK2_INTERNAL
#      define CRYPTK2_API __stdcall
#    else
#      define CRYPTK2_API __declspec(dllimport) __stdcall
#    endif
#  endif
#elif __GNUC__ >= 4
#  define CRYPTK2_API __attribute__ ((visibility ("default")))
#  define CRYPTK2_LOCAL __attribute__ ((visibility ("hidden")))
#endif
#ifndef CRYPTK2_API
#  define CRYPTK2_API
#endif
#ifndef CRYPTK2_LOCAL
#  define CRYPTK2_LOCAL
#endif


// ensure the backward compatibility
#define KCIPHER2 CRYPTK2
#define new_kcipher2 new_cryptk2
#define kcipher2_setup cryptk2_setup
#define kcipher2_crypt cryptk2_crypt
#define kcipher2_decrypt cryptk2_crypt
#define kcipher2_encrypt cryptk2_crypt
#define kcipher2_stream cryptk2_stream
#define delete_kcipher2 delete_cryptk2
#define cryptk2_decrypt cryptk2_crypt
#define cryptk2_encrypt cryptk2_crypt


typedef struct _cryptk2 *CRYPTK2;

CRYPTK2 CRYPTK2_API new_cryptk2(void);
void CRYPTK2_API cryptk2_setup(CRYPTK2 state, const uint8_t *key, const uint8_t *iv);
void CRYPTK2_API cryptk2_crypt(CRYPTK2 state, size_t len, const uint8_t *in, uint8_t *out);
void CRYPTK2_API cryptk2_stream(CRYPTK2 state, size_t len, uint8_t *out);
void CRYPTK2_API delete_cryptk2(CRYPTK2 state);

#ifdef __cplusplus
}
#endif

#endif
