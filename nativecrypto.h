/* Copyright 2020 Ricardo Iván Vieitez Parra
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef NATIVECRYPTO_H_
#define NATIVECRYPTO_H_
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef NATIVECRYPTO_NAME
#define NATIVECRYPTO_NAME(NAME) NATIVECRYPTO_ ## NAME
#endif

#ifndef NATIVECRYPTO_CYPHER_AES_ECB
#define NATIVECRYPTO_CYPHER_AES_ECB 1
#endif

#ifndef NATIVECRYPTO_CYPHER_AES_CTR
#define NATIVECRYPTO_CYPHER_AES_CTR 2
#endif

#ifndef NATIVECRYPTO_CYPHER_AES_CBC_PKCS7
#define NATIVECRYPTO_CYPHER_AES_CBC_PKCS7 3
#endif

#include <stddef.h>

#ifndef NATIVECRYPTO_OK
#define NATIVECRYPTO_OK 0
#endif

#ifndef NATIVECRYPTO_ERR_UNKNOWN
#define NATIVECRYPTO_ERR_UNKNOWN -1
#endif

#ifndef NATIVECRYPTO_ERR_NOMEM
#define NATIVECRYPTO_ERR_NOMEM -2
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_ARGUMENTS
#define NATIVECRYPTO_ERR_INVALID_ARGUMENTS -3
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_CYPHER
#define NATIVECRYPTO_ERR_INVALID_CYPHER -4
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_MESSAGE
#define NATIVECRYPTO_ERR_INVALID_MESSAGE -10
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_PADDING
#define NATIVECRYPTO_ERR_INVALID_PADDING -11
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_IV
#define NATIVECRYPTO_ERR_INVALID_IV -12
#endif

#ifndef NATIVECRYPTO_ERR_INVALID_KEY
#define NATIVECRYPTO_ERR_INVALID_KEY -13
#endif

int NATIVECRYPTO_NAME(encrypt)(char * output_p, size_t * output_len,
                               int cypher,
                               char const * key_p, size_t key_len,
                               char const * iv_p, size_t iv_len,
                               char const * plaintext_p, size_t plaintext_len);
int NATIVECRYPTO_NAME(decrypt)(char * output_p, size_t * output_len,
                               int cypher,
                               char const * key_p, size_t key_len,
                               char const * iv_p, size_t iv_len,
                               char const * cyphertext_p, size_t cyphertext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NATIVECRYPTO_H_ */
