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

#ifndef CYPHER_H_
#define CYPHER_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h>
#include "nativecrypto.h"

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

#endif /* CYPHER_H_ */
