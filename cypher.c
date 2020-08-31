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

#include "aes.h"
#include "cypher.h"

int encrypt(char * output_p, size_t * output_len,
            int cypher,
            char const * key_p, size_t key_len,
            char const * iv_p, size_t iv_len,
            char const * input_p, size_t input_len)
{
	switch (cypher)
	{
	case NATIVECRYPTO_CYPHER_AES_ECB:
	case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
	case NATIVECRYPTO_CYPHER_AES_CTR:
		return AES_encrypt(output_p, output_len, cypher, key_p, key_len, iv_p, iv_len,
		                   input_p, input_len);
	default:
		return NATIVECRYPTO_ERR_INVALID_CYPHER;
	}
}

int decrypt(char * output_p, size_t * output_len,
            int cypher,
            char const * key_p, size_t key_len,
            char const * iv_p, size_t iv_len,
            char const * input_p, size_t input_len)
{
	switch (cypher)
	{
	case NATIVECRYPTO_CYPHER_AES_ECB:
	case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
	case NATIVECRYPTO_CYPHER_AES_CTR:
		return AES_decrypt(output_p, output_len, cypher, key_p, key_len, iv_p, iv_len,
		                   input_p, input_len);
	default:
		return NATIVECRYPTO_ERR_INVALID_CYPHER;
	}
}
