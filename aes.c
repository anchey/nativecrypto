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

#include <stddef.h>
#include <stdlib.h>

#include "nativecrypto.h"

#include "aes.h"
#include "aes_aesni.h"
#include "util.h"

int AES_encrypt(char * output_p, size_t * output_len,
                int cypher,
                char const * key_p, size_t key_len,
                char const * iv_p, size_t iv_len,
                char const * input_p, size_t input_len)
{

	struct cypher_state (* encryption_function)(char * pOutput, char const * pInput,
	        size_t input_len, void const * const pKey, void const * const pIV);
	struct cypher_state state;

	if (key_p == NULL)
	{
		return NATIVECRYPTO_ERR_INVALID_KEY;
	}

	if ((output_p == NULL && output_len == NULL) || input_p == NULL)
	{
		return NATIVECRYPTO_ERR_INVALID_ARGUMENTS;
	}

	if (iv_len != (NATIVECRYPTO_CYPHER_AES_ECB == cypher ? 0 : 16))
	{
		return NATIVECRYPTO_ERR_INVALID_IV;
	}

	switch (key_len)
	{
	case 16:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			encryption_function = &AES_EXPORT(128, ENC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			encryption_function = &AES_EXPORT(128, ENC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			encryption_function = &AES_EXPORT(128, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	case 24:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			encryption_function = &AES_EXPORT(192, ENC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			encryption_function = &AES_EXPORT(192, ENC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			encryption_function = &AES_EXPORT(192, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	case 32:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			encryption_function = &AES_EXPORT(256, ENC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			encryption_function = &AES_EXPORT(256, ENC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			encryption_function = &AES_EXPORT(256, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	default:
		return NATIVECRYPTO_ERR_INVALID_KEY;
	}

	state = encryption_function(output_p, input_p, input_len, key_p, iv_p);

	if (state.status == NATIVECRYPTO_OK && output_len != NULL)
	{
		*output_len = state.output_len;
	}

	return state.status;
}

int AES_decrypt(char * output_p, size_t * output_len,
                int cypher,
                char const * key_p, size_t key_len,
                char const * iv_p, size_t iv_len,
                char const * input_p, size_t input_len)
{

	struct cypher_state (* decryption_function)(char * pOutput, char const * pInput,
	        size_t input_len, void const * const pKey, void const * const pIV);
	struct cypher_state state;

	if (key_p == NULL)
	{
		return NATIVECRYPTO_ERR_INVALID_KEY;
	}

	if ((output_p == NULL && output_len == NULL) || input_p == NULL)
	{
		return NATIVECRYPTO_ERR_INVALID_ARGUMENTS;
	}

	if (iv_len != (NATIVECRYPTO_CYPHER_AES_ECB == cypher ? 0 : 16))
	{
		return NATIVECRYPTO_ERR_INVALID_IV;
	}

	switch (key_len)
	{
	case 16:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			decryption_function = &AES_EXPORT(128, DEC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			decryption_function = &AES_EXPORT(128, DEC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			decryption_function = &AES_EXPORT(128, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	case 24:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			decryption_function = &AES_EXPORT(192, DEC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			decryption_function = &AES_EXPORT(192, DEC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			decryption_function = &AES_EXPORT(192, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	case 32:
		switch (cypher)
		{
		case NATIVECRYPTO_CYPHER_AES_ECB:
			decryption_function = &AES_EXPORT(256, DEC, ECB);
			break;
		case NATIVECRYPTO_CYPHER_AES_CBC_PKCS7:
			decryption_function = &AES_EXPORT(256, DEC, CBC_PKCS7);
			break;
		case NATIVECRYPTO_CYPHER_AES_CTR:
			decryption_function = &AES_EXPORT(256, ALL, CTR);
			break;
		default:
			return NATIVECRYPTO_ERR_INVALID_CYPHER;
		}
		break;
	default:
		return NATIVECRYPTO_ERR_INVALID_KEY;
	}

	state = decryption_function(output_p, input_p, input_len, key_p, iv_p);

	if (state.status == NATIVECRYPTO_OK && output_len != NULL)
	{
		*output_len = state.output_len;
	}

	return state.status;
}
