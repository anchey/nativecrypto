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

#ifndef AES_AESNI_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef __AES__
#error "AES support is required"
#endif

#ifdef __SSE2__
#include <emmintrin.h> /* SSE2 */
#endif /* __SSE2__ */

#ifdef __SSSE3__
#include <tmmintrin.h> /* SSE3 */
#endif /* __SSSE3__ */

#ifdef __AES__
#include <immintrin.h> /* AES-NI */
#endif /* __AES__ */

#ifdef __PCLMUL__
#include <wmmintrin.h> /* pclmulqdq */
#endif /* __PCLMUL__ */

#include "util.h"
#include "aes_internal.h"
#include "cypher_internal_sse.h"
#include "mm_bswap_epi32.h"
#include "mm_bswap_si128.h"
#include "memset_s.h"

#include <assert.h>

#define FOR_N(I, M) do { M(I); } while(0)
#define FOR_0(M) do { } while(0)
#define FOR_1(M) FOR_N(0, M)
#define FOR_2(M) do { FOR_1(M); FOR_N(1, M); } while(0)
#define FOR_3(M) do { FOR_2(M); FOR_N(2, M); } while(0)
#define FOR_4(M) do { FOR_3(M); FOR_N(3, M); } while(0)
#define FOR_5(M) do { FOR_4(M); FOR_N(4, M); } while(0)
#define FOR_6(M) do { FOR_5(M); FOR_N(5, M); } while(0)
#define FOR_7(M) do { FOR_6(M); FOR_N(6, M); } while(0)
#define FOR_8(M) do { FOR_7(M); FOR_N(7, M); } while(0)
#define FOR_9(M) do { FOR_8(M); FOR_N(8, M); } while(0)
#define FOR_10(M) do { FOR_9(M); FOR_N(9, M); } while(0)
#define FOR_11(M) do { FOR_10(M); FOR_N(10, M); } while(0)
#define FOR_12(M) do { FOR_11(M); FOR_N(11, M); } while(0)
#define FOR(N, M) FOR_ ## N(M)

/* BEGIN AES MACROS */
#ifdef __SSSE3__
#define AESXXX_SHUFFLE_MASK _mm_setr_epi32((int) 0xFFFFFFFFUL, 0x03020100UL, 0x07060504UL, 0x0B0A0908UL)
#define AESXXX_KEY_SHUFFLE_HELPER(N) do { \
	__m128i const AES_KEY_SHUFFLE_HELPER_mask = AES_INTERNAL(ALL, ALL, SHUFFLE_MASK); \
	__m128i const AES_KEY_SHUFFLE_HELPER_temp = _mm_shuffle_epi8(KEY, AES_KEY_SHUFFLE_HELPER_mask); \
	KEY = _mm_xor_si128(KEY, AES_KEY_SHUFFLE_HELPER_temp); \
} while(0)
#else
#define AESXXX_KEY_SHUFFLE_HELPER(N) do { \
	__m128i const AES_KEY_SHUFFLE_HELPER_temp = _mm_slli_si128(KEY, 4); \
	KEY = _mm_xor_si128(KEY, AES_KEY_SHUFFLE_HELPER_temp); \
} while(0);
#endif

#define AESXXX_DO_INDIRECT(VARIANT, OP, KEY_SCHEDULE, IN, OUT) do { \
	__m128i AES_CRYPT_INDIRECT_temp; \
	AES_CRYPT_INDIRECT_temp = _mm_loadu_si128((__m128i const *)(IN)); \
	AES_INTERNAL(ALL, OP, DO)(VARIANT, KEY_SCHEDULE, AES_CRYPT_INDIRECT_temp, AES_CRYPT_INDIRECT_temp); \
	_mm_storeu_si128((__m128i *)(OUT), AES_CRYPT_INDIRECT_temp); \
} while(0)

#define AESENC_DO(VARIANT, KEY_SCHEDULE, PLAINTEXT, CYPHERTEXT) do { \
	__m128i AESENC_DO_temp; \
	unsigned char AESENC_DO_i; \
	\
	AESENC_DO_temp = _mm_xor_si128(PLAINTEXT, KEY_SCHEDULE[0]); \
	for (AESENC_DO_i = 1; AESENC_DO_i != AES_ROUNDS(VARIANT) - 1; AESENC_DO_i++) { \
		AESENC_DO_temp = _mm_aesenc_si128(AESENC_DO_temp, KEY_SCHEDULE[AESENC_DO_i + 0]); \
	} \
	CYPHERTEXT = _mm_aesenclast_si128(AESENC_DO_temp, KEY_SCHEDULE[AESENC_DO_i]); \
} while(0)

#define AESDEC_DO(VARIANT, KEY_SCHEDULE, CYPHERTEXT, PLAINTEXT) do { \
	__m128i AESDEC_DO_temp; \
	unsigned char AESDEC_DO_i = AES_ROUNDS(VARIANT) - 1; \
	\
	AESDEC_DO_temp = _mm_xor_si128(CYPHERTEXT, KEY_SCHEDULE[AESDEC_DO_i--]); \
	for (; 0 != AESDEC_DO_i; AESDEC_DO_i--) { \
		AESDEC_DO_temp = _mm_aesdec_si128(AESDEC_DO_temp, KEY_SCHEDULE[AESDEC_DO_i + 0]); \
	} \
	PLAINTEXT = _mm_aesdeclast_si128(AESDEC_DO_temp, KEY_SCHEDULE[AESDEC_DO_i]); \
} while(0)

#define AES128ENC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(128, ALL, expand_key)(&KEY_SCHEDULE[INDEX + 1], &KEY_SCHEDULE[INDEX], _mm_aeskeygenassist_si128(KEY_SCHEDULE[INDEX], AES_INTERNAL(128, ALL, RCON)(INDEX)), INDEX); \
} while(0)

#define AES128DEC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(128, ENC, EXPAND_KEY)(KEY_SCHEDULE, INDEX); \
	if (0 != INDEX) KEY_SCHEDULE[INDEX] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX]); \
} while(0)

#define AES192ENC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(192, ALL, expand_key)(&KEY_SCHEDULE[INDEX + 1 + ((INDEX + 1) % 3)], &KEY_SCHEDULE[INDEX], _mm_aeskeygenassist_si128(KEY_SCHEDULE[INDEX + 1], AES_INTERNAL(192, ALL, RCON)(INDEX)), INDEX); \
} while(0)

#define AES192DEC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(192, ENC, EXPAND_KEY)(KEY_SCHEDULE, INDEX); \
	if (0 != (INDEX % 3)) { \
		if (2 != INDEX) KEY_SCHEDULE[INDEX - 2] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX - 2]); \
		KEY_SCHEDULE[INDEX - 1] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX - 1]); \
		KEY_SCHEDULE[INDEX] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX]); \
	} \
} while(0)

#define AES256ENC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(256, ALL, expand_key)(&KEY_SCHEDULE[INDEX + 2], &KEY_SCHEDULE[INDEX], _mm_aeskeygenassist_si128(KEY_SCHEDULE[INDEX + 1], AES_INTERNAL(256, ALL, RCON)(INDEX)), INDEX); \
} while(0)

#define AES256DEC_EXPAND_KEY(KEY_SCHEDULE, INDEX) do { \
	AES_INTERNAL(256, ENC, EXPAND_KEY)(KEY_SCHEDULE, INDEX); \
	if (0 != INDEX) KEY_SCHEDULE[INDEX] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX]); \
	KEY_SCHEDULE[INDEX + 1] = _mm_aesimc_si128(KEY_SCHEDULE[INDEX + 1]); \
} while(0)

/* TODO: Define AES_API, etc. instead of AES_INTERNAL */
#define AESXXX_ECB(VARIANT, OP, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) do { \
	size_t AESXXX_ECB_input_len = (size_t)(INSZ); \
	char const * AESXXX_ECB_input = (char const *)(IN); \
	char * AESXXX_ECB_output = (char *)(OUT); \
	\
	/* Firstly, encrypt/decrypt four blocks at once */ \
	while(AESXXX_ECB_input_len >= 4 * AES_BLOCK_SIZE(VARIANT)) { \
		AES_INTERNAL(ALL, ALL, DO_INDIRECT)(VARIANT, OP, KEY_SCHEDULE, &AESXXX_ECB_input[0 * AES_BLOCK_SIZE(VARIANT)], &AESXXX_ECB_output[0 * AES_BLOCK_SIZE(VARIANT)]); \
		AES_INTERNAL(ALL, ALL, DO_INDIRECT)(VARIANT, OP, KEY_SCHEDULE, &AESXXX_ECB_input[1 * AES_BLOCK_SIZE(VARIANT)], &AESXXX_ECB_output[1 * AES_BLOCK_SIZE(VARIANT)]); \
		AES_INTERNAL(ALL, ALL, DO_INDIRECT)(VARIANT, OP, KEY_SCHEDULE, &AESXXX_ECB_input[2 * AES_BLOCK_SIZE(VARIANT)], &AESXXX_ECB_output[2 * AES_BLOCK_SIZE(VARIANT)]); \
		AES_INTERNAL(ALL, ALL, DO_INDIRECT)(VARIANT, OP, KEY_SCHEDULE, &AESXXX_ECB_input[3 * AES_BLOCK_SIZE(VARIANT)], &AESXXX_ECB_output[3 * AES_BLOCK_SIZE(VARIANT)]); \
		AESXXX_ECB_input_len -= 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_ECB_input += 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_ECB_output += 4 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, encrypt/decrypt blocks one by one */ \
	while(AESXXX_ECB_input_len >= AES_BLOCK_SIZE(VARIANT)) { \
		AES_INTERNAL(ALL, ALL, DO_INDIRECT)(VARIANT, OP, KEY_SCHEDULE, &AESXXX_ECB_input[0], &AESXXX_ECB_output[0]); \
		AESXXX_ECB_input_len -= 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_ECB_input += 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_ECB_output += 1 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	STATE.status = NATIVECRYPTO_OK; \
	STATE.output_len = INSZ; \
} while(0)

#define AESENC_ECB(VARIANT, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) AESXXX_ECB(VARIANT, ENC, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV)
#define AESDEC_ECB(VARIANT, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) AESXXX_ECB(VARIANT, DEC, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV)

#define AES_ECB_FN_BODY(VARIANT, OP) static struct cypher_state AES_EXPORT(VARIANT, OP, ECB)(char * const pOutput, char const * const pInput, size_t const input_len, void const * const pKey, void const * const pIV) { \
	__m128i key_schedule[AES_ROUNDS(VARIANT)]; \
	static struct cypher_state state = { NATIVECRYPTO_ERR_UNKNOWN, 0 }; \
	\
	(void) pIV;\
	if (0 != (input_len % AES_BLOCK_SIZE(VARIANT))) { \
		state.status = NATIVECRYPTO_ERR_INVALID_MESSAGE; \
		return state; \
	} \
	\
	if (NULL == pOutput) { \
		state.output_len = input_len; \
		state.status = NATIVECRYPTO_OK; \
		return state; \
	} \
	\
	AES_INTERNAL(VARIANT, OP, keygen)(key_schedule, (__m128i const *) pKey); \
	\
	AES_INTERNAL(ALL, OP, ECB)(VARIANT, state, pOutput, pInput, input_len, key_schedule, pIV); \
	\
	(void) memset_s(key_schedule, sizeof(key_schedule), 0, sizeof(key_schedule)); \
	\
	return state; \
}

#define AESENC_CBC_PKCS7(VARIANT, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) do { \
	__m128i AESENC_CBC_PKCS7_previous_block; \
	__m128i AESENC_CBC_PKCS7_current_block; \
	__m128i AESENC_CBC_PKCS7_tbd_block; \
	__m128i AESENC_CBC_PKCS7_result_block; \
	\
	size_t AESENC_CBC_PKCS7_input_len = (size_t)(INSZ); \
	char const * AESENC_CBC_PKCS7_input = (char const *)(IN); \
	char * AESENC_CBC_PKCS7_output = (char *)(OUT); \
	\
	if (NULL == AESENC_CBC_PKCS7_output) { \
		state.status = NATIVECRYPTO_OK; \
		state.output_len = (size_t)(((INSZ / AES_BLOCK_SIZE(VARIANT)) + 1) * AES_BLOCK_SIZE(VARIANT)); \
		break; \
	} \
	\
	AESENC_CBC_PKCS7_previous_block = _mm_loadu_si128((__m128i const *) (IV)); \
	\
	/* First blocks */ \
	while(AESENC_CBC_PKCS7_input_len >= 1 * AES_BLOCK_SIZE(VARIANT)) { \
		AESENC_CBC_PKCS7_current_block = _mm_loadu_si128((__m128i const *) &AESENC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)]); \
		AESENC_CBC_PKCS7_tbd_block = _mm_xor_si128(AESENC_CBC_PKCS7_current_block, AESENC_CBC_PKCS7_previous_block); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESENC_CBC_PKCS7_tbd_block, AESENC_CBC_PKCS7_result_block); \
		_mm_storeu_si128((__m128i *) &AESENC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], AESENC_CBC_PKCS7_result_block); \
		AESENC_CBC_PKCS7_previous_block = AESENC_CBC_PKCS7_result_block; \
		AESENC_CBC_PKCS7_input_len -= 1 * AES_BLOCK_SIZE(VARIANT); \
		AESENC_CBC_PKCS7_input += 1 * AES_BLOCK_SIZE(VARIANT); \
		AESENC_CBC_PKCS7_output += 1 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Last block, including PKCS#7 padding */ \
	{ \
		char AESENC_CBC_PKCS7_last_block[AES_BLOCK_SIZE(VARIANT)]; \
		if (AESENC_CBC_PKCS7_input_len > 0) { \
			memcpy(&AESENC_CBC_PKCS7_last_block[0], &AESENC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)], AESENC_CBC_PKCS7_input_len); \
		} \
		memset_s(&AESENC_CBC_PKCS7_last_block[AESENC_CBC_PKCS7_input_len], AES_BLOCK_SIZE(VARIANT) - AESENC_CBC_PKCS7_input_len, AES_BLOCK_SIZE(VARIANT) - (int) AESENC_CBC_PKCS7_input_len, AES_BLOCK_SIZE(VARIANT) - AESENC_CBC_PKCS7_input_len); \
		AESENC_CBC_PKCS7_current_block = _mm_loadu_si128((__m128i const *) &AESENC_CBC_PKCS7_last_block[0 * AES_BLOCK_SIZE(VARIANT)]); \
		AESENC_CBC_PKCS7_tbd_block = _mm_xor_si128(AESENC_CBC_PKCS7_current_block, AESENC_CBC_PKCS7_previous_block); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESENC_CBC_PKCS7_tbd_block, AESENC_CBC_PKCS7_result_block); \
		_mm_storeu_si128((__m128i *) &AESENC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], AESENC_CBC_PKCS7_result_block); \
		\
		(void)memset_s(AESENC_CBC_PKCS7_last_block, sizeof(AESENC_CBC_PKCS7_last_block), 0, sizeof(AESENC_CBC_PKCS7_last_block)); \
	} \
	\
	/* Cleaning up */ \
	memset_s(&AESENC_CBC_PKCS7_previous_block, sizeof(AESENC_CBC_PKCS7_previous_block), 0, sizeof(AESENC_CBC_PKCS7_previous_block)); \
	memset_s(&AESENC_CBC_PKCS7_current_block, sizeof(AESENC_CBC_PKCS7_current_block), 0, sizeof(AESENC_CBC_PKCS7_current_block)); \
	memset_s(&AESENC_CBC_PKCS7_tbd_block, sizeof(AESENC_CBC_PKCS7_tbd_block), 0, sizeof(AESENC_CBC_PKCS7_tbd_block)); \
	memset_s(&AESENC_CBC_PKCS7_result_block, sizeof(AESENC_CBC_PKCS7_result_block), 0, sizeof(AESENC_CBC_PKCS7_result_block)); \
	STATE.output_len = (size_t)(((INSZ / AES_BLOCK_SIZE(VARIANT)) + 1) * AES_BLOCK_SIZE(VARIANT)); \
	STATE.status = NATIVECRYPTO_OK; \
	\
} while(0)

/* NOTE: Padding verification leaks information (padding oracle attack). Not much can be done, other than using a verification scheme beforehand
 */
#define AESDEC_CBC_PKCS7(VARIANT, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) do { \
	__m128i AESDEC_CBC_PKCS7_tempctx[5]; \
	__m128i AESDEC_CBC_PKCS7_tempout[4]; \
	\
	size_t AESDEC_CBC_PKCS7_input_len = (size_t)(INSZ); \
	char const * AESDEC_CBC_PKCS7_input = (char const *)(IN); \
	char * AESDEC_CBC_PKCS7_output = (char *)(OUT); \
	char const * AESDEC_CBC_PKCS7_IV = (char const *)(IV); \
	\
	if (0 != (INSZ % AES_BLOCK_SIZE(VARIANT))) { \
		STATE.output_len = 0; \
		STATE.status = NATIVECRYPTO_ERR_INVALID_MESSAGE; \
		break; \
	} \
	\
	if (NULL == AESDEC_CBC_PKCS7_output && AESDEC_CBC_PKCS7_input_len > AES_BLOCK_SIZE(VARIANT)) { \
		AESDEC_CBC_PKCS7_input_len = AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_input += (INSZ) - AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_IV = &AESDEC_CBC_PKCS7_input[-AES_BLOCK_SIZE(VARIANT)]; \
	} \
	\
	AESDEC_CBC_PKCS7_tempctx[0] = _mm_loadu_si128((__m128i const *) (AESDEC_CBC_PKCS7_IV)); \
	\
	/* Firstly, decrypt four blocks at once */ \
	while(AESDEC_CBC_PKCS7_input_len >= (4 + 1) * AES_BLOCK_SIZE(VARIANT)) { \
		AESDEC_CBC_PKCS7_tempctx[1] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)])); \
		AESDEC_CBC_PKCS7_tempctx[2] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[1 * AES_BLOCK_SIZE(VARIANT)])); \
		AESDEC_CBC_PKCS7_tempctx[3] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[2 * AES_BLOCK_SIZE(VARIANT)])); \
		AESDEC_CBC_PKCS7_tempctx[4] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[3 * AES_BLOCK_SIZE(VARIANT)])); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[1], AESDEC_CBC_PKCS7_tempout[0]); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[2], AESDEC_CBC_PKCS7_tempout[1]); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[3], AESDEC_CBC_PKCS7_tempout[2]); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[4], AESDEC_CBC_PKCS7_tempout[3]); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[0], AESDEC_CBC_PKCS7_tempctx[0])); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[1 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[1], AESDEC_CBC_PKCS7_tempctx[1])); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[2 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[2], AESDEC_CBC_PKCS7_tempctx[2])); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[3 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[3], AESDEC_CBC_PKCS7_tempctx[3])); \
		AESDEC_CBC_PKCS7_tempctx[0] = AESDEC_CBC_PKCS7_tempctx[4]; \
		AESDEC_CBC_PKCS7_input_len -= 4 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_input += 4 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_output += 4 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, decrypt two blocks at once */ \
	while(AESDEC_CBC_PKCS7_input_len >= (2 + 1) * AES_BLOCK_SIZE(VARIANT)) { \
		AESDEC_CBC_PKCS7_tempctx[1] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)])); \
		AESDEC_CBC_PKCS7_tempctx[2] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[1 * AES_BLOCK_SIZE(VARIANT)])); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[1], AESDEC_CBC_PKCS7_tempout[0]); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[2], AESDEC_CBC_PKCS7_tempout[1]); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[0], AESDEC_CBC_PKCS7_tempctx[0])); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[1 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[1], AESDEC_CBC_PKCS7_tempctx[1])); \
		AESDEC_CBC_PKCS7_tempctx[0] = AESDEC_CBC_PKCS7_tempctx[2]; \
		AESDEC_CBC_PKCS7_input_len -= 2 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_input += 2 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_output += 2 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, decrypt blocks one by one */ \
	while(AESDEC_CBC_PKCS7_input_len >= (1 + 1) * AES_BLOCK_SIZE(VARIANT)) { \
		AESDEC_CBC_PKCS7_tempctx[1] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)])); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[1], AESDEC_CBC_PKCS7_tempout[0]); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[0], AESDEC_CBC_PKCS7_tempctx[0])); \
		AESDEC_CBC_PKCS7_tempctx[0] = AESDEC_CBC_PKCS7_tempctx[1]; \
		AESDEC_CBC_PKCS7_input_len -= 1 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_input += 1 * AES_BLOCK_SIZE(VARIANT); \
		AESDEC_CBC_PKCS7_output += 1 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Special case for the last block, which contains padding */ \
	if (AESDEC_CBC_PKCS7_input_len > 0) { \
		char AESDEC_CBC_PKCS7_last_block[AES_BLOCK_SIZE(VARIANT)]; \
		unsigned char AESDEC_CBC_PKCS7_padding; \
		unsigned char AESDEC_CBC_PKCS7_invalid_padding; \
		\
		AESDEC_CBC_PKCS7_tempctx[1] = _mm_loadu_si128(((__m128i const *) &AESDEC_CBC_PKCS7_input[0 * AES_BLOCK_SIZE(VARIANT)])); \
		AES_INTERNAL(ALL, DEC, DO)(VARIANT, KEY_SCHEDULE, AESDEC_CBC_PKCS7_tempctx[1], AESDEC_CBC_PKCS7_tempout[0]); \
		AESDEC_CBC_PKCS7_tempout[1] = _mm_xor_si128(AESDEC_CBC_PKCS7_tempout[0], AESDEC_CBC_PKCS7_tempctx[0]); \
		_mm_storeu_si128((__m128i *) &AESDEC_CBC_PKCS7_last_block[0 * AES_BLOCK_SIZE(VARIANT)], AESDEC_CBC_PKCS7_tempout[1]); \
		\
		/* Verify padding in constant time */ \
		{ \
			__m128i AESDEC_CBC_PKCS7_order, AESDEC_CBC_PKCS7_padding_val, AESDEC_CBC_PKCS7_padding_mask; \
			__m128i AESDEC_CBC_PKCS7_padding_and[2], AESDEC_CBC_PKCS7_padding_result; \
			register int AESDEC_CBC_PKCS7_valid_padding_value; \
			\
			AESDEC_CBC_PKCS7_order = _mm_setr_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL); \
			AESDEC_CBC_PKCS7_padding_val = _mm_shuffle_epi8(AESDEC_CBC_PKCS7_tempout[1], _mm_set1_epi8(0x0F)); \
			AESDEC_CBC_PKCS7_padding_mask = _mm_cmplt_epi8(AESDEC_CBC_PKCS7_order, AESDEC_CBC_PKCS7_padding_val); \
			AESDEC_CBC_PKCS7_padding_and[0] = _mm_and_si128(AESDEC_CBC_PKCS7_padding_mask, AESDEC_CBC_PKCS7_tempout[1]); \
			AESDEC_CBC_PKCS7_padding_and[1] = _mm_and_si128(AESDEC_CBC_PKCS7_padding_mask, AESDEC_CBC_PKCS7_padding_val); \
			AESDEC_CBC_PKCS7_padding_result = _mm_cmpeq_epi32(AESDEC_CBC_PKCS7_padding_and[0], AESDEC_CBC_PKCS7_padding_and[1]); \
			AESDEC_CBC_PKCS7_valid_padding_value = _mm_movemask_epi8(AESDEC_CBC_PKCS7_padding_result); \
			\
			AESDEC_CBC_PKCS7_padding = (unsigned char) AESDEC_CBC_PKCS7_last_block[AES_BLOCK_SIZE(VARIANT) - 1]; \
			\
			AESDEC_CBC_PKCS7_invalid_padding = (unsigned char) ((unsigned char) (AESDEC_CBC_PKCS7_padding - 1U) & (unsigned char) ((0xFFU << LOG2(AES_BLOCK_SIZE(VARIANT))) & 0xFFU)); \
			AESDEC_CBC_PKCS7_invalid_padding |= (unsigned char) (((AESDEC_CBC_PKCS7_valid_padding_value >> 010) & 0xFF) ^ 0xFF); \
			AESDEC_CBC_PKCS7_invalid_padding |= (unsigned char) (((AESDEC_CBC_PKCS7_valid_padding_value >> 000) & 0xFF) ^ 0xFF); \
		} \
		\
		/* TODO: Remove/rewrite this branch to make code run in constant time */ \
		if (0 != AESDEC_CBC_PKCS7_invalid_padding) { \
			memset_s((OUT), (rsize_t) (AESDEC_CBC_PKCS7_output - (OUT)), 0, (rsize_t) (AESDEC_CBC_PKCS7_output - (OUT))); \
			\
			STATE.output_len = 0; \
			STATE.status = NATIVECRYPTO_ERR_INVALID_PADDING; \
		} else { \
			if (NULL != AESDEC_CBC_PKCS7_output && AES_BLOCK_SIZE(VARIANT) - AESDEC_CBC_PKCS7_padding != 0) { \
				memcpy(&AESDEC_CBC_PKCS7_output[0 * AES_BLOCK_SIZE(VARIANT)], AESDEC_CBC_PKCS7_last_block, (unsigned char) (AES_BLOCK_SIZE(VARIANT) - AESDEC_CBC_PKCS7_padding)); \
			} \
			\
			STATE.output_len = (size_t)((((INSZ / AES_BLOCK_SIZE(VARIANT))) * AES_BLOCK_SIZE(VARIANT)) - AESDEC_CBC_PKCS7_padding); \
			STATE.status = NATIVECRYPTO_OK; \
		} \
		\
		(void)memset_s(AESDEC_CBC_PKCS7_last_block, sizeof(AESDEC_CBC_PKCS7_last_block), 0, sizeof(AESDEC_CBC_PKCS7_last_block)); \
	} \
	\
	/* Cleaning up */ \
	(void)memset_s(AESDEC_CBC_PKCS7_tempctx, sizeof(AESDEC_CBC_PKCS7_tempctx), 0, sizeof(AESDEC_CBC_PKCS7_tempctx)); \
	(void)memset_s(AESDEC_CBC_PKCS7_tempout, sizeof(AESDEC_CBC_PKCS7_tempout), 0, sizeof(AESDEC_CBC_PKCS7_tempout)); \
} while(0)

#define AES_CBC_PKCS7_FN_BODY(VARIANT, OP) static struct cypher_state AES_EXPORT(VARIANT, OP, CBC_PKCS7)(char * pOutput, char const * pInput, size_t input_len, void const * const pKey, void const * const pIV) { \
	__m128i key_schedule[AES_ROUNDS(VARIANT)]; \
	static struct cypher_state state = { NATIVECRYPTO_ERR_UNKNOWN, 0 }; \
	\
	if (NULL == pIV) { \
		state.status = NATIVECRYPTO_ERR_INVALID_IV; \
		return state; \
	} \
	\
	AES_INTERNAL(VARIANT, OP, keygen)(key_schedule, (__m128i const *) pKey); \
	\
	AES_INTERNAL(ALL, OP, CBC_PKCS7)(VARIANT, state, pOutput, pInput, input_len, key_schedule, pIV); \
	\
	(void)memset_s(key_schedule, sizeof(key_schedule), 0, sizeof(key_schedule)); \
	\
	return state; \
}

/* FIXME: Using _mm_add_epi64 (packed 64-bit addition) results in unexpected behaviour when the lower half of the IV overflows */
#define AESXXX_CTR(VARIANT, OP, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) do { \
	__m128i const AESXXX_CTR_c1 = _mm_setr_epi32(0x0UL, 0x0UL, 0x0UL, 0x1UL); \
	__m128i const AESXXX_CTR_c2 = _mm_setr_epi32(0x0UL, 0x0UL, 0x0UL, 0x2UL); \
	__m128i const AESXXX_CTR_c3 = _mm_setr_epi32(0x0UL, 0x0UL, 0x0UL, 0x3UL); \
	__m128i const AESXXX_CTR_c4 = _mm_setr_epi32(0x0UL, 0x0UL, 0x0UL, 0x4UL); \
	\
	__m128i AESXXX_CTR_ctrbe = _mm_loadu_si128((__m128i const *) (IV)); \
	__m128i AESXXX_CTR_ctrle = _mm_bswap_epi32(AESXXX_CTR_ctrbe); \
	\
	__m128i AESXXX_CTR_tempctr[4]; \
	__m128i AESXXX_CTR_tempout[4]; \
	\
	size_t AESXXX_CTR_input_len = (size_t)(INSZ); \
	char const * AESXXX_CTR_input = (char const *)(IN); \
	char * AESXXX_CTR_output = (char *)(OUT); \
	\
	/* Firstly, encrypt/decrypt four blocks at once */ \
	while(AESXXX_CTR_input_len >= 4 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_CTR_tempctr[0] = AESXXX_CTR_ctrbe; \
		AESXXX_CTR_tempctr[1] = _mm_bswap_epi32(_mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c1)); \
		AESXXX_CTR_tempctr[2] = _mm_bswap_epi32(_mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c2)); \
		AESXXX_CTR_tempctr[3] = _mm_bswap_epi32(_mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c3)); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[0], AESXXX_CTR_tempout[0]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[1], AESXXX_CTR_tempout[1]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[2], AESXXX_CTR_tempout[2]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[3], AESXXX_CTR_tempout[3]); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[0 * AES_BLOCK_SIZE(VARIANT)])))); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[1 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[1], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[1 * AES_BLOCK_SIZE(VARIANT)])))); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[2 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[2], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[2 * AES_BLOCK_SIZE(VARIANT)])))); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[3 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[3], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[3 * AES_BLOCK_SIZE(VARIANT)])))); \
		AESXXX_CTR_ctrle = _mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c4); \
		AESXXX_CTR_ctrbe = _mm_bswap_epi32(AESXXX_CTR_ctrle); \
		AESXXX_CTR_input_len -= 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_input += 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_output += 4 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, encrypt/decrypt two blocks at once */ \
	while(AESXXX_CTR_input_len >= 2 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_CTR_tempctr[0] = AESXXX_CTR_ctrbe; \
		AESXXX_CTR_tempctr[1] = _mm_bswap_epi32(_mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c1)); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[0], AESXXX_CTR_tempout[0]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[1], AESXXX_CTR_tempout[1]); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[0 * AES_BLOCK_SIZE(VARIANT)])))); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[1 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[1], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[1 * AES_BLOCK_SIZE(VARIANT)])))); \
		AESXXX_CTR_ctrle = _mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c2); \
		AESXXX_CTR_ctrbe = _mm_bswap_epi32(AESXXX_CTR_ctrle); \
		AESXXX_CTR_input_len -= 2 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_input += 2 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_output += 2 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, encrypt/decrypt blocks one by one */ \
	while(AESXXX_CTR_input_len >= 1 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_CTR_tempctr[0] = AESXXX_CTR_ctrbe; \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[0], AESXXX_CTR_tempout[0]); \
		_mm_storeu_si128((__m128i *) &AESXXX_CTR_output[0 * AES_BLOCK_SIZE(VARIANT)], _mm_xor_si128(AESXXX_CTR_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_input[0 * AES_BLOCK_SIZE(VARIANT)])))); \
		AESXXX_CTR_ctrle = _mm_add_epi64(AESXXX_CTR_ctrle, AESXXX_CTR_c1); \
		AESXXX_CTR_ctrbe = _mm_bswap_epi32(AESXXX_CTR_ctrle); \
		AESXXX_CTR_input_len -= 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_input += 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_CTR_output += 1 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Special case for the last block */ \
	if (AESXXX_CTR_input_len > 0) { \
		char AESXXX_CTR_last_block[AES_BLOCK_SIZE(VARIANT)]; \
		\
		AESXXX_CTR_tempctr[0] = AESXXX_CTR_ctrbe; \
		memcpy(&AESXXX_CTR_last_block[0], AESXXX_CTR_input, AESXXX_CTR_input_len); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_CTR_tempctr[0], AESXXX_CTR_tempout[0]); \
		AESXXX_CTR_tempout[1] = _mm_xor_si128(AESXXX_CTR_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_CTR_last_block))); \
		_mm_storeu_si128((__m128i *) AESXXX_CTR_last_block, AESXXX_CTR_tempout[1]); \
		(void)memcpy(&AESXXX_CTR_output[0 * AES_BLOCK_SIZE(VARIANT)], AESXXX_CTR_last_block, AESXXX_CTR_input_len); \
		\
		(void)memset_s(AESXXX_CTR_last_block, sizeof(AESXXX_CTR_last_block), 0, sizeof(AESXXX_CTR_last_block)); \
	} \
	\
	/* Cleaning up */ \
	(void)memset_s(&AESXXX_CTR_ctrbe, sizeof(AESXXX_CTR_ctrbe), 0, sizeof(AESXXX_CTR_ctrbe)); \
	(void)memset_s(&AESXXX_CTR_ctrle, sizeof(AESXXX_CTR_ctrle), 0, sizeof(AESXXX_CTR_ctrle)); \
	(void)memset_s(AESXXX_CTR_tempctr, sizeof(AESXXX_CTR_tempctr), 0, sizeof(AESXXX_CTR_tempctr)); \
	(void)memset_s(AESXXX_CTR_tempout, sizeof(AESXXX_CTR_tempout), 0, sizeof(AESXXX_CTR_tempout)); \
	\
	STATE.status = NATIVECRYPTO_OK; \
	STATE.output_len = INSZ; \
} while(0)

#define AES_CTR_FN_BODY(VARIANT, OP) static struct cypher_state AES_EXPORT(VARIANT, OP, CTR)(char * const pOutput, char const * const pInput, size_t const input_len, void const * const pKey, void const * const pIV) { \
	__m128i key_schedule[AES_ROUNDS(VARIANT)]; \
	static struct cypher_state state = { NATIVECRYPTO_ERR_UNKNOWN, 0 }; \
	\
	if (NULL == pIV) { \
		state.status = NATIVECRYPTO_ERR_INVALID_IV; \
		return state; \
	} \
	\
	if (NULL == pOutput) { \
		state.output_len = input_len; \
		state.status = NATIVECRYPTO_OK; \
		return state; \
	} \
	\
	AES_INTERNAL(VARIANT, ENC, keygen)(key_schedule, (__m128i const *) pKey); \
	\
	AES_INTERNAL(ALL, OP, CTR)(VARIANT, _, state, pOutput, pInput, input_len, key_schedule, pIV); \
	\
	(void)memset_s(key_schedule, sizeof(key_schedule), 0, sizeof(key_schedule)); \
	\
	return state; \
}

ALWAYS_INLINE static __m128i gfmul(__m128i a, __m128i b)
{
	__m128i tmp[10];

	tmp[3] = _mm_clmulepi64_si128(a, b, 0x00);
	tmp[4] = _mm_clmulepi64_si128(a, b, 0x10);
	tmp[5] = _mm_clmulepi64_si128(a, b, 0x01);
	tmp[6] = _mm_clmulepi64_si128(a, b, 0x11);

	tmp[4] = _mm_xor_si128(tmp[4], tmp[5]);
	tmp[5] = _mm_slli_si128(tmp[4], 8);
	tmp[4] = _mm_srli_si128(tmp[4], 8);
	tmp[3] = _mm_xor_si128(tmp[3], tmp[5]);
	tmp[6] = _mm_xor_si128(tmp[6], tmp[4]);

	tmp[7] = _mm_srli_si128(tmp[3], 31);
	tmp[8] = _mm_srli_si128(tmp[6], 31);
	tmp[3] = _mm_slli_si128(tmp[3], 1);
	tmp[6] = _mm_slli_si128(tmp[6], 1);

	tmp[9] = _mm_srli_si128(tmp[7], 12);
	tmp[8] = _mm_slli_si128(tmp[8], 4);
	tmp[7] = _mm_slli_si128(tmp[7], 4);
	tmp[3] = _mm_or_si128(tmp[3], tmp[7]);
	tmp[6] = _mm_or_si128(tmp[6], tmp[8]);
	tmp[6] = _mm_or_si128(tmp[6], tmp[9]);

	tmp[7] = _mm_slli_si128(tmp[3], 31);
	tmp[8] = _mm_slli_si128(tmp[3], 30);
	tmp[9] = _mm_slli_si128(tmp[3], 25);

	tmp[7] = _mm_xor_si128(tmp[7], tmp[8]);
	tmp[7] = _mm_xor_si128(tmp[7], tmp[9]);
	tmp[8] = _mm_srli_si128(tmp[7], 4);
	tmp[7] = _mm_slli_si128(tmp[7], 12);
	tmp[3] = _mm_xor_si128(tmp[3], tmp[7]);

	tmp[2] = _mm_srli_si128(tmp[3], 1);
	tmp[4] = _mm_srli_si128(tmp[3], 2);
	tmp[5] = _mm_srli_si128(tmp[3], 7);
	tmp[2] = _mm_xor_si128(tmp[2], tmp[4]);
	tmp[2] = _mm_xor_si128(tmp[2], tmp[5]);
	tmp[2] = _mm_xor_si128(tmp[2], tmp[8]);
	tmp[3] = _mm_xor_si128(tmp[3], tmp[2]);
	tmp[6] = _mm_xor_si128(tmp[6], tmp[3]);

	return tmp[6];
}

/* FIXME: Using _mm_add_epi64 (packed 64-bit addition) results in unexpected behaviour when the lower half of the IV overflows */
#define AESXXX_GCM(VARIANT, OP, STATE, OUT, IN, INSZ, KEY_SCHEDULE, IV) do { \
	__m128i const AESXXX_GCM_c1 = _mm_setr_epi32(0x0UL, 0x0UL, 0x1UL, 0x0UL); \
	__m128i const AESXXX_GCM_c2 = _mm_setr_epi32(0x0UL, 0x0UL, 0x2UL, 0x0UL); \
	__m128i const AESXXX_GCM_c3 = _mm_setr_epi32(0x0UL, 0x0UL, 0x3UL, 0x0UL); \
	__m128i const AESXXX_GCM_c4 = _mm_setr_epi32(0x0UL, 0x0UL, 0x4UL, 0x0UL); \
	\
	__m128i AESXXX_GCM_ctrbe = _mm_loadu_si128((__m128i const *) (IV)); \
	__m128i AESXXX_GCM_ctrle = _mm_bswap_epi32(AESXXX_GCM_ctrbe); \
	\
	__m128i AESXXX_GCM_X, AESXXX_GCM_H, AESXXX_GCM_Y, AESXXX_GCM_T; \
	__m128i AESXXX_GCM_tempctr[4]; \
	__m128i AESXXX_GCM_tempout[4]; \
	\
	size_t AESXXX_GCM_input_len = (size_t)(INSZ); \
	char const * AESXXX_GCM_input = (char const *)(IN); \
	char * AESXXX_GCM_output = (char *)(OUT); \
	AESXXX_GCM_X = _mm_setzero_si128();\
	\
	/* TODO: Case for initial GH values */\
	\
	/* TODO: Case for initial additional data */\
	\
	/* Firstly, encrypt/decrypt four blocks at once */ \
	while(AESXXX_GCM_input_len >= 4 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_GCM_tempctr[0] = AESXXX_GCM_ctrbe; \
		AESXXX_GCM_tempctr[1] = _mm_bswap_epi32(_mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c1)); \
		AESXXX_GCM_tempctr[2] = _mm_bswap_epi32(_mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c2)); \
		AESXXX_GCM_tempctr[3] = _mm_bswap_epi32(_mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c3)); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[0], AESXXX_GCM_tempout[0]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[1], AESXXX_GCM_tempout[1]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[2], AESXXX_GCM_tempout[2]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[3], AESXXX_GCM_tempout[3]); \
		AESXXX_GCM_tempout[0] = _mm_xor_si128(AESXXX_GCM_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[0 * AES_BLOCK_SIZE(VARIANT)]))); \
		AESXXX_GCM_tempout[1] = _mm_xor_si128(AESXXX_GCM_tempout[1], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[1 * AES_BLOCK_SIZE(VARIANT)]))); \
		AESXXX_GCM_tempout[2] = _mm_xor_si128(AESXXX_GCM_tempout[2], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[2 * AES_BLOCK_SIZE(VARIANT)]))); \
		AESXXX_GCM_tempout[3] = _mm_xor_si128(AESXXX_GCM_tempout[3], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[3 * AES_BLOCK_SIZE(VARIANT)]))); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[0 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[0]); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[1 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[1]); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[2 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[2]); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[3 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[3]); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[0])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[1])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[2])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[3])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_ctrle = _mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c4); \
		AESXXX_GCM_ctrbe = _mm_bswap_epi32(AESXXX_GCM_ctrle); \
		AESXXX_GCM_input_len -= 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_input += 4 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_output += 4 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, encrypt/decrypt two blocks at once */ \
	while(AESXXX_GCM_input_len >= 2 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_GCM_tempctr[0] = AESXXX_GCM_ctrbe; \
		AESXXX_GCM_tempctr[1] = _mm_bswap_epi32(_mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c1)); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[0], AESXXX_GCM_tempout[0]); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[1], AESXXX_GCM_tempout[1]); \
		AESXXX_GCM_tempout[0] = _mm_xor_si128(AESXXX_GCM_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[0 * AES_BLOCK_SIZE(VARIANT)]))); \
		AESXXX_GCM_tempout[1] = _mm_xor_si128(AESXXX_GCM_tempout[1], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[1 * AES_BLOCK_SIZE(VARIANT)]))); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[0 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[0]); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[1 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[1]); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[0])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[1])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_ctrle = _mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c2); \
		AESXXX_GCM_ctrbe = _mm_bswap_epi32(AESXXX_GCM_ctrle); \
		AESXXX_GCM_input_len -= 2 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_input += 2 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_output += 2 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Then, encrypt/decrypt blocks one by one */ \
	while(AESXXX_GCM_input_len >= 1 * AES_BLOCK_SIZE(VARIANT)) { \
		AESXXX_GCM_tempctr[0] = AESXXX_GCM_ctrbe; \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[0], AESXXX_GCM_tempout[0]); \
		AESXXX_GCM_tempout[0] = _mm_xor_si128(AESXXX_GCM_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_input[0 * AES_BLOCK_SIZE(VARIANT)]))); \
		_mm_storeu_si128((__m128i *) &AESXXX_GCM_output[0 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_tempout[0]); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[0])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		AESXXX_GCM_ctrle = _mm_add_epi32(AESXXX_GCM_ctrle, AESXXX_GCM_c1); \
		AESXXX_GCM_ctrbe = _mm_bswap_epi32(AESXXX_GCM_ctrle); \
		AESXXX_GCM_input_len -= 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_input += 1 * AES_BLOCK_SIZE(VARIANT); \
		AESXXX_GCM_output += 1 * AES_BLOCK_SIZE(VARIANT); \
	} \
	\
	/* Special case for the last block */ \
	if (AESXXX_GCM_input_len > 0) { \
		char AESXXX_GCM_last_block[AES_BLOCK_SIZE(VARIANT)]; \
		\
		AESXXX_GCM_tempctr[0] = AESXXX_GCM_ctrbe; \
		memcpy(&AESXXX_GCM_last_block[0], AESXXX_GCM_input, AESXXX_GCM_input_len); \
		AES_INTERNAL(ALL, ENC, DO)(VARIANT, KEY_SCHEDULE, AESXXX_GCM_tempctr[0], AESXXX_GCM_tempout[0]); \
		AESXXX_GCM_tempout[1] = _mm_xor_si128(AESXXX_GCM_tempout[0], _mm_loadu_si128(((__m128i const *) &AESXXX_GCM_last_block))); \
		_mm_storeu_si128((__m128i *) AESXXX_GCM_last_block, AESXXX_GCM_tempout[1]); \
		AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, _mm_bswap_si128(AESXXX_GCM_tempout[1])); \
		AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
		(void)memcpy(&AESXXX_GCM_output[0 * AES_BLOCK_SIZE(VARIANT)], AESXXX_GCM_last_block, AESXXX_GCM_input_len); \
		\
		(void)memset_s(AESXXX_GCM_last_block, sizeof(AESXXX_GCM_last_block), 0, sizeof(AESXXX_GCM_last_block)); \
	} \
	\
	AESXXX_GCM_tempout[0] = _mm_setr_epi64((__m64)(INSZ*8), (__m64)0); /* TODO ABYTES (add data) */ \
	AESXXX_GCM_X = _mm_xor_si128(AESXXX_GCM_X, AESXXX_GCM_tempout[0]); \
	AESXXX_GCM_X = gfmul(AESXXX_GCM_X, AESXXX_GCM_H); \
	AESXXX_GCM_X = _mm_bswap_si128(AESXXX_GCM_X); \
	AESXXX_GCM_T = _mm_xor_si128(AESXXX_GCM_X, AESXXX_GCM_T); \
	\
	/* Cleaning up */ \
	(void)memset_s(&AESXXX_GCM_ctrbe, sizeof(AESXXX_GCM_ctrbe), 0, sizeof(AESXXX_GCM_ctrbe)); \
	(void)memset_s(&AESXXX_GCM_ctrle, sizeof(AESXXX_GCM_ctrle), 0, sizeof(AESXXX_GCM_ctrle)); \
	(void)memset_s(AESXXX_GCM_tempctr, sizeof(AESXXX_GCM_tempctr), 0, sizeof(AESXXX_GCM_tempctr)); \
	(void)memset_s(AESXXX_GCM_tempout, sizeof(AESXXX_GCM_tempout), 0, sizeof(AESXXX_GCM_tempout)); \
	\
	STATE.status = NATIVECRYPTO_OK; \
	STATE.output_len = INSZ; \
} while(0)
/* END AES MACROS */

/* BEGIN AES-128 */
ALWAYS_INLINE static void AES_INTERNAL(128, ALL,
                                       expand_key)(STATIC_SZ_ARRAY(__m128i, pExpanded, 1),
                                               STATIC_SZ_ARRAY(__m128i const, pKey, 1), __m128i const generated_key,
                                               unsigned char const index)
{
	__m128i key = pKey[0];
	(void)index;

	assert((index + 1) < AES_ROUNDS(128));

#define KEY key
	FOR(3, AES_INTERNAL(ALL, ALL, KEY_SHUFFLE_HELPER));
#undef KEY
	key = _mm_xor_si128(key, _mm_shuffle_epi32(generated_key, _MM_SHUFFLE(3, 3, 3,
	                    3)));

	pExpanded[0] = key;
}

#define AESXXX_DEBUG_SCHEDULE(VARIANT, OP, KEY_SCHEDULE) do { \
	size_t AES_KEYGEN_DBG_i; \
	for (AES_KEYGEN_DBG_i = 0; AES_KEYGEN_DBG_i < AES_ROUNDS(VARIANT); AES_KEYGEN_DBG_i++) { \
		AES_DEBUG_PRINTF(TOKENIZE(AES_INTERNAL(VARIANT, OP, keygen)), "%s[%u] = ", #KEY_SCHEDULE, (unsigned int)AES_KEYGEN_DBG_i); \
		AES_fprintf__m128i(KEY_SCHEDULE[AES_KEYGEN_DBG_i]); \
		AES_DEBUG_PRINTF_CALL("\n"); \
	} \
} while (0) \


#define AES128XXX_KEYGEN_FN_BODY(OP) ALWAYS_INLINE static void AES_INTERNAL(128, OP, keygen)(STATIC_SZ_ARRAY(__m128i, key_schedule, AES_ROUNDS(128)), __m128i const * const pKey) { \
	key_schedule[0] = _mm_loadu_si128(&pKey[0]); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 0); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 1); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 2); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 3); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 4); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 5); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 6); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 7); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 8); \
	AES_INTERNAL(128, OP, EXPAND_KEY)(key_schedule, 9); \
	AES_INTERNAL(ALL, ALL, DEBUG_SCHEDULE)(128, OP, key_schedule); \
}

AES_KEYGEN_FN_BODY(128, ENC)
AES_KEYGEN_FN_BODY(128, DEC)

AES_ECB_FN_BODY(128, ENC)
AES_ECB_FN_BODY(128, DEC)

AES_CBC_PKCS7_FN_BODY(128, ENC)
AES_CBC_PKCS7_FN_BODY(128, DEC)

AES_CTR_FN_BODY(128, ALL)
/* END AES-128 */

/* BEGIN AES-192 */
#define AES192XXX_KEYGEN_FN_BODY(OP) ALWAYS_INLINE static void AES_INTERNAL(192, OP, keygen)(STATIC_SZ_ARRAY(__m128i, key_schedule, AES_ROUNDS(192)), __m128i const * const pKey) { \
	key_schedule[0] = _mm_loadu_si128(&pKey[0]); \
	key_schedule[1] = _mm_loadl_epi64(&pKey[1]); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 0); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 2); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 3); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 5); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 6); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 8); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 9); \
	AES_INTERNAL(192, OP, EXPAND_KEY)(key_schedule, 11); \
	AES_INTERNAL(ALL, ALL, DEBUG_SCHEDULE)(192, OP, key_schedule); \
}

ALWAYS_INLINE static void AES_INTERNAL(192, ALL,
                                       expand_key)(STATIC_SZ_ARRAY(__m128i, pExpanded, 1),
                                               STATIC_SZ_ARRAY(__m128i const, pKey, 2), __m128i const generated_key,
                                               unsigned char const index)
{
	__m128i key1 = pKey[0];
	__m128i key2 = pKey[1];

	assert((index + 1) < AES_ROUNDS(192));

	if (0 != (index % 3))
	{
		pExpanded[-2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(pKey[-1]),
		                                 _mm_castsi128_pd(key1), 0));
		pExpanded[-1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key1),
		                                 _mm_castsi128_pd(key2), 1));
	}

#define KEY key1
	FOR(3, AES_INTERNAL(ALL, ALL, KEY_SHUFFLE_HELPER));
#undef KEY
	key1 = _mm_xor_si128(key1, _mm_shuffle_epi32(generated_key, _MM_SHUFFLE(1, 1, 1,
	                     1)));

	pExpanded[0] = key1;

	if ((index + 2) < AES_ROUNDS(192))
	{
		__m128i temp;

		temp = _mm_slli_si128(key2, 4);
		key2 = _mm_xor_si128(key2, temp);
		key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));

		pExpanded[1] = key2;
	}
}

AES_KEYGEN_FN_BODY(192, ENC)
AES_KEYGEN_FN_BODY(192, DEC)


AES_ECB_FN_BODY(192, ENC)
AES_ECB_FN_BODY(192, DEC)

AES_CBC_PKCS7_FN_BODY(192, ENC)
AES_CBC_PKCS7_FN_BODY(192, DEC)

AES_CTR_FN_BODY(192, ALL)
/* END AES-192 */

/* BEGIN AES-256 */
#define AES256XXX_KEYGEN_FN_BODY(OP) ALWAYS_INLINE static void AES_INTERNAL(256, OP, keygen)(STATIC_SZ_ARRAY(__m128i, key_schedule, AES_ROUNDS(256)), __m128i const * const pKey) { \
	key_schedule[0] = _mm_loadu_si128(&pKey[0]); \
	key_schedule[1] = _mm_loadu_si128(&pKey[1]); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 0); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 2); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 4); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 6); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 8); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 10); \
	AES_INTERNAL(256, OP, EXPAND_KEY)(key_schedule, 12); \
	AES_INTERNAL(ALL, ALL, DEBUG_SCHEDULE)(256, OP, key_schedule); \
}

ALWAYS_INLINE static void AES_INTERNAL(256, ALL,
                                       expand_key)(STATIC_SZ_ARRAY(__m128i, pExpanded, 1),
                                               STATIC_SZ_ARRAY(__m128i const, pKey, 2), __m128i const generated_key,
                                               unsigned char const index)
{
	__m128i key1 = pKey[0];
	__m128i key2 = pKey[1];

	assert((index + 2) < AES_ROUNDS(256));

#define KEY key1
	FOR(3, AES_INTERNAL(ALL, ALL, KEY_SHUFFLE_HELPER));
#undef KEY
	key1 = _mm_xor_si128(key1, _mm_shuffle_epi32(generated_key, _MM_SHUFFLE(3, 3, 3,
	                     3)));

	pExpanded[0] = key1;

	if ((index + 3) < AES_ROUNDS(256))
	{
#define KEY key2
		FOR(3, AES_INTERNAL(ALL, ALL, KEY_SHUFFLE_HELPER));
#undef KEY
		key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key1, 0),
		                     _MM_SHUFFLE(2, 2, 2, 2)));
		pExpanded[1] = key2;
	}
}

AES_KEYGEN_FN_BODY(256, ENC)
AES_KEYGEN_FN_BODY(256, DEC)

AES_ECB_FN_BODY(256, ENC)
AES_ECB_FN_BODY(256, DEC)

AES_CBC_PKCS7_FN_BODY(256, ENC)
AES_CBC_PKCS7_FN_BODY(256, DEC)

AES_CTR_FN_BODY(256, ALL)
/* END AES-256 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_AESNI_H_ */
