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

#ifndef AES_INTERNAL_H_
#define AES_INTERNAL_H_

#include "cypher.h"

#define AES_INTERNAL__(VARIANT, OP, NAME) VARIANT ## OP ## _ ## NAME
#define AES_INTERNAL_(VARIANT, OP, NAME) AES_INTERNAL__(VARIANT, OP, NAME)
#define AES_INTERNAL(VARIANT, OP, NAME) AES_INTERNAL_(AES_VARIANT_ ## VARIANT, CYPHER_OP_INTERNAL_ ## OP, NAME)

#define AES_EXPORT(VARIANT, OP, NAME) AES_INTERNAL_(AES_VARIANT_ ## VARIANT, _ ## NAME, CYPHER_OP_EXPORT_ ## OP)

#define AES_BLOCK_SIZE(VARIANT) (16)

#define AES_VARIANT_ALL AES
#define AES_VARIANT_128 AES128
#define AES_VARIANT_192 AES192
#define AES_VARIANT_256 AES256

#define RCON(I) ( \
	(0 == (I)) ? 0x01 : \
	(1 == (I)) ? 0x02 : \
	(2 == (I)) ? 0x04 : \
	(3 == (I)) ? 0x08 : \
	(4 == (I)) ? 0x10 : \
	(5 == (I)) ? 0x20 : \
	(6 == (I)) ? 0x40 : \
	(7 == (I)) ? 0x80 : \
	(8 == (I)) ? 0x1B : \
	(9 == (I)) ? 0x36 : \
	/* INVALID*/ 0 \
)

#define AES128XXX_RCON(I) RCON(I)
#define AES192XXX_RCON(I) RCON(((I) * 2) / 3)
#define AES256XXX_RCON(I) RCON((I) / 2)

#define AES_ROUNDS(VARIANT) AES_INTERNAL(VARIANT, ALL, ROUNDS)
#define AES128XXX_ROUNDS (11)
#define AES192XXX_ROUNDS (13)
#define AES256XXX_ROUNDS (15)

#define AES_KEYGEN_FN_BODY(VARIANT, OP) AES_INTERNAL(VARIANT, ALL, KEYGEN_FN_BODY)(OP)

#ifdef AES_DEBUG
#define AES_DEBUG_PRINTF      DEBUG_PRINTF
#define AES_DEBUG_PRINTF_CALL DEBUG_PRINTF_CALL
#define AES_fprintf__m128i    fprintf__m128i
#else /* !defined(AES_DEBUG) */
#define AES_fprintf__m128i(X) do { } while(0)
#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define AES_DEBUG_PRINTF(...)      do { } while(0)
#define AES_DEBUG_PRINTF_CALL(...) do { } while(0)
#else /* !(defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) */
ALWAYS_INLINE static void AES_DEBUG_PRINTF(char const * const x, ...)
{
	(void)x;
}
ALWAYS_INLINE static void AES_DEBUG_PRINTF_CALL(char const * const x, ...)
{
	(void)x;
}
#endif
#endif

#endif /* AES_INTERNAL_H_ */
