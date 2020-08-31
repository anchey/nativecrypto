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

#ifndef CYPHER_INTERNAL_SSE_H_
#define CYPHER_INTERNAL_SSE_H_

#include "cypher_internal.h"

#ifdef DEBUG
#include <stdio.h>
#include <inttypes.h>

ALWAYS_INLINE static void fprintf__m128i(__m128i var)
{
	union
	{
		__m128i m128;
		uint8_t u8[16];
	} val;
	val.m128 = var;
	DEBUG_PRINTF_CALL("%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 " %02" PRIx8
	                  "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 " %02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02"
	                  PRIx8 " %02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8,
	                  val.u8[0], val.u8[1], val.u8[2], val.u8[3], val.u8[4], val.u8[5], val.u8[6],
	                  val.u8[7],
	                  val.u8[8], val.u8[9], val.u8[10], val.u8[11], val.u8[12], val.u8[13],
	                  val.u8[14], val.u8[15]
	                 );
}
#else
#define fprintf__m128i(x) do { } while(0)
#endif

#endif /* CYPHER_INTERNAL_SSE_H_ */
