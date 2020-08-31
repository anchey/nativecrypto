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

#ifndef MEMSET_S_H_
#define MEMSET_S_H_
#define __STDC_WANT_LIB_EXT1__ 1
#include <errno.h>
#include <string.h>
#include "util.h"

#if !defined(__STDC_LIB_EXT1__)
#if !defined(RSIZE_MAX)
#include <stdint.h>

#define RSIZE_MAX (SIZE_MAX >> 1)
typedef size_t rsize_t;
#endif /* !defined(RSIZE_MAX) */

static INLINE int memset_s(void *dest, rsize_t destsz, int ch, rsize_t count);

ATTR_NO_OPTIMIZE static INLINE int memset_s(void *dest, rsize_t destsz, int ch,
        rsize_t count)
{
	int r = 0;
	char volatile * vdest = (char volatile *) dest;

	if (NULL == vdest || destsz > RSIZE_MAX)
	{
		errno = EINVAL;
		return errno;
	}

	if (count > destsz)
	{
		count = destsz;
		r = errno = EINVAL;
	}

	while (count)
	{
		vdest[0] = (char)ch;
		count--;
		vdest++;
	}

	return r;
}
#endif /* !defined(__STDC_LIB_EXT1__) */
#endif /* MEMSET_S_H_ */
