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

#ifndef UTIL_H_
#define UTIL_H_

#define PRIMITIVE_CAT(A, B) A ## B
#define CAT(A, B) PRIMITIVE_CAT(A, B)

/* Clang compat */
#ifndef __has_attribute
#define __has_attribute(X) (0)
#endif /* __has_attribute */

/* GCC compat */
#if defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
#define GNUC_VERSION(OP, MAJOR, MINOR, PATCH) \
	( __GNUC__ OP MAJOR || \
	  (__GNUC__ == MAJOR && __GNUC_MINOR__ OP MINOR) || \
	  (__GNUC__ == MAJOR && __GNUC_MINOR__ == MINOR && __GNUC_PATCHLEVEL__ CAT(OP, =) PATCH))
#else
#define GNUC_VERSION(OP, MAJOR, MINOR, PATCH) (0)
#endif /* defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__) */

#define GNUC_VERSION_MIN(MAJOR, MINOR, PATCH) GNUC_VERSION(>, MAJOR, MINOR, PATCH)

#if defined(__clang__) && __has_attribute(optnone)
#define ATTR_NO_OPTIMIZE __attribute__((optnone))
#elif GNUC_VERSION_MIN(4, 7, 0)
#define ATTR_NO_OPTIMIZE __attribute__((optimize("-O0")))
#elif defined(_MSC_VER)
#define ATTR_NO_OPTIMIZE __pragma(optimize("", off))
#else
#define ATTR_NO_OPTIMIZE /* */
#endif /* defined(__clang__) && __has_attribute(optnone) */

/* ANSI C and C++ have no static array sizes */
#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define STATIC_SZ_ARRAY(TYPE, NAME, SIZE) TYPE NAME[static (SIZE)]
#else
#define STATIC_SZ_ARRAY(TYPE, NAME, SIZE) TYPE * NAME
#endif /* defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L */

/* ANSI C has no inline */
#if defined(__cplusplus) || (defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
#define INLINE inline
#elif GNUC_VERSION_MIN(0, 0, 0) /* TODO */
#define INLINE __inline__
#else
#define INLINE /* */
#endif /* defined(__cplusplus) || (defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) */

#if __has_attribute(__always_inline__) || GNUC_VERSION_MIN(0, 0, 0) /* TODO */
#define ALWAYS_INLINE INLINE __attribute__((__always_inline__))
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE INLINE
#endif /* __has_attribute(__always_inline__) || GNUC_VERSION_MIN(0, 0, 0) */


/* INTERNAL */
#define BASICTOKENIZE(A) #A
#define TOKENIZE(A) BASICTOKENIZE(A)

#define INDIRECT(A) A

#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#ifdef DEBUG
#ifndef DEBUG_PRINTF_CALL
#define DEBUG_PRINTF_CALL(...) fprintf(stderr, __VA_ARGS__)
#endif /* DEBUG_PRINTF_CALL */
#define DEBUG_PRINTF(SRC, STR, ...) DEBUG_PRINTF_CALL(INDIRECT(__FILE__) ":" TOKENIZE(__LINE__) ":[" SRC "] " STR, __VA_ARGS__)
#else /* !defined(DEBUG) */
#ifdef DEBUG_PRINTF_CALL
#undefine DEBUG_PRINTF_CALL
#endif  /* DEBUG_PRINTF_CALL */
#define DEBUG_PRINTF_CALL(...) do { } while(0)
#define DEBUG_PRINTF(...) do { } while(0)
#endif /* DEBUG */
#else /* !(defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) */
ALWAYS_INLINE static void DEBUG_PRINTF_CALL(char const * const x, ...)
{
	(void)x;
}
ALWAYS_INLINE static void DEBUG_PRINTF(char const * const x, ...)
{
	(void)x;
}
#endif /* defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L */

#endif /* UTIL_H_ */
