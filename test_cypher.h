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

#ifndef TEST_CYPHER_H_
#define TEST_CYPHER_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h>

struct test_cypher_vector
{
	char const * description;
	char const * key;
	size_t key_len;
	char const * iv;
	size_t iv_len;
	char const * plaintext;
	size_t plaintext_len;
	char const * cyphertext;
	size_t cyphertext_len;
};

struct test_cypher_vector_group
{
	char const * description;
	int cypher;
	struct test_cypher_vector const * vectors;
	size_t vectors_len;
};

int test_cypher(int cypher, struct test_cypher_vector const v);
int test_cypher_group(struct test_cypher_vector_group const * const vg,
                      size_t vg_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TEST_CYPHER_H_ */
