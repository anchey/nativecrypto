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

#ifndef CYPHER_INTERNAL_H_
#define CYPHER_INTERNAL_H_

#define CYPHER_OP_INTERNAL_ALL XXX
#define CYPHER_OP_INTERNAL_ENC ENC
#define CYPHER_OP_INTERNAL_DEC DEC

#define CYPHER_OP_EXPORT_ALL xcrypt
#define CYPHER_OP_EXPORT_ENC encrypt
#define CYPHER_OP_EXPORT_DEC decrypt

struct cypher_state
{
	int status;
	size_t output_len;
};

#endif /* CYPHER_INTERNAL_H_ */
