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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nativecrypto.h"
#include "test_cypher.h"

#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define PRIsz "zu"
#define SZ_C(X) (X)
#else
#define PRIsz "lu"
#define SZ_C(X) (unsigned long)(X)
#endif

static int test_cypher_encrypt(int cypher, struct test_cypher_vector const v)
{
	size_t cyphertext_len;
	int res;

	if ((res = NATIVECRYPTO_NAME(encrypt)(NULL, &cyphertext_len, cypher, v.key,
	                                      v.key_len, v.iv,
	                                      v.iv_len, v.plaintext, v.plaintext_len)) != NATIVECRYPTO_OK)
	{
		fprintf(stderr,
		        "ERROR: Unable to determine cyphertext length (return value %d != %d)\n", res,
		        NATIVECRYPTO_OK);
		return 1;
	}

	if (v.cyphertext_len != cyphertext_len)
	{
		fprintf(stderr,
		        "ERROR: Output cyphertext length (before encryption) different than expected (%"
		        PRIsz " != %" PRIsz ")\n", SZ_C(cyphertext_len), SZ_C(v.cyphertext_len));
		return 2;
	}

	{
		char * cyphertext_p = NULL;
		int ret = 0;

		cyphertext_p = (char *) malloc(v.cyphertext_len);

		do
		{
			if (NULL == cyphertext_p)
			{
				fprintf(stderr, "ERROR: Unable to allocate %" PRIsz
				        " bytes for the cyphertext\n", SZ_C(v.cyphertext_len));
				ret = 3;
				break;
			}

			if ((res = NATIVECRYPTO_NAME(encrypt)(cyphertext_p, &cyphertext_len, cypher,
			                                      v.key, v.key_len,
			                                      v.iv, v.iv_len, v.plaintext, v.plaintext_len)) !=
			        NATIVECRYPTO_OK)
			{
				fprintf(stderr, "ERROR: Unable to perform encryption (return value %d != %d)\n",
				        res, NATIVECRYPTO_OK);
				ret = 4;
				break;
			}

			if (v.cyphertext_len != cyphertext_len)
			{
				fprintf(stderr,
				        "ERROR: Output cyphertext length (after encryption) different than expected (%"
				        PRIsz " != %" PRIsz ")\n", SZ_C(cyphertext_len), SZ_C(v.cyphertext_len));
				ret = 5;
				break;
			}

			if (memcmp(v.cyphertext, cyphertext_p, v.cyphertext_len))
			{
				size_t i;

				fprintf(stderr, "ERROR: Output cyphertext different than expected (");
				for (i = 0; i < cyphertext_len; i++)
				{
					if (i != 0 && i % 16 == 0)
					{
						fprintf(stderr, " ");
					}
					fprintf(stderr, "%02x", cyphertext_p[i] & 0xFF);
				}
				fprintf(stderr, " != ");
				for (i = 0; i < v.cyphertext_len; i++)
				{
					if (i != 0 && i % 16 == 0)
					{
						fprintf(stderr, " ");
					}
					fprintf(stderr, "%02x", v.cyphertext[i] & 0xFF);
				}
				fprintf(stderr, ")\n");

				ret = 6;
				break;
			}
		}
		while(0);

		free(cyphertext_p);
		return ret;
	}
}

static int test_cypher_decrypt(int cypher, struct test_cypher_vector const v)
{
	size_t plaintext_len;
	int res;

	if ((res = NATIVECRYPTO_NAME(decrypt)(NULL, &plaintext_len, cypher, v.key,
	                                      v.key_len, v.iv,
	                                      v.iv_len, v.cyphertext, v.cyphertext_len)) != NATIVECRYPTO_OK)
	{
		fprintf(stderr,
		        "ERROR: Unable to determine plaintext length (return value %d != %d)\n", res,
		        NATIVECRYPTO_OK);
		return 1;
	}

	if (v.plaintext_len != plaintext_len)
	{
		fprintf(stderr,
		        "ERROR: Output plaintext length (before decryption) different than expected (%"
		        PRIsz " != %" PRIsz ")\n", SZ_C(plaintext_len), SZ_C(v.plaintext_len));
		return 2;
	}

	{
		char * plaintext_p = NULL;
		int ret = 0;

		plaintext_p = (char *) malloc(v.plaintext_len);

		do
		{
			if (NULL == plaintext_p)
			{
				fprintf(stderr, "ERROR: Unable to allocate %" PRIsz
				        " bytes for the plaintext\n", SZ_C(v.plaintext_len));
				ret = 3;
				break;
			}

			if ((res = NATIVECRYPTO_NAME(decrypt)(plaintext_p, &plaintext_len, cypher,
			                                      v.key, v.key_len, v.iv,
			                                      v.iv_len, v.cyphertext, v.cyphertext_len)) !=
			        NATIVECRYPTO_OK)
			{
				fprintf(stderr, "ERROR: Unable to perform decryption (return value %d != %d)\n",
				        res, NATIVECRYPTO_OK);
				ret = 4;
				break;
			}

			if (v.plaintext_len != plaintext_len)
			{
				fprintf(stderr,
				        "ERROR: Output plaintext length (after decryption) different than expected (%"
				        PRIsz " != %" PRIsz ")\n", SZ_C(plaintext_len), SZ_C(v.plaintext_len));
				ret = 5;
				break;
			}

			if (memcmp(v.plaintext, plaintext_p, v.plaintext_len))
			{
				size_t i;

				fprintf(stderr, "ERROR: Output plaintext different than expected (");
				for (i = 0; i < plaintext_len; i++)
				{
					if (i != 0 && i % 16 == 0)
					{
						fprintf(stderr, " ");
					}
					fprintf(stderr, "%02x", plaintext_p[i] & 0xFF);
				}
				fprintf(stderr, " != ");
				for (i = 0; i < v.plaintext_len; i++)
				{
					if (i != 0 && i % 16 == 0)
					{
						fprintf(stderr, " ");
					}
					fprintf(stderr, "%02x", v.plaintext[i] & 0xFF);
				}
				fprintf(stderr, ")\n");

				ret = 6;
				break;
			}
		}
		while(0);

		free(plaintext_p);
		return ret;
	}
}

int test_cypher(int cypher, struct test_cypher_vector const v)
{
	volatile int re, rd;

	re = test_cypher_encrypt(cypher, v);
	rd = test_cypher_decrypt(cypher, v);


	return re | rd;
}

int test_cypher_group(struct test_cypher_vector_group const * const vg,
                      size_t const vg_len)
{
	int pres, f = 0;
	size_t i, cur = 0;

	size_t total = 0;

	for(i = 0; i < vg_len; i++)
	{
		total += vg[i].vectors_len;
	}

	{
		char buf[64];
#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
		pres = snprintf(buf, sizeof(buf), "%" PRIsz, SZ_C(total));
#else
		pres = sprintf(buf, "%" PRIsz, SZ_C(total));
#endif
	}

	for(i = 0; i < vg_len; i++)
	{
		size_t j;
		int r;

		printf("== %s ==\n", vg[i].description);

		for (j = 0; j < vg[i].vectors_len; cur++, j++)
		{
			r = test_cypher(vg[i].cypher, vg[i].vectors[j]);
			printf("Test %.*" PRIsz "/%" PRIsz ": %s\t%s\n", pres, SZ_C((cur + 1)),
			       SZ_C(total), (r == 0) ? "PASS" : "FAIL", vg[i].vectors[j].description);
			if (r != 0)
			{
				f |= 1;
			}
		}

		printf("\n");
	}

	return (f == 0);
}
