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
#include "aes.h"
#include "test_cypher.h"

#define AES_TEST_VECTOR(DESCRIPTION, KEY, IV, PLAINTEXT, CYPHERTEXT) { \
    (DESCRIPTION), \
    (KEY), \
    sizeof(KEY) - 1, \
    (IV), \
    sizeof(IV) - 1, \
    (PLAINTEXT), \
    sizeof(PLAINTEXT) - 1, \
    (CYPHERTEXT), \
    sizeof(CYPHERTEXT) - 1, \
}


static struct test_cypher_vector const aes_ecb_test_vectors[] =
{
	/* AES-128 */
	AES_TEST_VECTOR(
	    "AES-128 ECB NIST",
	    ("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	    (""),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97" "\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf" "\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88" "\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4")
	),
	/* AES-192 */
	AES_TEST_VECTOR(
	    "AES-192 ECB NIST",
	    ("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	    (""),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc" "\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef" "\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e" "\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e")
	),
	/* AES-256 */
	AES_TEST_VECTOR(
	    "AES-256 ECB NIST",
	    ("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	    (""),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8" "\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70" "\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d" "\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7")
	),
};

static struct test_cypher_vector const aes_ctr_test_vectors[] =
{
	/* AES-128 */
	AES_TEST_VECTOR(
	    "AES-128 CTR NIST",
	    ("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee")
	),
	AES_TEST_VECTOR(
	    "AES-128 CTR NIST (incomplete last block)",
	    ("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00")
	),
	AES_TEST_VECTOR(
	    "AES-128 CTR RFC 3686 Test Vector #1",
	    ("\xae\x68\x52\xf8\x12\x10\x67\xcc\x4b\xf7\xa5\x76\x55\x77\xf3\x9e"),
	    ("\x00\x00\x00\x30" "\x00\x00\x00\x00\x00\x00\x00\x00" "\0\0\0\1"),
	    ("Single block msg"),
	    ("\xe4\x09\x5d\x4f\xb7\xa7\xb3\x79\x2d\x61\x75\xa3\x26\x13\x11\xb8")
	),
	AES_TEST_VECTOR(
	    "AES-128 CTR RFC 3686 Test Vector #2",
	    ("\x7e\x24\x06\x78\x17\xfa\xe0\xd7\x43\xd6\xce\x1f\x32\x53\x91\x63"),
	    ("\x00\x6c\xb6\xdb" "\xc0\x54\x3b\x59\xda\x48\xd9\x0b" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	    ("\x51\x04\xa1\x06\x16\x8a\x72\xd9\x79\x0d\x41\xee\x8e\xda\xd3\x88\xeb\x2e\x1e\xfc\x46\xda\x57\xc8\xfc\xe6\x30\xdf\x91\x41\xbe\x28")
	),
	AES_TEST_VECTOR(
	    "AES-128 CTR RFC 3686 Test Vector #3",
	    ("\x76\x91\xbe\x03\x5e\x50\x20\xa8\xac\x6e\x61\x85\x29\xf9\xa0\xdc"),
	    ("\x00\xe0\x01\x7b" "\x27\x77\x7f\x3f\x4a\x17\x86\xf0" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23"),
	    ("\xc1\xcf\x48\xa8\x9f\x2f\xfd\xd9\xcf\x46\x52\xe9\xef\xdb\x72\xd7\x45\x40\xa4\x2b\xde\x6d\x78\x36\xd5\x9a\x5c\xea\xae\xf3\x10\x53\x25\xb2\x07\x2f")
	),
	/* AES-192 */
	AES_TEST_VECTOR(
	    "AES-192 CTR NIST",
	    ("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50")
	),
	AES_TEST_VECTOR(
	    "AES-192 CTR NIST (incomplete last block)",
	    ("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6")
	),
	AES_TEST_VECTOR(
	    "AES-192 CTR RFC 3686 Test Vector #4",
	    ("\x16\xaf\x5b\x14\x5f\xc9\xf5\x79\xc1\x75\xf9\x3e\x3b\xfb\x0e\xed\x86\x3d\x06\xcc\xfd\xb7\x85\x15"),
	    ("\x00\x00\x00\x48" "\x36\x73\x3c\x14\x7d\x6d\x93\xcb" "\0\0\0\1"),
	    ("Single block msg"),
	    ("\x4b\x55\x38\x4f\xe2\x59\xc9\xc8\x4e\x79\x35\xa0\x03\xcb\xe9\x28")
	),
	AES_TEST_VECTOR(
	    "AES-192 CTR RFC 3686 Test Vector #5",
	    ("\x7c\x5c\xb2\x40\x1b\x3d\xc3\x3c\x19\xe7\x34\x08\x19\xe0\xf6\x9c\x67\x8c\x3d\xb8\xe6\xf6\xa9\x1a"),
	    ("\x00\x96\xb0\x3b" "\x02\x0c\x6e\xad\xc2\xcb\x50\x0d" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	    ("\x45\x32\x43\xfc\x60\x9b\x23\x32\x7e\xdf\xaa\xfa\x71\x31\xcd\x9f\x84\x90\x70\x1c\x5a\xd4\xa7\x9c\xfc\x1f\xe0\xff\x42\xf4\xfb\x00")
	),
	AES_TEST_VECTOR(
	    "AES-192 CTR RFC 3686 Test Vector #6",
	    ("\x02\xbf\x39\x1e\xe8\xec\xb1\x59\xb9\x59\x61\x7b\x09\x65\x27\x9b\xf5\x9b\x60\xa7\x86\xd3\xe0\xfe"),
	    ("\x00\x07\xbd\xfd" "\x5c\xbd\x60\x27\x8d\xcc\x09\x12" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23"),
	    ("\x96\x89\x3f\xc5\x5e\x5c\x72\x2f\x54\x0b\x7d\xd1\xdd\xf7\xe7\x58\xd2\x88\xbc\x95\xc6\x91\x65\x88\x45\x36\xc8\x11\x66\x2f\x21\x88\xab\xee\x09\x35")
	),
	/* AES-256 */
	AES_TEST_VECTOR(
	    "AES-256 CTR NIST",
	    ("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6")
	),
	AES_TEST_VECTOR(
	    "AES-256 CTR NIST (incomplete last block)",
	    ("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	    ("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79")
	),
	AES_TEST_VECTOR(
	    "AES-256 CTR RFC 3686 Test Vector #7",
	    ("\x77\x6b\xef\xf2\x85\x1d\xb0\x6f\x4c\x8a\x05\x42\xc8\x69\x6f\x6c\x6a\x81\xaf\x1e\xec\x96\xb4\xd3\x7f\xc1\xd6\x89\xe6\xc1\xc1\x04"),
	    ("\x00\x00\x00\x60" "\xdb\x56\x72\xc9\x7a\xa8\xf0\xb2" "\0\0\0\1"),
	    ("Single block msg"),
	    ("\x14\x5a\xd0\x1d\xbf\x82\x4e\xc7\x56\x08\x63\xdc\x71\xe3\xe0\xc0")
	),
	AES_TEST_VECTOR(
	    "AES-256 CTR RFC 3686 Test Vector #8",
	    ("\xf6\xd6\x6d\x6b\xd5\x2d\x59\xbb\x07\x96\x36\x58\x79\xef\xf8\x86\xc6\x6d\xd5\x1a\x5b\x6a\x99\x74\x4b\x50\x59\x0c\x87\xa2\x38\x84"),
	    ("\x00\xfa\xac\x24" "\xc1\x58\x5e\xf1\x5a\x43\xd8\x75" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	    ("\xf0\x5e\x23\x1b\x38\x94\x61\x2c\x49\xee\x00\x0b\x80\x4e\xb2\xa9\xb8\x30\x6b\x50\x8f\x83\x9d\x6a\x55\x30\x83\x1d\x93\x44\xaf\x1c")
	),
	AES_TEST_VECTOR(
	    "AES-256 CTR RFC 3686 Test Vector #9",
	    ("\xff\x7a\x61\x7c\xe6\x91\x48\xe4\xf1\x72\x6e\x2f\x43\x58\x1d\xe2\xaa\x62\xd9\xf8\x05\x53\x2e\xdf\xf1\xee\xd6\x87\xfb\x54\x15\x3d"),
	    ("\x00\x1c\xc5\xb7" "\x51\xa5\x1d\x70\xa1\xc1\x11\x48" "\0\0\0\1"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23"),
	    ("\xeb\x6c\x52\x82\x1d\x0b\xbb\xf7\xce\x75\x94\x46\x2a\xca\x4f\xaa\xb4\x07\xdf\x86\x65\x69\xfd\x07\xf4\x8c\xc0\xb5\x83\xd6\x07\x1f\x1e\xc0\xe6\xb8")
	),
};

static struct test_cypher_vector const aes_cbc_pkcs7_test_vectors[] =
{
	/* AES-128 */
	AES_TEST_VECTOR(
	    "AES-128 CBC with PKCS#7 padding NIST",
	    ("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7\x8c\xb8\x28\x07\x23\x0e\x13\x21\xd3\xfa\xe0\x0d\x18\xcc\x20\x12")
	),
	AES_TEST_VECTOR(
	    "AES-128 CBC with PKCS#7 padding NIST (incomplete last block)",
	    ("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16\x09\x52\x3d\x36\x2e\x3d\xe6\x4b\x0b\x03\x1d\xb0\x19\x53\x36\xd9")
	),
	AES_TEST_VECTOR(
	    "AES-128 CBC with PKCS#7 padding RFC 3602 Case #1",
	    ("\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06"),
	    ("\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41"),
	    ("Single block msg"),
	    ("\xe3\x53\x77\x9c\x10\x79\xae\xb8\x27\x08\x94\x2d\xbe\x77\x18\x1a" "\xb9\x7c\x82\x5e\x1c\x78\x51\x46\x54\x2d\x39\x69\x41\xbc\xe5\x5d")
	),
	AES_TEST_VECTOR(
	    "AES-128 CBC with PKCS#7 padding RFC 3602 Case #2",
	    ("\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a"),
	    ("\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	    ("\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1" "\xbc\xfd\x81\x02\x22\x02\x36\x6b\xde\x6d\xd2\x60\xa1\x58\x41\xa1")
	),
	AES_TEST_VECTOR(
	    "AES-128 CBC with PKCS#7 padding RFC 3602 Case #3",
	    ("\x6c\x3e\xa0\x47\x76\x30\xce\x21\xa2\xce\x33\x4a\xa7\x46\xc2\xcd"),
	    ("\xc7\x82\xdc\x4c\x09\x8c\x66\xcb\xd9\xcd\x27\xd8\x25\x68\x2c\x81"),
	    ("This is a 48-byte message (exactly 3 AES blocks)"),
	    ("\xd0\xa0\x2b\x38\x36\x45\x17\x53\xd4\x93\x66\x5d\x33\xf0\xe8\x86\x2d\xea\x54\xcd\xb2\x93\xab\xc7\x50\x69\x39\x27\x67\x72\xf8\xd5\x02\x1c\x19\x21\x6b\xad\x52\x5c\x85\x79\x69\x5d\x83\xba\x26\x84" "\xd2\x48\xb3\xe0\xf2\x38\x8c\x13\x71\x02\x84\x6e\xb0\x62\x72\xff")
	),
	/* AES-192 */
	AES_TEST_VECTOR(
	    "AES-192 CBC with PKCS#7 padding NIST",
	    ("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd\x61\x2c\xcd\x79\x22\x4b\x35\x09\x35\xd4\x5d\xd6\xa9\x8f\x81\x76")
	),
	AES_TEST_VECTOR(
	    "AES-192 CBC with PKCS#7 padding NIST (incomplete last block)",
	    ("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0\xcd\xb5\x26\x29\x4c\x4b\x8f\xb8\xad\x86\x4e\x43\x7c\xc1\xd2\x22")
	),
	/* AES-256 */
	AES_TEST_VECTOR(
	    "AES-256 CBC with PKCS#7 padding NIST",
	    ("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"),
	    ("\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b\x3f\x46\x17\x96\xd6\xb0\xd6\xb2\xe0\xc2\xa7\x2b\x4d\x80\xe6\x44")
	),
	AES_TEST_VECTOR(
	    "AES-256 CBC with PKCS#7 padding NIST (incomplete last block)",
	    ("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	    ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	    ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c"),
	    ("\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61\x15\x14\xcf\x0f\x74\xa1\x8f\xba\x43\xb8\x8e\x93\xb2\x47\x3b\xfa")
	),
};

static struct test_cypher_vector_group const aes_vg[] =
{
	{
		"AES ECB",
		NATIVECRYPTO_CYPHER_AES_ECB,
		aes_ecb_test_vectors,
		sizeof(aes_ecb_test_vectors) / sizeof(*aes_ecb_test_vectors)
	},
	{
		"AES CTR",
		NATIVECRYPTO_CYPHER_AES_CTR,
		aes_ctr_test_vectors,
		sizeof(aes_ctr_test_vectors) / sizeof(*aes_ctr_test_vectors)
	},
	{
		"AES CBC PKCS#7",
		NATIVECRYPTO_CYPHER_AES_CBC_PKCS7,
		aes_cbc_pkcs7_test_vectors,
		sizeof(aes_cbc_pkcs7_test_vectors) / sizeof(*aes_cbc_pkcs7_test_vectors)
	},
};

int main(int argc, char * * argv)
{
	int r;

	(void)argc;
	(void)argv;

	r = test_cypher_group(aes_vg, sizeof(aes_vg) / sizeof(*aes_vg));

	return (r == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
