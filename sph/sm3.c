/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stddef.h>
#include <string.h>

#include "sph_sm3.h"

static const sph_u32 IV256[] = {
	SPH_C32(0x7380166F), SPH_C32(0x4914B2B9),
	SPH_C32(0x172442D7), SPH_C32(0xDA8A0600),
	SPH_C32(0xA96F30BC), SPH_C32(0x163138AA),
	SPH_C32(0xE38DEE4D), SPH_C32(0xB0FB0E4E)
};

void sm3_init(sph_sm3_context *sc, const sph_u32 *iv)
{
	memcpy(sc->digest, iv, sizeof sc->digest);

/*
	sc->digest[0] = 0x7380166F;
	sc->digest[1] = 0x4914B2B9;
	sc->digest[2] = 0x172442D7;
	sc->digest[3] = 0xDA8A0600;
	sc->digest[4] = 0xA96F30BC;
	sc->digest[5] = 0x163138AA;
	sc->digest[6] = 0xE38DEE4D;
	sc->digest[7] = 0xB0FB0E4E;
*/

	sc->nblocks = 0;
	sc->ptr = 0;
}

void sph_sm3_init(sph_sm3_context *cc)
{
	sm3_init((sph_sm3_context *)cc, IV256);
}

void sph_sm3_update(sph_sm3_context *sc, const void* data, size_t len)
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->buf) {
			sm3_compress(sc->digest, buf);
			sc->nblocks++;
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

void sph_sm3_close(void *cc, void *dst)
{
	sm3_final(cc, dst);
	sph_sm3_init(cc);
//	memset(cc, 0, sizeof(sph_sm3_context));
}

void sm3_final(sph_sm3_context *sc, void *dst)
{
	unsigned char *buf, *out;
	size_t ptr, i;

	buf = sc->buf;
	ptr = sc->ptr;

	buf[ptr ++] = 0x80;
	if (ptr > (sizeof sc->buf) - 8) {
		memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
		sm3_compress(sc->digest, buf);
		ptr = 0;
	}
	memset(buf + ptr, 0, (sizeof sc->buf) - 8 - ptr);

	sph_enc32be(sc->buf + (sizeof sc->buf) - 8, (sc->nblocks >> 23));
	sph_enc32be(sc->buf + (sizeof sc->buf) - 4, (sc->nblocks << 9) + (sc->ptr << 3));

	sm3_compress(sc->digest, sc->buf);
	out = dst;
	for (i = 0; i < sizeof(sc->digest)/sizeof(sc->digest[0]); i++) {
		sph_enc32be(out + 4 * i, sc->digest[i]);
	}
}

#define P0(x) ((x) ^  SPH_ROTL32((x),9)  ^ SPH_ROTL32((x),17))
#define P1(x) ((x) ^  SPH_ROTL32((x),15) ^ SPH_ROTL32((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


void sm3_compress(sph_u32 digest[8], const unsigned char block[64])
{
	int j;
	sph_u32 W[68], W1[64];
	const sph_u32 *pblock = (const sph_u32 *)block;

	sph_u32 A = digest[0];
	sph_u32 B = digest[1];
	sph_u32 C = digest[2];
	sph_u32 D = digest[3];
	sph_u32 E = digest[4];
	sph_u32 F = digest[5];
	sph_u32 G = digest[6];
	sph_u32 H = digest[7];
	sph_u32 SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = sph_dec32be_aligned(pblock + j);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ SPH_ROTL32(W[j-3],15)) ^ SPH_ROTL32(W[j - 13],7 ) ^ W[j-6];
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = SPH_ROTL32((SPH_ROTL32(A,12) + E + SPH_ROTL32(T[j],j)), 7);
		SS2 = SS1 ^ SPH_ROTL32(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = SPH_ROTL32(B,9);
		B = A;
		A = TT1;
		H = G;
		G = SPH_ROTL32(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = SPH_ROTL32((SPH_ROTL32(A,12) + E + SPH_ROTL32(T[j],j)), 7);
		SS2 = SS1 ^ SPH_ROTL32(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = SPH_ROTL32(B,9);
		B = A;
		A = TT1;
		H = G;
		G = SPH_ROTL32(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3(const unsigned char *msg, size_t msglen,
	unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sph_sm3_context ctx;

	sph_sm3_init(&ctx);
	sph_sm3_update(&ctx, msg, msglen);
	sph_sm3_close(&ctx, dgst);

	memset(&ctx, 0, sizeof(sph_sm3_context));
}
