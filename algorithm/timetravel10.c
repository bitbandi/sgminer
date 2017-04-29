/*-
* Copyright 2009 Colin Percival, 2011 ArtForz
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
* This file was originally written by Colin Percival as part of the Tarsnap
* online backup system.
*/

#include "config.h"
#include "miner.h"
#include "timetravel10.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
//#include <algorithm.h>

#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"
#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"

uint32_t timetravel_permutations[] = {
    #include "timetravel-permutations.h"
};

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context    blake;
	sph_bmw512_context      bmw;
	sph_groestl512_context  groestl;
	sph_skein512_context    skein;
	sph_jh512_context       jh;
	sph_keccak512_context   keccak;
	sph_luffa512_context    luffa;
	sph_cubehash512_context cubehash;
	sph_shavite512_context  shavite;
	sph_simd512_context     simd;
} Xhash_context_holder;

static Xhash_context_holder base_contexts;


static void init_Xhash_contexts()
{
	sph_blake512_init(&base_contexts.blake);
	sph_bmw512_init(&base_contexts.bmw);
	sph_groestl512_init(&base_contexts.groestl);
	sph_skein512_init(&base_contexts.skein);
	sph_jh512_init(&base_contexts.jh);
	sph_keccak512_init(&base_contexts.keccak);
	sph_luffa512_init(&base_contexts.luffa);
	sph_cubehash512_init(&base_contexts.cubehash);
	sph_shavite512_init(&base_contexts.shavite);
	sph_simd512_init(&base_contexts.simd);
}


static inline void xhash(void *state, const void *input , const uint32_t ntime)
{
	uint32_t permutation = timetravel_permutations[(ntime - TIMETRAVEL10_BASE_TIMESTAMP) % TIMETRAVEL10_COUNT_PERMUTATIONS];

	init_Xhash_contexts();

	Xhash_context_holder ctx;

	uint32_t hash[16], i;
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	sph_bmw512(&ctx.bmw, hash, 64);
	sph_bmw512_close(&ctx.bmw, hash);

	for (i = 0; i < (4 * (TIMETRAVEL10_COUNT-2)); i += 4) {
		switch ((permutation >> i) & 0xf) {

			case 0:
				sph_groestl512(&ctx.groestl, hash, 64);
				sph_groestl512_close(&ctx.groestl, hash);
				break;

			case 1:
				sph_skein512(&ctx.skein, hash, 64);
				sph_skein512_close(&ctx.skein, hash);
				break;

			case 2:
				sph_jh512(&ctx.jh, hash, 64);
				sph_jh512_close(&ctx.jh, hash);
				break;

			case 3:
				sph_keccak512(&ctx.keccak, hash, 64);
				sph_keccak512_close(&ctx.keccak, hash);
				break;

			case 4:
				sph_luffa512(&ctx.luffa, hash, 64);
				sph_luffa512_close(&ctx.luffa, hash);
				break;

			case 5:
				sph_cubehash512(&ctx.cubehash, hash, 64);
				sph_cubehash512_close(&ctx.cubehash, hash);
				break;

			case 6:
				sph_shavite512(&ctx.shavite, hash, 64);
				sph_shavite512_close(&ctx.shavite, hash);
				break;

			case 7:
				sph_simd512(&ctx.simd, hash, 64);
				sph_simd512_close(&ctx.simd, hash);
				break;
		}
	}

	memcpy(state, hash, 32);
}

static const uint32_t diff1targ = 0x0000ffff;


/* Used externally as confirmation of correct OCL code */
int timetravel10_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
	xhash(ohash, data, TIMETRAVEL10_BASE_TIMESTAMP);
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
		(long unsigned int)Htarg,
		(long unsigned int)diff1targ,
		(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

void timetravel10_regenhash(struct work *work)
{
	uint32_t data[20];
	uint32_t *nonce = (uint32_t *)(work->data + 76);
	uint32_t *ntime = (uint32_t *)(work->data + 68);
	uint32_t *ohash = (uint32_t *)(work->hash);

	be32enc_vect(data, (const uint32_t *)work->data, 19);
	data[19] = htobe32(*nonce);
	xhash(ohash, data, be32toh(*ntime));
}

bool scanhash_timetravel10(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
	unsigned char *pdata, unsigned char __maybe_unused *phash1,
	unsigned char __maybe_unused *phash, const unsigned char *ptarget,
	uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while (1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		xhash(ostate, data, TIMETRAVEL10_BASE_TIMESTAMP);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
			(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}




