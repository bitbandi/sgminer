#ifndef VELTOR_H
#define VELTOR_H

#include "miner.h"

extern int veltor_test(unsigned char *pdata, const unsigned char *ptarget,
			uint32_t nonce);
extern void veltor_regenhash(struct work *work);
extern void veltor_prepare_work(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata);
extern void veltor_midstate(struct work *work);

#endif /* VELTOR_H */
