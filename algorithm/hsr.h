#ifndef HSR_H
#define HSR_H

#include "miner.h"

extern int hsr_test(unsigned char *pdata, const unsigned char *ptarget,
			uint32_t nonce);
extern void hsr_regenhash(struct work *work);

#endif /* HSR_H */