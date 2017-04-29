#ifndef TIMETRAVEL10_H
#define TIMETRAVEL10_H

#include "miner.h"

#define TIMETRAVEL10_BASE_TIMESTAMP 1492973331 // BitCore: Genesis Timestamp
#define TIMETRAVEL10_COUNT 10                  // BitCore: TIMETRAVEL10_COUNT of 10
#define TIMETRAVEL10_COUNT_PERMUTATIONS 40320  // BitCore: TIMETRAVEL10_COUNT!

extern uint32_t timetravel_permutations[];
extern int timetravel10_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);
extern void timetravel10_regenhash(struct work *work);

#endif /* TIMETRAVEL10_H */
