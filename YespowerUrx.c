#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h> // For seeding random number generator

// Define the number of threads, adjust as needed
#define NUM_THREADS 4 // Set this to the number of threads you plan to use

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = (const uint8_t *)"UraniumX",
		.perslen = 8
	};
	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data;
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;
	uint32_t n_start = pdata[19] + thr_id; // Start nonce for this thread
	const uint32_t Htarg = ptarget[7];
	int i;

	// Seed the random number generator only once
	if (thr_id == 0) {
		srand(time(NULL));
	}

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	// Calculate how many nonces each thread will handle
	uint32_t total_nonces_per_thread = (max_nonce - pdata[19]) / NUM_THREADS;
	uint32_t n_end = n_start + total_nonces_per_thread;

	// Ensure we don't exceed max_nonce
	if (n_end > max_nonce) {
		n_end = max_nonce;
	}

	// Normal mining
	for (uint32_t n = n_start; n < n_end; n += NUM_THREADS) {
		be32enc(&data.u32[19], n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			if (fulltest(hash.u32, ptarget)) {
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = n;
				return 1;
			}
		}
	}

	*hashes_done = n_end - pdata[19];
	pdata[19] = n_end - 1; // Update nonce
	return 0;
}
