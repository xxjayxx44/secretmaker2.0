#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define NUM_THREADS 4 // Define the number of threads used

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
	uint32_t n = pdata[19]; // Start from the current nonce
	const uint32_t Htarg = ptarget[7];
	int i;

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	// Calculate the range of nonces for this thread
	uint32_t total_nonces = max_nonce - pdata[19];
	uint32_t nonces_per_thread = total_nonces / NUM_THREADS;
	uint32_t n_start = pdata[19] + thr_id * nonces_per_thread;
	uint32_t n_end = (thr_id == NUM_THREADS - 1) ? max_nonce : n_start + nonces_per_thread;

	// Loop through the assigned range of nonces
	for (n = n_start; n < n_end; n++) {
		be32enc(&data.u32[19], n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			if (fulltest(hash.u32, ptarget)) {
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = n; // Update the current nonce
				return 1; // Found valid hash
			}
		}
	}

	*hashes_done = n_end - pdata[19]; // Update the total hashes done
	pdata[19] = n_end; // Update the current nonce
	return 0; // No valid hash found
}
