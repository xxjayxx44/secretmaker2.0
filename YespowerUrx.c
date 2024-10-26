#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define NUM_THREADS 8 // Total number of threads
#define GROUP_SIZE 4  // Number of threads in each group

// Pure brute-force mining function for URX with Yespower algorithm
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
		uint8_t u8[80];  // Correct size for data
		uint32_t u32[20];
	} data;

	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;

	const uint32_t Htarg = ptarget[7]; // Extract target hash value for comparisons
	uint32_t n_start = pdata[19] + (thr_id / GROUP_SIZE); // Start nonce for brute-forcing
	uint32_t n_end = n_start + max_nonce / 10; // Initial nonce range with incremental adjustments

	// Load initial data (excluding nonce)
	for (int i = 0; i < 19; i++) {
		be32enc(&data.u32[i], pdata[i]);
	}

	// Brute-force mining loop over extended nonce range
	while (1) {
		for (uint32_t n = n_start; n < n_end; n += GROUP_SIZE) {
			be32enc(&data.u32[19], n);  // Encode nonce

			// Perform Yespower hashing
			if (yespower_tls(data.u8, 80, &params, &hash.yb)) {
				abort(); // Stop if hashing fails
			}

			// Check if hash meets target difficulty
			if (le32dec(&hash.u32[7]) <= Htarg) {
				for (int i = 0; i < 7; i++) {
					hash.u32[i] = le32dec(&hash.u32[i]);
				}
				// Validate full hash
				if (fulltest(hash.u32, ptarget)) {
					*hashes_done = n - pdata[19] + 1;
					pdata[19] = n; // Update nonce
					return 1; // Valid hash found
				}
			}
		}

		// Extend nonce range for further brute-forcing
		n_start = n_end;
		n_end += max_nonce / 10; // Increment nonce range gradually
		*hashes_done = n_end - pdata[19]; // Update hashes done count
	}

	return 0; // Return 0 if no valid hash is found (infinite brute-force loop)
}
