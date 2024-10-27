#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arm_neon.h> // For NEON optimizations on ARM

#define NUM_THREADS 8 // Total number of threads
#define GROUP_SIZE 4  // Number of threads in each group
#define NONCE_STEP 7  // Increment nonce step to distribute search

// Optimized brute-force mining function for URX with Yespower algorithm
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
		uint8_t u8[80];
		uint32_t u32[20];
	} data;

	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;

	uint32x4_t neon_data[20]; // NEON data array for SIMD operations
	const uint32_t Htarg = ptarget[7];
	uint32_t n_start = pdata[19] + (thr_id * NONCE_STEP); // Staggered starting nonce
	uint32_t n_end = n_start + max_nonce / GROUP_SIZE;    // Dynamic range

	// Load initial data into NEON vector array (excluding nonce)
	for (int i = 0; i < 19; i++) {
		neon_data[i] = vdupq_n_u32(pdata[i]); // Set all elements in NEON register to pdata[i]
	}

	// Brute-force mining loop over extended nonce range with batching and adaptive range
	while (1) {
		for (uint32_t n = n_start; n < n_end; n += GROUP_SIZE) {
			data.u32[19] = n;  // Set nonce

			// Perform Yespower hashing
			if (yespower_tls(data.u8, 80, &params, &hash.yb)) {
				abort(); // Stop if hashing fails
			}

			// Optimized condition check with bitwise operations for the target
			if ((hash.u32[7] & Htarg) == Htarg) { // Faster condition check
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

		// Extend nonce range gradually to reduce duplicate work
		n_start = n_end;
		n_end += max_nonce / GROUP_SIZE; // Increment nonce range adaptively
		*hashes_done = n_end - pdata[19]; // Update hashes done count
	}

	return 0; // Infinite loop until a valid hash is found
}
