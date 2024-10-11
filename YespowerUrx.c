#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <immintrin.h> // For SIMD intrinsics

#define NUM_THREADS 8 // Total number of threads
#define GROUP_SIZE 4  // Number of threads in each group

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
		uint8_t u8[80];  // Correct size for the data
		uint32_t u32[20];
	} data;

	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;

	const uint32_t Htarg = ptarget[7];
	uint32_t n_start = pdata[19] + (thr_id / GROUP_SIZE);
	uint32_t n_end = n_start + 10000; // Limit initial range to 10,000 nonces for regular mining

	// Step 1: Regular mining attempt in a limited range of nonces
	for (int i = 0; i < 19; i++) {
		be32enc(&data.u32[i], pdata[i]);
	}

	// Normal mining loop
	for (uint32_t n = n_start; n < n_end; n += GROUP_SIZE) {
		be32enc(&data.u32[19], n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb)) {
			abort(); // Stop if the hash fails
		}

		// Check if the resulting hash is valid
		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (int i = 0; i < 7; i++) {
				hash.u32[i] = le32dec(&hash.u32[i]);
			}
			// If valid, return success
			if (fulltest(hash.u32, ptarget)) {
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = n; // Update current nonce
				return 1; // Found a valid hash
			}
		}
	}

	// Step 2: If no valid hash found, switch to brute-forcing

	n_start = n_end;  // Continue where the normal mining ended
	n_end = max_nonce;  // Use the full range of nonces for brute-forcing

	// Brute-force mining loop
	while (1) {
		for (uint32_t n = n_start; n < n_end; n += GROUP_SIZE) {
			be32enc(&data.u32[19], n);

			if (yespower_tls(data.u8, 80, &params, &hash.yb)) {
				abort(); // Stop if hashing fails
			}

			// Check if the resulting hash is valid
			if (le32dec(&hash.u32[7]) <= Htarg) {
				for (int i = 0; i < 7; i++) {
					hash.u32[i] = le32dec(&hash.u32[i]);
				}
				// If valid, return success
				if (fulltest(hash.u32, ptarget)) {
					*hashes_done = n - pdata[19] + 1;
					pdata[19] = n; // Update current nonce
					return 1; // Found valid hash
				}
			}
		}

		// Extend the nonce range for further brute-forcing
		n_start = n_end;
		n_end += max_nonce; // Increase range for next brute-force iteration
		*hashes_done = n_end - pdata[19]; // Periodically update hashes done
	}

	return 0; // No valid hash found (although brute-forcing will continue indefinitely)
}
