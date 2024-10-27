#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arm_neon.h> // NEON for ARM optimizations
#include <stdio.h>    // For printf

#define NONCE_BATCH_SIZE 8 // Number of nonces processed per loop iteration
#define UNROLL_FACTOR 4    // Additional unrolling for efficiency

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

    // Dynamically allocate memory to prevent stack overflow
    uint8_t *data_u8 = (uint8_t *)malloc(80 * sizeof(uint8_t));
    uint32_t *hash_u32 = (uint32_t *)malloc(7 * sizeof(uint32_t));
    if (!data_u8 || !hash_u32) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0; // Early return in case of failure
    }

    uint32_t n = pdata[19];          // Start nonce
    const uint32_t Htarg = ptarget[7]; // Target threshold
    uint32x4_t target_vec = vdupq_n_u32(Htarg); // NEON vector for target comparison

    // Load initial data and prepare for NEON
    uint32x4_t neon_data[20];
    for (int i = 0; i < 19; i++) {
        neon_data[i] = vdupq_n_u32(pdata[i]);
    }

    // Main mining loop with batch processing and extensive unrolling
    while (n < max_nonce) {
        for (int j = 0; j < UNROLL_FACTOR; j++) {
            // Correctly calculate nonce_vector using j
            uint32x4_t nonce_vec = vaddq_u32(vdupq_n_u32(n), vdupq_n_u32(j * NONCE_BATCH_SIZE)); // Correct nonce calculation

            // Store nonce values in data array
            vst1q_u32((uint32_t *)&data_u8[76], nonce_vec); // Last 4 bytes hold nonce

            // Perform Yespower hashing on batched data
            if (yespower_tls(data_u8, 80, &params, (yespower_binary_t *)hash_u32)) {
                fprintf(stderr, "Hashing failed\n");
                free(data_u8); // Free allocated memory
                free(hash_u32); // Free allocated memory
                return 0; // Return 0 if hashing fails
            }

            // Bitwise comparison for multiple nonces in a batch
            uint32x4_t hash_vec = vld1q_u32(hash_u32);
            uint32x4_t cmp_result = vcleq_u32(hash_vec, target_vec); // Compare hash to target

            // Check if any of the hashes in the batch met the target condition
            uint64_t result_mask = vget_lane_u64(vreinterpret_u64_u32(vorr_u32(vget_low_u32(cmp_result), vget_high_u32(cmp_result))), 0);
            if (result_mask != 0) {
                for (int i = 0; i < NONCE_BATCH_SIZE; i++) {
                    // Reload and verify in sequence if a valid nonce is found
                    data_u8[76] = (uint8_t)(n + j * NONCE_BATCH_SIZE + i); // Correct nonce assignment
                    if (yespower_tls(data_u8, 80, &params, (yespower_binary_t *)hash_u32)) {
                        fprintf(stderr, "Hashing failed for nonce %u\n", (n + j * NONCE_BATCH_SIZE + i));
                        free(data_u8); // Free allocated memory
                        free(hash_u32); // Free allocated memory
                        return 0; // Return 0 if hashing fails
                    }

                    if (le32dec(&hash_u32[7]) <= Htarg) {
                        for (int k = 0; k < 7; k++) {
                            hash_u32[k] = le32dec(&hash_u32[k]);
                        }

                        // Final hash validity check
                        if (fulltest(hash_u32, ptarget)) {
                            *hashes_done = (n + j * NONCE_BATCH_SIZE + i) - pdata[19] + 1;
                            pdata[19] = n + j * NONCE_BATCH_SIZE + i;
                            free(data_u8); // Free allocated memory
                            free(hash_u32); // Free allocated memory
                            return 1; // Valid hash found
                        }
                    }
                }
            }
        }
        n += NONCE_BATCH_SIZE * UNROLL_FACTOR; // Increment nonce for the next batch
    }

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;

    // Clean up memory before returning
    free(data_u8);
    free(hash_u32);
    return 0;
}
