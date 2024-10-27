#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arm_neon.h> // NEON for ARM optimizations

#define NONCE_BATCH_SIZE 16 // Batch size for nonce processing
#define UNROLL_FACTOR 8      // Loop unrolling factor for maximum throughput

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

    uint32_t n = pdata[19];           // Start nonce
    const uint32_t Htarg = ptarget[7]; // Target threshold
    uint32x4_t target_vec = vdupq_n_u32(Htarg); // NEON vector for target comparison
    uint32x4_t nonce_base = vdupq_n_u32(n); // Base nonce for NEON operations

    // Load initial data for hashing
    uint32x4_t neon_data[20];
    for (int i = 0; i < 19; i++) {
        neon_data[i] = vdupq_n_u32(pdata[i]);
    }

    // Main mining loop with extreme batch processing
    while (n < max_nonce) {
        for (int j = 0; j < UNROLL_FACTOR; j++) {
            uint32x4_t nonce_vec = vaddq_u32(nonce_base, vdupq_n_u32(j * NONCE_BATCH_SIZE)); // Calculate nonce vector

            // Store nonce values in data array
            vst1q_u32(&data.u32[19], nonce_vec);

            // Perform Yespower hashing on batched data
            if (yespower_tls(data.u8, 80, &params, &hash.yb))
                abort();

            // Load hash results into NEON register
            uint32x4_t hash_vec = vld1q_u32(hash.u32);
            // Compare hash results with target
            uint32x4_t cmp_result = vcleq_u32(hash_vec, target_vec); 

            // Check if any of the hashes in the batch met the target condition
            uint32_t result_mask = vgetq_lane_u32(cmp_result, 0) | 
                                   vgetq_lane_u32(cmp_result, 1) |
                                   vgetq_lane_u32(cmp_result, 2) |
                                   vgetq_lane_u32(cmp_result, 3);

            if (result_mask) {
                for (int i = 0; i < NONCE_BATCH_SIZE; i++) {
                    data.u32[19] = n + j * NONCE_BATCH_SIZE + i;
                    if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                    // Check if hash meets target
                    if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (int k = 0; k < 7; k++)
                            hash.u32[k] = le32dec(&hash.u32[k]);

                        // Final hash validity check
                        if (fulltest(hash.u32, ptarget)) {
                            *hashes_done = (n + j * NONCE_BATCH_SIZE + i) - pdata[19] + 1;
                            pdata[19] = n + j * NONCE_BATCH_SIZE + i;
                            return 1; // Valid hash found
                        }
                    }
                }
            }
        }
        n += NONCE_BATCH_SIZE * UNROLL_FACTOR;
    }

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
