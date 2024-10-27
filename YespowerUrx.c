#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arm_neon.h> // NEON for ARM optimizations

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

    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

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
            uint32x4_t nonce_vec = vaddq_u32(vdupq_n_u32(n), vld1q_dup_u32(&j * NONCE_BATCH_SIZE)); // Batch of nonces

            // Store nonce values in data array
            vst1q_u32(&data.u32[19], nonce_vec);

            // Perform Yespower hashing on batched data
            if (yespower_tls(data.u8, 80, &params, &hash.yb))
                abort();

            // Bitwise comparison for multiple nonces in a batch
            uint32x4_t hash_vec = vld1q_u32(hash.u32);
            uint32x4_t cmp_result = vcleq_u32(hash_vec, target_vec); // Compare hash to target

            // Check if any of the hashes in the batch met the target condition
            uint64_t result_mask = vget_lane_u64(vreinterpret_u64_u32(vorr_u32(vget_low_u32(cmp_result), vget_high_u32(cmp_result))), 0);
            if (result_mask != 0) {
                for (int i = 0; i < NONCE_BATCH_SIZE; i++) {
                    // Reload and verify in sequence if a valid nonce is found
                    data.u32[19] = n + i * NONCE_BATCH_SIZE;
                    if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                    if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (int k = 0; k < 7; k++)
                            hash.u32[k] = le32dec(&hash.u32[k]);

                        // Final hash validity check
                        if (fulltest(hash.u32, ptarget)) {
                            *hashes_done = (n + i * NONCE_BATCH_SIZE) - pdata[19] + 1;
                            pdata[19] = n + i * NONCE_BATCH_SIZE;
                            return 1;
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
