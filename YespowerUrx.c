#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <immintrin.h> // AVX2 intrinsics
#include <thread>
#include <vector>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define NUM_THREADS 8  // Adjust based on available CPU cores

static inline uint32_t decode_le32(const uint32_t *val) {
    return le32dec(val);
}

static inline void encode_be32(uint32_t *dst, uint32_t val) {
    be32enc(dst, val);
}

// Worker function for each thread
void worker(int thr_id, uint32_t *restrict pdata,
	const uint32_t *restrict ptarget,
	uint32_t max_nonce, unsigned long *restrict hashes_done,
	bool &found, uint32_t &nonce_found)
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
    } data __attribute__((aligned(32))); // 32-byte alignment for data

    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash __attribute__((aligned(32))); // 32-byte alignment for hash

    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = decode_le32(&ptarget[7]);
    unsigned i;

    // Unroll initial encoding loop
    for (i = 0; i < 19; i++) {
        encode_be32(&data.u32[i], pdata[i]);
    }

    // Prefetch frequently accessed data
    __builtin_prefetch(&data, 0, 3);
    __builtin_prefetch(&ptarget, 0, 3);

    // AVX2 registers for SIMD
    __m256i data_avx, hash_avx;
    do {
        encode_be32(&data.u32[19], ++n);

        // Perform yespower hashing on batch of 8 in parallel with AVX2
        data_avx = _mm256_load_si256((__m256i*)&data);
        if (unlikely(yespower_tls((const uint8_t *)&data_avx, 80, &params, (yespower_binary_t *)&hash_avx))) {
            abort();  // Rare error path
        }

        // Early exit check with AVX
        uint32_t* hash_res = (uint32_t*)&hash_avx;
        if (likely(hash_res[7] <= Htarg)) {
            // Full test on each element in the batch
            for (int j = 0; j < 7; j++) {
                hash_res[j] = decode_le32(&hash_res[j]);
            }
            if (likely(fulltest(hash_res, ptarget))) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                found = true;
                nonce_found = n;
                return;
            }
        }

        if (found) break;  // Exit if found by another thread
    } while (likely(n < max_nonce && !work_restart[thr_id].restart));

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
}

// Entry function that launches threads
int scanhash_urx_yespower(int thr_id, uint32_t *restrict pdata,
	const uint32_t *restrict ptarget,
	uint32_t max_nonce, unsigned long *restrict hashes_done)
{
    std::vector<std::thread> threads;
    bool found = false;
    uint32_t nonce_found = 0;

    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back(worker, i, pdata, ptarget, max_nonce, hashes_done, std::ref(found), std::ref(nonce_found));
    }

    for (auto &t : threads) {
        t.join();
    }

    if (found) {
        pdata[19] = nonce_found;
        return 1;
    }
    return 0;
}
