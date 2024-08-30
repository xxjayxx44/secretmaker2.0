#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

#define NUM_THREADS 8  // Number of threads to use
#define HALF_THREADS (NUM_THREADS / 2)

typedef struct {
    int thr_id;
    uint32_t *pdata;
    const uint32_t *ptarget;
    uint32_t max_nonce;
    unsigned long *hashes_done;
    int randomized;
} thread_data_t;

static const yespower_params_t params = {
    .version = YESPOWER_1_0,
    .N = 2048,
    .r = 32,
    .pers = (const uint8_t *)"UraniumX",
    .perslen = 8
};

void *scanhash_urx_yespower_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int thr_id = data->thr_id;
    uint32_t *pdata = data->pdata;
    const uint32_t *ptarget = data->ptarget;
    uint32_t max_nonce = data->max_nonce;
    unsigned long *hashes_done = data->hashes_done;
    int randomized = data->randomized;

    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } hash_data;

    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    for (i = 0; i < 19; i++)
        be32enc(&hash_data.u32[i], pdata[i]);

    do {
        uint32_t nonce = randomized ? rand() : ++n;
        be32enc(&hash_data.u32[19], nonce);

        if (yespower_tls(hash_data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = nonce - pdata[19] + 1;
                pdata[19] = nonce;
                return (void *)1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return (void *)0;
}

int main(int argc, char **argv) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    uint32_t pdata[20] = {0};  // Initialize with appropriate values
    uint32_t ptarget[8] = {0}; // Initialize with appropriate values
    unsigned long hashes_done[NUM_THREADS] = {0};
    uint32_t max_nonce = 0xFFFFFFFF;

    // Initialize pdata and ptarget with actual values

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thr_id = i;
        thread_data[i].pdata = pdata;
        thread_data[i].ptarget = ptarget;
        thread_data[i].max_nonce = max_nonce;
        thread_data[i].hashes_done = &hashes_done[i];
        thread_data[i].randomized = (i >= HALF_THREADS) ? 1 : 0;

        if (pthread_create(&threads[i], NULL, scanhash_urx_yespower_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        void *result;
        if (pthread_join(threads[i], &result) != 0) {
            perror("pthread_join");
            return 1;
        }
        if ((int)result == 1) {
            printf("Thread %d found a valid hash\n", i);
        }
    }

    return 0;
}
