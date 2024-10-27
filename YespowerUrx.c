
#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>  // Include pthread library

#define NUM_THREADS 8  // Adjust based on available CPU cores

typedef struct {
    int thr_id;
    uint32_t *pdata;
    const uint32_t *ptarget;
    uint32_t max_nonce;
    unsigned long *hashes_done;
    int found;
    uint32_t nonce_found;
} thread_data_t;

// Worker function for each thread
void *worker(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

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
    } thread_data __attribute__((aligned(32)));

    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash __attribute__((aligned(32)));

    uint32_t n = data->pdata[19] - 1;
    const uint32_t Htarg = le32dec(&data->ptarget[7]);
    unsigned i;

    for (i = 0; i < 19; i++) {
        be32enc(&thread_data.u32[i], data->pdata[i]);
    }

    do {
        be32enc(&thread_data.u32[19], ++n);

        if (yespower_tls(thread_data.u8, 80, &params, &hash.yb))
            pthread_exit(NULL);

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, data->ptarget)) {
                *(data->hashes_done) = n - data->pdata[19] + 1;
                data->pdata[19] = n;
                data->found = 1;
                data->nonce_found = n;
                pthread_exit(NULL);
            }
        }
    } while (n < data->max_nonce);

    *(data->hashes_done) = n - data->pdata[19] + 1;
    data->pdata[19] = n;
    pthread_exit(NULL);
}

// Main function that launches threads
int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    int found = 0;
    uint32_t nonce_found = 0;

    // Initialize and create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thr_id = i;
        thread_data[i].pdata = pdata;
        thread_data[i].ptarget = ptarget;
        thread_data[i].max_nonce = max_nonce;
        thread_data[i].hashes_done = hashes_done;
        thread_data[i].found = 0;
        thread_data[i].nonce_found = 0;

        pthread_create(&threads[i], NULL, worker, (void *)&thread_data[i]);
    }

    // Join threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (thread_data[i].found) {
            found = 1;
            nonce_found = thread_data[i].nonce_found;
        }
    }

    if (found) {
        pdata[19] = nonce_found;
        return 1;
    }
    return 0;
}
