/*
 * Copyright 2011 ArtForz, 2011-2014 pooler, 2018 The Resistance developers, 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is loosely based on a tiny portion of pooler's cpuminer scrypt.c.
 */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

#define BATCH_SIZE 2

typedef struct {
    int thr_id;
    uint32_t *pdata;
    const uint32_t *ptarget;
    uint32_t max_nonce;
    unsigned long *hashes_done;
} thread_data_t;

static const yespower_params_t params = {
    .version = YESPOWER_1_0,
    .N = 2048,
    .r = 32,
    .pers = (const uint8_t *)"UraniumX",
    .perslen = 8
};

void *scan_hash(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint32_t n = data->pdata[19] - 1;
    const uint32_t Htarg = data->ptarget[7];

    union {
        uint8_t u8[8];
        uint32_t u32[20];
    } batch_data[BATCH_SIZE];

    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

    for (int i = 0; i < 19; i++) {
        be32enc(&batch_data[0].u32[i], data->pdata[i]);
    }

    while (n < data->max_nonce) {
        for (int j = 0; j < BATCH_SIZE && n < data->max_nonce; ++j) {
            be32enc(&batch_data[j].u32[19], ++n);
            if (yespower_tls(batch_data[j].u8, 80, &params, &hash.yb)) {
                // Handle error, possibly log or abort
                abort();
            }

            if (le32dec(&hash.u32[7]) <= Htarg) {
                for (int k = 0; k < 7; k++) {
                    hash.u32[k] = le32dec(&hash.u32[k]);
                }
                if (fulltest(hash.u32, data->ptarget)) {
                    *(data->hashes_done) = n - data->pdata[19] + 1;
                    data->pdata[19] = n;
                    return NULL;  // Valid hash found, exit thread
                }
            }
        }
    }

    *(data->hashes_done) = n - data->pdata[19] + 1;
    data->pdata[19] = n;
    return NULL;
}

int scanhash_urx_yespower(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done) {
    pthread_t threads[BATCH_SIZE];
    thread_data_t thread_data[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        thread_data[i] = (thread_data_t){thr_id, pdata, ptarget, max_nonce, hashes_done};
        pthread_create(&threads[i], NULL, scan_hash, &thread_data[i]);
    }

    for (int i = 0; i < BATCH_SIZE; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
