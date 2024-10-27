/*
 * Copyright 2011 ArtForz, 2011-2014 pooler, 2018 The Resistance developers, 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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

#define BATCH_SIZE 4 // Process multiple nonces at a time

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
		uint8_t u8[80]; // Size required for yespower_tls
		uint32_t u32[20];
	} data;

	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;

	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	unsigned int i;

	// Initialize data
	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	uint32_t processed_hashes = 0; // Track total processed hashes

	do {
		// Batch processing for increased throughput
		for (int j = 0; j < BATCH_SIZE && n < max_nonce; j++) {
			be32enc(&data.u32[19], ++n);

			if (yespower_tls(data.u8, sizeof(data.u8), &params, &hash.yb)) {
				abort();
			}

			if (le32dec(&hash.u32[7]) <= Htarg) {
				for (i = 0; i < 7; i++)
					hash.u32[i] = le32dec(&hash.u32[i]);

				if (fulltest(hash.u32, ptarget)) {
					*hashes_done = n - pdata[19] + 1;
					pdata[19] = n; // Update nonce
					return 1; // Found a valid hash
				}
			}
			processed_hashes++;
		}

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = processed_hashes; // Return the number of hashes processed
	pdata[19] = n; // Update last nonce attempted
	return 0; // No valid hash found
}
