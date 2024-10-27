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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
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
		uint8_t u8[8];
		uint32_t u32[20];
	} data[2]; // Array for two hash attempts
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash[2]; // Array for two hashes
	uint32_t n[2]; // Nonces for two attempts
	const uint32_t Htarg = ptarget[7];
	int i;

	// Initialize nonces for both hash attempts
	n[0] = pdata[19] - 1;
	n[1] = n[0] + 1; // Second nonce starts just after the first

	for (i = 0; i < 19; i++) {
		be32enc(&data[0].u32[i], pdata[i]);
		be32enc(&data[1].u32[i], pdata[i]); // Initialize second data as well
	}

	do {
		for (int j = 0; j < 2; j++) {
			be32enc(&data[j].u32[19], n[j]); // Set current nonce for each hash attempt

			if (yespower_tls(data[j].u8, 80, &params, &hash[j].yb)) {
				abort();
			}

			if (le32dec(&hash[j].u32[7]) <= Htarg) {
				for (i = 0; i < 7; i++)
					hash[j].u32[i] = le32dec(&hash[j].u32[i]);
				if (fulltest(hash[j].u32, ptarget)) {
					*hashes_done += 1; // Count the found hash
					pdata[19] = n[j]; // Update the nonce
					return 1;
				}
			}
			n[j] += 2; // Increment nonces for the next iteration
		}
	} while ((n[0] < max_nonce || n[1] < max_nonce) && !work_restart[thr_id].restart);

	*hashes_done += (n[0] - pdata[19]) + (n[1] - pdata[19]) / 2; // Count total hashes done
	pdata[19] = n[0]; // Update pdata with the last processed nonce
	return 0;
}
