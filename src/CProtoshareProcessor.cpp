/*
 * CProtosharePoocessor.cpp
 *
 *  Created on: 20/12/2013
 *      Author: girino
 *
 * Copyright (c) 2014 Girino Vey.
 *
 * All code in this file is copyrighted to me, Girino Vey, and licensed under Girino's
 * Anarchist License, available at http://girino.org/license and is available on this
 * repository as the file girino_license.txt
 *
 */

#include "CProtoshareProcessor.h"
#include "sha_utils.h"
#include "OpenCLMomentumV3.h"
#include "OpenCLMomentumV4.h"
#include "OpenCLMomentumV5.h"
#include "OpenCLMomentumV6.h"
#include "OpenCLMomentum2.h"
#include "global.h"
#include <sys/mman.h>

#define repeat2(x) {x} {x}
#define repeat4(x) repeat2(x) repeat2(x)
#define repeat8(x) repeat4(x) repeat4(x)
#define repeat16(x) repeat8(x) repeat8(x)
#define repeat32(x) repeat16(x) repeat16(x)
#define repeat64(x) repeat32(x) repeat32(x)

bool protoshares_revalidateCollision(blockHeader_t* block, uint8_t* midHash,
		uint32_t indexA_orig, uint32_t indexB, uint64_t birthdayB,
		CBlockProvider* bp, sha512_func_t sha512_func, uint32_t thread_id) {
	//if( indexA > MAX_MOMENTUM_NONCE )
	//        printf("indexA out of range\n");
	//if( indexB > MAX_MOMENTUM_NONCE )
	//        printf("indexB out of range\n");
	//if( indexA == indexB )
	//        printf("indexA == indexB");

	uint8_t tempHash[32 + 4];
	uint64_t resultHash[8];
	memcpy(tempHash + 4, midHash, 32);
	if (birthdayB == 0) {
		*(uint32_t*) tempHash = indexB & ~7;
		sha512_func(tempHash, 32 + 4, (unsigned char*) resultHash);
		birthdayB = resultHash[indexB & 7] >> (64ULL - SEARCH_SPACE_BITS);
	}

	uint64_t birthdayA;        //, birthdayB;
	*(uint32_t*) tempHash = indexA_orig & ~7;
	sha512_func(tempHash, 32 + 4, (unsigned char*) resultHash);
	uint32_t indexA = indexA_orig;
	for (; indexA < indexA_orig + BIRTHDAYS_PER_HASH; indexA++) {
		birthdayA = resultHash[indexA & 7] >> (64ULL - SEARCH_SPACE_BITS);
		if (birthdayA == birthdayB) {
			break;
		}
	}
	if (birthdayA != birthdayB) {
		//printf("invalid share %d %d %X %X\n", indexA_orig, indexB, birthdayB, birthdayA);
		return false; // invalid share;
	}
	// birthday collision found
	totalCollisionCount += 2; // we can use every collision twice -> A B and B A (srsly?)
	//printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);

	sph_sha256_context c256; //SPH

	// get full block hash (for A B)
	block->birthdayA = indexA;
	block->birthdayB = indexB;
	uint8_t proofOfWorkHash[32];
	//SPH
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*) block, 80 + 8);
	sph_sha256_close(&c256, proofOfWorkHash);
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*) proofOfWorkHash, 32);
	sph_sha256_close(&c256, proofOfWorkHash);
	bool hashMeetsTarget = true;
	uint32_t* generatedHash32 = (uint32_t*) proofOfWorkHash;
	uint32_t* targetHash32 = (uint32_t*) block->targetShare;
	for (uint64_t hc = 7; hc != 0; hc--) {
		if (generatedHash32[hc] < targetHash32[hc]) {
			hashMeetsTarget = true;
			break;
		} else if (generatedHash32[hc] > targetHash32[hc]) {
			hashMeetsTarget = false;
			break;
		}
	}
	if (hashMeetsTarget)
		bp->submitBlock(block, thread_id);

	// get full block hash (for B A)
	block->birthdayA = indexB;
	block->birthdayB = indexA;
	//SPH
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*) block, 80 + 8);
	sph_sha256_close(&c256, proofOfWorkHash);
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*) proofOfWorkHash, 32);
	sph_sha256_close(&c256, proofOfWorkHash);
	hashMeetsTarget = true;
	generatedHash32 = (uint32_t*) proofOfWorkHash;
	targetHash32 = (uint32_t*) block->targetShare;
	for (uint64_t hc = 7; hc != 0; hc--) {
		if (generatedHash32[hc] < targetHash32[hc]) {
			hashMeetsTarget = true;
			break;
		} else if (generatedHash32[hc] > targetHash32[hc]) {
			hashMeetsTarget = false;
			break;
		}
	}
	if (hashMeetsTarget)
		bp->submitBlock(block, thread_id);

	return true;
}

#define CACHED_HASHES         (32)

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V2(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];
	uint32_t hashes_stored = 0;

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	memset(collisionIndices, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
	// start search
	uint8_t tempHash[32 + 4];
	uint64_t resultHash[8];
	memcpy(tempHash + 4, midHash, 32);

	for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
	{
		*(uint32_t*) tempHash = n;
		SHA512_FUNC(tempHash, 32 + 4, (unsigned char*) resultHash);
		for (uint32_t f = 0; f < 8; f++) {
			uint64_t birthdayB = resultHash[f] >> (64ULL - SEARCH_SPACE_BITS);
			uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
					& COLLISION_KEY_MASK);
			uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
			if (((collisionIndices[birthday] & COLLISION_KEY_MASK)
					== collisionKey)) {
				// try to avoid submitting bad shares
				if (ob != bp->getOriginalBlock())
					return;
				protoshares_revalidateCollision(block, midHash,
						(collisionIndices[birthday] & ~COLLISION_KEY_MASK) * 8,
						n + f, birthdayB, bp, SHA512_FUNC, thread_id);
				// invalid collision -> ignore or mark this entry as invalid?
			} else {
				collisionIndices[birthday] = (n / 8) | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V1(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];
	uint32_t hashes_stored = 0;

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	memset(collisionIndices, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
	// start search
	uint8_t tempHash[32 + 4];
	uint64_t resultHashStorage[8 * CACHED_HASHES];
	memcpy(tempHash + 4, midHash, 32);

#pragma unroll (8388608) //MAX_MOMENTUM_NONCE/BIRTHDAYS_PER_HASH
	for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE;
			n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
			{
#pragma unroll (CACHED_HASHES)
		for (uint32_t m = 0; m < CACHED_HASHES; m++) {
			*(uint32_t*) tempHash = n + m * 8;
			SHA512_FUNC(tempHash, 32 + 4,
					(unsigned char*) (resultHashStorage + 8 * m));
		}
#pragma unroll (CACHED_HASHES)
		for (uint32_t m = 0; m < CACHED_HASHES; m++) {
			uint64_t* resultHash = resultHashStorage + 8 * m;
			uint32_t i = n + m * 8;
#pragma unroll (8)
			for (uint32_t f = 0; f < 8; f++) {
				uint64_t birthdayB = resultHash[f]
						>> (64ULL - SEARCH_SPACE_BITS);
				uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
						& COLLISION_KEY_MASK);
				//uint64_t birthday = birthdayB % collisionTableSize;
				uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
				if (((collisionIndices[birthday] & COLLISION_KEY_MASK)
						== collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock())
						return;
					protoshares_revalidateCollision(block, midHash,
							(collisionIndices[birthday] & ~COLLISION_KEY_MASK)
									* 8, i + f, birthdayB, bp, SHA512_FUNC,
							thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (i / 8) | collisionKey; // we have 6 bits available for validation
//                                	hashes_stored++;
//                                	if (hashes_stored >= ((collisionTableSize>>1))) {
//                                		return; // table half full, that's enough
//                                	}
				}
			}
		}
	}
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V3(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	memset(collisionIndices, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
	// start search
	uint8_t tempHash[32 + 4];
	uint64_t resultHash[8];
	memcpy(tempHash + 4, midHash, 32);

#pragma unroll (8388608) //MAX_MOMENTUM_NONCE/BIRTHDAYS_PER_HASH
	for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
	{
		*(uint32_t*) tempHash = n;
		SHA512_FUNC(tempHash, 32 + 4, (unsigned char*) resultHash);

		uint64_t birthdayB = resultHash[0] >> (64ULL - SEARCH_SPACE_BITS);
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
		uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 0, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[1] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 1, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[2] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 2, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[3] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 3, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[4] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 4, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[5] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 5, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[6] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 6, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[7] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					n + 7, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = (n >> 3) | collisionKey; // we have 6 bits available for validation
		}

	}
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V4(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];
	uint32_t hashes_stored = 0;

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	memset(collisionIndices, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
	// start search
	uint8_t tempHash[32 + 4];
	uint64_t resultHash[8];
	memcpy(tempHash + 4, midHash, 32);

#pragma unroll (8388608) //MAX_MOMENTUM_NONCE/BIRTHDAYS_PER_HASH
	for (uint32_t n = 0; n < (MAX_MOMENTUM_NONCE >> 3); n++) {
		*(uint32_t*) tempHash = n << 3;
		SHA512_FUNC(tempHash, 32 + 4, (unsigned char*) resultHash);

		uint64_t birthdayB = resultHash[0] >> (64ULL - SEARCH_SPACE_BITS);
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
		uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3), birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[1] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 1, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[2] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 2, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[3] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 3, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[4] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 4, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[5] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 5, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[6] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 6, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

		birthdayB = resultHash[7] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((collisionIndices[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash,
					(collisionIndices[birthday] & ~COLLISION_KEY_MASK) << 3,
					(n << 3) + 7, birthdayB, bp, SHA512_FUNC, thread_id);
			// invalid collision -> ignore or mark this entry as invalid?
		} else {
			collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
		}

	}
}

// first, create new datastructure
template<int COLLISION_TABLE_SIZE>
class CHashTable {
public:
	CHashTable(uint32_t* _buffer) {
		buffer = _buffer;
		memset(buffer, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
	}
	~CHashTable() {
		// do nothing for now;
	}
	__inline uint32_t check(uint64_t birthdayB, uint32_t nonce) {
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
		uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE - 1);
		if (((buffer[birthday] & COLLISION_KEY_MASK) == collisionKey)) {
			return (buffer[birthday] & ~COLLISION_KEY_MASK) << 3;
		}
		buffer[birthday] = (nonce >> 3) | collisionKey; // we have 6 bits available for validation
		return 0;
	}

private:
	uint32_t* buffer;
};

// first, create new datastructure
template<int COLLISION_TABLE_SIZE, int COLLISION_RETRIES>
class CHashTableLinearCollision {
public:
	CHashTableLinearCollision(uint32_t* _buffer) {
		buffer = _buffer;
		memset(buffer, 0x00, sizeof(uint32_t) * COLLISION_TABLE_SIZE);
#ifdef DEBUG_HT
		num_checks = 0;
		num_retries = 0;
		for (int i = 0; i < COLLISION_RETRIES; i++) {
			num_found[i] = 0;
		}
#endif
	}
	~CHashTableLinearCollision() {
		// do nothing for now;
	}
	__inline uint32_t check(uint64_t birthdayB, uint32_t nonce) {
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
#ifdef DEBUG_HT
		num_checks++;
#endif
#pragma unroll (4)
		for (int i = 0; i < COLLISION_RETRIES; i++) {
			uint64_t birthday = (birthdayB + i) % COLLISION_TABLE_SIZE;
			if (!buffer[birthday]) {
				buffer[birthday] = (nonce >> 3) | collisionKey; // we have 6 bits available for validation
				return 0;
			} else if ((buffer[birthday] & COLLISION_KEY_MASK)
					== collisionKey) {
#ifdef DEBUG_HT
				num_found[i]++;
#endif
				return (buffer[birthday] & ~COLLISION_KEY_MASK) << 3;
			}
#ifdef DEBUG_HT
			num_retries++;
#endif
		}
		// not found after COLLISION_RETRIES
		return 0;
	}

#ifdef DEBUG_HT
	uint32_t num_checks;
	uint32_t num_retries;
	uint32_t num_found[COLLISION_RETRIES];

	void debug() {
		std::cout << "checks: " << num_checks << " retries: " << num_retries << std::endl;
		uint32_t total = 0;
		for(int i = 0; i < COLLISION_RETRIES; i++) {
			std::cout << "  found at [" << i << "]: " << (num_found[i]) << " " << std::endl;
			total += num_found[i];
		}
		std::cout << "   Total found: " << total << std::endl;
	}
#endif
private:
	uint32_t* buffer;
};

#ifndef RETRIES
#define RETRIES 4
#endif
template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V5(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* _collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];
//        CHashTable<COLLISION_TABLE_SIZE> htable(_collisionIndices);
	CHashTableLinearCollision<COLLISION_TABLE_SIZE, RETRIES> htable(
			_collisionIndices);

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	// start search
	uint8_t tempHash[32 + 4];
	uint64_t resultHash[8];
	memcpy(tempHash + 4, midHash, 32);

#pragma unroll (8388608) //MAX_MOMENTUM_NONCE/BIRTHDAYS_PER_HASH
	for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
	{
		*(uint32_t*) tempHash = n;
		SHA512_FUNC(tempHash, 32 + 4, (unsigned char*) resultHash);

		uint64_t birthdayB = resultHash[0] >> (64ULL - SEARCH_SPACE_BITS);
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
		uint32_t birthdayA = htable.check(birthdayB, n + 0);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 0,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[1] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 1);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 1,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[2] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 2);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 2,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[3] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 3);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 3,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[4] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 4);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 4,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[5] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 5);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 5,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[6] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 6);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 6,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[7] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 7);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 7,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

	}
#ifdef DEBUG_HT
	if (thread_id == 0) {
		htable.debug();
	}
#endif
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V6(blockHeader_t* block, CBlockProvider* bp,
		uint32_t* _collisionIndices, unsigned int thread_id) {
	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
//    CHashTable<COLLISION_TABLE_SIZE> htable(_collisionIndices);
	CHashTableLinearCollision<COLLISION_TABLE_SIZE, RETRIES> htable(_collisionIndices);

	uint8_t seed[32+4];
	uint8_t *midHash = seed+4;
	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}
	// start search
	uint64_t resultHash[8];

	SHA512_Context c512_avxsse; //AVX/SSE
	SHA512_Init(&c512_avxsse);
	SHA512_Update(&c512_avxsse, seed, 32+4);
	SHA512_PreFinal(&c512_avxsse);

#pragma unroll (8388608) //MAX_MOMENTUM_NONCE/BIRTHDAYS_PER_HASH
	for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
	{
	    SHA512_Final_Shift(&c512_avxsse, n, (uint8_t*)resultHash);

		uint64_t birthdayB = resultHash[0] >> (64ULL - SEARCH_SPACE_BITS);
		uint32_t collisionKey = (uint32_t) ((birthdayB >> 18)
				& COLLISION_KEY_MASK);
		uint32_t birthdayA = htable.check(birthdayB, n + 0);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 0,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[1] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 1);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 1,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[2] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 2);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 2,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[3] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 3);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 3,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[4] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 4);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 4,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[5] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 5);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 5,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[6] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 6);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 6,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

		birthdayB = resultHash[7] >> (64ULL - SEARCH_SPACE_BITS);
		collisionKey = (uint32_t) ((birthdayB >> 18) & COLLISION_KEY_MASK);
		birthdayA = htable.check(birthdayB, n + 7);
		if (birthdayA) {
			// try to avoid submitting bad shares
			if (ob != bp->getOriginalBlock())
				return;
			protoshares_revalidateCollision(block, midHash, birthdayA, n + 7,
					birthdayB, bp, SHA512_FUNC, thread_id);
		}

	}
#ifdef DEBUG_HT
	if (thread_id == 0) {
		htable.debug();
	}
#endif
}

void sha512_func_debug(unsigned char* in, unsigned int size,
		unsigned char* out) {

	sha512_func_avx(in, size, out);

	uint64_t resultHash[8];
	uint64_t* resultHash2 = (uint64_t*) out;

	sha512_ctx c512_yp; //SPH
	sha512_init(&c512_yp);
	sha512_update_final(&c512_yp, in, size, (unsigned char*) resultHash);

	for (int i = 0; i < 8; i++) {

		if (resultHash[i] != resultHash2[i]) {
			printf("ERROR: %llX != %llX\n", resultHash[i], resultHash2[i]);
		}
	}
}

CProtoshareProcessor::CProtoshareProcessor() {
	;
}

CProtoshareProcessor::CProtoshareProcessor(SHAMODE _shamode,
		unsigned int _collisionTableBits, unsigned int _thread_id) {
	shamode = _shamode;
	collisionTableBits = _collisionTableBits;
	thread_id = _thread_id;

	// allocate collision table
#ifndef MAP_HUGETLB
	collisionIndices = (uint32_t*) malloc(
			sizeof(uint32_t) * (1 << collisionTableBits));
#else

	size_t bigbufsize = sizeof(uint32_t) * (1 << collisionTableBits);
	void *addr;
	addr = mmap(0, bigbufsize, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (addr == MAP_FAILED) {
		printf(
				"Couldn't use the hugepage speed optimization.  Enable huge pages for a slight speed boost.\n");
		collisionIndices = (uint32_t*) malloc(
				sizeof(uint32_t) * (1 << collisionTableBits));
	} else {
		madvise(addr, bigbufsize, MADV_RANDOM);
		collisionIndices = (uint32_t *) addr;
	}

#endif
}

CProtoshareProcessor::~CProtoshareProcessor() {
	delete collisionIndices;
}

void CProtoshareProcessor::protoshares_process(blockHeader_t* block,
		CBlockProvider* bp) {
	if (shamode == AVXSSE4) {
#define sha_func_to_use sha512_func_avx
#define process_func _protoshares_process_V6
		switch (collisionTableBits) {
			case 20: process_func<(1<<20),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 21: process_func<(1<<21),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 22: process_func<(1<<22),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 23: process_func<(1<<23),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 24: process_func<(1<<24),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 25: process_func<(1<<25),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 26: process_func<(1<<26),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 27: process_func<(1<<27),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 28: process_func<(1<<28),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 29: process_func<(1<<29),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 30: process_func<(1<<30),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
		}
#undef process_func
#undef sha_func_to_use
	} else if (shamode == SPHLIB) {
#define sha_func_to_use sha512_func_sph
#define process_func _protoshares_process_V5
		switch (collisionTableBits) {
			case 20: process_func<(1<<20),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 21: process_func<(1<<21),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 22: process_func<(1<<22),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 23: process_func<(1<<23),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 24: process_func<(1<<24),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 25: process_func<(1<<25),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 26: process_func<(1<<26),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 27: process_func<(1<<27),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 28: process_func<(1<<28),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 29: process_func<(1<<29),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 30: process_func<(1<<30),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
		}
#undef sha_func_to_use
	} else if (shamode == FIPS180_2) {
#define sha_func_to_use sha512_func_fips
		switch (collisionTableBits) {
			case 20: process_func<(1<<20),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 21: process_func<(1<<21),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 22: process_func<(1<<22),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 23: process_func<(1<<23),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 24: process_func<(1<<24),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 25: process_func<(1<<25),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 26: process_func<(1<<26),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 27: process_func<(1<<27),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 28: process_func<(1<<28),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 29: process_func<(1<<29),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
			case 30: process_func<(1<<30),sha_func_to_use>(block, bp, collisionIndices, thread_id); break;
		}
#undef sha_func_to_use
	}
}

CProtoshareProcessorGPU::CProtoshareProcessorGPU(SHAMODE _shamode,
		GPUALGO gpu_algorithm, unsigned int _collisionTableBits,
		unsigned int _thread_id, unsigned int _device_num) {
	if (gpu_algorithm == GPUV2) {
		M1 = new OpenCLMomentum2(_collisionTableBits, _device_num);
	} else if (gpu_algorithm == GPUV3) {
		M1 = new OpenCLMomentumV3(_collisionTableBits, _device_num);
	} else if (gpu_algorithm == GPUV4) {
		M1 = new OpenCLMomentumV4(_collisionTableBits, _device_num);
	} else if (gpu_algorithm == GPUV5) {
		M1 = new OpenCLMomentumV5(_collisionTableBits, _device_num);
	} else if (gpu_algorithm == GPUV6) {
		M1 = new OpenCLMomentumV6(_collisionTableBits, _device_num);
	} else {
		assert(gpu_algorithm <= 4 && gpu_algorithm >= 2);
	}
	this->collisionTableBits = _collisionTableBits;
	this->shamode = _shamode;
	this->thread_id = _thread_id;
	this->device_num = _device_num;
	this->collisions = new collision_struct[M1->getCollisionCeiling()];

	Init_SHA512_sse4();
}

CProtoshareProcessorGPU::~CProtoshareProcessorGPU() {
	delete M1;
	delete collisions;
}

void CProtoshareProcessorGPU::protoshares_process(blockHeader_t* block,
		CBlockProvider* bp) {

	size_t count_collisions = 0;

	// generate mid hash using sha256 (header hash)
	blockHeader_t* ob = bp->getOriginalBlock();
	uint8_t midHash[32];

	{
		//SPH
		sph_sha256_context c256;
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) block, 80);
		sph_sha256_close(&c256, midHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*) midHash, 32);
		sph_sha256_close(&c256, midHash);
	}

	M1->find_collisions(midHash, collisions, &count_collisions);

	if (count_collisions > M1->getCollisionCeiling()) {
		std::cerr
				<< "Warning: found more candidate collisions than storage space available"
				<< std::endl;
		count_collisions = M1->getCollisionCeiling();
	}

	for (int i = 0; i < count_collisions; i++) {
		protoshares_revalidateCollision(block, midHash, collisions[i].nonce_a,
				collisions[i].nonce_b, collisions[i].birthday, bp,
				sha512_func_sse4, thread_id);
	}
	//printf("DEBUG: collisions = %d\n", count_collisions);

}
