/*
 * Copyright (c) 2014 Girino Vey.
 *
 * All code in this file is copyrighted to me, Girino Vey, and licensed under Girino's
 * Anarchist License, available at http://girino.org/license and is available on this
 * repository as the file girino_license.txt
 *
 */

#ifdef _ECLIPSE_OPENCL_HEADER
#   include "OpenCLKernel.hpp"
#endif

#define _OPENCL_COMPILER
#define SEARCH_SPACE_BITS (50)
#define GET_BIRTHDAY(x) (x >> (64UL - SEARCH_SPACE_BITS));
#define COLLISION_KEY_MASK 0xFF800000UL

// my code
typedef struct _collision_struct {
	uint64_t birthday;
	uint32_t nonce_a;
	uint32_t nonce_b;
} collision_struct;

kernel void kernel_clean_hash_table(global uint32_t * hash_table) {
	size_t id = get_global_id(0);
	hash_table[id] = 0;
}

// first pass, hashes
kernel void calculate_all_hashes(constant ulong * message,
								 global ulong8 * hashes) {
	size_t id = get_global_id(0);
	uint spot = (id*8);

	ulong8 H;

    ulong w[16];
    ulong* wp = &w;
   	ulong tmp = (message[0] & 0xffffffff00000000) | (spot);
   	wp[0] = SWAP64(tmp);
  	#pragma unroll
  	for (int i = 1; i < 5; i++) {
  		w[i] = message[i];
  	}
  	#pragma unroll
  	for (int i = 5; i < 15; i++) {
  	  w[i] = 0;
  	}
  	w[15] = 0x120; /* SWAP64(0x2001000000000000ULL); */


	sha512_block(&H, w);

	hashes[id] = GET_BIRTHDAY(H);
}

// second pass, fill table
kernel void fill_table(global uint64_t * hashes,
						  global uint32_t * hash_table,
                          uint32_t HASH_TABLE_SIZE) {
	size_t nonce = get_global_id(0);
	unsigned long birthdayB = hashes[nonce];
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	hash_table[birthday] = (nonce>>3) | collisionKey; // we have 6 bits available for validation
}

#define HT_RETRIES (4)
// third pass, lookup
kernel void find_collisions(global uint64_t * hashes,
							global uint32_t * hash_table,
							uint32_t HASH_TABLE_SIZE,
							global collision_struct * collisions,
							global uint32_t * collision_count) {
	size_t nonce = get_global_id(0);
	size_t gid = get_group_id(0);
	size_t lsz = get_local_size(0);

	prefetch(hashes+(lsz*gid), lsz*sizeof(uint64_t));

	unsigned long birthdayB = hashes[nonce];
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	unsigned int ht_value = hash_table[birthday];
#pragma unroll
	for (int i = 0; i < HT_RETRIES; i++) {
		if (!ht_value || (ht_value&COLLISION_KEY_MASK) == collisionKey) break;
		birthday = (birthday+1)%(HASH_TABLE_SIZE);
		ht_value = hash_table[birthday];
	}
	if( ht_value && ((ht_value&COLLISION_KEY_MASK) == collisionKey)) {
		// collision candidate
		unsigned int nonceA = (ht_value&~COLLISION_KEY_MASK)<<3;
		for (int i = 0; i < 8; i++) {
			unsigned long birthdayA = hashes[nonceA+i];
			if (birthdayA == birthdayB && (nonceA+i) != nonce) {
//			if (nonceA>>3 != nonce>>3) {
				uint32_t pos = atomic_inc(collision_count);
				collisions[pos].nonce_b = nonce;
				collisions[pos].nonce_a = nonceA;
				collisions[pos].birthday = birthdayB;
			}
		}
	}
	hash_table[birthday] = (nonce>>3) | collisionKey; // we have 6 bits available for validation

}
