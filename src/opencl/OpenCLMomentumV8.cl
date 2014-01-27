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

typedef struct _collision_struct {
	ulong birthday;
	uint nonce_a;
	uint nonce_b;
} collision_struct;

kernel void kernel_clean_hash_table(global uint * hash_table) {
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
   	ulong tmp = (message[0] & 0xffffffff00000000) | (spot);
   	w[0] = SWAP64(tmp);
	w[1] = message[1];
	w[2] = message[2];
	w[3] = message[3];
	w[4] = message[4];

	w[5] = 0; w[6] = 0; w[7] = 0; w[8] = 0; w[9] = 0;
	w[10] = 0;w[11] = 0;w[12] = 0;w[13] = 0;w[14] = 0;
  	w[15] = 0x120; /* SWAP64(0x2001000000000000ULL); */

  	sha512_block(&H, w);

	hashes[id] = GET_BIRTHDAY(H);
}

// second pass, fill table
kernel void fill_table(global ulong * hashes,
						  global uint * hash_table,
                          uint HASH_TABLE_SIZE) {
	size_t nonce = get_global_id(0);
	unsigned long birthdayB = hashes[nonce];
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	hash_table[birthday] = (nonce>>3) | collisionKey; // we have 6 bits available for validation
}

// third pass, lookup
kernel void find_collisions(global ulong * hashes,
							global uint * hash_table,
							uint HASH_TABLE_SIZE,
							global collision_struct * collisions,
							global uint * collision_count) {
	size_t nonce = get_global_id(0);
	unsigned long birthdayB = hashes[nonce];
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	unsigned int ht_value = hash_table[birthday];
	if( ht_value && ((ht_value&COLLISION_KEY_MASK) == collisionKey)) {
		// collision candidate
		unsigned int nonceA = (ht_value&~COLLISION_KEY_MASK)<<3;
		for (int i = 0; i < 8; i++) {
			unsigned long birthdayA = hashes[nonceA+i];
			if (birthdayA == birthdayB && (nonceA+i) != nonce) {
//			if (nonceA>>3 != nonce>>3) {
				uint pos = atomic_inc(collision_count);
				collisions[pos].nonce_b = nonce;
				collisions[pos].nonce_a = nonceA;
				collisions[pos].birthday = birthdayB;
			}
		}
	}

}
