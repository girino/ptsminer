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
	uint64_t birthday;
	uint32_t nonce_a;
	uint32_t nonce_b;
} collision_struct;

kernel void kernel_clean_hash_table(global uint32_t * hash_table) {
	size_t id = get_local_id(0);
	size_t gid = get_group_id(0) * get_local_size(0);
	hash_table[id + gid] = 0;
}

kernel void kernel_sha512(constant ulong * message,
                          global uint32_t * hash_table,
                          uint32_t HASH_TABLE_SIZE,
                          global collision_struct * collisions,
                          global uint32_t * collision_count) {

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

	H = GET_BIRTHDAY(H);
	ulong * hash = (ulong*)&H;
    
    // pra cada hash
	#pragma unroll
    for (int i = 0; i < 8; i++) {
	    // checks in the hash table
		unsigned long birthdayB = hash[i];
		unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
		unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
		//collisions[(gid*8) + (id*8)+i] = 0;
		if( hash_table[birthday] && ((hash_table[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
			// collision candidate
			unsigned int nonceA = (hash_table[birthday]&~COLLISION_KEY_MASK)<<3;
			if (nonceA != spot) {
				uint32_t pos = atomic_inc(collision_count);
				collisions[pos].nonce_b = spot+ i;
				collisions[pos].nonce_a = nonceA;
				collisions[pos].birthday = birthdayB;
			}
		}
		hash_table[birthday] = (spot>>3) | collisionKey; // we have 6 bits available for validation
	}
}
