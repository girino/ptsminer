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

kernel void kernel_sha512(global char * message,
                          global uint32_t * hash_table,
                          uint32_t HASH_TABLE_SIZE,
                          global collision_struct * collisions,
                          global uint32_t * collision_count) {

	size_t id = get_local_id(0);
	size_t gid = get_group_id(0) * get_local_size(0);
	uint32_t nonce = (gid*8) + (id*8);
	char tempHash[36];
	for (int i = 0; i < 32; i++) tempHash[i+4] = message[i];
	*((uint32_t*)tempHash) = nonce;
	
    sha512_ctx sctx;	
    init_ctx(&sctx);
    ctx_update(&sctx, tempHash, 36);
    uint64_t hash[8];
    sha512_digest(&sctx, hash);
    
    // pra cada hash
	#pragma unroll
    for (int i = 0; i < 8; i++) {
	    // checks in the hash table
		unsigned long birthdayB = GET_BIRTHDAY(hash[i]);
		unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
		unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
		//collisions[(gid*8) + (id*8)+i] = 0;
		if( hash_table[birthday] && ((hash_table[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
			// collision candidate
			unsigned int nonceA = (hash_table[birthday]&~COLLISION_KEY_MASK)<<3;
			if (nonceA != nonce) {
				uint32_t pos = atomic_inc(collision_count);
				collisions[pos].nonce_b = (gid*8) + (id*8)+ i;
				collisions[pos].nonce_a = nonceA;
				collisions[pos].birthday = birthdayB;
			}
		}
		hash_table[birthday] = (nonce>>3) | collisionKey; // we have 6 bits available for validation
	}
}
