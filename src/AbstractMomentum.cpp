/*
 * AbstractMomentum.cpp
 *
 *  Created on: 02/01/2014
 *      Author: girino
 *
 * Copyright (c) 2014 Girino Vey.
 *
 * All code in this file is copyrighted to me, Girino Vey, and licensed under Girino's
 * Anarchist License, available at http://girino.org/license and is available on this
 * repository as the file girino_license.txt
 *
 */

#include "AbstractMomentum.h"
#include "global.h"
#include "sha_utils.h"

AbstractMomentum::AbstractMomentum() {
	// TODO Auto-generated constructor stub

}

AbstractMomentum::~AbstractMomentum() {
	// TODO Auto-generated destructor stub
}


void native_create_hashes(uint8_t* message, uint64_t* hashes, uint32_t begin_nonce, uint32_t size) {
	for(uint32_t id = 0; id < (size/BIRTHDAYS_PER_HASH); id++) {
		uint8_t temp_message[36];
		uint32_t delta_nonce = (id*BIRTHDAYS_PER_HASH);
		memcpy(temp_message+4, message, 32);
		*((uint32_t*)temp_message) = (begin_nonce + delta_nonce);
		SHA512_FUNC((unsigned char*)temp_message, 36, (unsigned char*)(hashes+delta_nonce));
	}
}

void native_match_hashes(uint8_t* message, uint64_t* hashes_origin, uint32_t* hash_table, uint32_t origin_offset, uint32_t* collisions, uint32_t size, int HASH_BITS) {
	#pragma unroll
	for(uint32_t id = 0; id < size; id++) {
		uint32_t nonce = origin_offset + id;
		uint64_t birthdayB = GET_BIRTHDAY(hashes_origin[id]);
		uint32_t collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
		uint64_t birthday = birthdayB % (1<<HASH_BITS);
		if( hash_table[birthday] && ((hash_table[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
			// collision candidate
			if ((nonce>>3) != (hash_table[birthday]&~COLLISION_KEY_MASK)) {
				uint32_t nonceA = (hash_table[birthday]&~COLLISION_KEY_MASK) << 3;
				#pragma unroll (8)
				for (int i = 0; i < 8; i++) {
					uint64_t birthdayA = GET_BIRTHDAY(hashes_origin[nonceA+i]);
					if (birthdayA == birthdayB) {
						collisions[id] = nonceA + i;
						break;
					}
				}
			}

		}
		hash_table[birthday] = (nonce>>3) | collisionKey;
	}
}
