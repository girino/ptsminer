/*
 * global.h
 *
 *  Created on: 02/01/2014
 *      Author: girino
 */

#ifndef GLOBAL_H_
#define GLOBAL_H_


#define MAX_MOMENTUM_NONCE (1<<26)
#define BIRTHDAYS_PER_HASH 8 // each hash has 8 64bit blocks
#define SEARCH_SPACE_BITS 50 // only 50 bits are valid for the collision

#define GET_BIRTHDAY(x) (x >> (64ULL - SEARCH_SPACE_BITS));
#define COLLISION_KEY_MASK 0xFF800000UL
#define HASH_TABLE_SIZE (1<<26) // start with the bit one ;)

typedef struct _collision_struct {
	uint64_t birthday;
	uint32_t nonce_a;
	uint32_t nonce_b;
} collision_struct;


#endif /* GLOBAL_H_ */
