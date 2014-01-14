/*
 * AbstractMomentum.h
 *
 *  Created on: 02/01/2014
 *      Author: girino
 */

#ifndef ABSTRACTMOMENTUM_H_
#define ABSTRACTMOMENTUM_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "global.h"

class AbstractMomentum {
public:
	AbstractMomentum();
	virtual ~AbstractMomentum();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t * collision_count) = 0;
	virtual int getCollisionCeiling() = 0;
};


void native_create_hashes(uint8_t* message, uint64_t* hashes, uint32_t begin_nonce, uint32_t size);
void native_match_hashes(uint8_t* message, uint64_t* hashes_origin, uint32_t* hash_table, uint32_t origin_offset, uint32_t* collisions, uint32_t size, int HASH_BITS=27);

#endif /* ABSTRACTMOMENTUM_H_ */
