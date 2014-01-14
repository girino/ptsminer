/*
 * sha_utils.h
 *
 *  Created on: 02/01/2014
 *      Author: girino
 */

#ifndef SHA_UTILS_H_
#define SHA_UTILS_H_
#include <stdlib.h>
#include <stdint.h>
#undef SHA512_BLOCK_SIZE
#include "sha2.h"
// hack to solve warnings
#undef SHA512_BLOCK_SIZE
#include "sha512.h"
extern "C" {
#include "sph_sha2.h"
}

void sha512_func_fips(unsigned char* in, unsigned int size, unsigned char* out);
void sha512_func_avx(unsigned char* in, unsigned int size, unsigned char* out);
void sha512_func_sph(unsigned char* in, unsigned int size, unsigned char* out);
void sha512_func_sse4(unsigned char* in, unsigned int size, unsigned char* out);

#define SHA512_FUNC sha512_func_sse4
#define GET_BIRTHDAY(x) (x >> (64ULL - SEARCH_SPACE_BITS));

uint32 revalidateCollision(uint8_t* midHash, uint32_t indexA_orig,
		uint32_t indexB)
;
int log2(size_t value);

#endif /* SHA_UTILS_H_ */
