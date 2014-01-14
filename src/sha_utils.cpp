/*
 * sha_utils.cpp
 *
 *  Created on: 02/01/2014
 *      Author: girino
 */

#include <string.h>
#include "sha_utils.h"
#include "global.h"

void sha512_func_sse4(unsigned char* in, unsigned int size, unsigned char* out) {
	sha512_func_avx(in, size, out);
}

void sha512_func_avx(unsigned char* in, unsigned int size, unsigned char* out) {
	//AVX/SSE
	SHA512_Context c512_avxsse; //AVX/SSE
	SHA512_Init(&c512_avxsse);
	SHA512_Update_Special(&c512_avxsse, in, size);
	SHA512_Final(&c512_avxsse, (unsigned char*)out);
}

void sha512_func_sph(unsigned char* in, unsigned int size, unsigned char* out) {
	//SPH
	sph_sha512_context c512_sph; //SPH
	sph_sha512_init(&c512_sph);
	sph_sha512(&c512_sph, in, size);
	sph_sha512_close(&c512_sph, out);
}

void sha512_func_fips(unsigned char* in, unsigned int size, unsigned char* out) {
	sha512_ctx c512_yp; //SPH
	sha512_init(&c512_yp);
	sha512_update_final(&c512_yp, in, size, out);
}

uint32 revalidateCollision(uint8_t* midHash, uint32_t indexA_orig,
		uint32_t indexB)
{
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);
		*(uint32_t*)tempHash = indexB&~7;
		SHA512_FUNC(tempHash, 32+4, (unsigned char*)resultHash);
        uint64_t birthdayB = GET_BIRTHDAY(resultHash[indexB&7]);

        uint64_t birthdayA;//, birthdayB;
		*(uint32_t*)tempHash = indexA_orig&~7;
		SHA512_FUNC(tempHash, 32+4, (unsigned char*)resultHash);
		uint32_t indexA = indexA_orig;
		for (;indexA < indexA_orig+BIRTHDAYS_PER_HASH; indexA++) {
			birthdayA = GET_BIRTHDAY(resultHash[indexA&7]);
	        if( birthdayA == birthdayB )
	        {
	                break;
	        }
		}
		if (birthdayA != birthdayB) {
			return 0; // invalid share;
		}
		return indexA;
}

int log2(size_t value) {
	int ret = 0;
	while (value > 1) {
		ret++;
		value = value>>1;
	}
	return ret;
}
