/*
 * CProtosharePoocessor.cpp
 *
 *  Created on: 20/12/2013
 *      Author: girino
 */

#include "CProtoshareProcessor.h"

#define repeat2(x) {x} {x}
#define repeat4(x) repeat2(x) repeat2(x)
#define repeat8(x) repeat4(x) repeat4(x)
#define repeat16(x) repeat8(x) repeat8(x)
#define repeat32(x) repeat16(x) repeat16(x)
#define repeat64(x) repeat32(x) repeat32(x)

static const uint64_t sha512_h0[SHA512_HASH_WORDS] = {
  0x6a09e667f3bcc908LL,
  0xbb67ae8584caa73bLL,
  0x3c6ef372fe94f82bLL,
  0xa54ff53a5f1d36f1LL,
  0x510e527fade682d1LL,
  0x9b05688c2b3e6c1fLL,
  0x1f83d9abfb41bd6bLL,
  0x5be0cd19137e2179LL
};

static inline void swap512(uint64_t *h)
{
	h[0] = BYTESWAP64(h[0]); h[1] = BYTESWAP64(h[1]);
	h[2] = BYTESWAP64(h[2]); h[3] = BYTESWAP64(h[3]);
	h[4] = BYTESWAP64(h[4]); h[5] = BYTESWAP64(h[5]);
	h[6] = BYTESWAP64(h[6]); h[7] = BYTESWAP64(h[7]);
}


bool protoshares_revalidateCollision(blockHeader_t* block, uint8_t* midHash, uint32_t indexA_orig,
		uint32_t indexB, uint64_t birthdayB, CBlockProvider* bp,
		sha512_func_t sha512_func, uint32_t thread_id)
{
        //if( indexA > MAX_MOMENTUM_NONCE )
        //        printf("indexA out of range\n");
        //if( indexB > MAX_MOMENTUM_NONCE )
        //        printf("indexB out of range\n");
        //if( indexA == indexB )
        //        printf("indexA == indexB");
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);
		uint64_t birthdayA;//, birthdayB;
		*(uint32_t*)tempHash = indexA_orig&~7;
		sha512_func(tempHash, 32+4, (unsigned char*)resultHash);
		uint32_t indexA = indexA_orig;
		for (;indexA < indexA_orig+BIRTHDAYS_PER_HASH; indexA++) {
			birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	        if( birthdayA == birthdayB )
	        {
	                break;
	        }
		}
		if (birthdayA != birthdayB) {
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
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        bool hashMeetsTarget = true;
        uint32_t* generatedHash32 = (uint32_t*)proofOfWorkHash;
        uint32_t* targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
			bp->submitBlock(block, thread_id);

        // get full block hash (for B A)
        block->birthdayA = indexB;
        block->birthdayB = indexA;
		//SPH
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        hashMeetsTarget = true;
        generatedHash32 = (uint32_t*)proofOfWorkHash;
        targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
			bp->submitBlock(block, thread_id);

		return true;
}

#define CACHED_HASHES         (32)
#define COLLISION_KEY_MASK 0xFF800000

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V2(blockHeader_t* block,  CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id)
{
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8_t midHash[32];
        uint32_t hashes_stored=0;

		{
			//SPH
			sph_sha256_context c256;
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)block, 80);
			sph_sha256_close(&c256, midHash);
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)midHash, 32);
			sph_sha256_close(&c256, midHash);
		}
        memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
        // start search
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);

        for(uint32_t n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
        {
        		*(uint32_t*)tempHash = n;
                SHA512_FUNC(tempHash, 32+4, (unsigned char*)resultHash);
                for(uint32_t f=0; f<8; f++)
				{
						uint64_t birthdayB = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
						uint32_t collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
						uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
						if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
							// try to avoid submitting bad shares
							if (ob != bp->getOriginalBlock()) return;
							protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)*8, n+f, birthdayB, bp, SHA512_FUNC, thread_id);
							// invalid collision -> ignore or mark this entry as invalid?
						} else {
							collisionIndices[birthday] = (n/8) | collisionKey; // we have 6 bits available for validation
						}
				}
        }
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V1(blockHeader_t* block,  CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id)
{
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8_t midHash[32];
        uint32_t hashes_stored=0;

		{
			//SPH
			sph_sha256_context c256;
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)block, 80);
			sph_sha256_close(&c256, midHash);
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)midHash, 32);
			sph_sha256_close(&c256, midHash);
		}
        memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
        // start search
        uint8_t tempHash[32+4];
        uint64_t resultHashStorage[8*CACHED_HASHES];
        memcpy(tempHash+4, midHash, 32);

        for(uint32_t n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
        {
                for(uint32_t m=0; m<CACHED_HASHES; m++)
                {
                        *(uint32_t*)tempHash = n+m*8;
                        SHA512_FUNC(tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
                }
                for(uint32_t m=0; m<CACHED_HASHES; m++)
                {
                        uint64_t* resultHash = resultHashStorage + 8*m;
                        uint32_t i = n + m*8;
                        for(uint32_t f=0; f<8; f++)
                        {
                                uint64_t birthdayB = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
                                uint32_t collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
                                //uint64_t birthday = birthdayB % collisionTableSize;
                                uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
                                if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
                            		// try to avoid submitting bad shares
                            		if (ob != bp->getOriginalBlock()) return;
                               		protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)*8, i+f, birthdayB, bp, SHA512_FUNC, thread_id);
                                        // invalid collision -> ignore or mark this entry as invalid?
                                } else {
                                	collisionIndices[birthday] = (i/8) | collisionKey; // we have 6 bits available for validation
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
void _protoshares_process_V3(blockHeader_t* block,  CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id)
{
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8_t midHash[32];
        uint32_t hashes_stored=0;

		{
			//SPH
			sph_sha256_context c256;
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)block, 80);
			sph_sha256_close(&c256, midHash);
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)midHash, 32);
			sph_sha256_close(&c256, midHash);
		}
        memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
        // start search
        uint64_t resultHash[8];

        uint8_t tempHash[128];
        memset(tempHash, 0, 128);
        tempHash[36] = 0x80;
        *((uint32_t *)(tempHash + 124)) = 0x20010000;
        memcpy(tempHash+4, midHash, 32);

        for(uint32_t n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH)
        {
        		*(uint32_t*)tempHash = n;
                if(sha512_update_func == NULL)  SHA512_FUNC(tempHash, 32+4, (unsigned char*)resultHash);
                else {
                    memcpy(resultHash, sha512_h0, 64);
                    sha512_update_func((void *)tempHash, resultHash, 1);
                    swap512(resultHash);
                }
                uint64_t birthdayB = resultHash[0] >> (64ULL-SEARCH_SPACE_BITS);
				uint32_t collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+0, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[1] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+1, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}


                birthdayB = resultHash[2] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+2, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[3] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+3, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[4] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+4, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[5] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+5, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[6] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+6, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[7] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, n+7, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = (n>>3) | collisionKey; // we have 6 bits available for validation
				}

        }
}

template<int COLLISION_TABLE_SIZE, sha512_func_t SHA512_FUNC>
void _protoshares_process_V4(blockHeader_t* block,  CBlockProvider* bp,
		uint32_t* collisionIndices, unsigned int thread_id)
{
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8_t midHash[32];
        uint32_t hashes_stored=0;

		{
			//SPH
			sph_sha256_context c256;
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)block, 80);
			sph_sha256_close(&c256, midHash);
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)midHash, 32);
			sph_sha256_close(&c256, midHash);
		}
        memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
        // start search
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);

        for(uint32_t n=0; n<(MAX_MOMENTUM_NONCE>>3); n++)
        {
        		*(uint32_t*)tempHash = n<<3;
                SHA512_FUNC(tempHash, 32+4, (unsigned char*)resultHash);

                uint64_t birthdayB = resultHash[0] >> (64ULL-SEARCH_SPACE_BITS);
				uint32_t collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				uint64_t birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3), birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[1] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+1, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}


                birthdayB = resultHash[2] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+2, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[3] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+3, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[4] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+4, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[5] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+5, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[6] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+6, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

                birthdayB = resultHash[7] >> (64ULL-SEARCH_SPACE_BITS);
				collisionKey = (uint32_t)((birthdayB>>18) & COLLISION_KEY_MASK);
				birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey)) {
					// try to avoid submitting bad shares
					if (ob != bp->getOriginalBlock()) return;
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday]&~COLLISION_KEY_MASK)<<3, (n<<3)+7, birthdayB, bp, SHA512_FUNC, thread_id);
					// invalid collision -> ignore or mark this entry as invalid?
				} else {
					collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
				}

        }
}


void sha512_func_avx(unsigned char* in, unsigned int size, unsigned char* out) {
	//AVX/SSE
	SHA512_Context c512_avxsse; //AVX/SSE
	SHA512_Init(&c512_avxsse);
	SHA512_Update(&c512_avxsse, in, size);
	SHA512_Final(&c512_avxsse, (unsigned char*)out);
}

void sha512_func_sph(unsigned char* in, unsigned int size, unsigned char* out) {
	//SPH
	sph_sha512_context c512_sph; //SPH
	sph_sha512_init(&c512_sph);
	sph_sha512(&c512_sph, in, size);
	sph_sha512_close(&c512_sph, out);
}

CProtoshareProcessor::CProtoshareProcessor(SHAMODE _shamode,
		unsigned int _collisionTableBits,
		unsigned int _thread_id) {
	shamode = _shamode;
	collisionTableBits = _collisionTableBits;
	thread_id = _thread_id;

	// allocate collision table
	collisionIndices = (uint32_t*)malloc(sizeof(uint32_t)*(1<<collisionTableBits));
}

CProtoshareProcessor::~CProtoshareProcessor() {
	delete collisionIndices;
}

void CProtoshareProcessor::protoshares_process(blockHeader_t* block,
		CBlockProvider* bp) {
#define process_func _protoshares_process_V3 
	if (shamode == AVXSSE4) {
		switch (collisionTableBits) {
		case 20: process_func<(1<<20),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 21: process_func<(1<<21),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 22: process_func<(1<<22),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 23: process_func<(1<<23),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 24: process_func<(1<<24),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 25: process_func<(1<<25),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 26: process_func<(1<<26),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 27: process_func<(1<<27),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 28: process_func<(1<<28),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 29: process_func<(1<<29),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		case 30: process_func<(1<<30),sha512_func_avx>(block,  bp, collisionIndices, thread_id); break;
		}
	} else if (shamode == SPHLIB) {
		switch (collisionTableBits) {
		case 20: process_func<(1<<20),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 21: process_func<(1<<21),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 22: process_func<(1<<22),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 23: process_func<(1<<23),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 24: process_func<(1<<24),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 25: process_func<(1<<25),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 26: process_func<(1<<26),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 27: process_func<(1<<27),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 28: process_func<(1<<28),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 29: process_func<(1<<29),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		case 30: process_func<(1<<30),sha512_func_sph>(block,  bp, collisionIndices, thread_id); break;
		}
	}
}

