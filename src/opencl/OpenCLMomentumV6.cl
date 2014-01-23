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

// DGA code
#define SHA512_HASH_WORDS 8 /* 64 bit words */

__constant const uint64_t iv512[SHA512_HASH_WORDS] = {
  0x6a09e667f3bcc908LL,
  0xbb67ae8584caa73bLL,
  0x3c6ef372fe94f82bLL,
  0xa54ff53a5f1d36f1LL,
  0x510e527fade682d1LL,
  0x9b05688c2b3e6c1fLL,
  0x1f83d9abfb41bd6bLL,
  0x5be0cd19137e2179LL
};

/***** SHA 512 code is derived from Lukas Odzioba's sha512 crypt implementation within JohnTheRipper.  It has its own copyright */
/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

#define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))



__constant uint64_t k[] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL, 0xb5c0fbcfec4d3b2fLL,
	    0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL, 0x923f82a4af194f9bLL,
	    0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL, 0x243185be4ee4b28cLL,
	    0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL, 0x9bdc06a725c71235LL,
	    0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL, 0x0fc19dc68b8cd5b5LL,
	    0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL, 0x5cb0a9dcbd41fbd4LL,
	    0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL, 0xb00327c898fb213fLL,
	    0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL, 0x06ca6351e003826fLL,
	    0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL, 0x4d2c6dfc5ac42aedLL,
	    0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL, 0x81c2c92e47edaee6LL,
	    0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL, 0xc24b8b70d0f89791LL,
	    0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL, 0xf40e35855771202aLL,
	    0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL, 0x2748774cdf8eeb99LL,
	    0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL, 0x5b9cca4f7763e373LL,
	    0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL, 0x84c87814a1f0ab72LL,
	    0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL, 0xbef9a3f7b2c67915LL,
	    0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL, 0xeada7dd6cde0eb1eLL,
	    0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL, 0x113f9804bef90daeLL,
	    0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL, 0x3c9ebe0a15c9bebcLL,
	    0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL, 0x5fcb6fab3ad6faecLL,
	    0x6c44198c4a475817LL,
};

void sha512_block(uint64_t H[8], const uint64_t data[5])
{
  uint64_t a = iv512[0];
  uint64_t b = iv512[1];
  uint64_t c = iv512[2];
  uint64_t d = iv512[3];
  uint64_t e = iv512[4];
  uint64_t f = iv512[5];
  uint64_t g = iv512[6];
  uint64_t h = iv512[7];

  uint64_t w[16];

	/* This can all be factored out onto the CPU setup, but let's
	 * get it working properly first. */
	/* n.b. - that optimizatoin of removing the swaps into setup
	 * will also work for our CPU version.  Just sayin' */
//#pragma unroll 16
	/* Lots of these middle entries are zero because of the pad */
        w[0] = SWAP64(data[0]);
#pragma unroll
	for (int i = 1; i < 5; i++)
		w[i] = data[i];
#pragma unroll
	for (int i = 5; i < 15; i++) {
	  w[i] = 0;
	}
	w[15] = 0x120; /* SWAP64(0x2001000000000000ULL); */

	uint64_t t1, t2;

	/* dga: Parts of this can be optimized for the first iteration
	 * to account for all of the fixed input values */

#pragma unroll 16
	for (int i = 0; i < 16; i++) {
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

#pragma unroll
	for (int i = 16; i < 80; i++) {


		w[i & 15] =sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15];
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;

	}

        H[0] = iv512[0] + a;
	H[1] = iv512[1] + b;
	H[2] = iv512[2] + c;
	H[3] = iv512[3] + d;
	H[4] = iv512[4] + e;
	H[5] = iv512[5] + f;
	H[6] = iv512[6] + g;
	H[7] = iv512[7] + h;

#pragma unroll
	for (int i = 0; i < 8; i++) {
	  H[i] = (SWAP64(H[i]));
	}
}

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
kernel void calculate_all_hashes(constant uint64_t * message,
								 global uint64_t * hashes) {
	size_t id = get_global_id(0);
	uint32_t spot = (id*8);

	uint64_t H[8];
	uint64_t D[5];
    for (int i = 0; i < 5; i++) {
	    D[i] = message[i]; /* constant memory would be better */
	}

	D[0] = (D[0] & 0xffffffff00000000) | (spot);
	for (int i = 1; i < 5; i++) {
	    D[i] = SWAP64(D[i]);
	}

	sha512_block(H, D);

	for (int i = 0; i < 8; i++) {
		hashes[spot+i] = H[i];
	}
}

// second pass, fill table
kernel void fill_table(global uint64_t * hashes,
						  global uint32_t * hash_table,
                          uint32_t HASH_TABLE_SIZE) {
	size_t nonce = get_global_id(0);
	unsigned long birthdayB = GET_BIRTHDAY(hashes[nonce]);
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	hash_table[birthday] = (nonce>>3) | collisionKey; // we have 6 bits available for validation
}

// third pass, lookup
kernel void find_collisions(global uint64_t * hashes,
							global uint32_t * hash_table,
							uint32_t HASH_TABLE_SIZE,
							global collision_struct * collisions,
							global uint32_t * collision_count) {
	size_t nonce = get_global_id(0);
	unsigned long birthdayB = GET_BIRTHDAY(hashes[nonce]);
	unsigned int collisionKey = (unsigned int)((birthdayB>>18) & COLLISION_KEY_MASK);
	unsigned long birthday = birthdayB % (HASH_TABLE_SIZE);
	unsigned int ht_value = hash_table[birthday];
	if( ht_value && ((ht_value&COLLISION_KEY_MASK) == collisionKey)) {
		// collision candidate
		unsigned int nonceA = (ht_value&~COLLISION_KEY_MASK)<<3;
//		for (int i = 0; i < 8; i++) {
//			unsigned long birthdayA = GET_BIRTHDAY(hashes[nonceA+i]);
//			if (birthdayA == birthdayB && (nonceA+i) != nonce) {
			if (nonceA>>3 != nonce>>3) {
				uint32_t pos = atomic_inc(collision_count);
				collisions[pos].nonce_b = nonce;
				collisions[pos].nonce_a = nonceA;
				collisions[pos].birthday = birthdayB;
			}
//		}
	}

}
