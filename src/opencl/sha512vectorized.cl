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
#   include "opencl_cryptsha512.h"
#endif

#define _OPENCL_COMPILER

__constant const ulong8 iv512 = {
  0x6a09e667f3bcc908L,
  0xbb67ae8584caa73bL,
  0x3c6ef372fe94f82bL,
  0xa54ff53a5f1d36f1L,
  0x510e527fade682d1L,
  0x9b05688c2b3e6c1fL,
  0x1f83d9abfb41bd6bL,
  0x5be0cd19137e2179L
};

/***** SHA 512 code is derived from Lukas Odzioba's sha512 crypt implementation within JohnTheRipper.  It has its own copyright */
/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

//#define rol(x,n) ((x << n) | (x >> (64-n)))
//#define rol(x,n) rotate(x, n)
//#define ror(x,n) ((x >> n) | (x << (64-n)))
//#define ror(x,n) rotate(x, (ulong)64-n)
//#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
//#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
//#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
//#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
//#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
//#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

//#define SWAP32(n) \
//    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

__constant ulong k[] = {
	0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
	    0xe9b5dba58189dbbcL,
	0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL,
	    0xab1c5ed5da6d8118L,
	0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL,
	    0x550c7dc3d5ffb4e2L,
	0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
	    0xc19bf174cf692694L,
	0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L,
	    0x240ca1cc77ac9c65L,
	0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L,
	    0x76f988da831153b5L,
	0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
	    0xbf597fc7beef0ee4L,
	0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL,
	    0x142929670a0e6e70L,
	0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL,
	    0x53380d139d95b3dfL,
	0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
	    0x92722c851482353bL,
	0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L,
	    0xc76c51a30654be30L,
	0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL,
	    0x106aa07032bbd1b8L,
	0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
	    0x34b0bcb5e19b48a8L,
	0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L,
	    0x682e6ff3d6b2b8a3L,
	0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L,
	    0x8cc702081a6439ecL,
	0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
	    0xc67178f2e372532bL,
	0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL,
	    0xf57d4f7fee6ed178L,
	0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL,
	    0x1b710b35131c471bL,
	0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
	    0x431d67c49c100d4cL,
	0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL,
	    0x6c44198c4a475817L,
};


inline void sha512_block(ulong8 * H, ulong w[16])
{
	*H = iv512;

	ulong t1, t2;

	// do not do this at home,
	// this is very, very bad practice, but it's really great for loop unrolling
#define step0to15(i) t1 = k[i] + w[i] + (*H).s7 + Sigma1((*H).s4) + Ch((*H).s4, (*H).s5, (*H).s6); \
	t2 = Maj((*H).s0, (*H).s1, (*H).s2) + Sigma0((*H).s0); \
	*H = (*H).s70123456; (*H).s0 = t1 + t2; (*H).s4 += t1;

	step0to15(0); step0to15(1); step0to15(2); step0to15(3);
	step0to15(4); step0to15(5); step0to15(6); step0to15(7);
	step0to15(8); step0to15(9); step0to15(10);step0to15(11);
	step0to15(12);step0to15(13);step0to15(14);step0to15(15);

	// do not do this at home,
	// this is very, very bad practice, but it's really great for loop unrolling
#define step16to80(i) w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15]; \
		t1 = k[i] + w[i & 15] + (*H).s7 + Sigma1((*H).s4) + Ch((*H).s4, (*H).s5, (*H).s6); \
		t2 = Maj((*H).s0, (*H).s1, (*H).s2) + Sigma0((*H).s0); \
		*H = (*H).s70123456; (*H).s0 = t1 + t2; (*H).s4 += t1;

	step16to80(16);step16to80(17);step16to80(18);step16to80(19);
	step16to80(20);step16to80(21);step16to80(22);step16to80(23);
	step16to80(24);step16to80(25);step16to80(26);step16to80(27);
	step16to80(28);step16to80(29);step16to80(30);step16to80(31);
	step16to80(32);step16to80(33);step16to80(34);step16to80(35);
	step16to80(36);step16to80(37);step16to80(38);step16to80(39);
	step16to80(40);step16to80(41);step16to80(42);step16to80(43);
	step16to80(44);step16to80(45);step16to80(46);step16to80(47);
	step16to80(48);step16to80(49);step16to80(50);step16to80(51);
	step16to80(52);step16to80(53);step16to80(54);step16to80(55);
	step16to80(56);step16to80(57);step16to80(58);step16to80(59);
	step16to80(60);step16to80(61);step16to80(62);step16to80(63);
	step16to80(64);step16to80(65);step16to80(66);step16to80(67);
	step16to80(68);step16to80(69);step16to80(70);step16to80(71);
	step16to80(72);step16to80(73);step16to80(74);step16to80(75);
	step16to80(76);step16to80(77);step16to80(78);step16to80(79);

	*H += iv512;
	*H = SWAP64(*H);

}
