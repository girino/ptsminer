#ifndef MAIN_POOLMINER_HPP_
#define MAIN_POOLMINER_HPP_

#if defined(__MINGW64__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <cstring>

extern "C" {
#include "sph_sha2.h"
}
#include "cpuid.h"
#include "sha512.h"

enum SHAMODE { SPHLIB = 0, AVXSSE4, FIPS180_2, GPU };
enum GPUALGO { GPUV2 = 2, GPUV3, GPUV4, GPUV5, GPUV3_AMD, GPUV4_AMD };

typedef struct {
  // comments: BYTES <index> + <length>
  int32_t nVersion;            // 0+4
  uint8_t hashPrevBlock[32];       // 4+32
  uint8_t hashMerkleRoot[32];      // 36+32
  uint32_t  nTime;               // 68+4
  uint32_t  nBits;               // 72+4
  uint32_t  nNonce;              // 76+4
  uint32_t  birthdayA;          // 80+32+4 (uint32_t)
  uint32_t  birthdayB;          // 84+32+4 (uint32_t)
  uint8_t   targetShare[32];
} blockHeader_t;              // = 80+32+8 bytes header (80 default + 8 birthdayA&B + 32 target)

class CBlockProvider {
public:
	CBlockProvider() { }
	~CBlockProvider() { }
	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) = 0;
	virtual blockHeader_t* getOriginalBlock() = 0;
	virtual void setBlockTo(blockHeader_t* newblock) = 0;
	virtual void submitBlock(blockHeader_t* block, unsigned int thread_id) = 0;
	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) = 0;
};


extern volatile uint64_t totalCollisionCount;
extern volatile uint64_t totalShareCount;

#define MAX_MOMENTUM_NONCE (1<<26) // 67.108.864
#define SEARCH_SPACE_BITS  50
#define BIRTHDAYS_PER_HASH 8

void print256(const char* bfstr, uint32_t* v);

#endif // MAIN_POOLMINER_HPP_
