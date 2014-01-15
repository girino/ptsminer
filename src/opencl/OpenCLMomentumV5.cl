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

typedef struct _hash_struct {
	uint64_t birthday;
	uint32_t nonce;
} hash_struct;

// first pass, hashes
kernel void calculate_all_hashes(constant char * message,
								 global hash_struct * hashes) {
	size_t id = get_global_id(0);
	uint32_t nonce = (id*8);
	char tempHash[36];

	#pragma unroll
	for (int i = 0; i < 32; i++) tempHash[i+4] = message[i];
	*((uint32_t*)tempHash) = nonce;

    sha512_ctx sctx;
    init_ctx(&sctx);
    ctx_update(&sctx, tempHash, 36);
    uint64_t hash[8];
    sha512_digest(&sctx, hash);

    for (int i = 0; i < 8; i++) {
    	hashes[nonce+i].birthday = GET_BIRTHDAY(hash[i]);
    	hashes[nonce+i].nonce = nonce+i;
    }
}


// third pass, lookup
kernel void find_collisions_sorted(global hash_struct * hashes,
							global collision_struct * collisions,
							global uint32_t * collision_count) {
	size_t id = get_global_id(0);
	if (id != 0) { // ignores first pos, since theres no predecessor
		if (hashes[id].birthday == hashes[id-1].birthday) {
			uint32_t pos = atomic_inc(collision_count);
			collisions[pos].nonce_b = hashes[id].nonce;
			collisions[pos].nonce_a = hashes[id-1].nonce&~7;
			collisions[pos].birthday = hashes[id].birthday;
		}
	}
}

void inner_merge(global hash_struct* inBuffer,
                          global hash_struct* tempBuffer,
                          int offset,
                          int numElements) {
 	int pos = offset+numElements-1; // starts from the end
 	int begini = offset;
 	int beginj = offset + numElements/2;
	int i = beginj-1;
	int j = pos;
	while(i >= begini && j >= beginj) {
		if (inBuffer[i].birthday > inBuffer[j].birthday) {
			tempBuffer[pos] = inBuffer[i];
			i--;
		} else {
			tempBuffer[pos] = inBuffer[j];
			j--;
		}
		pos--;
	}
	while(i >= begini) {
			tempBuffer[pos] = inBuffer[i];
			i--;
			pos--;
	}
	while(j >= beginj) {
			tempBuffer[pos] = inBuffer[j];
			j--;
			pos--;
	}
	//copies back
	for (int i = 0; i < numElements; i++) {
		inBuffer[i+offset] = tempBuffer[i+offset];
	}
}

kernel void sort_hashes(global hash_struct* inBuffer,
                          global hash_struct* tempBuffer,
                          unsigned int numElements) {

    size_t id = get_global_id(0);
    int begin_index = id * numElements;
    for (int n = 2; n <= numElements; n*=2) {
    	for (int i = 0; i < numElements; i+=n) {
    		inner_merge(inBuffer, tempBuffer, begin_index+i, n);
		}
    }

}

kernel void merge_hashes(global hash_struct* inBuffer,
                          global hash_struct* tempBuffer,
                          unsigned int numElements) {
    size_t id = get_global_id(0);
    int begin_index = id * numElements;
	inner_merge(inBuffer, tempBuffer, begin_index, numElements);
}
