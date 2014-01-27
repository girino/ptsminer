//
//  OpenCLMomentumV7.cpp
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//
/*
 * Copyright (c) 2014 Girino Vey.
 *
 * All code in this file is copyrighted to me, Girino Vey, and licensed under Girino's
 * Anarchist License, available at http://girino.org/license and is available on this
 * repository as the file girino_license.txt
 *
 */
#include "OpenCLMomentumV7.h"
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <assert.h>
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif
#include "global.h"
#include "sha_utils.h"

OpenCLMomentumV7::OpenCLMomentumV7(int _HASH_BITS, int _device_num) {
	max_threads = 1<<30; // very big
	HASH_BITS = _HASH_BITS;
	device_num = _device_num;

	OpenCLMain& main = OpenCLMain::getInstance();

	// checks if device exists
	if (main.getNumDevices() <= device_num) {
		printf("ERROR: DEVICE %d does not exist. Please limit your threads to one per device.\n", device_num);
		assert(false);
	}

	// compiles
	fprintf(stdout, "Starting OpenCLMomentum V7\n");
	fprintf(stdout, "Device %02d: %s\n", device_num, main.getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = main.getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = main.getDevice(device_num)->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/sha512vectorized.cl");
	program_filenames.push_back("opencl/OpenCLMomentumV7.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	// prealoc kernels
	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_fill_table = program->getKernel("fill_table");
	OpenCLKernel *kernel_find_collisions = program->getKernel("find_collisions");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	// only one queue, helps with memory leaking
	queue = context->createCommandQueue(main.getDevice(device_num));

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*SHA512_BLOCK_SIZE, CL_MEM_READ_ONLY, NULL);
	hashes = context->createBuffer(sizeof(uint64_t)*MAX_MOMENTUM_NONCE, CL_MEM_READ_WRITE, NULL);
	hash_table = context->createBuffer(sizeof(uint32_t)*(1<<HASH_BITS), CL_MEM_READ_WRITE, NULL);
	collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);

	// prepare arguments
	kernel_cleanup->resetArgs();
	kernel_cleanup->addGlobalArg(hash_table);

	kernel_calculate_all_hashes->resetArgs();
	kernel_calculate_all_hashes->addGlobalArg(cl_message);
	kernel_calculate_all_hashes->addGlobalArg(hashes);

	kernel_fill_table->resetArgs();
	kernel_fill_table->addGlobalArg(hashes);
	kernel_fill_table->addGlobalArg(hash_table);
	uint32_t ht_size = 1<<HASH_BITS;
	kernel_fill_table->addScalarUInt(ht_size);

	kernel_find_collisions->resetArgs();
	kernel_find_collisions->addGlobalArg(hashes);
	kernel_find_collisions->addGlobalArg(hash_table);
	kernel_find_collisions->addScalarUInt(ht_size);
	kernel_find_collisions->addGlobalArg(collisions);
	kernel_find_collisions->addGlobalArg(collisions_count);
}

OpenCLMomentumV7::~OpenCLMomentumV7() {
	// destroy
	delete hashes;
	delete hash_table;
	delete (collisions);
	delete (collisions_count);
	delete (cl_message);

	// oops, memory was leeeeeeaking...
	delete queue;
}
#define SWAP64(n) \
            (((n) << 56)                      \
          | (((n) & 0xff00) << 40)            \
          | (((n) & 0xff0000) << 24)          \
          | (((n) & 0xff000000) << 8)         \
          | (((n) >> 8) & 0xff000000)         \
          | (((n) >> 24) & 0xff0000)          \
          | (((n) >> 40) & 0xff00)            \
          | ((n) >> 56))

void OpenCLMomentumV7::find_collisions(uint8_t* message, collision_struct* out_buff, size_t* out_count) {

	// temp storage
	*out_count = 0;
	uint32_t ht_size = 1<<HASH_BITS;
	SHA512_Context c512_avxsse;

	SHA512_Init(&c512_avxsse);
	uint8_t midhash[32+4];
	memcpy(midhash+4, message, 32);
	*((uint32_t*)midhash) = 0;
	SHA512_Update_Simple(&c512_avxsse, midhash, 32+4);
	SHA512_PreFinal(&c512_avxsse);

	*(uint32_t *)(&c512_avxsse.buffer.bytes[0]) = 0;
	uint64_t * swap_helper = (uint64_t*)(&c512_avxsse.buffer.bytes[0]);
	for (int i = 1; i < 5; i++) {
		swap_helper[i] = SWAP64(swap_helper[i]);
	}

	OpenCLContext *context = OpenCLMain::getInstance().getDevice(device_num)->getContext();
	OpenCLProgram *program = context->getProgram(0);

	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_fill_table = program->getKernel("fill_table");
	OpenCLKernel *kernel_find_collisions = program->getKernel("find_collisions");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	OpenCLDevice * device = OpenCLMain::getInstance().getDevice(device_num);

	// cleans up the hash table
	size_t kc_wgsize = kernel_cleanup->getWorkGroupSize(device);
	kc_wgsize = 1<<log2(kc_wgsize);
	queue->enqueueKernel1D(kernel_cleanup, 1<<HASH_BITS, kc_wgsize);

//	printf("Cleaning the HT\n");
//	queue->finish();

	queue->enqueueWriteBuffer(cl_message, c512_avxsse.buffer.bytes, sizeof(uint8_t)*SHA512_BLOCK_SIZE);
	// step 1, calculate hashes
	size_t kcah_wgsize = kernel_calculate_all_hashes->getWorkGroupSize(device);
	kcah_wgsize = 1<<log2(kcah_wgsize);
	queue->enqueueKernel1D(kernel_calculate_all_hashes, MAX_MOMENTUM_NONCE/8,
			kcah_wgsize);

//	uint64_t * apa = new uint64_t[MAX_MOMENTUM_NONCE];
//	queue->enqueueReadBuffer(hashes, apa, sizeof(uint64_t)*MAX_MOMENTUM_NONCE);
//	queue->finish();
//
//	printf("testing hashes\n");
//	uint64_t count = 0;
//	for (int i = 0; i < MAX_MOMENTUM_NONCE; i++) {
//		if (apa[i] == 0) {
//			count++;
//			printf("BAD HASH AT: %d %X\n", i, apa[i]);
//		}
//	}
//	printf("counted %X bad hashes\n", count);
//	printf("NOW REALLY TEST THEM hashes\n");
//	count = 0;
//	for (uint32_t i = 0; i < MAX_MOMENTUM_NONCE/8; i+=8) {
//		sph_sha512_context c512_sph; //SPH
//		sph_sha512_init(&c512_sph);
//		sph_sha512(&c512_sph, &i, 4);
//		sph_sha512(&c512_sph, message, 32);
//		uint64_t out[8];
//		sph_sha512_close(&c512_sph, out);
//		for (int j =0; j < 8; j++) {
//			if (apa[i+j] != out[j]) {
//				count++;
//				uint64_t xxx = apa[i+j];
//				printf("BAD HASH AT: %d => %X != %X\n", i, apa[i+j], out[j]);
//			}
//		}
//	}
//	printf("counted %X bad hashes\n", count);

	// step 2, populate hashtable
//	size_t kft_wgsize = kernel_fill_table->getWorkGroupSize(device);
//	kft_wgsize = 1<<log2(kft_wgsize);
//	queue->enqueueKernel1D(kernel_fill_table, MAX_MOMENTUM_NONCE,
//							kft_wgsize);

//	printf("step 2, populate hashtable\n");
//	queue->finish();

	queue->enqueueWriteBuffer(collisions_count, out_count, sizeof(size_t));
	// step 3, find collisions
	size_t kfc_wgsize = kernel_find_collisions->getWorkGroupSize(device);
	kfc_wgsize = 1<<log2(kfc_wgsize);
	queue->enqueueKernel1D(kernel_find_collisions, MAX_MOMENTUM_NONCE,
							kfc_wgsize);

//	printf("step 3, find collisions\n");
//	queue->finish();

	queue->enqueueReadBuffer(collisions_count, out_count, sizeof(size_t));
	queue->enqueueReadBuffer(collisions, out_buff, sizeof(collision_struct)*getCollisionCeiling());

//	printf("step 4, copy output\n");
	queue->finish();


#ifdef DEBUG
	printf("Collision Count = %d\n", (*out_count));
#endif

}

int OpenCLMomentumV7::getCollisionCeiling() {
	return (1<<8);
}
