//
//  OpenCLMomentumV9.cpp
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
/*
 * Copyright (c) 2014 Girino Vey.
 *
 * All code in this file is copyrighted to me, Girino Vey, and licensed under Girino's
 * Anarchist License, available at http://girino.org/license and is available on this
 * repository as the file girino_license.txt
 *
 */

#include "OpenCLMomentumV9.h"
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
#include "sha512.h"

OpenCLMomentumV9::OpenCLMomentumV9(int _HASH_BITS, int _device_num) {
	max_threads = 1<<30; // very big
	HASH_BITS = _HASH_BITS;
	device_num = _device_num;

	OpenCLMain& main = OpenCLMain::getInstance();

	// checks if device exists
	if (main.getInstance().getNumDevices() <= device_num) {
		printf("ERROR: DEVICE %d does not exist. Please limit your threads to one per device.\n", device_num);
		assert(false);
	}

	// compiles
	fprintf(stdout, "Starting OpenCLMomentum V9\n");
	fprintf(stdout, "Device %02d: %s\n", device_num, main.getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = main.getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = main.getDevice(device_num)->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/sha512vectorized.cl");
	program_filenames.push_back("opencl/OpenCLMomentumV9.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	// prealoc kernels
	OpenCLKernel *kernel = program->getKernel("kernel_sha512");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	// only one queue, helps with memory leaking
	queue = context->createCommandQueue(main.getDevice(device_num));

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*SHA512_BLOCK_SIZE, CL_MEM_READ_ONLY, NULL);
	internal_hash_table = context->createBuffer(sizeof(uint32_t)*(1<<HASH_BITS), CL_MEM_READ_WRITE, NULL);
	temp_collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	temp_collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);

	// sets args
	kernel_cleanup->resetArgs();
	kernel_cleanup->addGlobalArg(internal_hash_table);

	kernel->resetArgs();
	kernel->addGlobalArg(cl_message);
	kernel->addGlobalArg(internal_hash_table);
	uint32_t ht_size = 1<<HASH_BITS;
	kernel->addScalarUInt(ht_size);
	kernel->addGlobalArg(temp_collisions);
	kernel->addGlobalArg(temp_collisions_count);

}

OpenCLMomentumV9::~OpenCLMomentumV9() {
	// destroy
	delete internal_hash_table;
	delete (temp_collisions);
	delete (temp_collisions_count);
	delete (cl_message);

	// oops, memory was leeeeeeaking...
	delete queue;
}

void OpenCLMomentumV9::find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count) {

	// temp storage
	*collision_count = 0;
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

	OpenCLKernel *kernel = program->getKernel("kernel_sha512");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	assert(kernel != NULL);

	//size_t BLOCKSIZE = main.getPlatform(0)->getDevice(0)->getMaxWorkGroupSize();
	size_t BLOCKSIZE = kernel->getWorkGroupSize(OpenCLMain::getInstance().getDevice(device_num));
	//has to be a power of 2
	BLOCKSIZE = 1<<log2(BLOCKSIZE);
	size_t BLOCKSIZE_CLEAN = kernel_cleanup->getWorkGroupSize(OpenCLMain::getInstance().getDevice(device_num));
	BLOCKSIZE_CLEAN = 1<<log2(BLOCKSIZE_CLEAN);

//	printf("BLOCKSIZE = %ld\n", BLOCKSIZE);
//	printf("BLOCKSIZE_CLEAN = %ld\n", BLOCKSIZE_CLEAN);

	// cleans up the hash table
	queue->enqueueKernel1D(kernel_cleanup, 1<<HASH_BITS, BLOCKSIZE_CLEAN);

	queue->enqueueWriteBuffer(cl_message, c512_avxsse.buffer.bytes, sizeof(uint8_t)*SHA512_BLOCK_SIZE);
	queue->enqueueWriteBuffer(temp_collisions_count, collision_count, sizeof(size_t));

	queue->enqueueKernel1D(kernel, MAX_MOMENTUM_NONCE/8, BLOCKSIZE);
	queue->enqueueReadBuffer(temp_collisions_count, collision_count, sizeof(size_t));
	queue->enqueueReadBuffer(temp_collisions, collisions, sizeof(collision_struct)*getCollisionCeiling());
	queue->finish();


}

int OpenCLMomentumV9::getCollisionCeiling() {
	return (1<<20);
}
