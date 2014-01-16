//
//  OpenCLMomentumV3.cpp
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

#include "OpenCLMomentumV3.h"
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

OpenCLMomentumV3::OpenCLMomentumV3(int _HASH_BITS, int _device_num) {
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
	fprintf(stdout, "Starting OpenCLMomentum V3\n");
	fprintf(stdout, "Device %02d: %s\n", device_num, main.getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = main.getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = main.getDevice(device_num)->getPlatform()->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/cryptsha512_kernel.cl");
	program_filenames.push_back("opencl/OpenCLMomentumV3.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	// prealoc kernels
	OpenCLKernel *kernel = program->getKernel("kernel_sha512");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	// only one queue, helps with memory leaking
	queue = context->createCommandQueue(main.getDevice(device_num));

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*32, CL_MEM_READ_ONLY, NULL);
	internal_hash_table = context->createBuffer(sizeof(uint32_t)*(1<<HASH_BITS), CL_MEM_READ_WRITE, NULL);
	temp_collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	temp_collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);
}

OpenCLMomentumV3::~OpenCLMomentumV3() {
	// destroy
	delete internal_hash_table;
	delete (temp_collisions);
	delete (temp_collisions_count);
	delete (cl_message);

	// oops, memory was leeeeeeaking...
	delete queue;
}

void OpenCLMomentumV3::find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count) {

	// temp storage
	*collision_count = 0;

	OpenCLContext *context = OpenCLMain::getInstance().getDevice(device_num)->getPlatform()->getContext();
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
	kernel_cleanup->resetArgs();
	kernel_cleanup->addGlobalArg(internal_hash_table);
	cl_event eventkc = queue->enqueueKernel1D(kernel_cleanup, 1<<HASH_BITS, BLOCKSIZE_CLEAN, NULL, 0);

	kernel->resetArgs();
	kernel->addGlobalArg(cl_message);
	kernel->addGlobalArg(internal_hash_table);
	uint32_t ht_size = 1<<HASH_BITS;
	kernel->addScalarUInt(ht_size);
	kernel->addGlobalArg(temp_collisions);
	kernel->addGlobalArg(temp_collisions_count);

	cl_event eventw1 = queue->enqueueWriteBuffer(cl_message, message, sizeof(uint8_t)*32, &eventkc, 1);
	cl_event eventw2 = queue->enqueueWriteBuffer(temp_collisions_count, collision_count, sizeof(size_t), &eventkc, 1);

//	cl_event eventk = queue->enqueueKernel1D(kernel, MAX_MOMENTUM_NONCE, worksize, &eventw, 1);
	cl_event eventk = queue->enqueueKernel1D(kernel, MAX_MOMENTUM_NONCE/8, BLOCKSIZE, &eventw2, 1);
	cl_event eventr1 = queue->enqueueReadBuffer(temp_collisions_count, collision_count, sizeof(size_t), &eventk, 1);
	queue->enqueueReadBuffer(temp_collisions, collisions, sizeof(collision_struct)*getCollisionCeiling(), &eventr1, 1);
	queue->finish();

}

int OpenCLMomentumV3::getCollisionCeiling() {
	return (1<<20);
}
