//
//  OpenCLMomentum2.cpp
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

#include "OpenCLMomentum2.h"
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

OpenCLMomentum2::OpenCLMomentum2(int _HASH_BITS, int _device_num) {
	max_threads = 1<<30; // very big
	HASH_BITS = _HASH_BITS;
	device_num = _device_num;

	// compiles
	fprintf(stdout, "Starting OpenCLMomentum V2\n");
	fprintf(stdout, "Device: %s\n", OpenCLMain::getInstance().getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = OpenCLMain::getInstance().getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = OpenCLMain::getInstance().getDevice(device_num)->getPlatform()->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/cryptsha512_kernel.cl");
	program_filenames.push_back("opencl/OpenCLMomentum2.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*32, CL_MEM_READ_ONLY, NULL);
	internal_hash_table = context->createBuffer(sizeof(uint32_t)*(1<<HASH_BITS), CL_MEM_READ_WRITE, NULL);
	temp_collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	temp_collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);
}

OpenCLMomentum2::~OpenCLMomentum2() {
	// destroy
	delete internal_hash_table;
	delete (temp_collisions);
	delete (temp_collisions_count);
	delete (cl_message);
}

void OpenCLMomentum2::find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count) {


	// temp storage
	*collision_count = 0;

	OpenCLContext *context = OpenCLMain::getInstance().getDevice(device_num)->getPlatform()->getContext();
	OpenCLProgram *program = context->getProgram(0);

	OpenCLKernel *kernel = program->getKernel("kernel_sha512");

	assert(kernel != NULL);

	//size_t BLOCKSIZE = main.getPlatform(0)->getDevice(0)->getMaxWorkGroupSize();
	size_t BLOCKSIZE = kernel->getWorkGroupSize(OpenCLMain::getInstance().getDevice(device_num));

	//printf("BLOCKSIZE = %lld\n", BLOCKSIZE);

	kernel->resetArgs();
	kernel->addGlobalArg(cl_message);
	kernel->addGlobalArg(internal_hash_table);
	uint32_t ht_size = 1<<HASH_BITS;
	kernel->addScalarUInt(ht_size);
	kernel->addGlobalArg(temp_collisions);
	kernel->addGlobalArg(temp_collisions_count);

	OpenCLCommandQueue *queue = context->createCommandQueue(OpenCLMain::getInstance().getDevice(device_num));
	cl_event eventw1 = queue->enqueueWriteBuffer(cl_message, message, sizeof(uint8_t)*32, NULL, 0);
	cl_event eventw2 = queue->enqueueWriteBuffer(temp_collisions_count, collision_count, sizeof(uint32_t), &eventw1, 1);

//	cl_event eventk = queue->enqueueKernel1D(kernel, MAX_MOMENTUM_NONCE, worksize, &eventw, 1);
	cl_event eventk = queue->enqueueKernel1D(kernel, MAX_MOMENTUM_NONCE/8, BLOCKSIZE, &eventw2, 1);
	cl_event eventr1 = queue->enqueueReadBuffer(temp_collisions_count, collision_count, sizeof(size_t), &eventk, 1);
	queue->enqueueReadBuffer(temp_collisions, collisions, sizeof(collision_struct)*getCollisionCeiling(), &eventr1, 1);
	queue->finish();
}

int OpenCLMomentum2::getCollisionCeiling() {
	return (1<<8);
}
