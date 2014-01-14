//
//  OpenCLMomentumV4.cpp
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//

#include "OpenCLMomentumV4.h"
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

OpenCLMomentumV4::OpenCLMomentumV4(int _HASH_BITS, int _device_num) {
	max_threads = 1<<30; // very big
	HASH_BITS = _HASH_BITS;
	device_num = _device_num;

	OpenCLMain& main = OpenCLMain::getInstance();

	// checks if device exists
	if (main.getInstance().getPlatform(0)->getNumDevices() <= device_num) {
		printf("ERROR: DEVICE %d does not exist. Please limit your threads to one per device.\n", device_num);
		assert(false);
	}

	// compiles
	fprintf(stdout, "Starting OpenCLMomentum V4\n");
	fprintf(stdout, "Device: %s\n", main.getPlatform(0)->getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = main.getPlatform(0)->getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = main.getPlatform(0)->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/cryptsha512_kernel.cl");
	program_filenames.push_back("opencl/OpenCLMomentumV4.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	// prealoc kernels
	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_fill_table = program->getKernel("fill_table");
	OpenCLKernel *kernel_find_collisions = program->getKernel("find_collisions");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	// only one queue, helps with memory leaking
	queue = context->createCommandQueue(device_num);

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*32, CL_MEM_READ_ONLY, NULL);
	hashes = context->createBuffer(sizeof(uint64_t)*MAX_MOMENTUM_NONCE, CL_MEM_READ_WRITE, NULL);
	hash_table = context->createBuffer(sizeof(uint32_t)*(1<<HASH_BITS), CL_MEM_READ_WRITE, NULL);
	collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);
}

OpenCLMomentumV4::~OpenCLMomentumV4() {
	// destroy
	delete hashes;
	delete hash_table;
	delete (collisions);
	delete (collisions_count);
	delete (cl_message);

	// oops, memory was leeeeeeaking...
	delete queue;
}

void OpenCLMomentumV4::find_collisions(uint8_t* message, collision_struct* out_buff, size_t* out_count) {

	// temp storage
	*out_count = 0;
	uint32_t ht_size = 1<<HASH_BITS;

	OpenCLContext *context = OpenCLMain::getInstance().getPlatform(0)->getContext();
	OpenCLProgram *program = context->getProgram(0);

	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_fill_table = program->getKernel("fill_table");
	OpenCLKernel *kernel_find_collisions = program->getKernel("find_collisions");
	OpenCLKernel *kernel_cleanup = program->getKernel("kernel_clean_hash_table");

	OpenCLDevice * device = OpenCLMain::getInstance().getPlatform(0)->getDevice(device_num);

	// cleans up the hash table
	kernel_cleanup->resetArgs();
	kernel_cleanup->addGlobalArg(hash_table);
	cl_event eventkc = queue->enqueueKernel1D(kernel_cleanup, 1<<HASH_BITS, kernel_cleanup->getWorkGroupSize(device), NULL, 0);

//	printf("Cleaning the HT\n");
//	queue->finish();

	cl_event eventwmsg = queue->enqueueWriteBuffer(cl_message, message, sizeof(uint8_t)*32, &eventkc, 1);
	// step 1, calculate hashes
	kernel_calculate_all_hashes->resetArgs();
	kernel_calculate_all_hashes->addGlobalArg(cl_message);
	kernel_calculate_all_hashes->addGlobalArg(hashes);
	cl_event eventcah = queue->enqueueKernel1D(kernel_calculate_all_hashes, MAX_MOMENTUM_NONCE/8,
							kernel_calculate_all_hashes->getWorkGroupSize(device), &eventwmsg, 1);

//	printf("step 1, calculate hashes\n");
//	queue->finish();

	// step 2, populate hashtable
	kernel_fill_table->resetArgs();
	kernel_fill_table->addGlobalArg(hashes);
	kernel_fill_table->addGlobalArg(hash_table);
	kernel_fill_table->addScalarUInt(ht_size);
	cl_event temp_events[] = {eventcah, eventkc};
	cl_event eventft = queue->enqueueKernel1D(kernel_fill_table, MAX_MOMENTUM_NONCE,
							kernel_fill_table->getWorkGroupSize(device), temp_events, 2);

//	printf("step 2, populate hashtable\n");
//	queue->finish();

	cl_event eventwcount = queue->enqueueWriteBuffer(collisions_count, out_count, sizeof(size_t), NULL, 0);
	// step 3, find collisions
	kernel_find_collisions->resetArgs();
	kernel_find_collisions->addGlobalArg(hashes);
	kernel_find_collisions->addGlobalArg(hash_table);
	kernel_find_collisions->addScalarUInt(ht_size);
	kernel_find_collisions->addGlobalArg(collisions);
	kernel_find_collisions->addGlobalArg(collisions_count);
	cl_event temp_events2[] = {eventft, eventwcount};
	cl_event eventfc = queue->enqueueKernel1D(kernel_find_collisions, MAX_MOMENTUM_NONCE,
							kernel_find_collisions->getWorkGroupSize(device), temp_events2, 2);

//	printf("step 3, find collisions\n");
//	queue->finish();

	queue->enqueueReadBuffer(collisions_count, out_count, sizeof(size_t), &eventfc, 1);
	queue->enqueueReadBuffer(collisions, out_buff, sizeof(collision_struct)*getCollisionCeiling(), &eventfc, 1);

//	printf("step 4, copy output\n");
	queue->finish();

#ifdef DEBUG
	printf("Collision Count = %d\n", (*out_count));
#endif

}

int OpenCLMomentumV4::getCollisionCeiling() {
	return (1<<8);
}
