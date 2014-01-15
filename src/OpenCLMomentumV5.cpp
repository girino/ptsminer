//
//  OpenCLMomentumV5.cpp
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//

#include "OpenCLMomentumV5.h"
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

typedef struct _hash_struct {
	cl_ulong hash;
	cl_ulong index;
} hash_struct;


void inner_merge(hash_struct* inBuffer,
		hash_struct* tempBuffer,
                          int offset,
                          int numElements) {
//	printf("inner_merge(in, out, %d, %d) => ", offset, numElements);
 	int pos = offset+numElements-1; // starts from the end
 	int begini = offset;
 	int beginj = offset + numElements/2;
	int i = offset + numElements/2 - 1;
	int j = offset + numElements - 1;
	while(i >= begini && j >= beginj) {
		if (inBuffer[i].hash > inBuffer[j].hash) {
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
//	printf("[");
	for (int i = 0; i < numElements; i++) {
		inBuffer[i+offset] = tempBuffer[i+offset];
//		printf("%d, ", inBuffer[i+offset].hash);
	}
//	printf("]\n");


}

void sort(hash_struct* inBuffer,
		hash_struct* tempBuffer,
                          unsigned int numElements,
                          size_t id) {

    int begin_index = id * numElements;
    for (int n = 2; n <= numElements; n*=2) {
    	for (int i = 0; i < numElements; i+=n) {
    		inner_merge(inBuffer, tempBuffer, begin_index+i, n);
		}
    }

}

void merge(hash_struct* inBuffer,
		hash_struct* tempBuffer,
                          unsigned int numElements,
						  size_t id) {
    int begin_index = id * numElements;
	inner_merge(inBuffer, tempBuffer, begin_index, numElements);
}


OpenCLMomentumV5::OpenCLMomentumV5(int _HASH_BITS, int _device_num) {
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
	fprintf(stdout, "Starting OpenCLMomentum V5\n");
	fprintf(stdout, "Device: %s\n", main.getPlatform(0)->getDevice(device_num)->getName().c_str());
	cl_ulong maxWorkGroupSize = main.getPlatform(0)->getDevice(device_num)->getMaxWorkGroupSize();
	fprintf(stdout, "Max work group size: %llu\n", maxWorkGroupSize);

	if (maxWorkGroupSize < max_threads) max_threads = maxWorkGroupSize;

	OpenCLContext *context = main.getPlatform(0)->getContext();
	std::vector<std::string> program_filenames;
	program_filenames.push_back("opencl/opencl_cryptsha512.h");
	program_filenames.push_back("opencl/cryptsha512_kernel.cl");
	program_filenames.push_back("opencl/OpenCLMomentumV5.cl");
	OpenCLProgram *program = context->loadProgramFromFiles(program_filenames);

	// prealoc kernels
	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_find_collisions_sorted = program->getKernel("find_collisions_sorted");
	OpenCLKernel *kernel_sort_hashes = program->getKernel("sort_hashes");
	OpenCLKernel *kernel_merge_hashes = program->getKernel("merge_hashes");

	// only one queue, helps with memory leaking
	queue = context->createCommandQueue(device_num);

	size_t BLOCKSIZE = max_threads;
	// allocate internal structure
	cl_message = context->createBuffer(sizeof(uint8_t)*32, CL_MEM_READ_ONLY, NULL);
	hashes = context->createBuffer(sizeof(hash_struct)*MAX_MOMENTUM_NONCE, CL_MEM_READ_WRITE, NULL);
	temp_buffer = context->createBuffer(sizeof(hash_struct)*MAX_MOMENTUM_NONCE, CL_MEM_READ_WRITE, NULL);
	collisions = context->createBuffer(sizeof(collision_struct)*getCollisionCeiling(), CL_MEM_WRITE_ONLY, NULL);
	collisions_count = context->createBuffer(sizeof(size_t), CL_MEM_READ_WRITE, NULL);
}

OpenCLMomentumV5::~OpenCLMomentumV5() {
	// destroy
	delete hashes;
	delete temp_buffer;
	delete (collisions);
	delete (collisions_count);
	delete (cl_message);

	// oops, memory was leeeeeeaking...
	delete queue;
}

void OpenCLMomentumV5::find_collisions(uint8_t* message, collision_struct* out_buff, size_t* out_count) {

	// temp storage
	*out_count = 0;
	uint32_t ht_size = 1<<HASH_BITS;

	OpenCLContext *context = OpenCLMain::getInstance().getPlatform(0)->getContext();
	OpenCLProgram *program = context->getProgram(0);

	OpenCLKernel *kernel_calculate_all_hashes = program->getKernel("calculate_all_hashes");
	OpenCLKernel *kernel_find_collisions_sorted = program->getKernel("find_collisions_sorted");
	OpenCLKernel *kernel_sort_hashes = program->getKernel("sort_hashes");
	OpenCLKernel *kernel_merge_hashes = program->getKernel("merge_hashes");

	OpenCLDevice * device = OpenCLMain::getInstance().getPlatform(0)->getDevice(device_num);

	cl_event eventwmsg = queue->enqueueWriteBuffer(cl_message, message, sizeof(uint8_t)*32, NULL, 0);
	// step 1, calculate hashes
	kernel_calculate_all_hashes->resetArgs();
	kernel_calculate_all_hashes->addGlobalArg(cl_message);
	kernel_calculate_all_hashes->addGlobalArg(hashes);
	size_t kcah_wgsize = kernel_calculate_all_hashes->getWorkGroupSize(device);
	kcah_wgsize = 1<<log2(kcah_wgsize);
	cl_event eventcah = queue->enqueueKernel1D(kernel_calculate_all_hashes, MAX_MOMENTUM_NONCE/8,
			kcah_wgsize, &eventwmsg, 1);

	// sort on GPU
	size_t worksize = kernel_calculate_all_hashes->getWorkGroupSize(device);
	worksize = 1<<log2(worksize);
	size_t gworksize = MAX_MOMENTUM_NONCE;
	uint32_t m = MAX_MOMENTUM_NONCE/gworksize; // how many in each sort
	printf("sorting %d blocks of size %d\n", gworksize, m);

	kernel_sort_hashes->resetArgs();
	kernel_sort_hashes->addGlobalArg(hashes);
	kernel_sort_hashes->addGlobalArg(temp_buffer);
	kernel_sort_hashes->addScalarUInt(m);
	cl_event eventsh = queue->enqueueKernel1D(kernel_sort_hashes, gworksize, worksize, &eventcah, 1);

	// i'm doing it manually for now.
	// finish sorting
	hash_struct * CPU_temp = (hash_struct*) malloc(sizeof(hash_struct)*MAX_MOMENTUM_NONCE);
	cl_event eventmh = eventsh;
	for (m = m * 2; m <= MAX_MOMENTUM_NONCE; m*=2) {
		size_t tmp_worksize = MAX_MOMENTUM_NONCE/m;
		printf("merging %d blocks of size %d\n", tmp_worksize, m);
		worksize = (worksize>tmp_worksize)?tmp_worksize:worksize;

		kernel_merge_hashes->resetArgs();
		kernel_merge_hashes->addGlobalArg(hashes);
		kernel_merge_hashes->addGlobalArg(temp_buffer);
		kernel_merge_hashes->addScalarUInt(m);
		cl_event eventmh_tmp = eventmh;
		eventmh = queue->enqueueKernel1D(kernel_merge_hashes, tmp_worksize, worksize, &eventmh_tmp, 1);

	}
	hash_struct * CPU_hashes = (hash_struct*) malloc(sizeof(hash_struct)*MAX_MOMENTUM_NONCE);
	queue->enqueueReadBuffer(hashes, CPU_hashes, sizeof(hash_struct)*MAX_MOMENTUM_NONCE, &eventcah, 1);
	queue->finish();
	printf("sorted all hashes\n");

	// asserts it's sorted
	for (int i = 1; i < MAX_MOMENTUM_NONCE; i++) {
		if (CPU_hashes[i].hash < CPU_hashes[i-1].hash) {
			printf("orig %d: %lX %d\n", i, CPU_hashes[i].hash, CPU_hashes[i].index);
		}
		assert(CPU_hashes[i].hash >= CPU_hashes[i-1].hash);
	}

	// looks for collisions
	*out_count = 0;
	for (int i = 1; i < MAX_MOMENTUM_NONCE; i++) {
		if (CPU_hashes[i].hash == CPU_hashes[i-1].hash) {
			printf("Collision %d: %lX %d\n", i, CPU_hashes[i].hash, CPU_hashes[i].index);
			out_buff[*out_count].birthday = CPU_hashes[i].hash;
			out_buff[*out_count].nonce_b = CPU_hashes[i].index;
			out_buff[*out_count].nonce_a = CPU_hashes[i-1].index&~7;
			(*out_count)++;
		}
	}
	printf("searched collisions\n");


//	queue->enqueueReadBuffer(collisions_count, out_count, sizeof(size_t), &eventfc, 1);
//	queue->enqueueReadBuffer(collisions, out_buff, sizeof(collision_struct)*getCollisionCeiling(), &eventfc, 1);

//	printf("step 4, copy output\n");

#ifdef DEBUG
	printf("Collision Count = %d\n", (*out_count));
#endif

	free(CPU_hashes);
	free(CPU_temp);
}

int OpenCLMomentumV5::getCollisionCeiling() {
	return (1<<8);
}
