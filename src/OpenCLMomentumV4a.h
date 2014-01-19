//
//  OpenCLMomentumV4a.h
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

#ifndef __momentumCL__OpenCLMomentumV4a__
#define __momentumCL__OpenCLMomentumV4a__

#include <iostream>
#include "fileutils.h"
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "OpenCLObjects.h"
#include "AbstractMomentum.h"

class OpenCLMomentumV4a: public AbstractMomentum {
public:
	OpenCLMomentumV4a(int _HASH_BITS, int device_num);
	virtual ~OpenCLMomentumV4a();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
	virtual int getCollisionCeiling();
private:
	size_t max_threads;

	// cache mem objects between runs
	OpenCLBuffer* cl_message;
	OpenCLBuffer* hashes;
	uint64_t* hashes2;
	OpenCLBuffer* hash_table;
	uint32_t* hash_table2;

	// reuse queue
	OpenCLCommandQueue *queue;

	// semi-constants
	int HASH_BITS;
	int device_num;

};

#endif /* defined(__momentumCL__OpenCLMomentumV4a__) */
