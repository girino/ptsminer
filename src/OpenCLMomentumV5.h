//
//  OpenCLMomentumV5.h
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

#ifndef __momentumCL__OpenCLMomentumV5__
#define __momentumCL__OpenCLMomentumV5__

#include <iostream>
#include "fileutils.h"
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "OpenCLObjects.h"
#include "AbstractMomentum.h"

class OpenCLMomentumV5: public AbstractMomentum {
public:
	OpenCLMomentumV5(int _HASH_BITS, int device_num);
	virtual ~OpenCLMomentumV5();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
	virtual int getCollisionCeiling();
private:
	size_t max_threads;

	// cache mem objects between runs
	OpenCLBuffer* cl_message;
	OpenCLBuffer* hashes;
	OpenCLBuffer* temp_buffer;
	OpenCLBuffer* collisions;
	OpenCLBuffer* collisions_count;

	// reuse queue
	OpenCLCommandQueue *queue;

	// semi-constants
	int HASH_BITS;
	int device_num;

};

#endif /* defined(__momentumCL__OpenCLMomentumV5__) */
