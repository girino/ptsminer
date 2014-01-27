//
//  OpenCLMomentumV9.h
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

#ifndef __momentumCL__OpenCLMomentumV9__
#define __momentumCL__OpenCLMomentumV9__

#include <iostream>
#include "fileutils.h"
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "OpenCLObjects.h"
#include "AbstractMomentum.h"

class OpenCLMomentumV9: public AbstractMomentum {
public:
	OpenCLMomentumV9(int _HASH_BITS, int device_num);
	virtual ~OpenCLMomentumV9();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
	virtual int getCollisionCeiling();
private:
	size_t max_threads;

	// cache mem objects between runs
	OpenCLBuffer* internal_hash_table;
	OpenCLBuffer* temp_collisions;
	OpenCLBuffer* temp_collisions_count;
	OpenCLBuffer* cl_message;

	// reuse queue
	OpenCLCommandQueue *queue;

	// semi-constants
	int HASH_BITS;
	int device_num;

};

#endif /* defined(__momentumCL__OpenCLMomentumV9__) */
