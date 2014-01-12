//
//  OpenCLMomentumV3.h
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//

#ifndef __momentumCL__OpenCLMomentumV3__
#define __momentumCL__OpenCLMomentumV3__

#include <iostream>
#include "fileutils.h"
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "OpenCLObjects.h"
#include "AbstractMomentum.h"

#define COLLISION_BUFFER_SIZE (1<<16)

class OpenCLMomentumV3: public AbstractMomentum {
public:
	OpenCLMomentumV3(int _HASH_BITS);
	virtual ~OpenCLMomentumV3();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
private:
	size_t max_threads;
	OpenCLMain main;

	// cache mem objects between runs
	OpenCLBuffer* internal_hash_table;
	OpenCLBuffer* temp_collisions;
	OpenCLBuffer* temp_collisions_count;
	OpenCLBuffer* cl_message;

	// semi-constants
	int HASH_BITS;

};

#endif /* defined(__momentumCL__OpenCLMomentumV3__) */
