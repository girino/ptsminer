//
//  OpenCLMomentum2.h
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//

#ifndef __momentumCL__OpenCLMomentum2__
#define __momentumCL__OpenCLMomentum2__

#include <iostream>
#include "fileutils.h"
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "OpenCLObjects.h"
#include "AbstractMomentum.h"

class OpenCLMomentum2: public AbstractMomentum {
public:
	OpenCLMomentum2(int _HASH_BITS);
	virtual ~OpenCLMomentum2();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
	virtual int getCollisionCeiling();
private:
	size_t max_threads;

	// cache mem objects between runs
	OpenCLBuffer* internal_hash_table;
	OpenCLBuffer* temp_collisions;
	OpenCLBuffer* temp_collisions_count;
	OpenCLBuffer* cl_message;

	// semi-constants
	int HASH_BITS;

};

#endif /* defined(__momentumCL__OpenCLMomentum2__) */
