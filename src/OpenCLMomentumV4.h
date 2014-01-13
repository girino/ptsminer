//
//  OpenCLMomentumV4.h
//  momentumCL
//
//  Created by Girino Vey on 02/01/14.
//
//

#ifndef __momentumCL__OpenCLMomentumV4__
#define __momentumCL__OpenCLMomentumV4__

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

class OpenCLMomentumV4: public AbstractMomentum {
public:
	OpenCLMomentumV4(int _HASH_BITS, int device_num);
	virtual ~OpenCLMomentumV4();
	virtual void find_collisions(uint8_t* message, collision_struct* collisions, size_t* collision_count);
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

#endif /* defined(__momentumCL__OpenCLMomentumV4__) */
