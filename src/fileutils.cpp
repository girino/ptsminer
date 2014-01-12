/*
 * fileutils.cpp
 *
 *  Created on: 03/01/2014
 *      Author: girino
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include "fileutils.h"

#define LOADFILE_SUCCESS 0
#define ERROR_NOT_OPEN -1
#define ERROR_BUFRFER_TOO_SMALL -2

int loadfile(const char* filename, char* buffer, size_t* size, size_t max_size) {
	std::ifstream file (filename, std::ios::in|std::ios::binary|std::ios::ate);
	if (file.is_open())
	{
	    file.seekg(0, std::ios::end);
	    *size = file.tellg();
	    if (*size >= max_size) {
	    	return ERROR_BUFRFER_TOO_SMALL;
	    }
	    file.seekg (0, std::ios::beg);
	    file.read (buffer, *size);
	    file.close();

	    buffer[*size] = 0;

	    return LOADFILE_SUCCESS;
	}
	return ERROR_NOT_OPEN;
}
