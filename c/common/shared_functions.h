#ifndef SHARED_FUNCTIONS_H
#define SHARED_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>

/*Function to print bytes in HEX format to the terminal */
extern void PrintHex(unsigned char * buffer,
                     size_t buf_size);

/* Function to write bytes to binary file */
extern void WriteBinaryFile(const char * filename,
                            unsigned char * buffer,
                            size_t buffer_size);

/* Function to read bytes from binary file.
   It returns number of read bytes. */
extern size_t ReadBinaryFile(const char * filename,
                             unsigned char * buffer);

#endif // SHARED_FUNCTIONS_H
