#include "shared_functions.h"

/* Function to print byte values in HEX format */
void PrintHex(unsigned char * buffer,
              size_t buf_size)
{
    for (size_t n = 0; n < buf_size; n++)
    {
        printf("%02X", buffer[n]);
    }
    printf("\n");
}

/* Write local buffer to binary file */
void WriteBinaryFile(const char * filename,
                     unsigned char * buffer,
                     size_t buffer_size)
{
    size_t write_bytes_count = 0;
    FILE* out_file = fopen(filename, "wb");
    if (!out_file) {
        printf("ERROR: can not open binary file\n");
        exit(EXIT_FAILURE);
    }
    /* Write all bytes from buffer to file */
    write_bytes_count = fwrite(buffer, 1, buffer_size,out_file );
    if ( write_bytes_count <= 0 ) {
        printf("ERROR during writing to binary file\n");
    }
    fclose(out_file);
}

/* Read binary file content to local buffer */
size_t ReadBinaryFile(const char * filename,
                      unsigned char * buffer)
{
    size_t file_size;
    size_t read_bytes_count = 0;
    FILE* in_file = fopen(filename, "rb");
    if (!in_file) {
        printf("ERROR: can not open binary file\n");
        exit(EXIT_FAILURE);
    }
    /* Determine number of bytes in file */
    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    /* Read all bytes from file to buffer */
    read_bytes_count = fread(buffer, 1, file_size,in_file );
    if ( read_bytes_count <= 0 ) {
        printf("ERROR during reading of binary file\n");
    }
    fclose(in_file);

    return read_bytes_count;
}
