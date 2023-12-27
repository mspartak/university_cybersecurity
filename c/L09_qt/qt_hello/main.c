#include <stdio.h>
#include "shared_functions.h"

int main()
{
    printf("Hello World!\n");

    unsigned char text[] = {"ABCDEFG"};
    printf("Print bytes in HEX:\n");
    PrintHex(text, 5);

    WriteBinaryFile("mybytes.txt",
                    text,
                    7);

    unsigned char buffer[] = {0};
    size_t read_bytes_count = 0;
    read_bytes_count = ReadBinaryFile("mybytes.txt",
                                      buffer);

    printf("\nRead bytes count %d \n", read_bytes_count);
    printf("Content read from file:\n");
    PrintHex(buffer, read_bytes_count);

    return 0;
}
