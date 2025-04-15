#include <stdio.h>
#include "shared_functions.h"
#include <wolfssl/wolfcrypt/random.h>

#define RAND_NUMBER_BYTE_SIZE (8)

WC_RNG my_rand; /* random number generator structure */
int    ret;     /* returned value */
/* Buffer to store random numbers */
byte   buffer[RAND_NUMBER_BYTE_SIZE];

int main()
{
    printf("Hello World!\n");

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", (int)ret);
        return 1;
    }

    ret = wc_InitRng(
        &my_rand
        );

    if (0 != ret) {
        printf("Error during random number generator initialization\n");
        return 1;
    }
    else {
        printf("Random number generator initialized\n");
    }

    ret = wc_RNG_GenerateBlock(
        &my_rand,
        buffer,
        RAND_NUMBER_BYTE_SIZE
        );

    if (0 != ret) {
        printf("Error during random number generation\n");
        return 1;
    }
    else {
        printf("Generated: ");
        PrintHex(buffer, RAND_NUMBER_BYTE_SIZE);
    }

    ret = wc_FreeRng(&my_rand);
    if (0 != ret) {
        printf("Error during random number generator deinitialization");
        return 1;
    }

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", (int)ret);
    }

    printf("completed\n");

    return 0;
}
