#include <stdio.h>
#include "shared_functions.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/hash.h>

/* The size of the first part of the message used for the fisrt update */
#define MESSAGE_PART_1_SIZE (8)

int    ret;     /* returned value */
/* Buffer to store calculated hash */
byte calculated_hash[WC_SHA256_DIGEST_SIZE] = {0};

 /* ===========================================================================================================
 * Test vector details:
 * ----- Filename: SHA256ShortMsg.rsp ------
 * from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 *
Len = 80
Msg = 74cb9381d89f5aa73368
MD = 73d6fad1caaa75b43b21733561fd3958bdc555194a037c2addec19dc2d7a52bd
 =========================================================================================================== */
byte Nist_Msg[]    = {0x74,0xcb,0x93,0x81,0xd8,0x9f,0x5a,0xa7,0x33,0x68};
byte Nist_Digest[] = {0x73,0xd6,0xfa,0xd1,0xca,0xaa,0x75,0xb4,0x3b,0x21,0x73,0x35,0x61,0xfd,0x39,0x58,0xbd,0xc5,0x55,0x19,0x4a,0x3,0x7c,0x2a,0xdd,0xec,0x19,0xdc,0x2d,0x7a,0x52,0xbd};

/****************************************************
 * Function compares the first bytes_size bytes in two hashes.
 * Returns 1 if the first bytes_size bytes are equeal
 * Returns 0 if the first bytes_size bytes are NOT equeal
 *****************************************************/
int AreHashesEqual(byte * hash1, byte * hash2, size_t bytes_size)
{
    size_t n;
    int ret = 0;

    for (n = 0 ; n < bytes_size; n++)
    {
        if (hash1[n] != hash2[n])
        {
            return ret;
        }
    }
    ret = 1;

    return ret;
}

/****************************************************
 * Function calculates hash of given message in the
 * NIST test vector and compares against the hash in
 * given in this test vector.
 *****************************************************/
void CheckHashAgainstNistTestVector()
{
    /* Feed the message to the SHA */
    ret = wc_Sha256Hash(
        Nist_Msg,
        sizeof(Nist_Msg),
        calculated_hash
        );
    if (ret != 0)
        printf("ERROR!\n");

    printf("NIST hash: \n");
    PrintHex(Nist_Digest, WC_SHA256_DIGEST_SIZE);

    printf("Calculated hash: \n");
    PrintHex(calculated_hash, WC_SHA256_DIGEST_SIZE);

    if (AreHashesEqual(Nist_Digest, calculated_hash, WC_SHA256_DIGEST_SIZE))
    {
        printf("Hashes are equal \n");
    }
    else
    {
        printf("Hashes MISMATCH! \n");
    }
}

/****************************************************
 * Function reads the message and its hash from the
 * binary file. Calculates hash for the message and
 * compares against the hash read from the file.
 *****************************************************/
void CheckHashAgainstPython()
{
    wc_Sha256 sha_struct;
    /* Buffer to store received hash */
    byte received_hash[WC_SHA256_DIGEST_SIZE];
    /* Buffer to store input message */
    byte message[500];
    /* Size of message in bytes */
    word32 message_len;

    /* Load message from binary file */
    message_len = ReadBinaryFile("message.dat", message);

    /* Load hash from binary file */
    ReadBinaryFile("message_hash.dat", received_hash);

    /* Initialize SHA structure first */
    ret = wc_InitSha256(&sha_struct);
    if (ret != 0)
        printf("ERROR!\n");

    /* Feed part #1 of the message to the SHA */
    ret = wc_Sha256Update(
        &sha_struct,
        message,
        MESSAGE_PART_1_SIZE
        );
    if (ret != 0)
        printf("ERROR!\n");

    /* Feed part #2 of the message to the SHA */
    ret = wc_Sha256Update(
        &sha_struct,
        &message[MESSAGE_PART_1_SIZE],
        (message_len - MESSAGE_PART_1_SIZE)
        );
    if (ret != 0)
        printf("ERROR!\n");

    /* Finalize hash calculation to get digest */
    ret = wc_Sha256Final(
        &sha_struct,
        calculated_hash
        );
    if (ret != 0)
        printf("ERROR!\n");

    printf("Received message: \n");
    for (word32 idx = 0; idx < message_len ; idx++){
        printf("%c", message[idx]);
    }

    printf("\n");
    printf("Received hash: \n");
    PrintHex(received_hash, sizeof(received_hash));

    printf("Calculated hash: \n");
    PrintHex(calculated_hash, sizeof(calculated_hash));

    if (AreHashesEqual(received_hash, calculated_hash, WC_SHA256_DIGEST_SIZE))
    {
        printf("Hashes are equal \n");
    }
    else
    {
        printf("Hashes MISMATCH! \n");
    }
}

int main()
{
    printf("Hash check demo\n");

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", (int)ret);
    }

    printf("Calculate and check hash against NIST Test Vector:\n");
    /* Calculate and check hash against NIST Test Vector */
    CheckHashAgainstNistTestVector();

    printf("\n==========================================\n\n");

    printf("Calculate and check hash against Python:\n");
    /* Calculate and check hash against Python */
    CheckHashAgainstPython();

    printf("completed\n");

    return 0;
}
