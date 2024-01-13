#include <stdio.h>
#include "shared_functions.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>

#define BUFFER_SIZE (1024)
#define DER_FILE_BUFFER (1024)

WC_RNG rng;
int    ret;     /* returned value */
/* Buffer to store keys */
byte   buffer[BUFFER_SIZE];

/* Reserve buffer content of file with key */
byte der_file_content[DER_FILE_BUFFER] = {0};

/* Buffer to exponent */
byte   exponent[1024];
/* Buffer to modulus */
byte   modulus[1024];

/* Read RSA keys pair from DER files. */
void ReadRsaKeyFromDerFile(void)
{
    size_t bytes_count;
    word32 w32;
    word32 eSz;
    word32 nSz;
    int    rsa_key_size;
    RsaKey private_key; /* private RSA key structure */
    RsaKey public_key;  /* public RSA key structure */

    /* ---------------------------------- */
    /* -------- Read private key -------- */
    /* ---------------------------------- */

    bytes_count = ReadBinaryFile("../demo_private_key.der", der_file_content);

    /* Convert serialized RSA key to RSA key structure */
    w32 = 0;
    ret = wc_RsaPrivateKeyDecode(
        der_file_content,
        &w32,
        &private_key,
        bytes_count);
    if ( ret != 0 )
    {
        printf("ERROR in private key decoding!\n");
    }

    rsa_key_size = wc_RsaEncryptSize(&private_key);
    printf("RSA key size %d \n", rsa_key_size);

    /* ---------------------------------- */
    /* -------- Read public key -------- */
    /* ---------------------------------- */

    /* Read public key */
    bytes_count = ReadBinaryFile("../demo_public_key.der", der_file_content);

    w32 = 0;
    ret = wc_RsaPublicKeyDecode(
        der_file_content,
        &w32,
        &public_key,
        bytes_count);
    if ( ret != 0 )
    {
        printf("ERROR in public key decoding!\n");
    }

    eSz = rsa_key_size;
    nSz = rsa_key_size;
    ret = wc_RsaFlattenPublicKey(
        &public_key,
        exponent,
        &eSz,
        modulus,
        &nSz
        );
    if ( ret != 0 )
    {
        printf("ERROR in wc_RsaFlattenPublicKey!\n");
    }

    printf("Public exponent: \n");
    PrintHex(exponent, rsa_key_size);
    printf("Modulus: \n");
    PrintHex(modulus, rsa_key_size);
}

/* Generate RSA keys pair and store to DER files. */
void GenerateRsaKeys(void)
{
    RsaKey rsa_key;
    word32 eSz;
    word32 nSz;
    long pubic_exponent = 65537; // standard public exponent
    const int rsa_key_bit_size = 512; // desired key length, in bits
    const int rsa_key_byte_size = rsa_key_bit_size / 8; // desired key length, in bytes

    if (wc_InitRng(&rng))
    {
        printf("Error during random number generator initialization\n");
    }

    /* Generate RSA Keys */
    ret = wc_MakeRsaKey(
        &rsa_key,
        rsa_key_bit_size,
        pubic_exponent,
        &rng
        );
    if ( ret != 0 )
    {
        printf("ERROR in wc_MakeRsaKey!\n");
    }
    else
    {
        printf("RSA Keys generated\n");
    }

    /* Serialize private key to DER */
    ret = wc_RsaKeyToDer(
        &rsa_key,
        der_file_content,
        DER_FILE_BUFFER
        );
    if ( ret < 0 )
    {
        printf("ERROR in wc_RsaKeyToDer! %d\n", ret);
    }
    else
    {
        printf("RSA Key converted to DER. Bytes in DER: %d \n", ret);
    }

    WriteBinaryFile("wolf_private_key.der",
                    der_file_content,
                    ret);

    /* Extract modulus and exponent from generated key and print them */
    eSz = rsa_key_byte_size;
    nSz = rsa_key_byte_size;
    ret = wc_RsaFlattenPublicKey(
        &rsa_key,
        exponent,
        &eSz,
        modulus,
        &nSz
        );
    if ( ret != 0 )
    {
        printf("ERROR in wc_RsaFlattenPublicKey!\n");
    }

    printf("Public exponent: \n");
    PrintHex(exponent, rsa_key_byte_size);
    printf("Modulus: \n");
    PrintHex(modulus, rsa_key_byte_size);

    /* Serialize public key to DER */
    ret = wc_RsaKeyToPublicDer(
        &rsa_key,
        der_file_content,
        DER_FILE_BUFFER
        );
    if ( ret < 0 )
    {
        printf("ERROR in wc_RsaKeyToDer! %d\n", ret);
    }
    else
    {
        printf("RSA Key converted to DER. Bytes in DER: %d\n", ret);
    }

    WriteBinaryFile("wolf_public_key.der",
                    der_file_content,
                    ret);

    if (wc_FreeRng(&rng))
    {
        printf("Error during random number generator deinitialization");
    }
}

int main()
{
    printf("Hello World!\n");

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", (int)ret);
    }

    printf("======== Read Existing RSA Keys ======== \n");
    ReadRsaKeyFromDerFile();

    printf("======== Generate RSA Keys ======== \n");
    GenerateRsaKeys();

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", (int)ret);
    }

    printf("completed\n");

    return 0;
}
