#include <stdio.h>
#include "shared_functions.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>

#define DER_FILE_BUFFER (1024)
#define OUTPUT_BUFFER_SIZE (1024)

int    ret;     /* returned value */

/* Random generator object */
WC_RNG rng_obj;
/* Reserve buffer content of file with key */
byte der_file_content[DER_FILE_BUFFER] = {0};
/* Buffer to exponent */
byte   exponent[1024];
/* Buffer to modulus */
byte   modulus[1024];
/* private RSA key structure */
RsaKey private_key;
/* public RSA key structure */
RsaKey public_key;
/* RSA key size */
int    rsa_key_size;
/* Reserve buffer to store ciphertext */
byte ciphertext[OUTPUT_BUFFER_SIZE] = {0};
/* Reserve buffer to store plaintext */
byte plaintext[OUTPUT_BUFFER_SIZE] = {0};

int ciphertext_size;

/* Message to encrypt */
char message[] = "Education is one thing no one can take away from you"; /* Author: Elin Nordegren */

/* Read RSA keys pair from DER files. */
void ReadRsaKeyFromDerFile(void)
{
    size_t bytes_count;
    word32 w32;
    word32 eSz;
    word32 nSz;

    /* ---------------------------------- */
    /* -------- Read private key -------- */
    /* ---------------------------------- */

    bytes_count = ReadBinaryFile("../../../demo_private_key.der", der_file_content);

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
    bytes_count = ReadBinaryFile("../../../demo_public_key.der", der_file_content);

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

void EncryptMessage()
{
    /* Encrypt message using public key.
       Positive returned value gives number of bytes stored to the output buffer. */
    ciphertext_size = wc_RsaPublicEncrypt(
        (const byte *) message,
        sizeof(message),
        ciphertext,
        sizeof(ciphertext),
        &public_key,
        &rng_obj
        );

    if (ciphertext_size >= 0)
    {
        printf("Encrypted message using public exponent: \n");
        PrintHex(ciphertext, ciphertext_size);
        printf("Encrypted message size: %d\n", ciphertext_size);
    }
    else
    {
        printf("ERROR: message encryption failed \n");
    }
}

void DecryptMessage()
{
    /* Decrypt message using private key.
       Positive returned value gives number of bytes stored to the output buffer. */
    ret = wc_RsaPrivateDecrypt(
        ciphertext,
        ciphertext_size,
        plaintext,
        sizeof(plaintext),
        &private_key
        );

    if (ret >= 0)
    {
        printf("Decrypted message using private key: \n");
        printf("%s", (char *) plaintext);
        printf("\n");
        PrintHex(plaintext, ret);
    }
    else
    {
        printf("ERROR: message encryption failed \n");
    }
}

int main()
{
    printf("Hello World!\n");

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", (int)ret);
    }

    if (wc_InitRng(&rng_obj) != 0)
    {
        printf("Error during random number generator initialization\n");
    }

    printf("======== Read Existing RSA Keys ======== \n");
    ReadRsaKeyFromDerFile();

    printf("\n======== Encrypt message using RSA public key ======== \n");
    EncryptMessage();

    printf("\n======== Decrypt message using RSA private key ======== \n");
    DecryptMessage();

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", (int)ret);
    }

    printf("completed\n");

    return 0;
}
