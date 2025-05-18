#include <stdio.h>
#include "shared_functions.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>

#define DER_FILE_BUFFER_SIZE  (1024)
#define SIGNATURE_BUFFER_SIZE (1024)
#define HASH_BUFFER_SIZE      (512)
#define OUTPUT_BUFFER_SIZE    (1024)
#define RSA_KEY_SIZE          (2048)

int    ret;     /* returned value */

/* Random generator object */
WC_RNG rng_obj;
/* Buffer to store serialized key to DER */
byte der_file_content[DER_FILE_BUFFER_SIZE] = {0};
/* private RSA key structure */
RsaKey private_key;
/* public RSA key structure */
RsaKey public_key;
/* Reserve buffer to store signature */
byte signature[SIGNATURE_BUFFER_SIZE] = {0};
/* Reserve buffer to store hash */
byte message_hash[HASH_BUFFER_SIZE] = {0};
/* Output buffer */
byte output_buffer[OUTPUT_BUFFER_SIZE] = {0};

int signature_size;

/* Message to sign */
char message[] = "Be yourself; everyone else is already taken.";  /* ― Oscar Wilde */

/* Generate RSA keys pair. */
int GenerateRsaKeyPair(void)
{
    int err = 0;
    word32 w32 = 0;

    ret = wc_InitRsaKey(&private_key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng_obj);
    } else
    {
        printf("ERROR: InitRng failed.\n");
        err = 1;
        return err;
    }

    ret = wc_MakeRsaKey(&private_key, RSA_KEY_SIZE, WC_RSA_EXPONENT, &rng_obj);
    if (ret != 0)
    {
        printf("ERROR: MakeRsaKey error %d.\n", ret);
        err = 2;
        return err;
    }

    /* Serialize public key to buffer */
    ret = wc_RsaKeyToPublicDer(
        &private_key,
        der_file_content,
        DER_FILE_BUFFER_SIZE
        );
    if (ret < 0)
    {
        printf("ERROR: Public key serialization failed. \n");
        err = 2;
        return err;
    }

    ret = wc_RsaPublicKeyDecode(
        der_file_content,
        &w32,
        &public_key,
        ret
        );
    if (ret < 0)
    {
        printf("ERROR: RsaPublicKeyDecode failed. \n");
        err = 3;
        return err;
    }

    return err;
}

/* Sign message */
int Sign()
{
    int err = 0;

    /* Calculate hash of the message */
    ret = wc_Sha256Hash(
        (const byte*) message,
        sizeof(message),
        message_hash
        );
    if (ret != 0)
    {
        printf("ERROR in hash calculation.\n");
        err = 1;
    }

    /* Sign message.
       Positive returned value gives size of signature. */
    signature_size = wc_RsaPSS_Sign(
        (const byte*) message_hash,           // * in      Buffer holding hash of message.
        WC_SHA256_DIGEST_SIZE,  // * inLen   Length of data in buffer (hash length).
        signature,              // * out     Buffer to write encrypted signature into.
        sizeof(signature),      // * outLen  Size of buffer to write to.
        WC_HASH_TYPE_SHA256,    // * hash    Hash algorithm.
        WC_MGF1SHA256,          // * mgf     Mask generation function.
        &private_key,           // * key     RSA key.
        &rng_obj                // * rng     Random number generator.
        );

    if (signature_size >= 0)
    {
        printf("Signature of the message: \n");
        PrintHex(signature, signature_size);
        printf("Signature size: %d\n", signature_size);
    }
    else
    {
        printf("ERROR: message encryption failed %d\n", signature_size);
        err = 2;
    }
    return err;
}

/* Verify signature */
int Verify()
{
    int err = 0;

    /* Calculate hash of the message */
    ret = wc_Sha256Hash(
        (const byte*) message,
        sizeof(message),
        message_hash
        );
    if (ret != 0)
    {
        printf("ERROR in hash calculation.\n");
        err = 1;
    }

    /* Sign message.
       Positive returned value gives size of signature. */
    ret = wc_RsaPSS_VerifyCheck(
        signature,             // * in     Buffer holding encrypted data.
        signature_size,        // * inLen  Length of data in buffer.
        output_buffer,         // * out    Pointer to address containing the PSS data.
        OUTPUT_BUFFER_SIZE,    // * outLen Length of the output.
        message_hash,          // * digest Hash of the data that is being verified.
        WC_SHA256_DIGEST_SIZE, // * digestLen Length of hash.
        WC_HASH_TYPE_SHA256,   // * hash   Hash algorithm.
        WC_MGF1SHA256,         // * mgf    Mask generation function.
        &public_key           // * key    Public RSA key.
        );

    if (ret >= 0)
    {
        printf("Verification result: %d\n", ret);
    }
    else
    {
        printf("ERROR: verification failed %d\n", ret);
        err = 2;
    }

    return err;
}


int main()
{
    printf("Hello World!\n");

    if (wolfCrypt_Init() != 0) {
        printf("wolfCrypt_Init failed %d\n", (int)ret);
    }

    printf("======== Generate RSA Keys ======== \n");
    ret = GenerateRsaKeyPair();
    if (ret != 0)
    {
        return 0;
    }

    printf("\n======== Sign message using RSA-PSS ======== \n");
    ret = Sign();
    if (ret != 0)
    {
        return 0;
    }

    printf("\n======== Verify signature RSA-PSS ======== \n");
    ret = Verify();
    if (ret != 0)
    {
        return 0;
    }

    printf("\n======== Verify signature RSA-PSS (corrupted message) ======== \n");
    message[12] = message[12] ^ 0x01;
    ret = Verify();
    if (ret != 0)
    {
        return 0;
    }

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", (int)ret);
    }

    printf("completed\n");

    return 0;
}
