/*
 * Copyright 2013-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES CCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* AES-CCM test data from NIST public test vectors */

static const unsigned char ccm_key[] = {
    0xce, 0xb0, 0x09, 0xae, 0xa4, 0x45, 0x44, 0x51, 0xfe, 0xad, 0xf0, 0xe6,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23, 0xba, 0xa4, 0x48, 0xe8
};

static const unsigned char ccm_nonce[] = {
    0x76, 0x40, 0x43, 0xc4, 0x94, 0x60, 0xb7
};


//plaintext
static const unsigned char ccm_pt[] = {
    0xc8, 0xd2, 0x75, 0xf9, 0x19, 0xe1, 0x7d, 0x7f, 0xe6, 0x9c, 0x2a, 0x1f,
    0x58, 0x93, 0x9d, 0xfe, 0x4d, 0x40, 0x37, 0x91, 0xb5, 0xdf, 0x13
};


static const unsigned char ccm_ct[] = {
    0x8a, 0x0f, 0x3d, 0x82, 0x29, 0xe4, 0x8e, 0x74, 0x87, 0xfd, 0x95, 0xa2,
    0x8a, 0xd3, 0x92, 0xc8, 0x0b, 0x36, 0x81, 0xd4, 0xfb, 0xc7, 0xbb
};

static const unsigned char ccm_tag[] = {
    0x2b, 0x2d, 0xea, 0xae, 0x8a, 0x7e, 0xc6, 0x9e, 0x86, 0x03, 0xc5, 0x2d, 0x8d, 0xcd, 0xce, 0xc8
};

void aes_ccm_encrypt(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("AES CCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, ccm_pt, sizeof(ccm_pt));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    /* Set nonce length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(ccm_nonce),
                        NULL);
    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(ccm_tag), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce);

    /* Encrypt plaintext: can only be called once */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, ccm_pt, sizeof(ccm_pt));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for CCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}

void aes_ccm_decrypt(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    printf("AES CCM Derypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ccm_ct, sizeof(ccm_ct));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    /* Set nonce length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(ccm_nonce),
                        NULL);
    /* Set expected tag value */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                        sizeof(ccm_tag), (void *)ccm_tag);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce);

    /* Decrypt plaintext, verify tag: can only be called once */
    rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ccm_ct, sizeof(ccm_ct));
    /* Output decrypted block: if tag verify failed we get nothing */
    if (rv > 0) {
        printf("Plaintext:\n");
        BIO_dump_fp(stdout, outbuf, outlen);
    } else
        printf("Plaintext not available: tag verify failed.\n");
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char **argv)
{
    aes_ccm_encrypt();
    aes_ccm_decrypt();
}