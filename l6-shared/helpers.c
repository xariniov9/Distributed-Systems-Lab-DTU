
#include "helpers.h"

void aes_aes_var_decrypt(char * ct, char * tag, char * aes_var_nonce, char * aes_var_key, int ctLen) {
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_var_nonce), NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_var_key, aes_var_nonce);
    rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ct, ctLen);
    if (rv > 0) {
        bzero(ct, 1024);
    	memcpy(ct, outbuf, outlen);
   	    BIO_dump_fp(stdout, outbuf, 16);
    } else  printf("Plaintext not available: tag verify failed.\n");
    EVP_CIPHER_CTX_free(ctx);
}

int aes_aes_var_encrypt(char * pt, char * tag, char * aes_var_nonce, char * aes_var_key, int len) {
	EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_var_nonce), NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, aes_var_key, aes_var_nonce);
    EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, len);
    EVP_EncryptUpdate(ctx, outbuf, &outlen, pt, len);
    bzero(pt, 1024);
    memcpy(pt, outbuf, outlen);
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    bzero(tag, sizeof(tag));
    memcpy(tag, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}

