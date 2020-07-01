#include <netdb.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h> 
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h> 
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <sys/types.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h> 

#ifndef HELPERS_H_INCLUDED
#define HELPERS_H_INCLUDED
void aes_aes_var_decrypt(char * ct, char * tag, char * aes_var_nonce, char * aes_var_key, int ctLen);
int aes_aes_var_encrypt(char * pt, char * tag, char * aes_var_nonce, char * aes_var_key, int len);
#endif
