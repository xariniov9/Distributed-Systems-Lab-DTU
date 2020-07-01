/**************************
Name: Himanshu Tiwari
Roll Number: 2k19/CSE/09
Date of Assignment: 11-May-2020
Assignment Name: Symmetric Authentication to avoid Reflection attack
**************************/


#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <openssl/bio.h>	
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define MAX 1024
#define BS 1024
#define PORT 8191
#define SA struct sockaddr 

int padding = RSA_PKCS1_PADDING;
 
RSA * createRSA(unsigned char * key, int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL) {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL) {
        printf( "Failed to create RSA");
    }
    return rsa;
}
	
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted) {
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted) {
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted) {
	printf("Apllying Digital Signature..\n");
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted) {
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg) {
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}


char * publicKey;
char * privateKey;
size_t pub_len;
size_t pri_len;


RSA *genRSA() {

  printf("Generating RSA key...\n");
  BIGNUM *e = BN_new();
  BN_set_word(e, 3);
  RSA *rsa = RSA_new();
  if (!RSA_generate_key_ex(rsa, 2048, e, 0)) { // seg fault must occur on this line
    while (getchar() != '\n'); // never gets here
    printf("ERROR: Failed to create RSA key\n");
    return NULL;
  }
  BN_free(e);
  if (!RSA_check_key(rsa)) {
    printf("ERROR: Key failed validation\n");
    return NULL;
  }
  printf("Key generation completed successfully\n");
  return rsa;
}



int generateKeys(char* publicDest, char* privateDest) {
	
    RSA * keypair = genRSA();
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    privateKey = malloc(pri_len + 1);
    publicKey = malloc(pub_len + 1);
	
	privateKey[pri_len] = '\0';
	publicKey[pub_len] = '\0';

    BIO_read(pri, privateKey, pri_len);
    BIO_read(pub, publicKey	, pub_len);
}

static const unsigned char ccm_key[] = {
    0xce, 0xb0, 0x09, 0xae, 0xa4, 0x45, 0x44, 0x51, 0xfe, 0xad, 0xf0, 0xe6,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23, 0xba, 0xa4, 0x48, 0xe8
};

unsigned char ccm_nonce[] = {
    0x76, 0x40, 0x43, 0xc4, 0x94, 0x60, 0xb7, 0x88
};

void generateRandomNonce() {
	RAND_bytes(ccm_nonce, sizeof(ccm_nonce));
}

unsigned char ccm_tag[16];


void aes_ccm_decrypt(char * ct, char * tag, int ctLen) {
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    printf("AES CCM Derypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ct, ctLen);

    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    /* Set nonce length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(ccm_nonce),
                        NULL);
    /* Set expected tag value */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                        16, (void *)tag);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce);

    /* Decrypt plaintext, verify tag: can only be called once */
    rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ct, ctLen);
    /* Output decrypted block: if tag verify failed we get nothing */
    if (rv > 0) {
        printf("Plaintext:\n");
        bzero(ct, 1024);
    	memcpy(ct, outbuf, outlen);
    
        BIO_dump_fp(stdout, outbuf, outlen);
    } else
        printf("Plaintext not available: tag verify failed.\n");
    EVP_CIPHER_CTX_free(ctx);
}



int aes_ccm_encrypt(char * pt, char * tag, int len)
{
	EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("AES CCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt, len);
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    /* Set nonce length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(ccm_nonce), NULL);
    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce);
    EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, len);
 	/* Encrypt plaintext: can only be called once */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, pt, len);
    /* Output encrypted block */
    printf("Ciphertext:\n");
    bzero(pt, 1024);
    memcpy(pt, outbuf, outlen);
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for CCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    bzero(tag, sizeof(tag));
    memcpy(tag, outbuf, 16);
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}


void SignAndEncrypt(char * buff, char * tag, int n) {
	char encrypted[1024];
	bzero(encrypted, sizeof(encrypted));
	int el = private_encrypt(buff, n, privateKey, encrypted);
	bzero(buff, 1024);
	memcpy(buff, encrypted, sizeof(encrypted));
	printf("Applying Encryption\n");
	aes_ccm_encrypt(buff, tag, el);
}

void DecryptAndVerifySign(char * ct, char *tag) {
	printf("Applying Decryption\n");
	aes_ccm_decrypt(ct, tag, 256);
	char pt[1024];
	bzero(pt, sizeof(pt));
	printf("Verifying Digital Signature\n");
	int len = public_decrypt(ct, 256, publicKey, pt);
	if(len > 0)
		printf("Digital Signature verified!\n");
	else
		printf("Digital Signature not able to verify!\n");
	printf("Decrypted: %s\nLength of decrypted message: %d\n", pt,len);
}

void func(int sockfd) 
{ 
	char Mbuff[BS], Tbuff[16]; 
	int n; 
	// infinite loop for chat 
	for (;;) { 
		bzero(Mbuff, MAX); 
		read(sockfd, Mbuff, sizeof(Mbuff)); 

		bzero(Tbuff, 16);
		read(sockfd, Tbuff, sizeof(Tbuff)); 
		
		//read(sockfd, ccm_nonce, sizeof(ccm_nonce)); 
		// DecryptAndVerifySign
		DecryptAndVerifySign(Mbuff, Tbuff);
		
		bzero(Mbuff, sizeof(Mbuff));
		bzero(Tbuff, sizeof(Tbuff));

		printf("Enter the string : "); 
		n = 0; 
		while ((Mbuff[n++] = getchar()) != '\n') 
			; 
        
		if (strncmp("exit", Mbuff, 4) == 0) { 
			printf("Server Exit...\n"); 
			break; 
		} 
		//generateRandomNonce();
        SignAndEncrypt(Mbuff, Tbuff, n);
        printf("Message sent after sign and encryption\n");
        write(sockfd, Mbuff, sizeof(Mbuff));
        write(sockfd, Tbuff, sizeof(Tbuff));
		//write(sockfd, ccm_nonce, sizeof(ccm_nonce));
	} 
} 

int sendChallengeNonce(int sockfd) {
	generateRandomNonce();
	write(sockfd, ccm_nonce, sizeof(ccm_nonce));
	char encrypted[1024];
	char Tbuff[16];
	read(sockfd, encrypted, sizeof(ccm_nonce));
	bzero(Tbuff, 16);
	read(sockfd, Tbuff, sizeof(Tbuff)); 
	aes_ccm_decrypt(encrypted, Tbuff, sizeof(ccm_nonce));
	if(strncmp(encrypted, ccm_nonce, sizeof(ccm_nonce)) == 0) {
		return 1;
	} else return 0;
}

void solveChallenge(int sockfd) {	
	read(sockfd, ccm_nonce, sizeof(ccm_nonce));
	char encrypted[1024];
	char tag[16];
	memcpy(encrypted, ccm_nonce, sizeof(ccm_nonce));
	aes_ccm_encrypt(encrypted, tag, sizeof(ccm_nonce));
	write(sockfd, encrypted, sizeof(ccm_nonce));
	write(sockfd, tag, 16);
}

int MutualAuth(int sockfd) {
	int result = 555;
	//for(;;) {
		solveChallenge(sockfd);
		result = sendChallengeNonce(sockfd);
		//if(result==1) break;
		if(result == 0) return 0;
	//}
	printf("Mutual Authentication done!\n");
	char publicKeySelf[2048];
	memcpy(publicKeySelf, publicKey, pub_len+1);
	printf("Sending own Public key to other party\n");

	write(sockfd, publicKey, pub_len+1);
	//bzero(publicKey, 2048);
	read(sockfd, publicKey, pub_len+1);
	printf("Recieved Public key of other party\n");

	printf("%s\n",publicKey);
}

// Driver function 
int main() { 
    generateKeys(publicKey, privateKey);
    printf("RSA Keys Generated!\n");
    printf("%s\n", publicKey);
    printf("%s\n", privateKey);
    
	
	int sockfd, connfd, len; 
	struct sockaddr_in servaddr, cli; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully binded..\n"); 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	else
		printf("Server listening..\n"); 
	len = sizeof(cli); 

	// Accept the data packet from client and verification 
	connfd = accept(sockfd, (SA*)&cli, &len); 
	if (connfd < 0) { 
		printf("server acccept failed...\n"); 
		exit(0); 
	} 
	else
		printf("server acccept the client...\n"); 

	MutualAuth(connfd);
	// Function for chatting between client and server 
	func(connfd); 

	// After chatting close the socket 
	close(sockfd); 
} 

