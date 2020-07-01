#include <stdlib.h> 
#include <stdio.h> 
#include "helpers.h"

#define PORT 8800
#define SA struct sockaddr 


unsigned char aes_var_key[] = {
    0xbf, 0x8f, 0x09, 0xae, 0x27, 0x23, 0xba, 0xa4, 0x48, 0xa4, 0x45, 0x44, 0x51, 0x45, 0xce, 0xb0, 0x0e, 0xad, 0x90, 0x52, 0x5d, 0xd0,  0x38, 0xe6  
};

unsigned char aes_var_nonce[16], aes_var_tag[16];



int SymmetricAuthentication(int sockfd) {
	printf("Waiting for random challenge\n");	
	read(sockfd, aes_var_nonce, sizeof(aes_var_nonce));
	printf("Recieved nonce:\n");
    BIO_dump_fp(stdout, aes_var_nonce, 16);
	printf("Solving random challenge\n");
	char encrypted[1024];
	char tag[16];
	memcpy(encrypted, aes_var_nonce, sizeof(aes_var_nonce));
	aes_aes_var_encrypt(encrypted, tag, aes_var_nonce, aes_var_key, sizeof(aes_var_nonce));
	printf("Sending encrypted response...\n");
	    BIO_dump_fp(stdout, encrypted, 16);
	write(sockfd, encrypted, sizeof(aes_var_nonce));
	write(sockfd, tag, 16);
	
	printf("Sending challenge...\n");
	printf("Generating random nonce\n");
	RAND_bytes(aes_var_nonce, sizeof(aes_var_nonce));
	write(sockfd, aes_var_nonce, sizeof(aes_var_nonce));
	printf("Sent nonce:\n");
    BIO_dump_fp(stdout, aes_var_nonce, 16);
	bzero(encrypted, sizeof(encrypted));
	char Tbuff[16];
	read(sockfd, encrypted, sizeof(aes_var_nonce));
	bzero(Tbuff, 16);
	read(sockfd, Tbuff, sizeof(Tbuff)); 
	printf("Recieved Response:\n");
    BIO_dump_fp(stdout, encrypted, 16);
	
	printf("Decrypting the response...\n");
	aes_aes_var_decrypt(encrypted, Tbuff, aes_var_nonce, aes_var_key, sizeof(aes_var_nonce));
	if(strncmp(encrypted, aes_var_nonce, sizeof(aes_var_nonce)) == 0) {
		printf("The other party is now authenticated!\n");
		return 1;
	} else{
		printf("The other party could not be authenticated!\n");
		return 0;
	} 
}
int main () {
	struct sockaddr_in servaddr, cli; 
	int	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr)); 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT);
	bind(sockfd, (SA*)&servaddr, sizeof(servaddr));
	int	len = sizeof(cli); 
	listen(sockfd, 5);
	int connfd = accept(sockfd, (SA*)&cli, &len);
	printf("Starting symmetric key mutual authentication:\n");	
	if(SymmetricAuthentication(connfd)) {
		printf("Mutual auth done!\n");
		//start message transfer using encryption and digital signature
	}
	else {
		printf("Mutual Auth failed\n");
	}
	close(sockfd);
	return 0;
}
