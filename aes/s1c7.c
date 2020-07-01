#include <stdio.h>
#include<string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "defs.h"


int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();

	/* Bogus key and IV: we'd normally set these from
	 * another source.
	 */
	unsigned char key[] = "YELLOW SUBMARINE";
	unsigned char iv[] = "1234567887654321";

	/* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
			do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	//OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	/* Now we can set key and IV */
	EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

	for(;;)
	{
		inlen = fread(inbuf, 1, 1024, in);
		if(inlen <= 0) break;
		if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
		{
			/* Error */
			EVP_CIPHER_CTX_cleanup(ctx);
			return 0;
		}
		char * op = rawtobase64(outbuf, outlen);
		printf("%s\n",op);
		fwrite(op, 1, strlen(op), out);
	}
	return 1;
}

char *base64toraw(char *input)
{
	int i, j, k = 0;
	char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int length = strlen(input);
	char *output = (char *) calloc(length*3/4, sizeof(char));

	for(i = 0; i < length; i+=4)
	{
		int temp = ((int) (strchr(map, input[i]) - map) << 18) |
			   ((int) (strchr(map, input[i+1]) - map) << 12) |
			   ((int) (strchr(map, input[i+2]) - map) << 6) |
			   ((int) (strchr(map, input[i+3]) - map));
		for(j = 2; j >= 0; j--)
		{
			output[k++] = temp>>j*8&0xFF;
		}

	}
	output[k] = '\0';
	return output;
}

char *rawtobase64(char *input, int length)
{
	int i = 0, j = 0, k = 0;
  	char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *out = calloc(length*4/3, sizeof(char));
	
	for(i = 0; i < length; i+=3)
	{
		int temp = (input[i] << 16) | (input[i+1] << 8) | (input[i+2]);
		for(j = 3; j >= 0; j--)
		{
			out[k++] = map[temp>>j*6&0x3F];
		}
	}
	out[k] = '\0';
	return out;
}

int main(int argc, char *argv[])
{
	if(argc == 3)
	{
		FILE *fin = fopen(argv[1], "r");
		char buffer[100*60];
		fgets(buffer, 100, fin);
		while(fgets(&buffer[strlen(buffer)-1], 100, fin));
		buffer[strlen(buffer)-1] = '\0';
		char *rawbuffer = base64toraw(buffer);
		FILE *fout = fopen("temp.bin", "wb");
		int i = 0;
		fwrite(rawbuffer, sizeof(char), strlen(buffer)*3/4, fout);
		fclose(fout);
		fclose(fin);

		fin = fopen("temp.bin", "rb");
		fout = fopen(argv[2], "w");
		if(do_crypt(fin, fout, 1)) {
			fclose(fin);
			fclose(fout);
			fin = fopen(argv[2], "r");
			char tempbuffer[100];
			while(fgets(&tempbuffer[0], 100, fin))
				printf("%s", tempbuffer);
		}
		else {
			printf("Something went wrong, decrypt failed\n");
			fclose(fout);
		}

		fclose(fin);
	}
	else {
		printf("Usage: ./s1c7.out input.txt output.txt\n");
	}

	return 0;
}
