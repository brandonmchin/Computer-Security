// CSC 480 Computer Security, Project 1
// Brandon Chin


#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	unsigned char* outBuf_hmac;
	unsigned char* outBuf_aes;
	unsigned char* outBuf_64;

	outBuf_hmac = malloc(32); 
	outBuf_aes = malloc(32);
	outBuf_64 = malloc(64);

	int i;
	if(entropy != NULL)
	{
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, outBuf_hmac, NULL); //HMAC for hmacKey
		HMAC(EVP_sha512(), KDF_KEY, 32, 0, 0, outBuf_aes, NULL);	// HMAC with null entropy args for aesKey.

		for (i = 0; i < 32; i++)
		{
			K->hmacKey[i] = outBuf_hmac[i];
			//printf("%02X", outBuf_hmac[i]);
		}

		for (i = 0; i < 32; i++)
		{
			K->aesKey[i] = outBuf_aes[i];
			//printf("%02X", outBuf_aes[i]);
		}
	}

	else
	{
		randBytes(outBuf_hmac, 32);   // Generate random bytes to be used for hmacKey and aesKey.
		randBytes(outBuf_aes, 32);

		for (i = 0; i < 32; i++) 
		{
			K->hmacKey[i] = outBuf_hmac[i];
			K->aesKey[i] = outBuf_aes[i];
		}
	}

	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	 // If IV is null, generate new IV.
	 if(!IV)
	 {	
	 	IV = malloc(16);
	 	memcpy(IV,inBuf,16);
	 }

	 memcpy(outBuf,IV, 16);

	 EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	 if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV))
	 	ERR_print_errors_fp(stderr);

	 int nWritten;

	 if (1 != EVP_EncryptUpdate(ctx, outBuf + 16, &nWritten, inBuf, len))
	 	ERR_print_errors_fp(stderr);

	 EVP_CIPHER_CTX_free(ctx);

	 int cipherlen = 16 + HM_LEN + nWritten;
	 unsigned char newbuffer[nWritten];
	 memcpy(newbuffer, &outBuf[16], nWritten);

	 unsigned char* HMAC_buf = malloc(HM_LEN);
	 HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWritten + 16, HMAC_buf, NULL);
	 memcpy(&outBuf[16+nWritten], HMAC_buf, HM_LEN);

	return cipherlen; /* TODO: should return number of bytes written, which
	             		 hopefully matches ske_getOutputLen(...). */
}

size_t ske_encrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	struct stat statbuf;

	int fdin = open(fnin, O_RDONLY);
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);

    unsigned char *addr;
    addr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);

    size_t fdin_len = strlen(addr) + 1;
    size_t cipher_len = ske_getOutputLen(fdin_len);

    unsigned char* ciphertext = malloc(cipher_len+1);
    
    size_t encrypted_len = ske_encrypt(ciphertext, addr, fdin_len, K, IV);

    write(fdout, ciphertext, encrypted_len);

	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned char hmac[HM_LEN];

	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len - HM_LEN, hmac, NULL);

	int i;
	for (i = 0; i < 32; i++)
        if (hmac[i] != inBuf[len-32+i]) 
        	return -1;

	unsigned char* IV = malloc(16);
	memcpy(IV,inBuf,16);
	
	int adjust_len = len - HM_LEN - 16;
	unsigned char ciphertext[adjust_len];

	
	for (i = 16; i < (16 + adjust_len); i++)
		ciphertext[i-16] = inBuf[i];

	EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
	ctx1 = EVP_CIPHER_CTX_new();
	
	if (1!=EVP_DecryptInit_ex(ctx1, EVP_aes_256_ctr(), 0, K->aesKey, IV))
		ERR_print_errors_fp(stderr);

	size_t cipherLen = adjust_len;

	int nWritten = 0;
	if (1!=EVP_DecryptUpdate(ctx1, outBuf, &nWritten, ciphertext, cipherLen))
		ERR_print_errors_fp(stderr);

	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */

	struct stat statbuf;

	int fdin = open(fnin, O_RDONLY);
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);

    unsigned char *addr;
    addr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);

    unsigned char* plaintext = malloc(statbuf.st_size);
    ske_decrypt(plaintext, addr, statbuf.st_size, K);

    write(fdout, plaintext, statbuf.st_size);

	return 0;
}
