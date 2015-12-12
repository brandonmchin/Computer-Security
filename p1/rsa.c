// CSC 480 Computer Security, Project 1
// Brandon Chin

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// find random distinct prime integers p and q
	mpz_t tmp;

	do {
		unsigned char* buffer = malloc(keyBits/8);
		buffer[(keyBits/8)-1] = 0;
		randBytes(buffer, (keyBits/8)-1);
		mpz_init(tmp);
		BYTES2Z(tmp, buffer, keyBits/8);
		free(buffer);
	} while (!ISPRIME(tmp));

	mpz_set(K->p, tmp);

	do {
		unsigned char* buffer = malloc(keyBits/8);
		buffer[(keyBits/8)-1] = 0;
		randBytes(buffer, (keyBits/8)-1);
		mpz_init(tmp);
		BYTES2Z(tmp, buffer, keyBits/8);
		free(buffer);
	} while (!ISPRIME(tmp));

	mpz_set(K->q, tmp);

	// compute n = pq
	mpz_mul(K->n, K->p, K->q);

	// compute phi(n) = (p - 1)(q - 1)
	NEWZ(p0); mpz_sub_ui(p0, K->p, 1);
	NEWZ(q0); mpz_sub_ui(q0, K->q, 1);
	NEWZ(phi); mpz_mul(phi, p0, q0);
	//gmp_printf("phi: %Zd\n", phi);

	// find an encrytion exponent e such that 1 < e < phi and e is relatively prime to phi (i.e. gcd(e,phi) = 1)
	NEWZ(i);
	NEWZ(gcd);
	for (mpz_set_ui(i, 3); mpz_cmp(i, phi) < 0; mpz_add_ui(i, i, 1))
	{
		mpz_gcd(gcd, i, phi);

		if (mpz_cmp_ui(gcd, 1) == 0)
		{
			mpz_set(K->e, i);
			break;
		}
	}

	// compute a decryption exponent d such that d is the multiplicative inverse of e mod phi
    mpz_invert(K->d, K->e, phi);

    // print key values for testing
    // gmp_printf("p: %Zd\n\n", K->p);
    // gmp_printf("q: %Zd\n\n", K->q);
    // gmp_printf("n: %Zd\n\n", K->n);
    // gmp_printf("e: %Zd\n\n", K->e);
    // gmp_printf("d: %Zd\n\n", K->d);

	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */

	NEWZ(c);		// ciphertext
	NEWZ(m);		// plaintext

	BYTES2Z(m, inBuf, len);		// convert input message into integers
	mpz_powm(c, m, K->e, K->n);		// public key encryption pair is (e, n)
	Z2BYTES(outBuf, len, c);

	// testing
	// size_t a;
	// for (a = 0; a < len; a++)
	// 	printf("%02x", (unsigned char)inBuf[a]);
	// printf("\n\n");
	// for (a = 0; a < len; a++)
	// 	printf("%02x", (unsigned char)outBuf[a]);
	// printf("\n\n");
	// gmp_printf("m: %Zd\n\n", m);
	// gmp_printf("c: %Zd\n\n", c);

	return rsa_numBytesN(K); /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */

	NEWZ(c);
	NEWZ(m);

	BYTES2Z(c, inBuf, len);
	mpz_powm(m, c, K->d, K->n);
	Z2BYTES(outBuf, len, m);

	return rsa_numBytesN(K);
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t); // number of bytes in n
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	//rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	//rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
