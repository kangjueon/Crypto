/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <gmp.h>

#include <stdint.h>

#include "pkcs.h"
#include "sha2.h"

 

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}



unsigned char* MGF1(unsigned char *mgfSeed, size_t seedLen, unsigned char *mask, size_t maskLen, void (*ptrfunc)(const unsigned char *m, unsigned int len, unsigned char *digest), size_t hLen) {
	uint64_t i, count, c;    	
    	unsigned char *mgfIn, *m;	
    	
    	if (maskLen > 0x0100000000 * hLen)
     	   return NULL;
    
    	if ((mgfIn = (unsigned char *)malloc(seedLen + 4)) == NULL)
    	    return NULL;

   	memcpy(mgfIn, mgfSeed, seedLen);
    	count = maskLen / hLen + (maskLen % hLen ? 1 : 0);

    	if ((m = (unsigned char *)malloc(count * hLen)) == NULL)
    	    return NULL;
    
    	for (i = 0; i < count; i++){
      		c = i;
      	  	mgfIn[seedLen + 3] = c & 0x000000ff; c >>= 8;
       	 	mgfIn[seedLen + 2] = c & 0x000000ff; c >>= 8;
       	 	mgfIn[seedLen + 1] = c & 0x000000ff; c >>= 8;
      	  	mgfIn[seedLen] = c & 0x000000ff; c >>= 8;
       	 	ptrfunc(mgfIn, seedLen + 4, m + i * hLen);
    	}
    	memcpy(mask, m, maskLen);
    	free(mgfIn); free(m);
    	return mask;
}


/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx)
{
	
	size_t hLen=0;
	size_t k = RSAKEYSIZE/8;
	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest)=NULL;
	
	switch (sha2_ndx) {
		case 0:
			ptrHash=sha224;hLen=28;if (strlen((char *)label)>=0x1fffffffffffffff) return PKCS_LABEL_TOO_LONG;break;
		case 1:
			ptrHash=sha256;hLen=32;if (strlen((char *)label)>=0x1fffffffffffffff) return PKCS_LABEL_TOO_LONG;break;
		case 2:
			ptrHash=sha384;hLen=48;break;
		case 3:
			ptrHash=sha512;hLen=64;break;
		case 4:
			ptrHash=sha512_224;hLen=28;break;
		case 5:
			ptrHash=sha512_256;hLen=32;break;
		default:
			break;
	}
	
	
	if (mLen > k - 2*hLen - 2) return PKCS_MSG_TOO_LONG;
	
	unsigned char lHash[k];
	unsigned char DB[k];
	unsigned char seed[k];
	unsigned char buf[k];
	unsigned char dbMask[k];
	unsigned char maskedDB[k];
	unsigned char seedMask[k];
	unsigned char maskedSeed[k];
	unsigned char EM[k];	
	
	ptrHash(label, strlen(label),lHash); 	

	memcpy(DB, lHash, hLen);
	memset(DB+hLen, 0x00, k-mLen-2*hLen-2);
	memset(DB+hLen+k-mLen-2*hLen-2, 0x01, 1);
	memcpy(DB+hLen+k-mLen-2*hLen-2+1, m, mLen);	

	arc4random_buf(buf, mLen);
	ptrHash(buf, mLen, seed);	

	MGF1(seed, hLen, dbMask, k-hLen-1, ptrHash, hLen);	
	for (int i=0;i<k-hLen-1;i++) {
		maskedDB[i]=DB[i]^dbMask[i];
	}	
	
	MGF1(maskedDB, k-hLen-1, seedMask, hLen, ptrHash, hLen);	
	for (int j=0;j<hLen;j++) {
		maskedSeed[j]=seed[j]^seedMask[j];
	}	
	
	memset(EM, 0x00, 1);
	memcpy(EM+1, maskedSeed, hLen);
	memcpy(EM+1+hLen, maskedDB, k-hLen-1);	
	
	rsa_cipher((void *)EM, e, n);
	memcpy(c, EM, k);	
	return 0;	
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{
	size_t hLen = 0, cnt = 0;
    	size_t k = RSAKEYSIZE / 8; // RSAKEYSIZE (bit) -> k (Byte)

    	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest) = NULL;

		switch (sha2_ndx) {
			case 0:
				ptrHash=sha224;hLen=28;if (strlen((char *)label)>=0x1fffffffffffffff) return PKCS_LABEL_TOO_LONG;break;
			case 1:
				ptrHash=sha256;hLen=32;if (strlen((char *)label)>=0x1fffffffffffffff) return PKCS_LABEL_TOO_LONG;break;
			case 2:
				ptrHash=sha384;hLen=48;break;
			case 3:
				ptrHash=sha512;hLen=64;break;
			case 4:
				ptrHash=sha512_224;hLen=28;break;
			case 5:
				ptrHash=sha512_256;hLen=32;break;
			default:
				break;
		}
		
	unsigned char EM[k];
 	unsigned char maskedSeed[k];
    	unsigned char maskedDB[k];
    	unsigned char seed[k];
    	unsigned char seedMask[k];
    	unsigned char dbMask[k];
   	unsigned char DB[k];
    	unsigned char lhash[k];

	ptrHash(label, strlen(label),lhash);
	
    	// EM = c^d mod n
    	memcpy(EM, c, k);
    	rsa_cipher((void*)EM, d, n);

    	//If first Byte of EM is not 0x00, return error code
    	if(EM[0] != 0x00) return PKCS_INITIAL_NONZERO;

    	//EM -> 00 / MaskedSeed / MaskedDB
    	memcpy(maskedSeed, EM+1, hLen);
    	memcpy(maskedDB, EM+1+hLen, k-hLen-1);

    	//MaskedSeed ^ MGF(MaskedDB) -> seed
    	MGF1(maskedDB, k-hLen-1, seedMask, hLen, ptrHash, hLen);
    	for(int i = 0 ; i < hLen ; i++)
        	seed[i] = maskedSeed[i] ^ seedMask[i];

    	//MaskedDB ^ MGF(seed) -> DB
    	MGF1(seed, hLen, dbMask, k-hLen-1, ptrHash, hLen);
    	for(int j = 0 ; j < k-hLen-1 ; j++)
        	DB[j] = maskedDB[j] ^ dbMask[j];    	

    	//compare Hash(L) to DB[0:hLen], If the two values do not match, return error code.
    	if(memcmp(DB, lhash, hLen)!=0)
        	return PKCS_HASH_MISMATCH;

    	//DB -> Hash(L) / Padding(00...0) / 01 / Message
    	while(1){
        	if(DB[hLen+cnt] == 0x01){
            	*mLen = k-2*hLen-cnt-2;
            	//If message is too long, return error code.
            	/*if (*mLen > k - 2*hLen - 2) return PKCS_MSG_TOO_LONG;*/
            	memcpy(m, DB+hLen+cnt+1, *mLen);
            	break;
        	}
        	//If the Byte of after Padding string is not 0x01, return error code.
        	if((DB[hLen+cnt] != 0x00) && (DB[hLen+cnt] != 0x01)) 
            	return PKCS_INVALID_PS;
        	cnt++;
    	}    
    	return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
	size_t hLen = 0;
	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest) = NULL;
	
	switch (sha2_ndx) {
		case 0:
			ptrHash=sha224;hLen=28;break;
		case 1:
			ptrHash=sha256;hLen=32;break;
		case 2:
			ptrHash=sha384;hLen=48;break;
		case 3:
			ptrHash=sha512;hLen=64;break;
		case 4:
			ptrHash=sha512_224;hLen=28;break;
		case 5:
			ptrHash=sha512_256;hLen=32;break;
		default:
			break;
   	 }
    	//m의 길이가 입력 제한보다 큰 경우 에러메시지 출력 및 중지 2^61-1 => 61자리 => 2^4(16진수)^15
    	if(mLen > 0x1fffffffffffffff) return PKCS_MSG_TOO_LONG;
    	//mHash = Hash(M)
    	unsigned char mHash[hLen];	
    	ptrHash(m, mLen, mHash);

    	//emLen < hLen + sLen + 2 "encoding error"
    	if(RSAKEYSIZE/8 < hLen + hLen + 2) return PKCS_HASH_TOO_LONG;
    
    	//salt 생성
	unsigned char salt[hLen];
    	arc4random_buf(salt, hLen);
	
	
    	//M' = 0x0000000000000000 || mHash || salt
    	unsigned char mm[8+2*hLen];
    	memset(mm, 0x00, 8);
    	memcpy(mm+8, mHash, hLen);
    	memcpy(mm+8+hLen, salt, hLen);
	

    	//H = Hash(M')
    	unsigned char h[hLen];
	
    	ptrHash(mm, 8+2*hLen, h);
    
    	//PS = emLen - sLen - hLen - 2
    	size_t maskLen = RSAKEYSIZE/8 - hLen - 1;
    	size_t ps = maskLen - hLen - 1;

    	//DB = PS || 0x01 || salt
    	unsigned char db[maskLen];
    	memset(db, 0x00, ps);
    	memset(db+ps, 0x01, 1);
    	memcpy(db+ps+1, salt, hLen);
	

    	unsigned char mgf[maskLen];
    	MGF1(h, hLen, mgf, maskLen, ptrHash, hLen);	

    	//EM길이는 RSAKEYSIZE와 동일
    	unsigned char em[RSAKEYSIZE/8];
    	//xor
    	for (uint8_t i=0; i<maskLen;++i){
        	em[i] = db[i]^mgf[i];
    	}
    	/*memcpy(em, mgf, maskLen);*/
	memcpy(em + maskLen, h, hLen);
	memset(em + maskLen + hLen, 0xbc, 1);
	
    	//맨 왼쪽 비트(MSB) 1이면 0으로 바꿈
    	if (em[0] >> 7) em[0] -= 128;
	                /*em[0] &= 0x00;*/
    	rsa_cipher((void *)em, d, n);
	
    	//s에 저장
    	memcpy(s, em, RSAKEYSIZE/8);
	
    	return 0;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
	size_t hLen = 0;
	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest) = NULL;

	switch (sha2_ndx) {
		case 0:
			ptrHash=sha224;hLen=28;break;
		case 1:
			ptrHash=sha256;hLen=32;break;
		case 2:
			ptrHash=sha384;hLen=48;break;
		case 3:
			ptrHash=sha512;hLen=64;break;
		case 4:
			ptrHash=sha512_224;hLen=28;break;
		case 5:
			ptrHash=sha512_256;hLen=32;break;
		default:
			break;
   	 }

	if(mLen > 0x1fffffffffffffff) return PKCS_MSG_TOO_LONG;

	unsigned char mHash[hLen];
    	ptrHash(m, mLen, mHash);
	

	if(RSAKEYSIZE/8 < hLen + hLen + 2) return PKCS_HASH_TOO_LONG;
		

	unsigned char em[RSAKEYSIZE/8];
	memcpy(em, s, RSAKEYSIZE/8);
	
	rsa_cipher((void*)em, e, n);
		
	if(em[(RSAKEYSIZE/8)-1]!=0xbc) return PKCS_INVALID_LAST;	

	size_t maskLen = RSAKEYSIZE/8 - hLen - 1;		
	unsigned char maskedDB[maskLen];
	memcpy(maskedDB, em, maskLen);
		
	
	unsigned char H[hLen];
	memcpy(H, em+maskLen, hLen);
	
	
	if (maskedDB[0] >> 7) return PKCS_INVALID_INIT;

	unsigned char dbMask[maskLen];
	MGF1(H, hLen, dbMask, maskLen, ptrHash, hLen);

	

	unsigned char DB[maskLen];
	for (uint8_t i=0; i<maskLen;++i){
        	DB[i] = maskedDB[i]^dbMask[i];
		
    	}
	
	size_t ps = maskLen - hLen - 1;
	unsigned char pad[ps];
	memset(pad, 0x00, ps);

	if (DB[0]!=0x80 && DB[0]!=0x00) return PKCS_INVALID_PD2;
	if (memcmp(pad+1, DB+1, ps-1)!=0) return PKCS_INVALID_PD2;
	if (DB[ps]!=0x01) return PKCS_INVALID_PD2;

	/*printf("DB[0~ps] = ");
    	for (int i = 0; i <= ps; ++i)
        	printf("%02hhx", DB[i]);
    	printf("\n");*/		

	unsigned char salt[hLen];
	memcpy(salt, DB+ps+1, hLen);	
	
	unsigned char mm[8+2*hLen];
	memset(mm, 0x00, 8);
    	memcpy(mm+8, mHash, hLen);
    	memcpy(mm+8+hLen, salt, hLen);	

	unsigned char h[hLen];
    	ptrHash(mm, 8+2*hLen, h);	

	if (memcmp(h, H, hLen)!=0) return PKCS_HASH_MISMATCH;
	
	return 0;
}






