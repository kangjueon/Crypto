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
#include <gmp.h>
#include "ecdsa.h"
#include "sha2.h"

mpz_t p, n, Gx, Gy;

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
 	mpz_inits(p, n, Gx, Gy, NULL);
	
	mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    	mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    	mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
   	mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);	    
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
	mpz_clears(p, n, Gx, Gy, NULL);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{	
	int idx;	
	mpz_t _d, Rx, Ry, m, inv, tmpx, tmpy;
	mpz_inits(_d, Rx, Ry, m, inv, tmpx, tmpy, NULL);
	
	gmp_randstate_t state;	
	gmp_randinit_default(state);
    	gmp_randseed_ui(state, arc4random());		

	mpz_urandomb(_d, state, ECDSA_P256);
	mpz_sub_ui(p, p, 1);
	mpz_mod(_d, _d, p);
	mpz_add_ui(_d, _d, 1);
	mpz_add_ui(p, p, 1);	

	idx = 0;

	while (idx<=(mpz_sizeinbase(_d, 2)-1)) {		
		if (mpz_tstbit(_d, idx))  {
			if (mpz_cmp_ui(Rx, 0)==0) {
				mpz_set(Rx, Gx);
				mpz_set(Ry, Gy);				
			}
			else {
				mpz_sub(m, Ry, Gy);
		
				mpz_sub(inv, Rx, Gx);
				mpz_invert(inv, inv, p);
		
				mpz_mul(m, m, inv);

				mpz_set(tmpx, Rx);
				mpz_set(tmpy, Ry);

				mpz_powm_ui(Rx, m, 2, p);
				mpz_sub(Rx, Rx, tmpx);
				mpz_sub(Rx, Rx, Gx);
				mpz_mod(Rx, Rx, p);

				mpz_sub(Ry, Gx, Rx);
				mpz_mul(Ry, Ry, m);
				mpz_sub(Ry, Ry, Gy);	
				mpz_mod(Ry, Ry, p);																	
			}
				 	
		}
		
		idx++;

		mpz_powm_ui(m, Gx, 2, p);
		mpz_mul_ui(m, m, 3);
		mpz_sub_ui(m, m, 3);

		mpz_mul_ui(inv, Gy, 2);
		mpz_invert(inv, inv, p);

		mpz_mul(m, m, inv);
		mpz_mod(m, m, p);

		mpz_set(tmpx, Gx);
		mpz_set(tmpy, Gy);
		
		mpz_powm_ui(Gx, m, 2, p);
		mpz_sub(Gx, Gx, tmpx);
		mpz_sub(Gx, Gx, tmpx);
		mpz_mod(Gx, Gx, p);

		mpz_sub(Gy, tmpx, Gx);
		mpz_mul(Gy, Gy, m);
		mpz_sub(Gy, Gy, tmpy);
		mpz_mod(Gy, Gy, p);											
	}

	mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
   	mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);	

	mpz_export(d, NULL, 1, ECDSA_P256/8, 1, 0, _d);
	mpz_export(Q->x, NULL, 1, ECDSA_P256/8, 1, 0, Rx);	
	mpz_export(Q->y, NULL, 1, ECDSA_P256/8, 1, 0, Ry);

	mpz_clears(_d, Rx, Ry, m, inv, tmpx, tmpy, NULL);	
}



/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{	
	size_t hLen = 0;
	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest) = NULL;
	
	switch (sha2_ndx) {
		case 0:
			ptrHash=sha224;hLen=28;if (len>=0x1fffffffffffffff) return ECDSA_MSG_TOO_LONG;break;
		case 1:
			ptrHash=sha256;hLen=32;if (len>=0x1fffffffffffffff) return ECDSA_MSG_TOO_LONG;break;
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

	unsigned char M[hLen];
    	mpz_t _d, e, k, r, s, x1, y1, m, inv, tmpx, tmpy;
    	gmp_randstate_t state;
    	gmp_randinit_default(state);
    	gmp_randseed_ui(state, arc4random());
	
    	//initialize mpz variables
   	mpz_inits(_d, e, k, r, s, x1, y1, m, inv, tmpx, tmpy, NULL);
    	//convert big-endian octets into mpz_t values
    	mpz_import(_d, ECDSA_P256/8, 1, 1, 1, 0, d);

    	//e = H(m)
	ptrHash(msg, len, M);
	
    	//e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다. bitlen(e) <= bitlen(n)
    	if(hLen*8>ECDSA_P256) mpz_import(e, ECDSA_P256/8, 1, 1, 1, 0, M);
    	else mpz_import(e, hLen, 1, 1, 1, 0, M);
    	do {
        	//비밀값 k를 무작위로 선택한다.
        	mpz_urandomb(k, state, ECDSA_P256);
        	if(mpz_cmp(k, n) >= 0 || mpz_cmp_ui(k, 1) <= 0) continue;
        	        
        	//(x1, y1) = kG
		int idx = 0;        
		while (idx<=(mpz_sizeinbase(k, 2)-1)) {
			if (mpz_tstbit(k, idx))  {
                		//x1, y1 값 Gx Gy로 초기화
				if (mpz_cmp_ui(x1, 0)==0) {
					mpz_set(x1, Gx);
					mpz_set(y1, Gy);				
				}
                
				else {
					mpz_sub(m, y1, Gy); //y1-Gy m에 저장
					mpz_sub(inv, x1, Gx); //x1-Gx inv에 저장
					mpz_invert(inv, inv, p); //(x1-Gx)^-1
			
					mpz_mul(m, m, inv); //m = (y1-Gy)*(x1-Gx)^-1

                    			//x1, y1값 임시 저장
					mpz_set(tmpx, x1); 
					mpz_set(tmpy, y1);

					mpz_powm_ui(x1, m, 2, p); //x1 = m^2 mod p = ((y1-Gy)*(x1-Gx)^-1)^2
					
                    			mpz_sub(x1, x1, tmpx);
					mpz_sub(x1, x1, Gx);
					mpz_mod(x1, x1, p);

					mpz_sub(y1, Gx, x1);
					mpz_mul(y1, y1, m);
					
					mpz_mod(y1, y1, p);	

					mpz_sub(y1, y1, Gy);	
					mpz_mod(y1, y1, p);																	
				} 	
			}
			
			idx++;
            		//y 구하기 y=(3x^2-3)/2
			mpz_powm_ui(m, Gx, 2, p); //m = Gx^2
			mpz_mul_ui(m, m, 3); // m = 3*Gx^2

			mpz_mod(m, m, p);

			mpz_sub_ui(m, m, 3); //m = 3*Gx^2 - 3

            		//2로 나누기
			mpz_mul_ui(inv, Gy, 2);
			mpz_invert(inv, inv, p);

			mpz_mul(m, m, inv);
			mpz_mod(m, m, p);

            		//tmp변수에 저장
			mpz_set(tmpx, Gx);
			mpz_set(tmpy, Gy);
			
			mpz_powm_ui(Gx, m, 2, p);
			mpz_sub(Gx, Gx, tmpx);
			mpz_sub(Gx, Gx, tmpx);
			mpz_mod(Gx, Gx, p);

			mpz_sub(Gy, tmpx, Gx);
			mpz_mul(Gy, Gy, m);
			mpz_sub(Gy, Gy, tmpy);
			mpz_mod(Gy, Gy, p);											
		}
		//r = x1 mod n
		mpz_mod(r, x1, n);
	    
	        if(mpz_cmp_ui(r, 0) == 0) continue;  //r=0이면 다시 k 선택
	    
	        //s = k^-1(e+rd) mod n
		mpz_set(s, r);
	        mpz_mul(s, s, _d);
	        mpz_mod(s, s, n);
	        mpz_add(s, s, e);
	        mpz_mod(s, s, n);

	        mpz_invert(k, k, n);
                mpz_mul(s, s, k);
	        mpz_mod(s, s, n);
	        if(mpz_cmp_ui(s, 0) != 0) break; //s = 0이면 다시 k 선택
	} while(1);

	mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
   	mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

	//(r, s)가 서명 값
        mpz_export(_r, NULL, 1, ECDSA_P256/8, 1, 0, r);
        mpz_export(_s, NULL, 1, ECDSA_P256/8, 1, 0, s);

        mpz_clears(_d, e, k, r, s, x1, y1, m, inv, tmpx, tmpy, NULL);
    
        return 0;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{

	size_t hLen = 0;
	void (*ptrHash)(const unsigned char *m, unsigned int len, unsigned char *digest) = NULL;	
	
	switch (sha2_ndx) {
		case 0:
			ptrHash=sha224;hLen=28;if (len>=0x1fffffffffffffff) return ECDSA_MSG_TOO_LONG;break;
		case 1:
			ptrHash=sha256;hLen=32;if (len>=0x1fffffffffffffff) return ECDSA_MSG_TOO_LONG;break;
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

	unsigned char M[hLen];
    	mpz_t Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy;

	//initialize mpz variables
   	mpz_inits(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);
    	//convert big-endian octets into mpz_t values
    	mpz_import(Qx, ECDSA_P256/8, 1, 1, 1, 0, _Q->x);
	mpz_import(Qy, ECDSA_P256/8, 1, 1, 1, 0, _Q->y);
	mpz_import(r, ECDSA_P256/8, 1, 1, 1, 0, _r);
	mpz_import(s, ECDSA_P256/8, 1, 1, 1, 0, _s);   				
	
	/*r과 s가 [1, n-1] 사이에 있지 않으면 잘못된 서명이다.*/
	mpz_sub_ui(n, n, 1);
	if (mpz_cmp_ui(s, 1)<0 || mpz_cmp(s, n)>0) {
		mpz_clears(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);
		mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		return ECDSA_SIG_INVALID;
	}
	if (mpz_cmp_ui(s, 1)<0 || mpz_cmp(s, n)>0) {
		mpz_clears(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);
		mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		return ECDSA_SIG_INVALID;
	}
	mpz_add_ui(n, n, 1);

	/*e=H(m). H()는 서명에서 사용한 해시함수와 같다.*/
	ptrHash(msg, len, M);


	/*e의 길이가 n의 길이(256b)보다 길면 뒷 부분은 자른다.*/
	if(hLen*8>ECDSA_P256) mpz_import(e, ECDSA_P256/8, 1, 1, 1, 0, M);
   	else mpz_import(e, hLen, 1, 1, 1, 0, M);

	/*u1=e*s^(-1) mod n, u2=r*s^(-1) mod n*/
	
	mpz_invert(s, s, n);

	mpz_mod(e, e, n);
	mpz_mul(u1, e, s);
	mpz_mod(u1, u1, n);

	mpz_mod(r, r, n);
	mpz_mul(u2, r, s);
	mpz_mod(u2, u2, n);	

	/*(x1, y1) = u1*G + u2*Q. 만일 (x1, y1)=O이면 잘못된 서명이다.*/	


	//(x2, y2) = u1*G

	int idx = 0;
	
	while (idx<=(mpz_sizeinbase(u1, 2)-1)) {
			if (mpz_tstbit(u1, idx))  {
                		
				if (mpz_cmp_ui(x2, 0)==0) {
					mpz_set(x2, Gx);
					mpz_set(y2, Gy);				
				}
                
				else {
					mpz_sub(m, y2, Gy); 
					mpz_sub(inv, x2, Gx); 
					mpz_invert(inv, inv, p); 
			
					mpz_mul(m, m, inv); 

                    			
					mpz_set(tmpx, x2); 
					mpz_set(tmpy, y2);

					mpz_powm_ui(x2, m, 2, p); 
					
                    			mpz_sub(x2, x2, tmpx);
					mpz_sub(x2, x2, Gx);
					mpz_mod(x2, x2, p);

					mpz_sub(y2, Gx, x2);
					mpz_mul(y2, y2, m);
					
					mpz_mod(y2, y2, p);	

					mpz_sub(y2, y2, Gy);	
					mpz_mod(y2, y2, p);																	
				} 	
			}
			
			idx++;
            		
			mpz_powm_ui(m, Gx, 2, p); 
			mpz_mul_ui(m, m, 3); 

			mpz_mod(m, m, p);

			mpz_sub_ui(m, m, 3); 

            		
			mpz_mul_ui(inv, Gy, 2);
			mpz_invert(inv, inv, p);

			mpz_mul(m, m, inv);
			mpz_mod(m, m, p);

            		
			mpz_set(tmpx, Gx);
			mpz_set(tmpy, Gy);
			
			mpz_powm_ui(Gx, m, 2, p);
			mpz_sub(Gx, Gx, tmpx);
			mpz_sub(Gx, Gx, tmpx);
			mpz_mod(Gx, Gx, p);

			mpz_sub(Gy, tmpx, Gx);
			mpz_mul(Gy, Gy, m);
			mpz_sub(Gy, Gy, tmpy);
			mpz_mod(Gy, Gy, p);											
	}	
		

	mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
   	mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
	
	//(x3, y3) = u2*Q

	idx=0;
	
	while (idx<=(mpz_sizeinbase(u2, 2)-1)) {
			if (mpz_tstbit(u2, idx))  {
                		
				if (mpz_cmp_ui(x3, 0)==0) {
					mpz_set(x3, Qx);
					mpz_set(y3, Qy);				
				}
                
				else {
					mpz_sub(m, y3, Qy); 
					mpz_sub(inv, x3, Qx); 
					mpz_invert(inv, inv, p); 
			
					mpz_mul(m, m, inv); 

                    			
					mpz_set(tmpx, x3); 
					mpz_set(tmpy, y3);

					mpz_powm_ui(x3, m, 2, p); 
					
                    			mpz_sub(x3, x3, tmpx);
					mpz_sub(x3, x3, Qx);
					mpz_mod(x3, x3, p);

					mpz_sub(y3, Qx, x3);
					mpz_mul(y3, y3, m);
					
					mpz_mod(y3, y3, p);	

					mpz_sub(y3, y3, Qy);	
					mpz_mod(y3, y3, p);																	
				} 	
			}
			
			idx++;
            		
			mpz_powm_ui(m, Qx, 2, p); 
			mpz_mul_ui(m, m, 3); 

			mpz_mod(m, m, p);

			mpz_sub_ui(m, m, 3); 

            		
			mpz_mul_ui(inv, Qy, 2);
			mpz_invert(inv, inv, p);

			mpz_mul(m, m, inv);
			mpz_mod(m, m, p);

            		
			mpz_set(tmpx, Qx);
			mpz_set(tmpy, Qy);
			
			mpz_powm_ui(Qx, m, 2, p);
			mpz_sub(Qx, Qx, tmpx);
			mpz_sub(Qx, Qx, tmpx);
			mpz_mod(Qx, Qx, p);

			mpz_sub(Qy, tmpx, Qx);
			mpz_mul(Qy, Qy, m);
			mpz_sub(Qy, Qy, tmpy);
			mpz_mod(Qy, Qy, p);											
	}		

	//(x1, y1) = O -> Invalid Signature
	if (mpz_cmp(x2, x3)==0 && mpz_cmp(y2, y3)!=0) {
		mpz_clears(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);
		return ECDSA_SIG_INVALID;	
	}
	
	//(x1, y1) = (x2, y2) + (x3, y3)	
	mpz_sub(m, y3, y2); 
	mpz_sub(inv, x3, x2); 
	mpz_invert(inv, inv, p); 
			
	mpz_mul(m, m, inv); 	

	mpz_powm_ui(x1, m, 2, p); 
					
        mpz_sub(x1, x1, x3);
	mpz_sub(x1, x1, x2);
	mpz_mod(x1, x1, p);

	mpz_sub(y1, x2, x1);
	mpz_mul(y1, y1, m);
					
	mpz_mod(y1, y1, p);	

	mpz_sub(y1, y1, y2);	
	mpz_mod(y1, y1, p);

	/*r=x1 (mod n)이면 올바른 서명이다.*/
	mpz_mod(x1, x1, n);
	
	if (mpz_cmp(r, x1)!=0) {
		mpz_clears(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);
		return ECDSA_SIG_MISMATCH;
	}

	mpz_clears(Qx, Qy, e, r, s, x1, y1, x2, y2, x3, y3, u1, u2, m, inv, tmpx, tmpy, NULL);

	return 0;	
}

