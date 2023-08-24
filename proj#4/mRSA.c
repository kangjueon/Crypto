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
#include "mRSA.h"

/*
 * mod_add() - computes a + b mod m
 */
static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
      if ( a  < m - b){
        return a + b ;
    } else // a >= (m - b)
    {
        return (a - (m - b)) % m;
    }
}

/*
 * mod_mul() - computes a * b mod m
 */
static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
     uint64_t r = 0;

    //큰 수 미리 mod 연산 적용. 
    if (a >= m) a %= m;
    if (b >= m) b %= m;
    // b가 0이 될때 까지
    while ( b > 0 ) {
        
        if ( b & 1)
            r = mod_add(r, a, m);
        b = b >> 1;
        a = mod_add(a, a, m);    // a + a
    }

    return r ;
}

/*
 * mod_pow() - computes a^b mod m
 */
static uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{    
    uint64_t r = 1;

    

    while (b > 0){
        if (b & 1)
            r = mod_mul(r, a, m);
        b = b >> 1;
        a = mod_mul(a, a, m);    
    }

    return r ;
}

/*
 * gcd() - Euclidean algorithm
 */
static uint64_t gcd(uint64_t a, uint64_t b)
{
    uint64_t tmp, n;

    if (a < b){
        tmp = a;
        a = b;
        b = tmp;

    }

    while(b != 0){
        n = a%b;
        a = b;
        b = n;
    }

    return a;


}

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 * It returns 0 if no inverse exist.
 */
static uint64_t mul_inv(uint64_t a, uint64_t m)
{       

    // a와 a^-1의 은 1임을 이용
    for ( int i = 0;  i < m ; i++){
        if ( ( ((a % m) * (i % m)) % m ) == 1 ) return i;
    }

    return 0;
}
    



/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3317044064679887385961981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
static const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
static int miller_rabin(uint64_t n)
{   
    if (n == 2) return PRIME;  // 짝수중 2는 소수
    if (n % 2 == 0) return COMPOSITE; //짝수는 합성수
    
    uint64_t q = n-1 ;
    uint64_t k  = 0 ;

    // n -1 = 2^k * q를 만족하는 k , q 찾기
    while((q & 1 ) == 1){
        q >>= 1; // 정수부분만 취한다. 
        k += 1;
    }
    /*
    while((q % 2 ) == 1){
        q /= 2; 
        k += 1;
    }
    */
    
    // select random number 'R' in list a 
    // n - 1보다 작은 걸로 뽑아야함
    uint64_t R ;
    uint64_t e = q;

    // a[i]에 있는 값들을 deterministic하게 전부 고르되
    // 1 < a < n - 1을 만족해야한다.
    for (int i = 1 ; i < BASELEN  && a[i] < (n - 1) ; i++){
       
        R = a[i];
        

               
        if (1 == mod_pow(R,q,n)){
            continue;
        }      
        
           
        for (int j = 0; j <  k ; j++)
        {   
          
            if ((n - 1) == mod_pow(R,e,n)){
                continue;
            }
            
            e = 2 * e;
        }
        
        return COMPOSITE;
    } 
    return PRIME;   
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 *
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{   
    uint64_t p, q, lambda, tmp;
    
    tmp = 0;

    /* 
    *   길이가 32bits 내외인 임의의 두 소수 p,q를 생성한다.
    *   32bits의 난수를 생성해 주는 arc4random()을 이용
    *   miller rabin test를 이용하여 소수인지 아닌지 
    *   판별하고 소수가 나올때 까지 반복한다.
    */

    while(tmp > MINIMUM_N){

        while(miller_rabin(p) == PRIME){

            p = arc4random();
        }

        while(miller_rabin(q) == PRIME){

            q = arc4random();
        }

        tmp = p * q;  // to calculate n

        
    }
    
    *n = tmp;

    //declare lambda function
    
    lambda = mod_mul(p-1, q-1 , tmp) / gcd(p-1, q-1);

    /*
    
        e * d = 1을 만족하는 d를 구한다. 이때, e는 65337로 고정.
        65337 = 2^16 + 1로 소수이면서, 충분히 큰 수이므로 이용한다.

        d는 mul_mul()를 이용한다.
    */

    *e = 65337 ;

    *d = mul_inv(65337, lambda);

   

}

/*
 * mRSA_cipher() - compute m^k mod n
 *
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{   
   

    *m = mod_pow(*m,k,n);

    
    if (*m >= n) return 1;
    else return 0;

}
