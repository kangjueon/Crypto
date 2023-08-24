/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#include "miller_rabin.h"
#include <stdlib.h>
/*
 * mod_add() - computes a+b mod m
 * a와 b가 m보다 작다는 가정하에서 a+b >= m이면 결과에서 m을 빼줘야 하므로
 * 오버플로가 발생하지 않도록 a-(m-b)를 계산하고, 그렇지 않으면 그냥 a+b를 계산하면 된다.
 * a+b >= m을 검사하는 과정에서 오버플로가 발생할 수 있으므로 a >= m-b를 검사한다.
 */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{   
    
    if ( a  < m - b){
        return a + b ;
    } else // a >= (m - b)
    {
        return (a - (m - b)) % m;
    }

}

/*
 * mod_sub() - computes a-b mod m
 * 만일 a < b이면 결과가 음수가 되므로 m을 더해서 양수로 만든다.
 */
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m)
{   
    // a - b < 0 음수가 되면
    if (a < b){
        return a + m - b;
    } else   // a >= b
    {
        return (a - b) % m ;
    }

}

/*
 * mod_mul() - computes a*b mod m
 * a*b에서 오버플로가 발생할 수 있기 때문에 덧셈을 사용하여 빠르게 계산할 수 있는
 * "double addition" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 0;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_add(r, a, m);
 *         b = b >> 1;
 *         a = mod_add(a, a, m);
 *     }
 */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
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
 * a^b에서 오버플로가 발생할 수 있기 때문에 곱셈을 사용하여 빠르게 계산할 수 있는
 * "square multiplication" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 1;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_mul(r, a, m);
 *         b = b >> 1;
 *         a = mod_mul(a, a, m);
 *     }
 */
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
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
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3,317,044,064,679,887,385,961,981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns PRIME if n is prime, COMPOSITE otherwise.
 */
int miller_rabin(uint64_t n)
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

