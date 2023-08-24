/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <omp.h>
#include <sys/time.h>
#include <unistd.h>
#include "miller_rabin.h"

int main(void)
{
    uint64_t a, b, m, x; 
    int i;
    atomic_int total;
    struct timeval start, end;
    double elapsed;
 
    /*
     * 모듈러 연산 검증 
     */
    a = 13053660249015046863ULL;
    b = 14731404471217122002ULL; 
    m = 16520077267041420904ULL;
    printf("a = %"PRIu64", b = %"PRIu64", m = %"PRIu64"\n", a, b, m);
    printf("a+b mod m = %"PRIu64, mod_add(a, b, m));
    if (mod_add(a, b, m) == 11264987453190747961ULL)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a-b mod m = %"PRIu64, mod_sub(a, b, m));
    if (mod_sub(a, b, m) == 14842333044839345765ULL)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a*b mod m = %"PRIu64, mod_mul(a, b, m));
    if (mod_mul(a, b, m) == 13008084103192797750ULL)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a^b mod m = %"PRIu64, mod_pow(a, b, m));
    if (mod_pow(a, b, m) == 12523224429397597497ULL)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    a = 18446744073709551615ULL;
    b = 72057594037927935ULL; 
    m = 65536ULL;
    printf("a = %"PRIu64", b = %"PRIu64", m = %"PRIu64"\n", a, b, m);
    printf("a+b mod m = %"PRIu64, mod_add(a, b, m));
    if (mod_add(a, b, m) == 65534)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a-b mod m = %"PRIu64, mod_sub(a, b, m));
    if (mod_sub(a, b, m) == 0)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a*b mod m = %"PRIu64, mod_mul(a, b, m));
    if (mod_mul(a, b, m) == 1)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("a^b mod m = %"PRIu64, mod_pow(a, b, m));
    if (mod_pow(a, b, m) == 65535)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    
    /*
     * 작은 모듈로 연산에서 피연산자 값이 큰 경우를 검증한다.
     * 간단한 연산이 1초 이상 걸리면 코드에 큰 문제가 있으므로 알람 신호를 보내 종료한다.
     */
    alarm(1); a = 18446744073709551613ULL; x = mod_pow(a,a,5); alarm(0);
    printf("%"PRIu64"^%"PRIu64" mod 5 = %"PRIu64, a, a, x);
    if (x == 3)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    
    /*
     * 2부터 처음 100개의 소수를 출력한다.
     */
    x = 2; i = 0;
    while (true) {
        if (miller_rabin(x)) {
            ++i;
            printf("%"PRIu64" ", x);
            if (i % 10 == 0)
                printf("\n");
            if (i == 100)
                break;
        }
        ++x;
    }

    /*
     * x = 0x8000000000000000부터 처음 100개의 소수를 출력한다.
     */
    x = 0x8000000000000000; i = 0;
    while (true) {
        if (miller_rabin(x)) {
            ++i;
            printf("%"PRIu64" ", x);
            if (i % 4 == 0)
                printf("\n");
            if (i == 100)
                break;
        }
        ++x;
    }
    
    /*
     * x = 1부터 67108864까지 소수의 개수를 계산한다.
     */
    printf("x = 1부터 67108864까지 소수를 세는 중"); fflush(stdout);
    gettimeofday(&start, NULL); total = 0;
    /*
     * 코어의 개수만큼 스레드를 생성하여 병렬로 개수를 센다.
     */
    #pragma omp parallel for
    for (i = 0; i < 16; ++i) {
    
        uint64_t x;
        int count = 0;
        
        for (x = 1+i*4194304; x < 1+(i+1)*4194304; x++) {
            if (miller_rabin(x))
                count++;
            if (x % 1048576 == 0) {
                printf(".");
                fflush(stdout);
            }
        }
        atomic_fetch_add(&total, count);
    }
    /*
     * 병렬 계산이 여기서 종료된다.
     */
    gettimeofday(&end, NULL);
    elapsed = (double)(end.tv_sec - start.tv_sec)+(double)(end.tv_usec - start.tv_usec)*1e-6;
    printf("소수 개수: %d개", total);
    if (total == 3957809)
        printf(".....PASSED\n");
    else {
        printf(".....FAILED\n");
        return 1;
    }
    printf("계산 시간: %.4f초\n", elapsed);
    
    return 0;
}
