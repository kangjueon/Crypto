/*
* Copyright 2020-2022. Heekuck Oh, all rights reserved
* 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
*/
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include "mRSA.h"

int main(void)
{
    uint64_t e, d, n, m, c;
    int i, count;

    /*
     * 기본시험 1: m = 0부터 19까지 암복호화 검증
     */
    mRSA_generate_key(&e, &d, &n);
    if (n < MINIMUM_N) {
        printf("FAILED: RSA key is not 64 bits: n = %016"PRIx64"\n", n);
        return 1;
    }
    printf("e = %016"PRIx64"\nd = %016"PRIx64"\nn = %016"PRIx64"\n", e, d, n);
    for (i = 0; i < 20; ++i) {
        m = i;
        printf("m = %"PRIu64", ", m);
        mRSA_cipher(&m, e, n);
        printf("c = %"PRIu64", ", m);
        mRSA_cipher(&m, d, n);
        printf("v = %"PRIu64"\n", m);
    }
    /*
     * 기본시험 2: 무작위로 m을 발생하여 암복호화 검증
     */
    mRSA_generate_key(&e, &d, &n);
    printf("e = %016"PRIx64"\nd = %016"PRIx64"\nn = %016"PRIx64"\n", e, d, n);
    for (i = 0; i < 20; ++i) {
        arc4random_buf(&m, sizeof(uint64_t));
        printf("m = %016"PRIx64", ", m);
        if (mRSA_cipher(&m, d, n))
            printf("m may be too big\n");
        else {
            printf("c = %016"PRIx64", ", m);
            mRSA_cipher(&m, e, n);
            printf("v = %016"PRIx64"\n", m);
        }
    }
    /*
     * RSA 키와 평문을 무작위로 선택해서 암호화와 복호화를 수행하여 원래 평문과 일치하는지 검증한다.
     * 이 과정을 여러번 반복하여 올바른지 확인한다.
     */
    printf("Random testing"); fflush(stdout);
    count = 0;
    do {
        mRSA_generate_key(&e, &d, &n);
        arc4random_buf(&m, sizeof(uint64_t)); m &= 0x7fffffffffffffff;
        c = m;
        if (mRSA_cipher(&c, e, n)) {
            printf("FAILED: RSA key may not be 64 bits: %"PRIx64"\n", n);
            return 1;
        };
        if (mRSA_cipher(&c, d, n)) {
            printf("FAILED: check your modular calculations.\n");
            return 1;
        };
        if (m != c) {
            printf("FAILED: your RSA key generation may be wrong.\n");
            return 1;
        }
        if (++count % 0xff == 0) {
            printf(".");
            fflush(stdout);
        }
    } while (count < 0xfff);
    printf("PASSED\n");
    
    return 0;
}
