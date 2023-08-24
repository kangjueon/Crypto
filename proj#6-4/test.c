/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#include <stdio.h>
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <time.h>
#include "ecdsa.h"

char *poem = "죽는 날까지 하늘을 우러러 한 점 부끄럼이 없기를, 잎새에 이는 바람에도 나는 괴로워했다. 별을 노래하는 마음으로 모든 죽어 가는 것을 사랑해야지 그리고 나한테 주어진 길을 걸어가야겠다. 오늘 밤에도 별이 바람에 스치운다.";
unsigned char poet_d[ECDSA_P256/8] = {0x0f,0x34,0x2f,0x4a,0xa6,0xe5,0x0d,0x19,0x0a,0x7d,0xf7,0xd9,0x07,0x56,0xa2,0x67,0x2a,0x72,0xc1,0x12,0x41,0xc3,0x41,0x85,0x63,0x07,0x52,0x84,0x1f,0x4d,0xd6,0x99};
ecdsa_p256_t poet_Q = {{0xc4,0xa5,0x21,0x10,0xd2,0x67,0x98,0x63,0xaa,0xd1,0x14,0x38,0x15,0x03,0x43,0x4d,0x1a,0x7f,0x67,0x67,0x77,0x11,0x7e,0x0e,0x0b,0x44,0xa7,0x08,0xa6,0x40,0x16,0x1d},{0xa9,0xd1,0x4b,0x94,0xd0,0x56,0x07,0x53,0x07,0xaa,0x43,0x96,0xfc,0xc6,0x26,0xed,0x77,0xb2,0x0d,0xd8,0x20,0x77,0x52,0x34,0x0d,0x93,0x4c,0x85,0x22,0xa0,0x85,0x9f}};
unsigned char poem_r1[ECDSA_P256/8] = {0xcd,0x1f,0x65,0x6a,0x61,0x73,0x48,0x11,0xd3,0x38,0x79,0xaf,0x6c,0x3a,0x0a,0x33,0x1f,0x08,0x63,0xd6,0xab,0x31,0xd9,0x2a,0x21,0xe2,0xbc,0x38,0xdc,0xd2,0x4e,0xac};
unsigned char poem_s1[ECDSA_P256/8] = {0x30,0x80,0xe9,0xbb,0x67,0x8f,0x03,0x29,0x8b,0x43,0x49,0xe3,0x6f,0xb9,0xc4,0x30,0x6f,0x65,0x85,0x53,0x00,0x6e,0x7f,0x54,0x24,0x80,0x04,0xb3,0xa9,0xbe,0x81,0x60};
unsigned char poem_r2[ECDSA_P256/8] = {0xba,0xab,0x19,0xc8,0x4f,0xaa,0x8d,0x75,0xc5,0x26,0x7e,0x71,0xca,0x12,0x7e,0x30,0x3c,0xb8,0xeb,0x36,0x41,0x29,0x70,0xc4,0x80,0x83,0xbe,0xb8,0x09,0x5f,0x7b,0x9f};
unsigned char poem_s2[ECDSA_P256/8] = {0xdc,0x87,0xe3,0x65,0xa7,0x55,0xc0,0x98,0x6b,0xb6,0x2e,0x71,0xf6,0xda,0x72,0xb1,0xd9,0x08,0x53,0xfe,0x90,0x8f,0x9a,0xc9,0x30,0x6a,0x81,0x3f,0x78,0xa6,0x73,0x4b};

int main(void)
{
    long data;
    int i, count,val;
    unsigned char d[ECDSA_P256/8];
    ecdsa_p256_t Q;
    unsigned char r[ECDSA_P256/8], s[ECDSA_P256/8];
    unsigned char r1[ECDSA_P256/8], s1[ECDSA_P256/8];
    clock_t start, end;
    double cpu_time;

    start = clock();
    /*
     * ECDSA 키 생성 시험
     */
    ecdsa_p256_init();
    ecdsa_p256_key(d, &Q);
    printf("d = ");
    for (i = 0; i < ECDSA_P256/8; ++i)
        printf("%02hhx", d[i]);
    printf("\n");
    printf("Qx = ");
    for (i = 0; i < ECDSA_P256/8; ++i)
        printf("%02hhx", Q.x[i]);
    printf("\n");
    printf("Qy = ");
    for (i = 0; i < ECDSA_P256/8; ++i)
        printf("%02hhx", Q.y[i]);
    printf("\n");
    
    /*
     * 생성된 키로 윤동주의 서시를 서명한 후 검증한다. SHA512_224 해시함수를 사용한다.
     */
    if ((val = ecdsa_p256_sign(poem, strlen(poem), d, r, s, SHA512_224)) != 0) {
        printf(" ...FAILED: signature generation error = %d\n", val);
        return 1;
    };
    printf("r = ");
    for (i = 0; i < ECDSA_P256/8; ++i)
        printf("%02hhx", r[i]);
    printf("\n");
    printf("s = ");
    for (i = 0; i < ECDSA_P256/8; ++i)
        printf("%02hhx", s[i]);
    printf("\n");
    if ((val = ecdsa_p256_sign(poem, strlen(poem), d, r1, s1, SHA512_224)) != 0) {
        printf(" ...FAILED: signature generation error = %d\n", val);
        return 1;
    };
    if (memcmp(r, r1, ECDSA_P256/8) == 0 || memcmp(s, s1, ECDSA_P256/8) == 0) {
        printf(" ...FAILED: k may not be random\n");
        return 1;
    };        
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &Q, r, s, SHA512_224)) != 0) {
        printf("Signature verification error = %d ...FAILED\n", val);
        return 1;
    }
    else
        printf("Valid signature ...PASSED\n");
    
    /*
     * 고의로 시의 길이를 변경하거나 다른 사람의 키를 사용해서 검증을 시도한다.
     */
    if ((val = ecdsa_p256_verify(poem, strlen(poem)+1, &Q, r, s, SHA512_224)) != 0)
        printf("Signature verification error = %d ...PASSED\n", val);
    else {
        printf("Signature varification error ...FAILED\n");
        return 1;
    }
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &poet_Q, r, s, SHA512_224)) != 0)
        printf("Signature verification error = %d ...PASSED\n", val);
    else {
        printf("Signature varification error ...FAILED\n");
        return 1;
    }
    printf("---\n");
    
    /*
     * 해시함수가 허용하는 메시지의 최대 길이를 초과한 경우를 시험한다.
     */
    if ((val = ecdsa_p256_verify(poem, 0x2000000000000000, &Q, r, s, SHA512_224)) != 0)
        printf("Signature verification error = %d ...PASSED\n", val);
    else {
        printf("Signature varification error ...FAILED\n");
        return 1;
    }
    printf("---\n");
    
    /*
     * 서명 값이 정상적인 범위에 있지 않는 경우를 시험한다.
     */
    memset(s, 0, ECDSA_P256/8);
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &Q, r, s, SHA512_224)) != 0)
        printf("Signature verification error = %d ...PASSED\n", val);
    else {
        printf("Signature varification error ...FAILED\n");
        return 1;
    }
    memset(s, 255, ECDSA_P256/8);
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &Q, r, s, SHA512_224)) != 0)
        printf("Signature verification error = %d ...PASSED\n", val);
    else {
        printf("Signature varification error ...FAILED\n");
        return 1;
    }
    printf("---\n");
    
    /*
     * 서명 검증이 표준 규격에 따라 구현이 되었는지 시험한다.
     */
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &poet_Q, poem_r1, poem_s1, SHA224)) != 0) {
        printf("Signature verification error = %d ...FAILED\n", val);
        return 1;
    }
    else
        printf("Valid signature ...PASSED\n");
    if ((val = ecdsa_p256_verify(poem, strlen(poem), &poet_Q, poem_r2, poem_s2, SHA384)) != 0) {
        printf("Signature verification error = %d ...FAILED\n", val);
        return 1;
    }
    else
        printf("Valid signature ...PASSED\n");
    printf("---\n");
    
    /*
     * 키 생성, 서명, 검증을 해시함수를 변경해 가면서 반복적으로 수행한다.
     */
    printf("Random Testing"); fflush(stdout);
    count = 0;
    do {
        ecdsa_p256_key(d, &Q);
        arc4random_buf(&data, sizeof(long));
        if (ecdsa_p256_sign(&data, sizeof(long), d, r, s, count%6)) {
            printf(" ...FAILED signature generation\n");
            return 1;
        };
        if (ecdsa_p256_verify(&data, sizeof(long), &Q, r, s, count%6)) {
            printf(" ...FAILED signature verification\n");
            return 1;
        }
        ++data;
        if (!ecdsa_p256_verify(&data, sizeof(long), &Q, r, s, count%6)) {
            printf(" ...FAILED signature varification\n");
            return 1;
        }
        if (++count % 0xff == 0) {
             printf(".");
             fflush(stdout);
         }
    } while (count < 0x4fff);
    printf(" ...PASSED\n");
    ecdsa_p256_clear();
    
    end = clock();
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("CPU 사용시간 = %.4f초\n", cpu_time);

    return 0;
}
