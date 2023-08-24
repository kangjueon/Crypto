#
# Copyright 2020-2022. Heekuck Oh, all rights reserved
# 이 파일은 한양대학교 ERICA 소프트웨어학부 재학생을 위해 만들었다.
#
CC = gcc
CFLAGS = -Wall -O3
CLIBS = -lgmp
#
OS := $(shell uname -s)
ifeq ($(OS), Linux)
#	CFLAGS += -fopenmp
	CLIBS += -lbsd
endif
ifeq ($(OS), Darwin)
#	CFLAGS += -Xpreprocessor -fopenmp
#	CLIBS += -lomp
endif
#
all: test.o ecdsa.o sha2.o
	$(CC) -o test test.o ecdsa.o sha2.o $(CLIBS)

test.o: test.c ecdsa.h
	$(CC) $(CFLAGS) -c test.c

ecdsa.o: ecdsa.c ecdsa.h sha2.h
	$(CC) $(CFLAGS) -c ecdsa.c

sha2.o: sha2.c sha2.h
	$(CC) $(CFLAGS) -c sha2.c

clean:
	rm -rf *.o
	rm -rf test
