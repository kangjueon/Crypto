#
# Copyright 2020-2022. Heekuck Oh, all rights reserved
# 이 파일은 한양대학교 ERICA 소프트웨어학부 재학생을 위해 만들었다.
#
CC = gcc
CFLAGS = -Wall -O3
CLIBS =
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
all: test.o mRSA.o
	$(CC) -o test test.o mRSA.o $(CLIBS)

test.o: test.c mRSA.h
	$(CC) $(CFLAGS) -c test.c

mRSA.o: mRSA.c mRSA.h
	$(CC) $(CFLAGS) -c mRSA.c

clean:
	rm -rf *.o
	rm -rf test
