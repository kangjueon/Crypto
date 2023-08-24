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
	CFLAGS += -fopenmp
	CLIBS += -fopenmp
endif
ifeq ($(OS), Darwin)
	CFLAGS += -Xpreprocessor -fopenmp
	CLIBS += -lomp
endif
#
all: test.o miller_rabin.o
	$(CC) -o test test.o miller_rabin.o $(CLIBS)

test.o: test.c miller_rabin.h
	$(CC) $(CFLAGS) -c test.c

miller_rabin.o: miller_rabin.c miller_rabin.h
	$(CC) $(CFLAGS) -c miller_rabin.c

clean:
	rm -rf *.o
	rm -rf test
