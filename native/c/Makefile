# NOSP C Core Compilation

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -std=c11 -fPIC
LDFLAGS = -shared

# For Windows
ifeq ($(OS),Windows_NT)
    TARGET = pattern_matcher.dll
    LDFLAGS += -lws2_32
else
    TARGET = libpattern_matcher.so
endif

all: $(TARGET) test

$(TARGET): pattern_matcher.c pattern_matcher.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) pattern_matcher.c

test: pattern_matcher.c pattern_matcher.h
	$(CC) $(CFLAGS) -DAC_TEST_MAIN -o pattern_matcher_test pattern_matcher.c
	./pattern_matcher_test

clean:
	rm -f $(TARGET) pattern_matcher_test *.o

.PHONY: all test clean
