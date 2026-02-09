# NOSP EVENT HORIZON - C Core Compilation

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -std=c11 -fPIC
LDFLAGS = -shared

# Platform detection
ifeq ($(OS),Windows_NT)
    EXT = .dll
    LIBS = -lws2_32
else
    EXT = .so
    LIBS =
endif

# All targets
all: pattern_matcher$(EXT) packet_capture$(EXT) packet_injector$(EXT)

# Pattern Matcher
pattern_matcher$(EXT): pattern_matcher.c pattern_matcher.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pattern_matcher.c

# Packet Capture
packet_capture$(EXT): packet_capture.c packet_capture.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ packet_capture.c $(LIBS)

# Packet Injector (EVENT HORIZON)
packet_injector$(EXT): packet_injector.c packet_injector.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ packet_injector.c $(LIBS)

# Test executables
test_pattern: pattern_matcher.c pattern_matcher.h
	$(CC) $(CFLAGS) -DBUILD_TEST -o $@ pattern_matcher.c

test_capture: packet_capture.c packet_capture.h
	$(CC) $(CFLAGS) -DBUILD_TEST -o $@ packet_capture.c $(LIBS)

test_injector: packet_injector.c packet_injector.h
	$(CC) $(CFLAGS) -DBUILD_TEST -o $@ packet_injector.c $(LIBS)

# Build and run all tests
test: test_pattern test_capture test_injector
	@echo "Running tests..."
	./test_pattern
	@echo "Note: test_capture and test_injector require Administrator/root"

clean:
	rm -f *$(EXT) test_* *.o

.PHONY: all test clean
