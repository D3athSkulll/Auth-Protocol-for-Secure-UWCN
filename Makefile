# Build the PEECC program (needs gcc + GMP; on Windows use MSYS2 mingw64).
#   make          build ./peecc
#   make run      encrypt + decrypt a sample message, printing every step (paper-exact [18])
#   make run-hardened   the same in hardened mode (deviation from [18])
#   make test     run the self-tests (both modes)
#   make lib      build the shared library used by protocol.py (peecc.dll / libpeecc.so)
CC     = gcc
CFLAGS = -O2 -Wall -Wextra -std=gnu11

ifeq ($(OS),Windows_NT)
  EXE = peecc.exe
  LIB = peecc.dll
  GMP = -l:libgmp.a
  LIBFLAGS = -shared -static-libgcc
else
  EXE = peecc
  LIB = libpeecc.so
  GMP = -lgmp
  LIBFLAGS = -shared -fPIC
endif

all: $(EXE)

$(EXE): peecc.c
	$(CC) $(CFLAGS) -o $@ $< $(GMP)

lib: $(LIB)

$(LIB): peecc.c
	$(CC) $(CFLAGS) $(LIBFLAGS) -DPEECC_LIB -o $@ $< $(GMP)

run: $(EXE)
	./$(EXE) "hello PEECC"

run-hardened: $(EXE)
	./$(EXE) --hardened "hello PEECC"

test: $(EXE)
	./$(EXE) --test

clean:
	rm -f peecc peecc.exe peecc.dll libpeecc.so

.PHONY: all lib run run-hardened test clean
