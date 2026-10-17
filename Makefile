# Build the PEECC program (needs gcc + GMP; on Windows use MSYS2 mingw64).
#   make          build ./peecc
#   make run      encrypt + decrypt a sample message, printing every step
#   make test     run the self-tests
CC     = gcc
CFLAGS = -O2 -Wall -Wextra -std=gnu11

ifeq ($(OS),Windows_NT)
  EXE = peecc.exe
  GMP = -l:libgmp.a
else
  EXE = peecc
  GMP = -lgmp
endif

all: $(EXE)

$(EXE): peecc.c
	$(CC) $(CFLAGS) -o $@ $< $(GMP)

run: $(EXE)
	./$(EXE) "hello PEECC"

test: $(EXE)
	./$(EXE) --test

clean:
	rm -f peecc peecc.exe

.PHONY: all run test clean
