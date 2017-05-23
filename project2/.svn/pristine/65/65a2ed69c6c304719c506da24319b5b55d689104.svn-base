## CC  = Compiler.
## CFLAGS = Compiler flags.
CC	= gcc
CFLAGS =	-Wall -Wextra -std=c99


## OBJ = Object files.
## SRC = Source files.
## EXE = Executable name.

SRC =		server.c sha256.c list.c
OBJ =		server.o sha256.o list.o
EXE = 		server

## Top level target is executable.
$(EXE):	$(OBJ)
		$(CC) $(CFLAGS) -o $(EXE) $(OBJ) -lpthread


## Clean: Remove object files and core dump files.
clean:
		/bin/rm $(OBJ)

## Clobber: Performs Clean and removes executable file.

clobber: clean
		/bin/rm $(EXE)

## Dependencies

server.o:			server.h uint256.h sha256.h list.h
sha256.o:			sha256.h
list.o:				list.h
