#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "uint256.h"
#include "sha256.h"

#define MASK_ALPHA  0b11111111000000000000000000000000
#define MASK_BETA   0b00000000111111111111111111111111

typedef struct {
    int client_fd;
} client_t;

void *work_function(void*);
char **buffer_reader(char*);
int input_handler(int, char**);
BYTE *proof_of_work(uint32_t, BYTE*, uint64_t);

#endif
