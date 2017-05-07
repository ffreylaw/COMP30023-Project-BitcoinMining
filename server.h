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

#include "unit256.h"
#include "sha256.h"

typedef struct {
    int client_fd;
} client_t;

void *work_function(void*);
char **buffer_reader(char*);
int input_handler(int, char**);
BYTE *byte_converter(char*);
void proof_of_work(BYTE*, BYTE*, BYTE*);

#endif
