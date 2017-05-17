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
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>

#include "uint256.h"
#include "sha256.h"

#define MASK_ALPHA  0b11111111000000000000000000000000
#define MASK_BETA   0b00000000111111111111111111111111

#define TEXT_LEN 40
#define BUFFER_SIZE 100
#define MAX_CLIENTS 100

pthread_mutex_t lock;
FILE *fp;

typedef struct{
	int socket_fd;
    struct sockaddr_in server_addr;
} arg_t;

typedef struct {
    int client_fd;
	struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
	int thread_idx;
} client_t;

pthread_t main_thread;
pthread_t clients[MAX_CLIENTS];
client_t client_args[MAX_CLIENTS];

int thread_count = 0;

void *main_work_function(void*);
void *message_work_function(void*);
char **buffer_reader(char*, int*);
void input_handler(char**, int, char**, int*);
bool is_solution(const char*, const char*, const char*);
BYTE *proof_of_work(const char*, const char*, const char*, const char*);
void connection_log(client_t*);
void receive_message_log(client_t*, char*);
void send_message_log(client_t*, char*);
void interrupt_handler(int);

#endif
