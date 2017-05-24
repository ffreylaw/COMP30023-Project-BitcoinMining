/*
 * COMP30023 Computer Systems
 * Semester 1 2017
 *
 * Project 2 - Bitcoin Mining
 *
 * Geoffrey Law (glaw@student.unimelb.edu.au)
 * Student ID: 759218
 *
 */

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
#include "list.h"

#define MASK_ALPHA  0b11111111000000000000000000000000
#define MASK_BETA   0b00000000111111111111111111111111

#define TEXT_LEN 40
#define BUFFER_SIZE 100
#define MAX_CLIENTS 100
#define MAX_PENGDING_JOBS 10

typedef struct{
	int socket_fd;
    struct sockaddr_in server_addr;
} server_t;

typedef struct {
    int client_fd;
	struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
	int thread_idx;
	bool *disconnect;
	bool *abrt;
} client_t;

typedef struct {
    client_t *client;
	List *work_queue;
	char *buffer;
} message_t;

typedef struct {
    client_t *client;
	char *difficulty;
	char *seed;
	char *start;
	char *worker_count;
} work_t;

typedef struct {
	pthread_t thread;
	work_t *work;
	int index;
	bool *is_done;
} worker_t;

pthread_mutex_t lock;
FILE *fp;

pthread_t main_thread;
bool server_termination_flag = false;

pthread_t client_threads[MAX_CLIENTS];
client_t client_args[MAX_CLIENTS];
int client_count = 0;

pthread_t work_thread;
List work_queue;

bool is_worker_done = false;

void *main_work_function(void*);
void *client_work_function(void*);
void *message_work_function(void*);
void *handle_work(void*);
void *handle_worker_bonus(void*);
bool is_solution(const char*, const char*, const char*);
void *proof_of_work(void*);
void connect_log(client_t*);
void disconnect_log(client_t*);
void receive_message_log(client_t*, char*);
void send_message_log(client_t*, char*);
char **split(char*, int*);
void interrupt_handler(int);

#endif
