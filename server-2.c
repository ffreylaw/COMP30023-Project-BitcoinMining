#include "server.h"

/** Main function
 */
int main(int argc, char* argv[]) {

	int socket_fd, port_no;
	struct sockaddr_in server_addr;

	if (argc < 2) {
		fprintf(stderr,"ERROR no port provided\n");
		exit(EXIT_FAILURE);
	}

	/* Create signal handler */
	signal(SIGINT, interrupt_handler);

	/* Initialize mutex */
	if (pthread_mutex_init(&lock, NULL) != 0) {
		perror("ERROR on mutex init");
        exit(EXIT_FAILURE);
	}

	/* Create log file */
	if ((fp = fopen("log.txt", "w")) == NULL) {
		perror("ERROR to create log file");
		exit(EXIT_FAILURE);
	}
	fclose(fp);

	/* Create TCP socket */
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (socket_fd < 0) {
		perror("ERROR opening socket");
		exit(EXIT_FAILURE);
	}

	bzero((char *) &server_addr, sizeof(server_addr));

	port_no = atoi(argv[1]);

	/* Create address we're going to listen on (given port number)
	 - converted to network byte order & any IP address for
	 this machine */

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port_no);  // store in machine-neutral format

	/* Bind address to the socket */
	if (bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		perror("ERROR on binding");
		exit(EXIT_FAILURE);
	}

	/* Listen on socket - means we're ready to accept connections -
	 incoming connection requests will be queued */
	listen(socket_fd, 5);

	/* Generate a server thread arguments */
	server_t *server = (server_t*)malloc(sizeof(server_t));
    server->socket_fd = socket_fd;
	server->server_addr = server_addr;

	/* Create a server thread */
    if (pthread_create(&main_thread, NULL, main_work_function, (void*)server)) {
        perror("ERROR to create main thread");
        exit(EXIT_FAILURE);
    }
    if (pthread_join(main_thread, NULL)) {
        perror("ERROR to join thread");
        exit(EXIT_FAILURE);
    }

	return 0;
}

/** Main work function for client thread
 */
void *main_work_function(void *param) {
	server_t *server = (server_t*)param;
	int socket_fd = server->socket_fd;
	struct sockaddr_in server_addr = server->server_addr;

    /* Read characters from the connection,
    	then process */
	while (true) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);

		/* Accept an incoming client */
		int client_fd = accept(socket_fd, (struct sockaddr *) &client_addr, &client_len);

        if (client_fd < 0) {
    		perror("ERROR on accept");
    		exit(EXIT_FAILURE);
    	}

		/* Check whether reach the limit */
		if (client_count >= MAX_CLIENTS) {
			if (write(client_fd, "Client limit exceeded\n", 22) < 0) {
				perror("ERROR writing to socket");
				exit(EXIT_FAILURE);
			}
			close(client_fd);
			continue;
		}

		/* Looking for empty slot in client threads array */
		int idx = 0;
		for(int i = 0; i < MAX_CLIENTS; i++){
			if (client_threads[i] == 0) {
				idx = i;
				break;
			}
		}

		/* Generate a client thread arguments */
		client_t *client = (client_t*)malloc(sizeof(client_t));
		client->client_fd = client_fd;
		client->server_addr = server_addr;
		client->client_addr = client_addr;
		client->thread_idx = idx;
		bool disconnect = false;
		client->disconnect = &disconnect;
		bool abrt = false;
		client->abrt = &abrt;

		client_args[idx] = *client;

		connect_log(client);

		/* Create a client thread */
	    if (pthread_create(&(client_threads[idx]), NULL, client_work_function, (void*)&(client_args[idx]))) {
	        perror("ERROR to create client thread");
	        exit(EXIT_FAILURE);
	    }

		/* Increment client count */
		client_count++;
	}

    return NULL;
}

/** Work function for handling a message
 */
void *client_work_function(void *param) {
	client_t *client = (client_t*)param;

	/* Create a work queue */
	List work_queue = NULL;

	work_arg_t *work_arg = (work_arg_t*)malloc(sizeof(work_arg_t));
	work_arg->client = client;
	work_arg->work_queue = &work_queue;

	/* Create a work thread to handle work queue */
	if (pthread_create(&(client->work_thread), NULL, handle_work, (void*)work_arg)) {
		perror("ERROR to create work thread");
		exit(EXIT_FAILURE);
	}

	while (true) {
		/* Check disconnection */
		if (*(client->disconnect)) {
			disconnect_log(client);
			break;
		}

		/* Initialize a buffer */
		char buffer[256];
		bzero(buffer, 256);

		/* Read message from client */
		if (read(client->client_fd, buffer, 255) < 0) {
			perror("ERROR reading from socket");
			*(client->disconnect) = true;
			continue;
		}

		/* Invalid input - disconnection */
		if (buffer[0] == '\0') {
			if (write(client->client_fd, "ERRO                     invalid input\r\n", 40) < 0) {
				perror("ERROR writing to socket");
				*(client->disconnect) = true;
			}
			continue;
		}

		receive_message_log(client, buffer);

		/* Create a message struct */
		message_t *message = (message_t*)malloc(sizeof(message_t));
		message->client = client;
		message->work_queue = &work_queue;
		message->buffer = (char*)malloc(256 * sizeof(char));
		memcpy(message->buffer, buffer, 256);

		/* Handle the input message */
		handle_message(message);
	}

	/* Close client socket */
	close(client->client_fd);

	/* Clean work queue */
	*(client->disconnect) = true;
	List node = work_queue;
	while (node != NULL) {
		List ptr = node;
		node = node->next;
		free(ptr);
	}
	work_queue = NULL;
	pthread_cancel(client->work_thread);

	/* Delete from array */
	pthread_mutex_lock(&lock);
	client_threads[client->thread_idx] = 0;
	client_count--;
	pthread_mutex_unlock(&lock);

	/* Client thread exit */
	pthread_exit(NULL);

	return NULL;
}

/** Handle work queue
 */
void *handle_work(void *param) {
	work_arg_t *work_arg = (work_arg_t*)param;

	while (true) {
		/* Check disconnection */
		if (*(work_arg->client->disconnect)) {
			break;
		}

		/* Get first element of the linked list */
		List *queue = (List*)work_arg->work_queue;
		List node = *queue;
		if (node != NULL) {
			work_t *data = node->data;

			/* To get a solution */
			BYTE *solution = proof_of_work(data->difficulty,
										   data->seed,
										   data->start,
									   	   data->worker_count,
									   	   work_arg->client);

			/* Check ABRT */
			if (*(work_arg->client->abrt)) {
   				*(work_arg->client->abrt) = false;
   				continue;
   			}

			/* Check disconnection */
			if (!solution || node == NULL) {
				break;
			}

			/* Generate output */
			char *out = (char*)malloc((95 + 2) * sizeof(char));
			char *soln = (char*)malloc((16 + 1) * sizeof(char));
			for (int i = 0; i < 8; i++) {
				sprintf(soln+(2*i), "%02x", solution[i]);
			}
			sprintf(out, "SOLN %s %s %s\r\n", data->difficulty, data->seed, soln);

			char *output = out;
			int len = 95 + 2;

			/* Write output */
			if (write(data->client->client_fd, output, len) < 0) {
				perror("ERROR writing to socket");
				*(work_arg->client->disconnect) = true;
				break;
			}
			send_message_log(data->client, output);

			/* Pop out the first element of the linked list */
			pop(queue);
		}
	}

	/* Work thread exit */
	pthread_exit(NULL);
}

/** Handle input message
 */
void *handle_message(void *param) {
	message_t *message = (message_t*)param;

	int n = 0;
	char **input = split(message->buffer, &n);
    char *output = NULL;
	int len = TEXT_LEN;

	if (!input) {
		/* Invalid message */
		output = "ERRO                     invalid input\r\n";
	} else {
		/* Switch all cases */
		char *command = input[0];
	    if (!strcmp(command, "PING")) {
	        output = "PONG\r\n";
			len = 6;
	    } else if (!strcmp(command, "PONG")) {
			output = "ERRO          reserved server response\r\n";
		} else if (!strcmp(command, "OKAY")) {
			output = "ERRO   not okay to send OKAY to server\r\n";
		} else if (!strcmp(command, "ERRO")) {
			output = "ERRO         should not send to server\r\n";
		} else if (!strcmp(command, "SOLN")) {
			if (n != 4) {
				output = "ERRO            invalid SOLN arguments\r\n";
			} else if ((strlen(input[1]) != 8) ||
				       (strlen(input[2]) != 64) ||
				       (strlen(input[3]) != 16)) {
				output = "ERRO            invalid SOLN arguments\r\n";
			} else {
				if (is_solution(input[1], input[2], input[3])) {
					output = "OKAY\r\n";
					len = 6;
				} else {
					output = "ERRO              solution is not okay\r\n";
				}
			}
	    } else if (!strcmp(command, "WORK")) {
			if (n != 5) {
				output = "ERRO            invalid WORK arguments\r\n";
			} else {
				if ((strlen(input[1]) != 8) ||
				    (strlen(input[2]) != 64) ||
				    (strlen(input[3]) != 16) ||
				    (strlen(input[4]) != 2)) {
					output = "ERRO            invalid WORK arguments\r\n";
				} else {
					int n = list_len(*(message->work_queue));
					if (n >= MAX_PENGDING_JOBS) {
						if (write(message->client->client_fd, "Pending job limit exceeded\n", 27) < 0) {
							perror("ERROR writing to socket");
							*(message->client->disconnect) = true;
						}
						return NULL;
					}

					work_t *work = (work_t*)malloc(sizeof(work_t));
					work->client = message->client;
					work->difficulty = input[1];
					work->seed = input[2];
					work->start = input[3];
					work->worker_count = input[4];

					insert(work, message->work_queue);

					return NULL;
				}
			}
	    } else if (!strcmp(command, "ABRT")) {
			List *queue = message->work_queue;
			List node = (*queue);
			while (node != NULL) {
		        List ptr = node;
		        node = node->next;
		        free(ptr);
			}
			(*queue) = NULL;

			*(message->client->abrt) = true;

			output = "OKAY\r\n";
			len = 6;
		} else {
	        output = "ERRO              unrecognized message\r\n";
	    }
	}

	/* Write output */
	if (write(message->client->client_fd, output, len) < 0) {
		perror("ERROR writing to socket");
		*(message->client->disconnect) = true;
	} else {
		send_message_log(message->client, output);
	}

    return NULL;
}

/** Split string by space \r \n
 */
char **split(char *buffer, int *s) {
	char **array = (char**)malloc(((*s)+1) * sizeof(char*));
	int n = 0;
	array[(*s)] = (char*)malloc((n+1) * sizeof(char));
	for (int i = 0; i < 256; i++) {
		if (buffer[i] == '\0' || buffer[i] == '\r' || buffer[i] == '\n') {
			array[(*s)] = (char*)realloc(array[(*s)], (n+1) * sizeof(char));
			array[(*s)][n] = '\0';
			(*s)++;
			break;
		} else if (buffer[i] == ' ' && (i > 0)) {
			array[(*s)] = (char*)realloc(array[(*s)], (n+1) * sizeof(char));
			array[(*s)][n] = '\0';
			(*s)++;
			array = (char**)realloc(array, ((*s)+1) * sizeof(char*));
			n = 0;
			array[(*s)] = (char*)malloc((n+1) * sizeof(char));
		} else {
			array[(*s)] = (char*)realloc(array[(*s)], (n+1) * sizeof(char));
			array[(*s)][n] = buffer[i];
			n += 1;
		}
	}
    return array;
}

/** Handle SOLN message; return true if is a solution
 */
bool is_solution(const char *difficulty_, const char *seed_, const char *solution_) {
	int i = 0;

	/* initialize variables */
	uint32_t difficulty = strtoull(difficulty_, NULL, 16);
	uint32_t alpha = (MASK_ALPHA & difficulty) >> 24;
    uint32_t beta = MASK_BETA & difficulty;

	BYTE base[32], coefficient[32], target[32];
    BYTE clean[32];
    uint256_init(base);
    uint256_init(coefficient);
    uint256_init(target);
    uint256_init(clean);

	base[31] = 0x02;

	/* Get coefficient of target */
    uint32_t temp = beta;
    for (i = 0; i < 32; i++) {
        coefficient[31-i] = temp & 0xff;
        temp >>= 8;
    }

	/* Calculate target */
    uint256_exp(clean, base, (8 * (alpha - 3)));
    uint256_mul(target, coefficient, clean);

	/* Initialize hash */
	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);

	/* Generate text */
    BYTE text[TEXT_LEN];
	int idx = 0;
	char buf[2];
	for (i = 0; i < 64; i+=2) {
		buf[0] = seed_[i];
		buf[1] = seed_[i+1];
		text[idx++] = strtoull(buf, NULL, 16);
	}
	for (i = 0; i < 16; i+=2) {
        buf[0] = solution_[i];
        buf[1] = solution_[i+1];
        text[idx++] = strtoull(buf, NULL, 16);
    }

	/* Do hash */
    uint256_init(clean);
	sha256_init(&ctx);
	sha256_update(&ctx, text, TEXT_LEN);
	sha256_final(&ctx, clean);

    sha256_init(&ctx);
	sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
	sha256_final(&ctx, result);

	// Compare result with target
    if (sha256_compare(result, target) < 0) {
		return true;
    } else {
        return false;
    }
}

/** Handle WORK message; return a solution
 */
BYTE *proof_of_work(const char *difficulty_, const char *seed_, const char *start_, const char *worker_count_, client_t *client) {
	(void) worker_count_;
	int i = 0;

	/* Initialize variables */
	uint32_t difficulty = strtoull(difficulty_, NULL, 16);
	BYTE seed[32];
	uint256_init(seed);
	char buf[2];
	for (i = 0; i < 64; i+=2) {
		buf[0] = seed_[i];
		buf[1] = seed_[i+1];
		seed[i/2] = strtoull(buf, NULL, 16);
	}
	uint64_t start = strtoull(start_, NULL, 16);
	uint32_t alpha = (MASK_ALPHA & difficulty) >> 24;
	uint32_t beta = MASK_BETA & difficulty;

	BYTE base[32], coefficient[32], target[32];
	BYTE clean[32];
	uint256_init(base);
	uint256_init(coefficient);
	uint256_init(target);
	uint256_init(clean);

	base[31] = 0x02;

	/* Get coefficient of target */
	uint32_t temp = beta;
	for (i = 0; i < 32; i++) {
		coefficient[31-i] = temp & 0xff;
		temp >>= 8;
	}

	/* Calculate target */
	uint256_exp(clean, base, (8 * (alpha - 3)));
	uint256_mul(target, coefficient, clean);

	/* Initialize hash */
	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);

	/* Generate text */
	BYTE text[TEXT_LEN];
	int idx = 0;
	for (i = 0; i < 32; i++) { text[idx++] = seed[i]; }

	/* Find solution */
	while (true) {
		// check disconnection or ABRT
		if (*(client->disconnect) || *(client->abrt)){
			break;
		}

		/* Concatenate with nonce */
		idx = 32;
		BYTE *nonce = (BYTE*)malloc(8 * sizeof(BYTE));
		char *soln_buf = (char*)malloc((16 + 1) * sizeof(char));
		sprintf(soln_buf, "%llx", start);
		for (i = 0; i < 16; i+=2) {
			buf[0] = soln_buf[i];
			buf[1] = soln_buf[i+1];
			nonce[i/2] = strtoull(buf, NULL, 16);
		}
		for (i = 0; i < 8; i++) { text[idx++] = nonce[i]; }

		/* Do hash */
		uint256_init(clean);
		sha256_init(&ctx);
		sha256_update(&ctx, text, TEXT_LEN);
		sha256_final(&ctx, clean);

		sha256_init(&ctx);
		sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
		sha256_final(&ctx, result);

		/* Compare result with target  */
		if (sha256_compare(result, target) < 0) {
			return nonce;
		} else {
			start++;
			continue;
		}
	}

	return NULL;
}

/** Log for connection
 */
void connect_log(client_t *client) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[BUFFER_SIZE];
	time_t now = time(0);
	strftime(time_buffer, BUFFER_SIZE, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char server_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->server_addr.sin_addr), server_ip4, INET_ADDRSTRLEN);
	char client_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s) ", time_buffer, server_ip4);
	fprintf(fp, "client(%s)(socket_id %d) connected\n", client_ip4, client->client_fd);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

/** Log for disconnection
 */
void disconnect_log(client_t *client) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[BUFFER_SIZE];
	time_t now = time(0);
	strftime(time_buffer, BUFFER_SIZE, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char server_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->server_addr.sin_addr), server_ip4, INET_ADDRSTRLEN);
	char client_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s) ", time_buffer, server_ip4);
	fprintf(fp, "client(%s)(socket_id %d) disconnected\n", client_ip4, client->client_fd);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

/** Log for receiving message
 */
void receive_message_log(client_t *client, char *message) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[BUFFER_SIZE];
	time_t now = time(0);
	strftime(time_buffer, BUFFER_SIZE, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char server_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->server_addr.sin_addr), server_ip4, INET_ADDRSTRLEN);
	char client_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s) ", time_buffer, server_ip4);
	fprintf(fp, "server receives a message from client(%s)(socket_id %d): %s", client_ip4, client->client_fd, message);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

/** Log for sending message
 */
void send_message_log(client_t *client, char *message) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[BUFFER_SIZE];
	time_t now = time(0);
	strftime(time_buffer, BUFFER_SIZE, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char server_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->server_addr.sin_addr), server_ip4, INET_ADDRSTRLEN);
	char client_ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s) ", time_buffer, server_ip4);
	fprintf(fp, "server sends a message to client(%s)(socket_id %d): %s", client_ip4, client->client_fd, message);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

/** Interrupt signal handler
 */
void interrupt_handler(int sig) {
	(void) sig;
	for (int i = 0; i < MAX_CLIENTS; i++){
		if (client_threads[i] != 0) {
			*(client_args[i].disconnect) = true;
			pthread_cancel(client_args[i].work_thread);
			pthread_cancel(client_threads[i]);
		}
	}
	pthread_cancel(main_thread);
	exit(EXIT_FAILURE);
}
