#include "server.h"

/** Main function
 */
int main(int argc, char* argv[]) {

	int socket_fd, port_no;
	struct sockaddr_in server_addr;

	signal(SIGINT, interrupt_handler);

	if (argc < 2) {
		fprintf(stderr,"ERROR no port provided\n");
		exit(EXIT_FAILURE);
	}

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

	/* Accept a connection - block until a connection is ready to
	 be accepted. Get back a new file descriptor to communicate on. */

	arg_t *arg = (arg_t*)malloc(sizeof(arg_t));
    arg->socket_fd = socket_fd;
	arg->server_addr = server_addr;

    if (pthread_create(&main_thread, NULL, main_work_function, (void*)arg)) {
        perror("ERROR to create thread");
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
	arg_t *arg = (arg_t*)param;
	int socket_fd = arg->socket_fd;
	struct sockaddr_in server_addr = arg->server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	int client_fd;

    /* Read characters from the connection,
    	then process */
	while (true) {
		client_fd = accept(socket_fd, (struct sockaddr *) &client_addr, &client_len);

        if (client_fd < 0) {
    		perror("ERROR on accept");
    		exit(EXIT_FAILURE);
    	}

		if (client_count >= MAX_CLIENTS) {
			if (write(client_fd, "Client limit exceeded\n", 22) < 0) {
				perror("ERROR writing to socket");
				exit(EXIT_FAILURE);
			}
			close(client_fd);
			continue;
		}

		int idx = 0;
		for(int i = 0; i < MAX_CLIENTS; i++){
			if (client_threads[i] == 0) {
				idx = i;
				break;
			}
		}

		client_t *client = (client_t*)malloc(sizeof(client_t));
		client->client_fd = client_fd;
		client->server_addr = server_addr;
		client->client_addr = client_addr;
		client->thread_idx = idx;

		client_args[idx] = *client;

		connection_log(client);

	    if (pthread_create(&(client_threads[idx]), NULL, client_work_function, (void*)&(client_args[idx]))) {
	        perror("ERROR to create thread");
	        exit(EXIT_FAILURE);
	    } else {
			client_count++;
		}
	}

    return NULL;
}

/** Work function for handling a message
 */
void *client_work_function(void *param) {
	client_t *client = (client_t*)param;

	pthread_t work_threads[MAX_PENGDING_JOBS];
	int work_count = 0;

	char buffer[256];

	while (true) {
		printf("%d\n", work_count);
		bzero(buffer, 256);

		if (read(client->client_fd, buffer, 255) < 0) {
			perror("ERROR reading from socket");
			break;
		}

		if (buffer[0] == '\0') {
			break;
		}

		receive_message_log(client, buffer);

		int idx = 0;
		for(int i = 0; i < MAX_PENGDING_JOBS; i++) {
			if (work_threads[i] == 0) {
				idx = i;
				break;
			}
		}

		message_t *message = (message_t*)malloc(sizeof(message_t));
		message->client = client;
		message->work_threads = work_threads;
		message->work_count = &work_count;
		message->buffer = (char*)malloc(256 * sizeof(char));
		memcpy(message->buffer, buffer, 256);
		message->thread_idx = idx;

		if (pthread_create(&(work_threads[idx]), NULL, message_work_function, (void*)message)) {
	        perror("ERROR to create thread");
	        exit(EXIT_FAILURE);
	    }
	}

	close(client->client_fd);

	pthread_mutex_lock(&lock);
	client_threads[client->thread_idx] = 0;
	client_count--;
	pthread_mutex_unlock(&lock);

	pthread_exit(NULL);

	return NULL;
}

/** Handle input message
 */
void *message_work_function(void *param) {
	message_t *message = (message_t*)param;
	int n = 0;
	char **input = buffer_reader(message->buffer, &n);
    char *output = NULL;
	int len = TEXT_LEN;
	if (!input) {
		output = "ERRO                     invalid input\r\n";
	} else {
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
			if (n < 4) {
				output = "ERRO               SOLN less arguments\r\n";
			} else if (is_solution(input[1], input[2], input[3])) {
				output = "OKAY\r\n";
				len = 6;
			} else {
				output = "ERRO              solution is not okay\r\n";
			}
	    } else if (!strcmp(command, "WORK")) {
			if (*(message->work_count) >= MAX_PENGDING_JOBS) {
				if (write(message->client->client_fd, "Pending job limit exceeded\n", 27) < 0) {
					perror("ERROR writing to socket");
					exit(EXIT_FAILURE);
				}
				return NULL;
			}

			pthread_mutex_lock(&lock);
			*(message->work_count) += 1;
			pthread_mutex_unlock(&lock);

			if (n < 5) {
				output = "ERRO               WORK less arguments\r\n";
			} else {
				BYTE *solution = proof_of_work(input[1], input[2], input[3], input[4]);
				char *out = (char*)malloc((95 + 2) * sizeof(char));
				char *soln = (char*)malloc((16 + 1) * sizeof(char));
				for (int i = 0; i < 8; i++) {
					sprintf(soln+(2*i), "%02x", solution[i]);
				}
				sprintf(out, "SOLN %s %s %s\r\n", input[1], input[2], soln);
		        output = out;
				len = 95 + 2;
			}

			pthread_mutex_lock(&lock);
			*(message->work_count) -= 1;
			pthread_mutex_unlock(&lock);

	    } else if (!strcmp(command, "ABRT")) {
			pthread_mutex_lock(&lock);
			for (int i = 0; i < MAX_PENGDING_JOBS; i++){
				if ((message->work_threads[i] != 0) &&
					(message->work_threads[i] != message->work_threads[message->thread_idx])) {
					pthread_cancel(message->work_threads[i]);
				}
				message->work_threads[i] = 0;
			}
			*(message->work_count) = 0;
			pthread_mutex_unlock(&lock);

			output = "OKAY\r\n";
			len = 6;
		} else {
	        output = "ERRO              unrecognized message\r\n";
	    }
	}

	if (write(message->client->client_fd, output, len) < 0) {
		perror("ERROR writing to socket");
	} else {
		send_message_log(message->client, output);
	}

	pthread_mutex_lock(&lock);
	message->work_threads[message->thread_idx] = 0;
	pthread_mutex_unlock(&lock);

	pthread_exit(NULL);

    return NULL;
}

/** Tokenize the buffer, split string by space \r \n
 */
char **buffer_reader(char *buffer, int *s) {
    char *ptr = strtok(buffer, " \r\n");
	if (!ptr) {
		return NULL;
	}
    char **array = (char**)malloc(sizeof(char*));
    while (ptr != NULL) {
        (*s)++;
        array = (char**)realloc(array, (*s) * sizeof(char*));
        array[(*s)-1] = ptr;
        ptr = strtok(NULL, " \r\n");
    }
    return array;
}

/** Handle SOLN message; return true if is a solution
 */
bool is_solution(const char *difficulty_, const char *seed_, const char *solution_) {
	int i = 0;

	// initialize variables
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

	// get coefficient of target
    uint32_t temp = beta;
    for (i = 0; i < 32; i++) {
        coefficient[31-i] = temp & 0xff;
        temp >>= 8;
    }

	// calculate target
    uint256_exp(clean, base, (8 * (alpha - 3)));
    uint256_mul(target, coefficient, clean);

	// initialize hash
	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);

	// generate text
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

	// do hash
    uint256_init(clean);
	sha256_init(&ctx);
	sha256_update(&ctx, text, TEXT_LEN);
	sha256_final(&ctx, clean);

    sha256_init(&ctx);
	sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
	sha256_final(&ctx, result);

	// compare
    if (sha256_compare(result, target) < 0) {
		return true;
    } else {
        return false;
    }
}

/** Handle WORK message; return a solution
 */
BYTE *proof_of_work(const char *difficulty_, const char *seed_, const char *start_, const char *worker_count_) {
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	(void) worker_count_;
	int i = 0;

	// initialize variables
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

	// get coefficient of target
	base[31] = 0x02;
	uint32_t temp = beta;
	for (i = 0; i < 32; i++) {
		coefficient[31-i] = temp & 0xff;
		temp >>= 8;
	}

	// calculate target
	uint256_exp(clean, base, (8 * (alpha - 3)));
	uint256_mul(target, coefficient, clean);

	// initialize hash
	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);

	// find solution
	while (true) {
		// generate text; concatenate seed and nonce
		BYTE text[TEXT_LEN];
		int idx = 0;
		for (i = 0; i < 32; i++) { text[idx++] = seed[i]; }
		BYTE *nonce = (BYTE*)malloc(8 * sizeof(BYTE));
		char *soln_buf = (char*)malloc((16 + 1) * sizeof(char));
		sprintf(soln_buf, "%llx", start);
		for (i = 0; i < 16; i+=2) {
			buf[0] = soln_buf[i];
			buf[1] = soln_buf[i+1];
			nonce[i/2] = strtoull(buf, NULL, 16);
		}
		for (i = 0; i < 8; i++) { text[idx++] = nonce[i]; }

		// do hash
		uint256_init(clean);
		sha256_init(&ctx);
		sha256_update(&ctx, text, TEXT_LEN);
		sha256_final(&ctx, clean);

		sha256_init(&ctx);
		sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
		sha256_final(&ctx, result);

		// compare
		if (sha256_compare(result, target) < 0) {
			return nonce;
		} else {
			start++;
			continue;
		}
	}
}

/** Log for connection
 */
void connection_log(client_t *client) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[BUFFER_SIZE];
	time_t now = time(0);
	strftime(time_buffer, BUFFER_SIZE, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) client connected\n", client->client_fd);

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

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) server receive a message from client: %s", client->client_fd, message);

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

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) server send a message to client: %s", client->client_fd, message);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

/** Interrupt signal handler
 */
void interrupt_handler(int sig) {
	(void) sig;

	for (int i = 0; i < MAX_CLIENTS; i++){
		if (client_threads[i] != 0)
			pthread_cancel(client_threads[i]);
	}
	pthread_cancel(main_thread);
}
