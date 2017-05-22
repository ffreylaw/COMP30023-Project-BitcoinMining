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
			if (write(client_fd, "Thread limit exceeded\n", 22) < 0) {
				perror("ERROR writing to socket");
				exit(EXIT_FAILURE);
			}
			close(client_fd);
			continue;
		}

		int idx = 0;
		for(int i = 0; i < MAX_CLIENTS; i++){
			if (clients[i] == 0) {
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

	    if (pthread_create(&(clients[idx]), NULL, client_work_function, (void*)&(client_args[idx]))) {
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

	char buffer[256];

	while (true) {
		bzero(buffer, 256);

		if (read(client->client_fd, buffer, 255) < 0) {
			perror("ERROR reading from socket");
			break;
		}

		if (buffer[0] == '\0') {
			if (write(client->client_fd, "ERRO                     invalid input\r\n", 40) < 0) {
				perror("ERROR writing to socket");
			}
			break;
		}

		receive_message_log(client, buffer);

		char *output = NULL;
		int len = 0;
		handle_message(buffer, &output, &len);

		if (write(client->client_fd, output, len) < 0) {
			perror("ERROR writing to socket");
			break;
		}
		send_message_log(client, output);
	}

	close(client->client_fd);

	pthread_mutex_lock(&lock);
	clients[client->thread_idx] = 0;
	client_count--;
	pthread_mutex_unlock(&lock);

	pthread_exit(NULL);

	return NULL;
}

/** Handle input message
 */
void handle_message(char *buffer, char **output, int *len) {
	int n = 0;
	char **input = split(buffer, &n);
    *output = NULL;
	*len = TEXT_LEN;
	if (!input) {
		*output = "ERRO                     invalid input\r\n";
		return;
	}
	char *command = input[0];
    if (!strcmp(command, "PING")) {
        *output = "PONG\r\n";
		*len = 6;
    } else if (!strcmp(command, "PONG")) {
		*output = "ERRO          reserved server response\r\n";
	} else if (!strcmp(command, "OKAY")) {
		*output = "ERRO   not okay to send OKAY to server\r\n";
	} else if (!strcmp(command, "ERRO")) {
		*output = "ERRO         should not send to server\r\n";
	} else if (!strcmp(command, "SOLN")) {
		if (n < 4) {
			*output = "ERRO               SOLN less arguments\r\n";
		} else if (is_solution(input[1], input[2], input[3])) {
			*output = "OKAY\r\n";
			*len = 6;
		} else {
			*output = "ERRO              solution is not okay\r\n";
		}
    } else if (!strcmp(command, "WORK")) {
		if (n < 5) {
			*output = "ERRO               WORK less arguments\r\n";
		} else {
			BYTE *solution = proof_of_work(input[1], input[2], input[3], input[4]);
			char *out = (char*)malloc((95 + 2) * sizeof(char));
			char *soln = (char*)malloc((16 + 1) * sizeof(char));
			for (int i = 0; i < 8; i++) {
				sprintf(soln+(2*i), "%02x", solution[i]);
			}
			sprintf(out, "SOLN %s %s %s\r\n", input[1], input[2], soln);
	        *output = out;
			*len = 95 + 2;
		}
    } else if (!strcmp(command, "ABRT")) {
		*output = "ERRO         me not implement this yet\r\n";
	} else {
        *output = "ERRO              unrecognized message\r\n";
    }
    return;
}

/** Tokenize the buffer, split string by space \r \n
 */
char **split(char *buffer, int *s) {
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
	// counter variable
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

	// concatenate with solution
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
	(void) worker_count_;

	// counter variable
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
	for (i = 0; i < 32; i++) { text[idx++] = seed[i]; }

	// find solution
	while (true) {
		// concatenate with nonce
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
			// increment nonce
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
		if (clients[i] != 0)
			pthread_cancel(clients[i]);
	}
	pthread_cancel(main_thread);
}
