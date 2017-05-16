#include "server.h"

int main(int argc, char* argv[]) {

	int socket_fd, client_fd, port_no, client_len;
	struct sockaddr_in server_addr, client_addr;

	if (argc < 2) {
		fprintf(stderr,"ERROR no port provided\n");
		exit(EXIT_FAILURE);
	}

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

	client_len = sizeof(client_addr);

	/* Accept a connection - block until a connection is ready to
	 be accepted. Get back a new file descriptor to communicate on. */

    while (true) {
        client_fd = accept(socket_fd, (struct sockaddr *) &client_addr, &client_len);

        if (client_fd < 0) {
    		perror("ERROR on accept");
    		exit(EXIT_FAILURE);
    	}

        client_t *client = (client_t*)malloc(sizeof(client_t));
        client->client_fd = client_fd;
		client->client_addr = client_addr;
		client->server_addr = server_addr;

		connection_log(client);

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, work_function, (void*)client)) {
            perror("ERROR to create thread");
            exit(EXIT_FAILURE);
        }
        if (pthread_detach(thread_id)) {
            perror("ERROR to detach thread");
            exit(EXIT_FAILURE);
        }
		// B U G !!! when client disconnected unexpectedly e.g. ctrl+c
    }

    /* close socket */

	//close(socket_fd);

	return 0;
}

/** work function for client thread
 */
void *work_function(void *param) {
    client_t *client = (client_t*) param;
    char buffer[256];

    //bzero(buffer, 256);

    /* Read characters from the connection,
    	then process */
	while (true) {
		bzero(buffer, 256);

	    if (read(client->client_fd, buffer, 255) < 0) {
	    	perror("ERROR reading from socket");
	    	exit(EXIT_FAILURE);
	    }

		int input_s = 0;
		char **input_v = buffer_reader(buffer, &input_s);
	    if (input_handler(client->client_fd, input_v, input_s) < 0) {
	    	perror("ERROR writing to socket");
	    	exit(EXIT_FAILURE);
	    }
	}

    return NULL;
}

/** tokenize the buffer
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

/** handle input message
 */
int input_handler(int client_fd, char **input_v, int input_s) {
	if (!input_v) {
		return write(client_fd, "ERRO                     invalid input\r\n", TEXT_LEN);
	}
    char *output = NULL;
	int len = TEXT_LEN;
	char *command = input_v[0];
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
		if (input_s < 4) {
			output = "ERRO               SOLN less arguments\r\n";
		} else if (is_solution(input_v[1], input_v[2], input_v[3])) {
			output = "OKAY\r\n";
			len = 6;
		} else {
			output = "ERRO              solution is not okay\r\n";
		}
    } else if (!strcmp(command, "WORK")) {
		if (input_s < 5) {
			output = "ERRO               WORK less arguments\r\n";
		} else {
			BYTE *solution = proof_of_work(input_v[1], input_v[2], input_v[3], input_v[4]);
			char *out = (char*)malloc((95 + 1) * sizeof(char));
			char *soln = (char*)malloc((16 + 1) * sizeof(char));
			char *buf = (char*)malloc(2 * sizeof(char));
			int idx = 0;
			for (int i = 0; i < 8; i++) {
				sprintf(buf, "%02x", solution[i]);
				soln[idx++] = buf[0];
				soln[idx++] = buf[1];
			}
			sprintf(out, "SOLN %s %s %s\r\n", input_v[1], input_v[2], soln);
	        output = out;
			len = 95 + 2;
		}
    } else if (!strcmp(command, "ABRT")) {
		output = "ERRO         me not implement this yet\r\n";
	} else {
        output = "ERRO              unrecognized message\r\n";
    }
    return write(client_fd, output, len);
}

/** handle SOLN message, return true if is a solution
 */
bool is_solution(const char *difficulty_, const char *seed_, const char *solution_) {
	int i = 0;

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
    uint32_t temp = beta;
    for (i = 0; i < 32; i++) {
        coefficient[31-i] = temp & 0xff;
        temp >>= 8;
    }

    uint256_exp(clean, base, (8 * (alpha - 3)));
    uint256_mul(target, coefficient, clean);

	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);

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

    uint256_init(clean);
	sha256_init(&ctx);
	sha256_update(&ctx, text, TEXT_LEN);
	sha256_final(&ctx, clean);

    sha256_init(&ctx);
	sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
	sha256_final(&ctx, result);

    if (sha256_compare(result, target) < 0) {
		return true;
    } else {
        return false;
    }
}

/** handle WORK message, return a solution
 */
BYTE *proof_of_work(const char *difficulty_, const char *seed_, const char *start_, const char *worker_count_) {
	int i = 0;

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
	uint32_t temp = beta;
	for (i = 0; i < 32; i++) {
		coefficient[31-i] = temp & 0xff;
		temp >>= 8;
	}

	uint256_exp(clean, base, (8 * (alpha - 3)));
	uint256_mul(target, coefficient, clean);

	SHA256_CTX ctx;
	BYTE result[SHA256_BLOCK_SIZE];
	uint256_init(result);
	while (true) {
		BYTE text[TEXT_LEN];
		int idx = 0;
		for (i = 0; i < 32; i++) { text[idx++] = seed[i]; }
		BYTE *nonce = (BYTE*)malloc(8 * sizeof(BYTE));
		char *soln_buf = (char*)malloc((16 + 1) * sizeof(char));
		sprintf(soln_buf, "%lx", start);
		for (i = 0; i < 16; i+=2) {
			buf[0] = soln_buf[i];
			buf[1] = soln_buf[i+1];
			nonce[i/2] = strtoull(buf, NULL, 16);
		}
		for (i = 0; i < 8; i++) { text[idx++] = nonce[i]; }

		uint256_init(clean);
		sha256_init(&ctx);
		sha256_update(&ctx, text, TEXT_LEN);
		sha256_final(&ctx, clean);

		sha256_init(&ctx);
		sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
		sha256_final(&ctx, result);

		if (sha256_compare(result, target) < 0) {
			return nonce;
		} else {
			start++;
			continue;
		}
	}
}

void connection_log(client_t *client) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[100];
	time_t now = time(0);
	strftime(time_buffer, 100, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) client connected\n", client->client_fd);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

void receive_message_log(client_t *client, char *message) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[100];
	time_t now = time(0);
	strftime(time_buffer, 100, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) server receive a message from client: %s\n", client->client_fd, message);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}

void send_message_log(client_t *client, char *message) {
	pthread_mutex_lock(&lock);

	fp = fopen("log.txt", "a");

	char time_buffer[100];
	time_t now = time(0);
	strftime(time_buffer, 100, "%d-%m-%Y %H:%M:%S", localtime(&now));

	char ip4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip4, INET_ADDRSTRLEN);

	fprintf(fp, "[%s](%s)", time_buffer, ip4);
	fprintf(fp, "(socket_id %d) server send a message to client: %s\n", client->client_fd, message);

	fclose(fp);

	pthread_mutex_unlock(&lock);
}
