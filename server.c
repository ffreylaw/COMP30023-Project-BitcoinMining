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

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, work_function, (void*)client)) {
            perror("ERROR to create thread");
            exit(EXIT_FAILURE);
        }
        if (pthread_detach(thread_id)) {
            perror("ERROR to detach thread");
            exit(EXIT_FAILURE);
        }
    }

    /* close socket */

	close(socket_fd);

	return 0;
}

void *work_function(void *param) {
    client_t *client = (client_t*) param;
    char buffer[256];

    bzero(buffer, 256);

    /* Read characters from the connection,
    	then process */

    if (read(client->client_fd, buffer, 255) < 0) {
    	perror("ERROR reading from socket");
    	exit(EXIT_FAILURE);
    }

	char **input = buffer_reader(buffer);
    if (input_handler(client->client_fd, input) < 0) {
    	perror("ERROR writing to socket");
    	exit(EXIT_FAILURE);
    }

    return NULL;
}

char **buffer_reader(char* buffer) {
    char *ptr = strtok(buffer, " \r\n");
    char **array = (char**)malloc(sizeof(char*));
    int i = 0;
    while (ptr != NULL) {
        i++;
        array = (char**)realloc(array, i * sizeof(char*));
        array[i-1] = ptr;
        ptr = strtok(NULL, " \r\n");
    }
    return array;
}

int input_handler(int client_fd, char** input) {
    char *output = NULL;
    int len = 40;
    char *command = input[0];
    if (!strcmp(command, "PING")) {
        output = "PONG";
    } else if (!strcmp(command, "SOLN")) {
        uint32_t difficulty = strtoull(input[1], NULL, 16);
		BYTE seed[32];
	    uint256_init(seed);
	    char buf[2];
	    for (int i = 0; i < 64; i+=2) {
	        buf[0] = input[2][i];
	        buf[1] = input[2][i+1];
	        seed[i/2] = strtoull(buf, NULL, 16);
	    }
        uint64_t solution = strtoull(input[3], NULL, 16);
		BYTE *soln = proof_of_work(difficulty, seed, solution);
		if (soln != NULL) {
			output = "OKAY";
		}
    } else if (!strcmp(command, "WORK")) {
        output = "ERRO";
    } else {
        output = "ERRO";
    }
    return write(client_fd, output, len);
}

BYTE *proof_of_work(uint32_t difficulty, BYTE *seed, uint64_t solution) {
	int i = 0;
	uint64_t nonce = solution;

	BYTE base[32], coefficient[32], target[32];
    BYTE clean[32];
    uint256_init(base);
    uint256_init(coefficient);
    uint256_init(target);
    uint256_init(clean);

	uint32_t alpha = (MASK_ALPHA & difficulty) >> 24;
    uint32_t beta = MASK_BETA & difficulty;

    base[31] = 0x02;
    uint32_t temp = beta;
    for (i = 0; i < 32; i++) {
        coefficient[31-i] = temp & 0xff;
        temp >>= 8;
    }

    uint256_exp(clean, base, (8 * (alpha - 3)));
    uint256_mul(target, coefficient, clean);

	SHA256_CTX ctx;
	BYTE *soln = (BYTE*)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	uint256_init(soln);
    while (true) {
        char *text = (char*)malloc(sizeof(char));
        int count = 0;
        char *buf = NULL;
		buf = (char*)malloc(2 * sizeof(char));
        for (i = 0; i < 32; i++) {
            count+=2;
            text = (char*)realloc(text, count * sizeof(char));
            sprintf(buf, "%02x", seed[i]);
            text[count-2] = buf[0];
            text[count-1] = buf[1];
        }
        buf = (char*)malloc((32 + 1) * sizeof(char));
        sprintf(buf, "%lx", nonce);
        for (i = 0; i < strlen(buf); i++) {
            count++;
            text = (char*)realloc(text, count * sizeof(char));
            text[count-1] = buf[i];
        }

        BYTE out[SHA256_BLOCK_SIZE];
    	sha256_init(&ctx);
    	sha256_update(&ctx, text, strlen(text));
    	sha256_final(&ctx, out);

        sha256_init(&ctx);
    	sha256_update(&ctx, out, strlen(out));
    	sha256_final(&ctx, soln);

        if (sha256_compare(soln, target) < 0) {
			return soln;
        } else {
            nonce++;
        }
    }
	
	return NULL;
}
