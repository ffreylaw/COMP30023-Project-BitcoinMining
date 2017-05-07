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

    if (input_handler(client->client_fd, buffer_reader(buffer)) < 0) {
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
        ptr = strtok (NULL, " \r\n");
    }
    return array;
}

int input_handler(int client_fd, char** input) {
    char *output = NULL;
    int len = 0;
    char *command = input[0];
    if (!strcmp(command, "PING")) {
        output = "PONG";
        len = 4;
    } else if (!strcmp(command, "PONG")) {
        output = "ERRO: PONG messages are strictly reserved for server responses";
        len = 62;
    } else if (!strcmp(command, "OKAY")) {
        output = "ERRO: is not okay to send OKAY messages to the server";
        len = 53;
    } else if (!strcmp(command, "SOLN")) {
        BYTE difficulty[32], seed[64], solution[64];
    } else if (!strcmp(command, "WORK")) {
        output = "ERRO: incomplete implementation";
        len = 31;
    } else {
        output = "ERRO: this message should not be sent to the server";
        len = 51;
    }
    return write(client_fd, output, len);
}

BYTE *byte_converter(char *str) {

}
