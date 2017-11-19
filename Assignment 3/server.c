#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <netdb.h>
#include "proxy.h"

int maximum(int a, int b) {
	if (a > b)
		return a;
	return b;
}

int start_server(int port, unsigned char *key, char *destination, int d_port) {

    int client_socket_desc, client_sock, service_sock;
 	int c, read_size, write_size, iv_flag = 0;

    struct sockaddr_in server , client;
	struct sockaddr_in service_server;
	struct hostent *service_server_add;
	fd_set read_fds;
	struct timeval tv;

    char client_message[BUFFER_SIZE], server_reply[BUFFER_SIZE];
	char plaintext[BUFFER_SIZE], ciphertext[BUFFER_SIZE];
    char iv_enc[BUFFER_SIZE], iv_dec[BUFFER_SIZE];

	AES_KEY enc_key, dec_key; 
	struct ctr enc_state, dec_state;

    client_socket_desc = socket(AF_INET, SOCK_STREAM , 0);
    if (client_socket_desc == -1) {
        fprintf(stderr, "Could not create socket. Socket Error.\n");
		return -1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);
     
    if (bind(client_socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "Bind failed. Try different port. Socket Error.\n");
        return -1;
    }

    listen(client_socket_desc, 3);

    c = sizeof(struct sockaddr_in);

	service_server_add = gethostbyname(destination);

    service_server.sin_family = AF_INET;
    service_server.sin_port = htons(d_port);
	bcopy((char *) service_server_add->h_addr, (char *) &service_server.sin_addr.s_addr, service_server_add->h_length);

	memset(&client_message[0], 0, sizeof(client_message));
	memset(&plaintext[0], 0, sizeof(plaintext));
	memset(&server_reply[0], 0, sizeof(server_reply));
	memset(&ciphertext[0], 0, sizeof(ciphertext));
	memset(&iv_enc[0], 0, sizeof(iv_enc));
	memset(&iv_dec[0], 0, sizeof(iv_dec));

	tv.tv_sec = 120;

	while (1) {

		client_sock = accept(client_socket_desc, (struct sockaddr *) &client, (socklen_t*) &c);
		if (client_sock < 0) {
		    fprintf(stderr, "Could not accept client. Socket Error.\n");
		    return -1;
		} else {
			fprintf(stderr, "Client is connecting.\n");
		}

		if (iv_flag == 0) {

			service_sock = socket(AF_INET, SOCK_STREAM, 0);
			if (service_sock == -1) {
				fprintf(stderr, "Could not create socket. Socket Error.\n");
				return -1;
			}

			if (connect(service_sock , (struct sockaddr *)&service_server , sizeof(service_server)) < 0) {
				fprintf(stderr, "Could not connect. Socket Error.\n");
				return -1;
   			}

			memset(&client_message[0], 0, sizeof(client_message));
			memset(&plaintext[0], 0, sizeof(plaintext));
			memset(&server_reply[0], 0, sizeof(server_reply));
			memset(&ciphertext[0], 0, sizeof(ciphertext));
			memset(&iv_enc[0], 0, sizeof(iv_enc));
			memset(&iv_dec[0], 0, sizeof(iv_dec));

			if ((read_size = read(client_sock , iv_dec , BUFFER_SIZE)) < 0) {
				fprintf(stderr, "Could not read IV. Socket Error.\n");
				return -1;
			}

			if (!RAND_bytes((unsigned char*)iv_enc, AES_BLOCK_SIZE)) {
	    		fprintf(stderr, "Could not generate IV.\n");
				return -1;
			}

    		if (write(client_sock, iv_enc, strlen(iv_enc)) < 0) {
    			fprintf(stderr, "Could not send IV. Socket Error.\n");
				return -1;
    		}

			init_ctr(&enc_key, (unsigned const char*)key, &enc_state, (const unsigned char*)iv_enc);
			init_ctr(&dec_key, (unsigned const char*)key, &dec_state, (const unsigned char*)iv_dec);

			iv_flag = 1;
		}

		while (1) {

			FD_ZERO(&read_fds);
			FD_SET(client_sock, &read_fds);
			FD_SET(service_sock, &read_fds);

			if (select(maximum(client_sock, service_sock)+1, &read_fds, NULL, NULL, &tv) < 0) {
				fprintf(stderr, "Select Error. Socket Error.\n");
				return -1;
			} 

			if (FD_ISSET(client_sock, &read_fds)) {

				if ((read_size = read(client_sock, client_message, BUFFER_SIZE)) > 0) {

					decrypt(&dec_key, dec_state, client_message, plaintext, (unsigned const char*)key, (unsigned char*)iv_dec, read_size);

					write_size = write(service_sock, plaintext, read_size);
					if (write_size < 0) {
						break;
					}

					memset(&client_message[0], 0, sizeof(client_message));
					memset(&plaintext[0], 0, sizeof(plaintext));

					usleep(20000);
				} else {
					fprintf(stderr, "Client is disconnecting.\n");
					iv_flag = 0;
					close(service_sock);
					break;
				}
			} else if (FD_ISSET(service_sock, &read_fds)) { 
				
				if ((read_size = read(service_sock, server_reply, BUFFER_SIZE)) > 0) {

					encrypt(&enc_key, enc_state, server_reply, ciphertext, (unsigned const char*)key, (unsigned char*)iv_enc, read_size);

					write_size = write(client_sock, ciphertext, read_size);
					if (write_size < 0) {
						break;
					}

					memset(&server_reply[0], 0, sizeof(server_reply));
					memset(&ciphertext[0], 0, sizeof(ciphertext));

					usleep(20000);
				} else {
					fprintf(stderr, "Client is disconnecting.\n");
					iv_flag = 0;
					close(service_sock);
					break;
				}
			}
		}

		if (service_sock != -1)
			close(service_sock);

		if (client_sock != -1)
			close(client_sock);
	}
     
    return 0;
}
