#include <stdio.h> 
#include <string.h>    
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <netdb.h>
#include <openssl/rand.h>
#include "proxy.h"
 
int start_client(char *destination, int port, unsigned char *key) {

    int sock;
    struct sockaddr_in server;
	struct hostent *server_add;
	fd_set read_fds;
	struct timeval tv;

    char message[BUFFER_SIZE], server_reply[BUFFER_SIZE]; 
	char ciphertext[BUFFER_SIZE], plaintext[BUFFER_SIZE];
    char iv_enc[BUFFER_SIZE], iv_dec[BUFFER_SIZE];

	int read_size, write_size;

	AES_KEY enc_key, dec_key; 
	struct ctr enc_state, dec_state;

    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1) {
        fprintf(stderr, "Socket Creation Failed. Socket Error.\n");
		return -1;
    }
     
	server_add = gethostbyname(destination);

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
	bcopy((char *) server_add->h_addr, (char *) &server.sin_addr.s_addr, server_add->h_length);
 
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "Connection Failed. Socket Error.\n");
        return -1;
    }

	memset(&iv_enc[0], 0, sizeof(iv_enc));
	memset(&iv_dec[0], 0, sizeof(iv_dec));

	if (!RAND_bytes((unsigned char*)iv_enc, AES_BLOCK_SIZE)) {
    	fprintf(stderr, "Could not generate IV.\n");
        return -1;
	}

    if (write(sock, iv_enc, strlen(iv_enc)) < 0) {
    	fprintf(stderr, "IV Transfer Failed. Socket Error.\n");
        return -1;
    }

	if (read(sock, iv_dec, BUFFER_SIZE) < 0) {
    	fprintf(stderr, "IV Receive Failed. Socket Error.\n");
		return -1;
    }

	memset(&message[0], 0, sizeof(message));	
	memset(&server_reply[0], 0, sizeof(server_reply));
	memset(&plaintext[0], 0, sizeof(plaintext));
	memset(&ciphertext[0], 0, sizeof(ciphertext));	

	init_ctr(&enc_key, (unsigned const char*)key, &enc_state, (const unsigned char*)iv_enc);
	init_ctr(&dec_key, (unsigned const char*)key, &dec_state, (const unsigned char*)iv_dec);

	tv.tv_sec = 120;

    while(1)
    {
		FD_ZERO(&read_fds);
		FD_SET(STDIN_FILENO, &read_fds);
		FD_SET(sock, &read_fds);

		if (select(sock + 1, &read_fds, NULL, NULL, &tv) < 0) {
			fprintf(stderr, "Socket Error.\n");
			return -1;
		}

		if (FD_ISSET(STDIN_FILENO, &read_fds)) {

			if ((read_size = read(STDIN_FILENO, message, BUFFER_SIZE)) > 0) {
	
				encrypt(&enc_key, enc_state, message, ciphertext, (unsigned const char*) key, (unsigned char*) iv_enc, read_size);

				write_size = write(sock, ciphertext, read_size);
				if (write_size < 0) {
					break;
				}
					
				memset(&message[0], 0, sizeof(message));
				memset(&ciphertext[0], 0, sizeof(ciphertext));

				usleep(20000);
			} else {
				break;
			}			
		} else if (FD_ISSET(sock, &read_fds)) {

			if ((read_size = read(sock, server_reply, BUFFER_SIZE)) > 0) {
				
				decrypt(&dec_key, dec_state, server_reply, plaintext, (unsigned const char*) key, (unsigned char*) iv_dec, read_size);

				write_size = write(STDOUT_FILENO, plaintext, read_size);
				if (write_size < 0) {
					break;
				}

				memset(&server_reply[0], 0, sizeof(server_reply));
				memset(&plaintext[0], 0, sizeof(plaintext));

				usleep(20000);
			} else {
				break;			
			}
		} else {
			break;		
		}
    }

	if (sock != -1)
    	close(sock);

	if (STDIN_FILENO != -1)
		close(STDIN_FILENO);

	if (STDOUT_FILENO != -1)
		close(STDOUT_FILENO);

    return 0;
}
