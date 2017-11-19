#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096

struct ctr {
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char cnt[AES_BLOCK_SIZE];
};

void init_ctr(AES_KEY *key, const unsigned char* enc_key, struct ctr *state, const unsigned char iv[16]);

int encrypt(AES_KEY *key, struct ctr state, char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv, int read_size);

int decrypt(AES_KEY *key, struct ctr state, char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv, int read_size);

int start_server(int port, unsigned char *key, char *destination, int d_port);

int start_client(char *destination, int d_port, unsigned char *key);


