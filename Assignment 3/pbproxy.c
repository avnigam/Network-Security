#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include "proxy.h"


void init_ctr(AES_KEY *key, const unsigned char* enc_key, struct ctr *state, const unsigned char iv[16]) {
    state->num = 0;
    memset(state->cnt, 0, AES_BLOCK_SIZE);

    memset(state->iv + 8, 0, 8);

    memcpy(state->iv, iv, 8);

    if (AES_set_encrypt_key(enc_key, 128, key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
    }
}

int encrypt(AES_KEY *key, struct ctr state, char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv, int read_size) {	

	AES_ctr128_encrypt((const unsigned char*)in_data, (unsigned char*)out_data, read_size, key, state.iv, state.cnt, &state.num);

	return 0;
}

int decrypt(AES_KEY *key, struct ctr state, char* in_data, char* out_data, const unsigned char* dec_key, unsigned char *iv, int read_size) {	

	AES_ctr128_encrypt((const unsigned char*)in_data, (unsigned char*)out_data, read_size, key, state.iv, state.cnt, &state.num);

	return 0;
}

int main(int argc, char **argv){

    extern int optind;
    extern char* optarg;

    char* destination = NULL; 
    char* port = NULL;
    char* keyfile = NULL;
    char* s_port = NULL;
	
	FILE *fp;
    char key[255];
	size_t nread;

    int help = 0;
    int option = 0;
	int ret_val = 0; 
    
    while ((option = getopt (argc, argv, "l:k:h")) != -1) {
        switch(option){
            case 'l':
                s_port = optarg;
                break;
            case 'k':
                keyfile = optarg;
            	break;
            case 'h':
                help = 1;
                break;
            default:
                help = 1;
        }
    }


    if (help) {
        fprintf(stderr, "USAGE: ./pbproxy [-l port] -k keyfile destination port \n");
		fprintf(stderr, "-l: Live capture from the network device <interface>. \n");
		fprintf(stderr, "-k: Read packets from <file> in tcpdump format. \n");
		fprintf(stderr, "destination: Keep only packets that contain <string> in their payload. \n");
		fprintf(stderr, "port: BPF filter that specifies which packets will be dumped.\n");
        return 0;
    }

    if (argc-optind != 2) {
        fprintf(stderr, "Please pass the right no. of arguments\n");
        fprintf(stderr, "Please Use \"./pbproxy -h\" for help\n");
        return -1;
    }

    destination = argv[optind];
	port = argv[optind+1];

    if(!(keyfile) || !(destination) || !(port)) {
        fprintf(stderr, "Invalid Arguments\n");
        fprintf(stderr, "Please Use \"./pbproxy -h\" for help\n");
        return -1;
    }

    fp = fopen(keyfile, "r");
	if (fp) {
    	while ((nread = fread(key, 1, sizeof key, fp)) > 0);
    	if (ferror(fp)) {
        	fprintf(stderr, "Invalid File Content.\n");
			return -1;
    	}
    	fclose(fp);
	} else {
		fprintf(stderr, "Invalid File.\n");
		fprintf(stderr, "Please Use \"./pbproxy -h\" for help\n");
		return -1;
	}

	if (s_port) {
		ret_val = start_server(atoi(s_port), (unsigned char*)key, destination, atoi(port));
	} else {
		ret_val = start_client(destination, atoi(port), (unsigned char*)key);
	}

    return ret_val;
}

