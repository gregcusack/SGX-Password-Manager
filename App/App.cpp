#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <iostream>
#include <Enclave_u.h>
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

#ifndef USERCLASS_H
#define USERCLASS_H
#include "userclass.h"
#endif

#ifndef VAULT_H
#define VAULT_H
#include "vault.h"
#endif

#define MAX_BUFF_LEN 32
#define CONCAT_LEN 60
#define MAC_LEN 16

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
	printf("Ocall says: %s\n", str);
}

void create_vault() {
	FILE *f;
	f = fopen("test.dat", "a+");
	if(f == NULL) {
		std::cerr << "Error in file open" << std::endl;
		exit(1);
	}
	fclose(f);
}

void gen_random_password(uint8_t *s, const unsigned int len) {
  	int i;
	static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len] = 0;
}

int main(int argc, char** argv) {
	remove("test.dat");
	vault vault;
	create_vault();
	if(initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
		fprintf(stderr, "Fail to initialize enclave.");
		return 1;
	}

	uint8_t str[MAX_BUFF_LEN] = "Hello World!";
	uint8_t create_pw[MAX_BUFF_LEN];
	uint8_t login_password_test[MAX_BUFF_LEN];


	uint8_t cipher_str[CONCAT_LEN];
	char mac[MAC_LEN];
	uint8_t decrypted_str[MAX_BUFF_LEN];
		
	if(vault.full) {
		std::cerr << "Vault full!" << std::endl;
		exit(1);
	}

	gen_random_password(create_pw, MAX_BUFF_LEN);
	memcpy(login_password_test, create_pw, MAX_BUFF_LEN);
	

	
	sgx_status_t status = encrypt_str(global_eid, str, MAX_BUFF_LEN, cipher_str, CONCAT_LEN);
	if (status != SGX_SUCCESS) {
		std::cout << "fail" << std::endl;
	}

	memset(str, 0, MAX_BUFF_LEN);
	std::cout << "zeroed input str: " << str << std::endl;
	std::cout << "encypted string: " << cipher_str << std::endl;

	
	status = decrypt_str(global_eid, cipher_str, CONCAT_LEN, decrypted_str, MAX_BUFF_LEN);
	if (status != SGX_SUCCESS) {
		std::cout << "fail decrypting" << std::endl;
	}

	std::cout << "decrypted string: " << decrypted_str << std::endl;
	
	return 0;	
}
















